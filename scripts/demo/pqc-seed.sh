#!/usr/bin/env bash
# Copyright (c) 2026 Thomas Pham — kimbo11ng
# SPDX-License-Identifier: Apache-2.0
#
# Seeds the running dev stack with the PQC demo: three certificate hierarchies, every CA key on
# the TestHSM token through kimbo11ng, and exports what the web server and pqc-check.sh need into
# .demo/pqc/. Safe to re-run: a key, CA or end entity that already exists is left alone.
#
#   hybrid     root  ECDSA P-384 + ML-DSA-87 alternative  ->  sub  ECDSA P-256 + ML-DSA-65
#              -> web certificate for localhost (served by the pqc-web container)
#   composite  root  MLDSA87-ECDSA-P384-SHA512  ->  sub  MLDSA65-ECDSA-P256-SHA512
#              -> web certificate for localhost (issued, but no TLS stack takes it yet)
#   ML-DSA     root  ML-DSA-87  ->  web certificate for localhost (ML-DSA-65 key; OpenSSL 3.5 serves
#              and accepts it, and so did Brave 1.98.63 / Chromium 156 with the root trusted)
#              and a document-signing certificate
#
# Needs: `just up` (EJBCA healthy), Maven on PATH (for the BouncyCastle classpath), Java 21.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"
OUT="$repo/.demo/pqc"
mkdir -p "$OUT"

TOKEN=TestHSM
PIN="${SOFTHSM_TOKEN_PIN:-1234}"
EE_PASSWORD=pqcdemo
ORG="O=kimbo11ng PQC demo,C=CH"

ejbca() { docker compose exec -T ejbca /opt/keyfactor/bin/ejbca.sh "$@" 2>&1 | sed 's/^.*(main) //'; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
step() { printf '  %-76s' "$*"; }
done_() { printf '%s\n' "${1:-done}"; }

run() { # an EJBCA CLI call that must succeed; its output is shown only on failure
    local out
    if ! out="$(docker compose exec -T ejbca /opt/keyfactor/bin/ejbca.sh "$@" 2>&1)"; then
        printf 'FAILED\n%s\n' "$(printf '%s' "$out" | sed 's/^.*(main) //' | tail -15)" >&2
        exit 1
    fi
}

classpath() {
    if [ ! -s "$OUT/classpath.txt" ]; then
        mvn -q dependency:build-classpath -Dmdep.outputFile="$OUT/classpath.txt" \
            -Dmdep.includeGroupIds=org.bouncycastle >/dev/null 2>&1
    fi
    cat "$OUT/classpath.txt"
}
pqcdemo() { java -cp "$(classpath)" "$repo/scripts/demo/PqcDemo.java" "$@"; }

has_key() { ejbca cryptotoken listkeys --token "$TOKEN" | grep -qE "^ $1	"; }
key() { # alias keyspec
    step "key $1 ($2)"
    if has_key "$1"; then done_ "exists"; return; fi
    run cryptotoken generatekey --token "$TOKEN" --alias "$1" --keyspec "$2"
    done_ "generated on the HSM"
}

ca_id() { ejbca ca listcas | awk -v n="CA Name: $1" '$0 ~ n"$" {getline; sub(/.*Id: */, ""); print; exit}'; }
props() { # sign-key [alternative-key] -> path of a token properties file inside the container
    local file="/tmp/pqcdemo-$1.properties"
    local body="certSignKey $1\ncrlSignKey $1\ndefaultKey $1\ntestKey $1\n"
    [ -n "${2:-}" ] && body="${body}alternativeCertSignKey $2\n"
    docker compose exec -T ejbca bash -c "printf '$body' > $file"
    echo "$file"
}
ca() { # name dn sigalg props validity-days [--signedby id --altsigalg alg ...]
    local name="$1" dn="$2" sigalg="$3" tokenprop="$4" days="$5"
    shift 5
    step "CA $name"
    if [ -n "$(ca_id "$name")" ]; then done_ "exists"; return; fi
    run ca init --caname "$name" --dn "$dn" --tokenName "$TOKEN" --tokenPass "$PIN" \
        --tokenprop "$tokenprop" -v "$days" --policy null -s "$sigalg" "$@"
    done_ "created, id $(ca_id "$name")"
}
cacert() { # name file
    run ca getcacert --caname "$1" -f "/tmp/$2"
    docker compose cp "ejbca:/tmp/$2" "$OUT/$2" >/dev/null 2>&1
}

has_ee() { ejbca ra findendentity --username "$1" | grep -q "Username: $1"; }
web_cert() { # username ca prefix
    local user="$1" ca="$2" prefix="$3"
    step "web certificate $prefix-web (CN=localhost, from $ca)"
    if [ -s "$OUT/$prefix-web.p12" ]; then done_ "exists"; return; fi
    if has_ee "$user"; then
        run ra setendentitystatus --username "$user" -S 10
    else
        run ra addendentity --username "$user" --dn "CN=localhost,$ORG" --altname "dNSName=localhost" \
            --caname "$ca" --type 1 --token P12 --certprofile SERVER --eeprofile EMPTY \
            --password "$EE_PASSWORD"
    fi
    run ra setclearpwd --username "$user" --password "$EE_PASSWORD"
    run batch --username "$user" -dir /tmp/pqcdemo-p12
    docker compose cp "ejbca:/tmp/pqcdemo-p12/$user.p12" "$OUT/$prefix-web.p12" >/dev/null 2>&1
    openssl pkcs12 -in "$OUT/$prefix-web.p12" -passin "pass:$EE_PASSWORD" -nokeys -clcerts \
        | openssl x509 -out "$OUT/$prefix-web.pem"
    openssl pkcs12 -in "$OUT/$prefix-web.p12" -passin "pass:$EE_PASSWORD" -nocerts -nodes \
        | openssl pkey -out "$OUT/$prefix-web.key"
    done_ "issued"
}

csr_cert() { # username dn altname certprofile prefix label: an ML-DSA-65 key made here, certified by the ML-DSA root
    local user="$1" dn="$2" altname="$3" profile="$4" prefix="$5"
    step "$6"
    if [ -s "$OUT/$prefix.pem" ]; then done_ "exists"; return; fi
    pqcdemo csr "$OUT/$prefix.key" "$OUT/$prefix.csr" "$dn" ML-DSA-65 >/dev/null 2>&1
    if has_ee "$user"; then
        run ra setendentitystatus --username "$user" -S 10
    else
        run ra addendentity --username "$user" --dn "$dn" ${altname:+--altname "$altname"} \
            --caname PQC-Demo-MLDSA-Root --type 1 --token USERGENERATED --certprofile "$profile" \
            --eeprofile EMPTY --password "$EE_PASSWORD"
    fi
    run ra setpwd --username "$user" --password "$EE_PASSWORD"
    docker compose cp "$OUT/$prefix.csr" "ejbca:/tmp/$user.csr" >/dev/null 2>&1
    run createcert --username "$user" --password "$EE_PASSWORD" -c "/tmp/$user.csr" -f "/tmp/$user.pem"
    docker compose cp "ejbca:/tmp/$user.pem" "$OUT/$prefix.pem" >/dev/null 2>&1
    done_ "issued"
}

say "PQC demo seed — keys on $TOKEN, output in ${OUT#"$repo/"}"
docker compose exec -T ejbca true 2>/dev/null || { echo "The ejbca container is not running: just up" >&2; exit 1; }
ejbca cryptotoken list | grep -q "\"$TOKEN\"" \
    || { echo "EJBCA has no crypto token named $TOKEN yet: just create-token" >&2; exit 1; }

say "1. Hybrid: a classical chain every client verifies, with an ML-DSA signature alongside"
key pqcdemo-hyb-root-ec P-384
key pqcdemo-hyb-root-mldsa ML-DSA-87
key pqcdemo-hyb-sub-ec P-256
key pqcdemo-hyb-sub-mldsa ML-DSA-65
ca PQC-Demo-Hybrid-Root "CN=PQC Demo Hybrid Root CA,$ORG" SHA384WithECDSA \
    "$(props pqcdemo-hyb-root-ec pqcdemo-hyb-root-mldsa)" 3650 --altsigalg ML-DSA-87
ca PQC-Demo-Hybrid-Sub "CN=PQC Demo Hybrid Sub CA,$ORG" SHA256WithECDSA \
    "$(props pqcdemo-hyb-sub-ec pqcdemo-hyb-sub-mldsa)" 1825 --altsigalg ML-DSA-65 \
    --signedby "$(ca_id PQC-Demo-Hybrid-Root)" -certprofile SUBCA
cacert PQC-Demo-Hybrid-Root hybrid-root.pem
cacert PQC-Demo-Hybrid-Sub hybrid-sub.pem
web_cert pqcdemo-hybrid-web PQC-Demo-Hybrid-Sub hybrid
cat "$OUT/hybrid-web.pem" "$OUT/hybrid-sub.pem" > "$OUT/hybrid-web-fullchain.pem"

say "2. Composite: every certificate signed with ML-DSA and ECDSA at once"
key pqcdemo-comp-root-COMPOSITE MLDSA87-ECDSA-P384-SHA512
key pqcdemo-comp-sub-COMPOSITE MLDSA65-ECDSA-P256-SHA512
ca PQC-Demo-Composite-Root "CN=PQC Demo Composite Root CA,$ORG" MLDSA87-ECDSA-P384-SHA512 \
    "$(props pqcdemo-comp-root-COMPOSITE)" 3650
ca PQC-Demo-Composite-Sub "CN=PQC Demo Composite Sub CA,$ORG" MLDSA65-ECDSA-P256-SHA512 \
    "$(props pqcdemo-comp-sub-COMPOSITE)" 1825 \
    --signedby "$(ca_id PQC-Demo-Composite-Root)" -certprofile SUBCA
cacert PQC-Demo-Composite-Root composite-root.pem
cacert PQC-Demo-Composite-Sub composite-sub.pem
web_cert pqcdemo-composite-web PQC-Demo-Composite-Sub composite

say "3. ML-DSA: post-quantum signatures end to end, in TLS between OpenSSL peers and on documents"
key pqcdemo-mldsa-root ML-DSA-87
ca PQC-Demo-MLDSA-Root "CN=PQC Demo ML-DSA Root CA,$ORG" ML-DSA-87 \
    "$(props pqcdemo-mldsa-root)" 3650
cacert PQC-Demo-MLDSA-Root mldsa-root.pem
csr_cert pqcdemo-signer "CN=PQC Demo Document Signer,$ORG" "" ENDUSER signer \
    "document-signing certificate (ML-DSA-65 key, kept off the HSM)"
csr_cert pqcdemo-mldsa-web "CN=localhost,$ORG" "dNSName=localhost" SERVER mldsa-web \
    "web certificate mldsa-web (ML-DSA-65 key, CN=localhost)"
step "a signed document"
printf 'Signed with ML-DSA-65 on %s by the kimbo11ng PQC demo.\n' "$(date -u +%Y-%m-%d)" > "$OUT/document.txt"
pqcdemo sign "$OUT/signer.key" "$OUT/signer.pem" "$OUT/document.txt" "$OUT/document.p7s" >/dev/null 2>&1
done_ "document.txt + document.p7s"

say "Done. Next: just demo-web (nginx, hybrid and ML-DSA sites), then just demo-check."

#!/usr/bin/env bash
# Copyright (c) 2026 Thomas Pham — kimbo11ng
# SPDX-License-Identifier: Apache-2.0
#
# Checks what pqc-seed.sh issued against the verifiers that exist today, and prints one line per
# check with the outcome expected in November 2026. A line is marked as a surprise when the outcome
# differs, in either direction: a composite chain that starts verifying in OpenSSL is news too.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"
OUT="$repo/.demo/pqc"
PORT="${PQC_DEMO_HTTPS_PORT:-8444}"
MLDSA_PORT="${PQC_DEMO_MLDSA_PORT:-8445}"
[ -s "$OUT/hybrid-web.pem" ] || { echo "Nothing to check yet: run just demo-seed first." >&2; exit 1; }

surprises=0
classpath() {
    if [ ! -s "$OUT/classpath.txt" ]; then
        mvn -q dependency:build-classpath -Dmdep.outputFile="$OUT/classpath.txt" \
            -Dmdep.includeGroupIds=org.bouncycastle >/dev/null
    fi
    cat "$OUT/classpath.txt"
}
pqcdemo() { java -cp "$(classpath)" "$repo/scripts/demo/PqcDemo.java" "$@" 2>&1; }

check() { # expected(pass|fail) label command...
    local expected="$1" label="$2"
    shift 2
    local output status=pass
    output="$("$@" 2>&1)" || status=fail
    local detail
    detail="$(printf '%s' "$output" | grep -m1 -E '^(OK|FAIL) ' | sed -E 's/^(OK|FAIL) //')"
    [ -n "$detail" ] || detail="$(printf '%s' "$output" | grep -v '^\s*$' | tail -1)"
    local mark
    if [ "$status" = "$expected" ]; then
        mark=$([ "$status" = pass ] && echo "  ok  " || echo " fails")
    else
        mark=" SURPRISE"
        surprises=$((surprises + 1))
    fi
    printf '%-9s %-46s %s\n' "$mark" "$label" "${detail:0:110}"
}
section() { printf '\n\033[1m%s\033[0m\n' "$*"; }

openssl_verify() { openssl verify -CAfile "$1" ${3:+-untrusted "$2"} "${3:-$2}"; }
tls_openssl() { # port root: what the demo web server negotiated with OpenSSL as the client
    local out
    out="$(echo Q | timeout 10 openssl s_client -connect "localhost:$1" -servername localhost \
        -CAfile "$2" -verify_return_error 2>&1)" || { printf '%s' "$out" | tail -2; return 1; }
    printf 'OK %s, server signed with %s, %s\n' \
        "$(printf '%s' "$out" | grep -m1 -oE 'Negotiated TLS1.3 group: [A-Za-z0-9]+' | sed 's/Negotiated TLS1.3 //')" \
        "$(printf '%s' "$out" | grep -m1 -oE 'Peer signature type: [A-Za-z0-9_]+' | sed 's/Peer signature type: //')" \
        "$(printf '%s' "$out" | grep -m1 -oE 'Verify return code: [0-9]+ \([a-z ]+\)' | sed 's/Verify return code/verify/')"
}
tls_curl() { # url root
    curl -sS --cacert "$2" "$1" | grep -m1 -E 'group=' | sed 's/^/OK /'
}
serve_composite() { # can OpenSSL, as nginx would, load the composite chain at all?
    local out
    out="$(timeout 3 openssl s_server -accept 28999 -cert "$OUT/composite-web.pem" \
        -key "$OUT/composite-web.key" -cert_chain "$OUT/composite-sub.pem" 2>&1)"
    if printf '%s' "$out" | grep -q "error setting certificate chain"; then
        echo "FAIL OpenSSL cannot load the chain: it does not decode a composite public key"
        return 1
    fi
    echo "OK OpenSSL loaded the chain"
}
openssl_cms() {
    openssl cms -verify -binary -inform DER -in "$OUT/document.p7s" -content "$OUT/document.txt" \
        -CAfile "$OUT/mldsa-root.pem" -purpose any -out /dev/null && echo "OK OpenSSL verified the CMS signature"
}

section "The certificates"
pqcdemo describe "$OUT"/hybrid-root.pem "$OUT"/hybrid-sub.pem "$OUT"/hybrid-web.pem \
    "$OUT"/composite-root.pem "$OUT"/composite-sub.pem "$OUT"/composite-web.pem \
    "$OUT"/mldsa-root.pem "$OUT"/signer.pem | sed 's/^/  /'

section "1. Hybrid chain (ECDSA + ML-DSA alternative signatures)"
check pass "BouncyCastle: path web -> sub -> root" pqcdemo chain "$OUT/hybrid-root.pem" "$OUT/hybrid-sub.pem" "$OUT/hybrid-web.pem"
check pass "OpenSSL 3.5: path, classical signatures" openssl_verify "$OUT/hybrid-root.pem" "$OUT/hybrid-sub.pem" "$OUT/hybrid-web.pem"
check pass "ML-DSA alternative signature: sub by root" pqcdemo altsig "$OUT/hybrid-root.pem" "$OUT/hybrid-sub.pem"
check pass "ML-DSA alternative signature: web by sub" pqcdemo altsig "$OUT/hybrid-sub.pem" "$OUT/hybrid-web.pem"
if docker compose --profile demo ps --status running pqc-web 2>/dev/null | grep -q pqc-web; then
    check pass "TLS to pqc-web, OpenSSL client" tls_openssl "$PORT" "$OUT/hybrid-root.pem"
    check pass "TLS to pqc-web, curl" tls_curl "https://localhost:$PORT/tls" "$OUT/hybrid-root.pem"
else
    printf '%-9s %-46s %s\n' "  skip" "TLS to pqc-web" "not running: just demo-web"
fi

section "2. Composite chain (ML-DSA and ECDSA in every signature)"
check pass "BouncyCastle: path web -> sub -> root" pqcdemo chain "$OUT/composite-root.pem" "$OUT/composite-sub.pem" "$OUT/composite-web.pem"
check fail "OpenSSL 3.5: path" openssl_verify "$OUT/composite-root.pem" "$OUT/composite-sub.pem" "$OUT/composite-web.pem"
check fail "OpenSSL 3.5 as a TLS server (nginx, Apache)" serve_composite

section "3. ML-DSA chain: a web certificate and a signed document"
check pass "BouncyCastle: path web -> root" pqcdemo chain "$OUT/mldsa-root.pem" "$OUT/mldsa-web.pem"
check pass "OpenSSL 3.5: path web -> root" openssl_verify "$OUT/mldsa-root.pem" "$OUT/mldsa-web.pem"
if docker compose --profile demo ps --status running pqc-web 2>/dev/null | grep -q pqc-web; then
    check pass "TLS to the ML-DSA site, OpenSSL client" tls_openssl "$MLDSA_PORT" "$OUT/mldsa-root.pem"
    check pass "TLS to the ML-DSA site, curl" tls_curl "https://localhost:$MLDSA_PORT/" "$OUT/mldsa-root.pem"
else
    printf '%-9s %-46s %s\n' "  skip" "TLS to the ML-DSA site" "not running: just demo-web"
fi
check pass "BouncyCastle: path signer -> root" pqcdemo chain "$OUT/mldsa-root.pem" "$OUT/signer.pem"
check pass "OpenSSL 3.5: path signer -> root" openssl_verify "$OUT/mldsa-root.pem" "$OUT/signer.pem"
check pass "BouncyCastle: CMS signature and its chain" pqcdemo verify "$OUT/document.p7s" "$OUT/document.txt" "$OUT/mldsa-root.pem"
check pass "OpenSSL 3.5: CMS signature and its chain" openssl_cms

section "What this shows"
cat <<SUMMARY
  Works today
    - Post-quantum key exchange: every connection above negotiated X25519MLKEM768.
    - Hybrid certificates: every client accepts the chain on its ECDSA signatures; the ML-DSA
      alternative signatures verify too, for whoever checks them (BouncyCastle here).
    - ML-DSA certificates: OpenSSL 3.5 serves and accepts them in TLS 1.3, so post-quantum
      authentication works with a root you trust (curl, services, internal PKI), and ML-DSA
      signatures work on documents, code and firmware.
  Not yet
    - Composite certificates: no TLS stack serves or accepts them; OpenSSL cannot even decode the
      public key. They verify in BouncyCastle only.
    - Browsers ignore the ML-DSA half of a hybrid chain. Brave 1.98.63 (Chromium 156) accepted the
      ML-DSA site once its root was trusted (measured by hand, docs/PQC_DEMO.md); other browsers
      untested. Open https://localhost:$MLDSA_PORT/ to see yours.
  The CA side is ready for all three; what limits the rollout is the relying parties.
SUMMARY
if [ "$surprises" -gt 0 ]; then
    printf '\n%d check(s) did not match what was expected in November 2026; see SURPRISE above.\n' "$surprises"
    exit 1
fi

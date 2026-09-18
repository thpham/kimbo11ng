#!/usr/bin/env bash
#
# Copyright (c) 2026 Thomas Pham — kimbo11ng
# SPDX-License-Identifier: Apache-2.0
#
# Proves that an existing deployment survives an EJBCA image swap: starts OLD_IMAGE, builds state on
# it, stops it, starts NEW_IMAGE on the same database and the same token, and checks that the state
# is still there and still usable. This is the test the integration suite cannot be, because the
# suite always starts from an empty database.
#
#   scripts/upgrade-swap.sh OLD_IMAGE NEW_IMAGE
#
# Both are locally built kimbo11ng images (`docker build -f docker/Dockerfile -t ...`), the old one
# from a checkout of the previous release, since the two ship different jars. What it does:
#
#   1. on OLD: creates a Pkcs11NgCryptoToken with EJBCA's own CLI, generates ML-DSA-65, RSA-2048 and
#      ML-KEM-768 keys, initialises a CA on the ML-DSA key and has it sign a CRL;
#   2. stops OLD, keeping the volumes;
#   3. starts NEW on those volumes, so EJBCA runs its own database upgrade;
#   4. has the CA sign another CRL, tests the CA key, and lists the keys and the stored token type.
#
# It passes when the second CRL is signed, the key fingerprints are the ones from step 1, and EJBCA
# does not refuse the token at start-up. It exits non-zero on the first failing step and prints what
# it saw either way. Host ports 18080/18443/19443 are used (EJBCA_HTTP_PORT, EJBCA_HTTPS_PORT and
# EJBCA_RA_PORT in docker-compose.yml), so it does not collide with a service on 8080. It removes its containers and volumes when it finishes.

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 OLD_IMAGE NEW_IMAGE" >&2
    exit 2
fi
OLD_IMAGE="$1"
NEW_IMAGE="$2"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
PROJECT="kimbo11ng-swap"
cd "$ROOT"

# Host ports for this run, through the variables docker-compose.yml reads.
export EJBCA_HTTP_PORT=18080 EJBCA_HTTPS_PORT=18443 EJBCA_RA_PORT=19443

dc() { # dc IMAGE args...
    local image="$1"; shift
    printf 'services:\n  ejbca:\n    image: %s\n' "$image" > "$WORK/image.yml"
    docker compose -p "$PROJECT" -f docker-compose.yml -f "$WORK/image.yml" "$@"
}
ej() { docker compose -p "$PROJECT" exec -T ejbca /opt/keyfactor/bin/ejbca.sh "$@" 2>&1 | grep -v '^$'; }
sql() { docker compose -p "$PROJECT" exec -T postgres psql -U ejbca -d ejbca -tAc "$1"; }
cleanup() { dc "$NEW_IMAGE" down -v >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

wait_healthy() {
    local status=""
    for _ in $(seq 1 40); do
        status="$(docker inspect -f '{{.State.Health.Status}}' "${PROJECT}-ejbca-1" 2>/dev/null || true)"
        [ "$status" = healthy ] && return 0
        sleep 10
    done
    echo "EJBCA did not become healthy (last status: ${status:-none})" >&2
    docker compose -p "$PROJECT" logs ejbca 2>&1 | grep -E 'ERROR|does not support' | tail -8 >&2 || true
    return 1
}
fingerprints() { ej cryptotoken listkeys --token NgSwap | awk '/(upgCA|upgRsa|upgKem)/ {print $(NF-3), $NF}' | sort; }

echo "== OLD: $OLD_IMAGE"
dc "$OLD_IMAGE" up -d >/dev/null
wait_healthy
ej cryptotoken create --token NgSwap --pin 1234 --autoactivate true --type Pkcs11NgCryptoToken \
    --lib /usr/local/lib/softhsm/libsofthsmv3.so --slotlabeltype SLOT_LABEL --slotlabel TestToken >/dev/null
ej cryptotoken generatekey --token NgSwap --alias upgCA --keyspec ML-DSA-65 >/dev/null
ej cryptotoken generatekey --token NgSwap --alias upgRsa --keyspec 2048 >/dev/null
ej cryptotoken generatekey --token NgSwap --alias upgKem --keyspec ML-KEM-768 >/dev/null
docker compose -p "$PROJECT" exec -T ejbca bash -c \
    "printf 'certSignKey upgCA\ncrlSignKey upgCA\ndefaultKey upgCA\ntestKey upgCA\n' > /tmp/swap.properties"
ej ca init --caname SwapRootCA --dn "CN=Swap Root CA,O=ithings,C=CH" --tokenName NgSwap \
    --tokenPass 1234 --tokenprop /tmp/swap.properties --keyspec ML-DSA-65 --keytype ML-DSA \
    -v 3650 --policy null -s ML-DSA-65 >/dev/null
echo "   $(ej ca createcrl --caname SwapRootCA | tail -1 | sed 's/.*(main) //')"
before="$(fingerprints)"
echo "   key fingerprints before:"; echo "$before" | sed 's/^/     /'
dc "$OLD_IMAGE" stop ejbca >/dev/null

echo "== NEW: $NEW_IMAGE (same database, same token)"
dc "$NEW_IMAGE" up -d >/dev/null
wait_healthy
echo "   stored token type: $(sql "SELECT tokenType FROM CryptoTokenData WHERE tokenName='NgSwap'")"
echo "   $(ej ca createcrl --caname SwapRootCA | tail -1 | sed 's/.*(main) //')"
echo "   $(ej cryptotoken testkey --token NgSwap --alias upgCA | tail -1 | sed 's/.*(main) //')"
after="$(fingerprints)"
echo "   key fingerprints after:"; echo "$after" | sed 's/^/     /'

if [ "$before" != "$after" ] || [ -z "$after" ]; then
    echo "FAIL: the keys on the token are not the ones that were there before the swap" >&2
    exit 1
fi
echo "PASS: the CA survived the swap and signs with the same keys"

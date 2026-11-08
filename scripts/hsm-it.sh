#!/usr/bin/env bash
#
# Copyright (c) 2026 Thomas Pham — kimbo11ng
# SPDX-License-Identifier: Apache-2.0
#
# Runs HsmConformanceIT — the HsmContract suite — against the SoftHSMv3 inside the kimbo11ng image,
# on a fresh token that disappears with the container.
#
#   scripts/hsm-it.sh            # or: just hsm-it
#
# Why a container: HsmConformanceIT needs a real PKCS#11 library, and the only one this project
# has is SoftHSMv3, which exists only inside the image — compiled for its AlmaLinux base, against an
# OpenSSL that lives at /opt/openssl in the image. Rather than bring that library to the host, this
# brings the tests to the library: the compiled classes and the Maven repository are mounted
# read-only, and the JUnit console launcher runs the one test class, since the image has a JDK and
# no Maven.
#
# What it tests is this checkout, not the image: the classes come from target/, and the image only
# supplies the library. A rebuilt image is needed only when SoftHSMv3 or OpenSSL change.
#
# The same suite runs on every build against FakeToken (HsmContractFakeTest). What this adds is the
# answer to every question the fake can only assume — that a post-quantum signature made by the
# library verifies with BouncyCastle, that CK_SIGN_ADDITIONAL_CONTEXT is read as kimbo11ng writes
# it, that CKA_ID survives re-enumeration.
#
# KIMBO11NG_IMAGE overrides the image. Reports: target/hsm-it/reports.

set -euo pipefail

IMAGE="${KIMBO11NG_IMAGE:-ghcr.io/thpham/kimbo11ng-ejbca:latest}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/target/hsm-it"
LIB=/usr/local/lib/softhsm/libsofthsmv3.so

docker image inspect "$IMAGE" > /dev/null 2>&1 || {
    echo "Image $IMAGE is not in the local daemon. Run 'just docker-build' first." >&2
    exit 1
}

cd "$REPO"
echo "Compiling the test classes (unit and integration)..."
mvn -q -Pit test-compile

mkdir -p "$OUT"
mvn -q -Pit dependency:build-classpath -Dmdep.includeScope=test -Dmdep.outputFile="$OUT/classpath.txt"
M2="$(mvn -q help:evaluate -Dexpression=settings.localRepository -DforceStdout)"

# The console launcher has to match the JUnit Platform the tests compile against, so its version is
# read off the classpath Maven just resolved rather than written down a second time.
PLATFORM="$(grep -o 'junit-platform-engine/[^/]*' "$OUT/classpath.txt" | head -1 | cut -d/ -f2)"
if [ -z "$PLATFORM" ]; then
    echo "Could not find junit-platform-engine on the test classpath." >&2
    exit 1
fi
CONSOLE="junit-platform-console-standalone-$PLATFORM.jar"
mvn -q dependency:copy \
    -Dartifact="org.junit.platform:junit-platform-console-standalone:$PLATFORM" \
    -DoutputDirectory="$OUT"

CP="$REPO/target/test-classes:$REPO/target/classes:$(cat "$OUT/classpath.txt")"
rm -rf "$OUT/reports"

echo "Running HsmConformanceIT against $LIB in $IMAGE..."
# The host's own user, so the reports under target/ are not left owned by root. The token store is
# moved to the container's /tmp for the same reason: the image's own is owned by EJBCA's user.
# The heredoc is unquoted on purpose — the paths are the host's, expanded here. The output is kept
# in console.txt as well as shown, for the check after it; pipefail keeps docker's exit status.
(
docker run --rm -i \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -v "$REPO:$REPO:ro" \
    -v "$OUT:$OUT" \
    -v "$M2:$M2:ro" \
    --entrypoint bash \
    "$IMAGE" -s <<EOF
set -euo pipefail
mkdir -p /tmp/softhsm/tokens
printf 'directories.tokendir = /tmp/softhsm/tokens/\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' \
    > /tmp/softhsm/softhsm.conf
export SOFTHSM2_CONF=/tmp/softhsm/softhsm.conf
/usr/local/bin/softhsm2-util --init-token --free --label HsmIt --pin 1234 --so-pin 12345678 > /dev/null

# --fail-if-no-tests: HsmConformanceIT skips itself when kimbo11ng.it.lib is unset, and a run that
# skipped everything must not read as a pass.
java \
    -Dkimbo11ng.it.lib=$LIB \
    -Dkimbo11ng.it.slotType=SLOT_LABEL \
    -Dkimbo11ng.it.slot=HsmIt \
    -Dkimbo11ng.it.pin=1234 \
    -jar "$OUT/$CONSOLE" execute \
    -cp "$CP" \
    --select-class ch.ithings.kimbo11ng.it.HsmConformanceIT \
    --details=tree --disable-banner --disable-ansi-colors --fail-if-no-tests \
    --reports-dir="$OUT/reports"
EOF
) | tee "$OUT/console.txt"

# HsmContract skips a test, through an assumption, when the token lacks what it needs — right for
# an arbitrary HSM, wrong here. This SoftHSMv3 is known to have everything the contract asks for,
# so a skipped test means the library lost something it had, and the console launcher would still
# report success.
aborted="$(grep -oE '[0-9]+ (tests|containers) aborted' "$OUT/console.txt" | awk '{n += $1} END {print n + 0}')"
if [ "$aborted" -ne 0 ]; then
    echo "$aborted test(s) or container(s) were skipped by an assumption; see $OUT/console.txt." >&2
    echo "Against this SoftHSMv3 every HsmContract test is expected to run." >&2
    exit 1
fi

echo "Reports: $OUT/reports"

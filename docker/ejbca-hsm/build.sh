#!/usr/bin/env bash
#
# Copyright (c) 2026 Thomas Pham — kimbo11ng
# SPDX-License-Identifier: Apache-2.0
#
# Builds the two artefacts that let EJBCA Community Edition 9.6 run HSM crypto tokens, using the JDK
# that ships in the EJBCA image itself. Run inside a container of the pinned image, as root:
#
#   ejbca-ejb.jar         the official jar with the start-up check emptied (StartupCheckPatcher)
#   ejbca-hsm-tokens.jar  PKCS11CryptoToken, AzureCryptoToken and AzureProvider, compiled
#
# Both land in $OUT. docker/Dockerfile's `hsm-build` stage runs this and its final stage copies them
# in. Compiling with the image's own javac means the class files are the version of the JVM that
# loads them, and there is no second toolchain image to pin.
#
# Every step that can find the wrong thing fails the build. That is the design: a check that quietly
# stopped matching would give an image that builds and then refuses to start its CA.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# The image's JDK has javac, jar and javap next to java, but only java is on PATH.
PATH="$(dirname "$(readlink -f "$(command -v java)")"):$PATH"
EAR="${EAR:-/opt/keyfactor/ejbca/dist/ejbca.ear}"
OUT="${OUT:-/out}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ASM rewrites the one method. It is fetched, checked and used here and never copied into the image.
# The SHA-256 is Maven Central's published one, and it matches the published SHA-1 as well.
ASM_VERSION=9.7.1
ASM_SHA256=8cadd43ac5eb6d09de05faecca38b917a040bb9139c7edeb4cc81c740b713281

mkdir -p "$OUT"

echo "== ASM ${ASM_VERSION}"
curl -fsSL -o "$WORK/asm.jar" \
    "https://repo1.maven.org/maven2/org/ow2/asm/asm/${ASM_VERSION}/asm-${ASM_VERSION}.jar"
printf '%s  %s\n' "$ASM_SHA256" "$WORK/asm.jar" | sha256sum -c -

echo "== start-up check"
cp "$EAR/lib/ejbca-ejb.jar" "$WORK/ejbca-ejb.jar"
java -cp "$WORK/asm.jar" "$HERE/StartupCheckPatcher.java" "$WORK/ejbca-ejb.jar"

# The patcher checks itself; this is the same claim made independently, from javap.
body="$(javap -p -c -cp "$WORK/ejbca-ejb.jar" org.ejbca.core.ejb.StartupSingletonBean \
    | sed -n '/void checkHsmTokensNotUsedInCommunityEdition()/,/^$/p' \
    | grep -E '^ +[0-9]+: ')"
if [ "$(printf '%s\n' "$body" | wc -l)" -ne 1 ] || ! printf '%s' "$body" | grep -qE '^ +0: return$'; then
    echo "the start-up check is not a bare return after patching:" >&2
    printf '%s\n' "$body" >&2
    exit 1
fi
echo "   javap: checkHsmTokensNotUsedInCommunityEdition() is a single 'return'"
install -m 0664 "$WORK/ejbca-ejb.jar" "$OUT/ejbca-ejb.jar"

echo "== crypto token classes"
classes="org/cesecore/keys/token/PKCS11CryptoToken.class
org/cesecore/keys/token/AzureCryptoToken.class
org/cesecore/keys/token/AzureProvider.class"
# Two classes of one name on the EAR classpath load in an unspecified order. Refuse to add a second.
for jar in "$EAR"/lib/*.jar; do
    for cls in $classes; do
        if jar tf "$jar" | grep -qx "$cls"; then
            echo "$jar already contains $cls; this release ships the class again and the overlay" \
                "would collide with it. See docs/EJBCA_UPSTREAM_WATCH.md, W2." >&2
            exit 1
        fi
    done
done

mkdir -p "$WORK/classes"
# -proc:none: nothing here uses annotation processing, and an image's classpath is full of jars
# that would otherwise be scanned for processors.
javac --release 21 -proc:none -nowarn -encoding UTF-8 \
    -cp "$EAR/lib/*" -d "$WORK/classes" \
    "$HERE"/src/org/cesecore/keys/token/*.java
jar --create --file "$OUT/ejbca-hsm-tokens.jar" --date=2026-01-01T00:00:00Z -C "$WORK/classes" .
chmod 0664 "$OUT/ejbca-hsm-tokens.jar"
for cls in $classes; do
    jar tf "$OUT/ejbca-hsm-tokens.jar" | grep -qx "$cls" \
        || { echo "$cls is missing from ejbca-hsm-tokens.jar" >&2; exit 1; }
done
echo "   $(jar tf "$OUT/ejbca-hsm-tokens.jar" | grep -c '\.class$') classes in ejbca-hsm-tokens.jar"
echo "== done"

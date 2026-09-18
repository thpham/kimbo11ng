#!/usr/bin/env bash
#
# Copyright (c) 2026 Thomas Pham — kimbo11ng
# SPDX-License-Identifier: Apache-2.0
#
# What StartupCheckPatcher does, and — the point of this file — what it refuses to do.
#
# The patcher's value is not that it empties a method; it is that it fails loudly on the day EJBCA
# moves, renames or duplicates the check, instead of producing an image that builds and then will
# not start its CA. Those refusals were verified by hand once, against jars built on the spot. This
# turns each of them into a case that runs in seconds, against synthetic classes shaped like the
# real one, with no EJBCA image needed.
#
#   ./test.sh
#
# Needs javac, jar and java on PATH (any JDK 17+) and network access for ASM, or ASM_JAR pointing at
# a copy. Run inside the image with the same PATH fix build.sh applies if the host has no JDK:
#   PATH="$(dirname "$(readlink -f "$(command -v java)")"):$PATH" ./test.sh

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ASM_VERSION=9.7.1
ASM_SHA256=8cadd43ac5eb6d09de05faecca38b917a040bb9139c7edeb4cc81c740b713281

if [ -n "${ASM_JAR:-}" ]; then
    asm="$ASM_JAR"
else
    asm="$WORK/asm.jar"
    curl -fsSL -o "$asm" \
        "https://repo1.maven.org/maven2/org/ow2/asm/asm/${ASM_VERSION}/asm-${ASM_VERSION}.jar"
    printf '%s  %s\n' "$ASM_SHA256" "$asm" | sha256sum -c - >/dev/null
fi

passed=0
failed=0

# Builds a jar holding one synthetic org.ejbca.core.ejb.StartupSingletonBean.
#
# $1 the jar to write, $2 the body of the class. Only the shapes the patcher inspects matter: the
# class name, the method name and descriptor, and which methods call hasNonCeSupportedTokenTypes.
# Nothing here links against EJBCA.
build_jar() {
    local jar="$1" body="$2" dir
    dir="$(mktemp -d "$WORK/src.XXXXXX")"
    mkdir -p "$dir/org/ejbca/core/ejb"
    cat > "$dir/org/ejbca/core/ejb/StartupSingletonBean.java" <<EOF
package org.ejbca.core.ejb;

public class StartupSingletonBean {

    private boolean hasNonCeSupportedTokenTypes() {
        return true;
    }

    private boolean isRunningEnterprise() {
        return false;
    }

${body}
}
EOF
    javac -nowarn -d "$dir/classes" "$dir/org/ejbca/core/ejb/StartupSingletonBean.java"
    jar --create --file "$jar" -C "$dir/classes" .
}

# $1 label, $2 expected outcome (pass|fail), $3 substring the output must contain, $4 jar
expect() {
    local label="$1" outcome="$2" needle="$3" jar="$4" out rc=0
    out="$(java -cp "$asm" "$HERE/StartupCheckPatcher.java" "$jar" 2>&1)" || rc=$?
    if [ "$outcome" = pass ] && [ "$rc" -ne 0 ]; then
        echo "FAIL $label: expected success, got exit $rc: $out" >&2
        failed=$((failed + 1))
        return
    fi
    if [ "$outcome" = fail ] && [ "$rc" -eq 0 ]; then
        echo "FAIL $label: expected a refusal, but it patched the jar: $out" >&2
        failed=$((failed + 1))
        return
    fi
    if ! printf '%s' "$out" | grep -qF "$needle"; then
        echo "FAIL $label: output did not mention '$needle': $out" >&2
        failed=$((failed + 1))
        return
    fi
    echo "ok   $label"
    passed=$((passed + 1))
}

# The real shape: the check calls hasNonCeSupportedTokenTypes and throws.
real_body='    private void checkHsmTokensNotUsedInCommunityEdition() {
        if (!isRunningEnterprise() && hasNonCeSupportedTokenTypes()) {
            throw new IllegalStateException("HSM crypto tokens are not supported in CE");
        }
    }'

echo "== the check as it stands"
build_jar "$WORK/ok.jar" "$real_body"
expect "patches the check" pass "patched checkHsmTokensNotUsedInCommunityEdition" "$WORK/ok.jar"

# javap, independently of the patcher's own verification — the same claim build.sh makes.
body="$(javap -p -c -cp "$WORK/ok.jar" org.ejbca.core.ejb.StartupSingletonBean \
    | sed -n '/void checkHsmTokensNotUsedInCommunityEdition()/,/^$/p' \
    | grep -E '^ +[0-9]+: ')"
if [ "$(printf '%s\n' "$body" | wc -l)" -eq 1 ] && printf '%s' "$body" | grep -qE '^ +0: return$'; then
    echo "ok   javap agrees the body is a single 'return'"
    passed=$((passed + 1))
else
    echo "FAIL javap: the body is not a single return: $body" >&2
    failed=$((failed + 1))
fi

# Running the image build twice must not rewrite an already-rewritten jar.
expect "is idempotent" pass "already patched" "$WORK/ok.jar"

echo "== the refusals"

# EJBCA moves the check to another class, or renames the bean.
jar --create --file "$WORK/empty.jar" -C "$WORK" /dev/null 2>/dev/null || {
    mkdir -p "$WORK/nothing"
    jar --create --file "$WORK/empty.jar" -C "$WORK/nothing" .
}
expect "refuses a jar without the class" fail "is not in" "$WORK/empty.jar"

# The method is renamed: the check still exists, somewhere, under another name.
build_jar "$WORK/renamed.jar" '    private void checkHsmTokensNotAllowed() {
        if (!isRunningEnterprise() && hasNonCeSupportedTokenTypes()) {
            throw new IllegalStateException("HSM crypto tokens are not supported in CE");
        }
    }'
expect "refuses a renamed method" fail "was renamed or" "$WORK/renamed.jar"

# The method survives but no longer enforces this: patching it would be guesswork.
build_jar "$WORK/changed.jar" '    private void checkHsmTokensNotUsedInCommunityEdition() {
        if (!isRunningEnterprise()) {
            throw new IllegalStateException("something else entirely");
        }
    }'
expect "refuses a method that no longer calls the check" fail \
    "no longer calls hasNonCeSupportedTokenTypes" "$WORK/changed.jar"

# A second caller would survive the patch, so the CA would still refuse to start — the failure this
# tool exists to turn into a build failure instead.
build_jar "$WORK/second.jar" "$real_body"'

    public void startup() {
        if (hasNonCeSupportedTokenTypes()) {
            throw new IllegalStateException("and again, from somewhere else");
        }
    }'
expect "refuses a second caller in the same class" fail \
    "is also called from" "$WORK/second.jar"

echo "== $passed passed, $failed failed"
[ "$failed" -eq 0 ]

#!/usr/bin/env bash
#
# Copyright (c) 2026 Thomas Pham — kimbo11ng
# SPDX-License-Identifier: Apache-2.0
#
# Launcher for the kimbo11ng command-line tool.
#
# Installed into the image at /usr/local/bin/kimbo11ng-cli, so inside the container the tool is
# just `kimbo11ng-cli listslots`. That is where it belongs: the PKCS#11 module, its OpenSSL, the
# SoftHSM token state and LD_LIBRARY_PATH all live in the container, and none of them is reachable
# from the host. It is also the shape EJBCA Enterprise ships p11ng-cli in — a script next to the
# install that assembles a classpath and calls one main class.
#
# The kimbo11ng jar carries only its own classes: every dependency is 'provided', because the jar's
# first job is to be dropped into ejbca.ear/lib where jacknji11, JNA, BouncyCastle and log4j already
# live. That is what makes the jar small and conflict-free inside the container, and it is why
# something has to name the classpath.
#
# Four ways to get one, tried in order:
#
#   1. KIMBO11NG_CLASSPATH — set it and nothing else is guessed.
#   2. EJBCA_HOME          — an EJBCA install elsewhere on the machine.
#   3. the default install  — /opt/keyfactor/ejbca, which is the container.
#   4. the build tree       — the assembled jar in target/ plus a classpath Maven resolves, for
#                             development.
#
# Cases 2 and 3 take the jars from a real EJBCA install, so the CLI runs against the same library
# versions the CA does and the two cannot disagree about what the token supports.
#
# Which PKCS#11 module to use is discovered the same way, from environment-hsm — see below.
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"

fail() { echo "kimbo11ng-cli: $*" >&2; exit 2; }

ejbca_lib() {
    local home="$1"
    local lib="$home/dist/ejbca.ear/lib"
    [ -d "$lib" ] || return 1
    # A wildcard, and the kimbo11ng jar is deployed into that same directory, so this picks up the
    # tool and everything it needs in one entry.
    printf '%s/*' "$lib"
}

build_jar() {
    # The name of the assembled jar is already written down twice — the pom's finalName and the
    # justfile's `artifact` — and a third spelling here is precisely how this branch came to look
    # for a target/kimbo11ng.jar that no build has ever written. So match on the suffix the
    # jar-with-dependencies descriptor appends, which is the same handle ArtifactContentsIT uses to
    # find the artifact, and let the build keep sole ownership of the name.
    local candidate
    for candidate in "$repo"/target/*-jar-with-dependencies.jar; do
        [ -f "$candidate" ] || continue
        printf '%s' "$candidate"
        return 0
    done
    return 1
}

classpath=""

if [ -n "${KIMBO11NG_CLASSPATH:-}" ]; then
    classpath="$KIMBO11NG_CLASSPATH"

elif [ -n "${EJBCA_HOME:-}" ]; then
    classpath="$(ejbca_lib "$EJBCA_HOME")" \
        || fail "EJBCA_HOME is set to '$EJBCA_HOME' but $EJBCA_HOME/dist/ejbca.ear/lib does not exist."

elif classpath="$(ejbca_lib /opt/keyfactor/ejbca)"; then
    :

elif jar="$(build_jar)"; then
    deps="$repo/target/cli-classpath.txt"
    if [ ! -f "$deps" ] || [ "$repo/pom.xml" -nt "$deps" ]; then
        echo "Resolving the dependency classpath (once)..." >&2
        mvn -q -f "$repo/pom.xml" dependency:build-classpath \
            -Dmdep.includeScope=provided -Dmdep.outputFile="$deps" >&2
    fi
    classpath="$jar:$(cat "$deps")"

else
    fail "No classpath. Set KIMBO11NG_CLASSPATH or EJBCA_HOME, or run 'just build' in a checkout."
fi

# ---- which PKCS#11 module, and what it needs to load -------------------------------------------
#
# Not a constant, and not something the image can bake in: this install is SoftHSMv3 normally and a
# side-mounted Thales Luna client when one is mounted, and a Luna module additionally needs its own
# directory on LD_LIBRARY_PATH before it will load at all.
#
# That decision already exists, made at runtime, in environment-hsm — the same file EJBCA's start.sh
# sources to set up the server process. Sourcing it here rather than restating it means the CLI and
# the CA can never disagree about which HSM this container talks to. A `docker exec` does not
# inherit the server's environment, which is why this has to be done again per invocation.
if [ -z "${KIMBO11NG_LIB_FILE:-}" ] && [ -r /opt/softhsm/environment-hsm ]; then
    # environment-hsm calls start.sh's `log`. Supply one that writes to stderr, so a discovery
    # message can never end up in output a script is parsing.
    log() { printf '[%s] %s\n' "${1:-INFO}" "${2:-}" >&2; }
    # shellcheck disable=SC1091
    source /opt/softhsm/environment-hsm || true
    if [ "${LUNA_PRESENT:-0}" = "1" ] && [ -n "${LUNA_CRYPTOKI:-}" ]; then
        KIMBO11NG_LIB_FILE="${LUNA_CRYPTOKI}"
    elif [ -r /usr/local/lib/softhsm/libsofthsmv3.so ]; then
        KIMBO11NG_LIB_FILE=/usr/local/lib/softhsm/libsofthsmv3.so
    fi
fi

# A default --lib-file when one is known and the command line does not give one — the --common-args
# pattern from Keyfactor's own automation guides, moved into the environment. An explicit
# --lib-file always wins, and outside a container where nothing is discovered the option stays
# required, which is the honest default.
args=("$@")
if [ -n "${KIMBO11NG_LIB_FILE:-}" ] && [ $# -gt 0 ]; then
    case " $* " in
        *" --lib-file "*|*" --lib-file="*) ;;
        *) args+=(--lib-file "$KIMBO11NG_LIB_FILE") ;;
    esac
fi

exec java ${JAVA_OPTS:-} -cp "$classpath" ch.ithings.kimbo11ng.cli.Main "${args[@]}"

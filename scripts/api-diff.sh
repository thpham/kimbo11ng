#!/usr/bin/env bash
#
# Copyright (c) 2026 Thomas Pham — kimbo11ng
# SPDX-License-Identifier: Apache-2.0
#
# Compares the EJBCA API surface kimbo11ng compiles against, between two EJBCA lib directories.
# Run it when the pinned EJBCA version moves; docs/EJBCA_UPSTREAM_WATCH.md says what to do with
# each kind of result.
#
#   scripts/api-diff.sh OLD_LIB NEW_LIB
#
# OLD_LIB and NEW_LIB each hold the jars of one release: `lib/` in a Keyfactor/ejbca-ce checkout at
# the release tag, or `ejbca.ear/lib` extracted from the image. The class list is not maintained
# here: it is every com.keyfactor.*, org.cesecore.* and org.pkcs11.* class named in an import under
# src/main, so a new dependency is covered the moment it is written, plus the EXTRA types below —
# ones kimbo11ng inherits or implements without importing, which a new release can still change
# (CryptoToken gained default methods between 9.3.7 and 9.6.3 that way).
#
# Classes that live in modules compiled from EJBCA source (cesecore-common is not in lib/ of a
# checkout) are reported as NOT FOUND, not as changed. Point both directories at extracted image
# jars to cover them.
#
# Output, one line per class: SAME, DIFF (with the changed member lines) or NOT FOUND.
# A DIFF that only adds members is source-compatible for kimbo11ng; a removed or re-typed member is
# the thing to fix. The exit status is 1 when any class differs, 0 otherwise.

set -euo pipefail

if [ "$#" -ne 2 ] || [ ! -d "$1" ] || [ ! -d "$2" ]; then
    echo "usage: $0 OLD_LIB NEW_LIB" >&2
    exit 2
fi
old_cp="$1/*"
new_cp="$2/*"
root="$(cd "$(dirname "$0")/.." && pwd)"

EXTRA="com.keyfactor.util.keys.token.CryptoToken
com.keyfactor.util.keys.token.pkcs11.PKCS11SlotListWrapperFactory"

classes="$( { grep -rhE '^import (com\.keyfactor|org\.cesecore|org\.pkcs11)\.' "$root/src/main/java" \
    | sed -E 's/^import (static )?//; s/;$//'; echo "$EXTRA"; } | sort -u)"

status=0
for cls in $classes; do
    old="$(javap -protected -constants -cp "$old_cp" "$cls" 2>/dev/null || true)"
    new="$(javap -protected -constants -cp "$new_cp" "$cls" 2>/dev/null || true)"
    if [ -z "$old" ] && [ -z "$new" ]; then
        echo "NOT FOUND  $cls"
    elif [ -z "$old" ]; then
        echo "ADDED      $cls"
    elif [ -z "$new" ]; then
        echo "REMOVED    $cls"
        status=1
    elif [ "$old" = "$new" ]; then
        echo "SAME       $cls"
    else
        echo "DIFF       $cls"
        diff <(echo "$old") <(echo "$new") | grep -E '^[<>]' | sed 's/^/             /' || true
        status=1
    fi
done

echo
echo "CryptoTokenFactory registrations (class names EJBCA looks up by string):"
for tag in old new; do
    cp_var="${tag}_cp"
    echo "  [$tag]"
    javap -p -c -cp "${!cp_var}" org.cesecore.keys.token.CryptoTokenFactory 2>/dev/null \
        | grep -E '// (String|class) (org[./]|se[./])' | sed -E 's#.*// (String|class) ##; s#/#.#g' | sort -u \
        | sed 's/^/    /' || true
done
exit "$status"

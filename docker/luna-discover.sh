#!/bin/bash
# Locate a side-mounted Thales Luna client, if one is there at all.
#
# Sourced by both docker/init-hsm.sh (as root, before the privilege drop) and
# docker/environment-hsm (as the app user, from EJBCA's start.sh). It only sets variables — it
# never logs and never exports — because those two callers want to report differently and only one
# of them has EJBCA's log() function.
#
# Nothing here fails: an absent client is the normal case, and the caller decides what to do about
# it. Call luna_discover, then read LUNA_PRESENT.
#
# The candidate lists exist because the minimal client's layout is not stable across versions —
# 10.x has moved the JSP files between jsp/lib/ and jsp/ plus jsp/64/. Globbing a fixed list of
# known layouts is deliberate: it says which shapes are supported, and a client that matches none
# of them produces a message naming what was looked for rather than a silent half-configured token.
# (`find` is not installed in the EJBCA base image, so this cannot search.)

# Sets, always:
#   LUNA_PRESENT     1 or 0
#   LUNA_CLIENT_DIR  the directory searched
#   LUNA_REASON      why not, when LUNA_PRESENT=0
# Sets, when present:
#   LUNA_CRYPTOKI    absolute path to libCryptoki2*.so
#   LUNA_LIBDIR      directory holding it, for LD_LIBRARY_PATH
#   LUNA_BINDIR      lunacm/vtl, or empty
#   LUNA_JSP_JAR     LunaProvider.jar, or empty
#   LUNA_JSP_LIBDIR  directory holding libLunaAPI.so, or empty
luna_discover() {
    LUNA_PRESENT=0
    LUNA_REASON=""
    LUNA_CRYPTOKI=""
    LUNA_LIBDIR=""
    LUNA_BINDIR=""
    LUNA_JSP_JAR=""
    LUNA_JSP_LIBDIR=""
    LUNA_CLIENT_DIR="${LUNA_CLIENT_DIR:-/usr/local/luna}"

    if [ ! -d "${LUNA_CLIENT_DIR}" ]; then
        LUNA_REASON="no directory at ${LUNA_CLIENT_DIR}"
        return 0
    fi

    # The PKCS#11 library is what makes a client usable; everything else is optional.
    local candidate
    for candidate in \
            "${LUNA_CLIENT_DIR}"/libs/64/libCryptoki2*.so \
            "${LUNA_CLIENT_DIR}"/libs/libCryptoki2*.so \
            "${LUNA_CLIENT_DIR}"/lib/libCryptoki2*.so \
            "${LUNA_CLIENT_DIR}"/libCryptoki2*.so ; do
        if [ -f "${candidate}" ]; then
            LUNA_CRYPTOKI="${candidate}"
            break
        fi
    done
    if [ -z "${LUNA_CRYPTOKI}" ]; then
        LUNA_REASON="${LUNA_CLIENT_DIR} exists but holds no libCryptoki2*.so under libs/64, libs, lib or the root"
        return 0
    fi

    LUNA_PRESENT=1
    LUNA_LIBDIR="$(dirname "${LUNA_CRYPTOKI}")"

    for candidate in "${LUNA_CLIENT_DIR}/bin/64" "${LUNA_CLIENT_DIR}/bin" ; do
        if [ -x "${candidate}/lunacm" ] || [ -x "${candidate}/vtl" ]; then
            LUNA_BINDIR="${candidate}"
            break
        fi
    done

    for candidate in \
            "${LUNA_CLIENT_DIR}"/jsp/LunaProvider.jar \
            "${LUNA_CLIENT_DIR}"/jsp/lib/LunaProvider.jar \
            "${LUNA_CLIENT_DIR}"/LunaProvider.jar ; do
        if [ -f "${candidate}" ]; then
            LUNA_JSP_JAR="${candidate}"
            break
        fi
    done

    # The JNI bridge is found through java.library.path, which HotSpot seeds from LD_LIBRARY_PATH —
    # so this directory is exported rather than passed as -Djava.library.path. That matters:
    # EJBCA's start.sh sources the environment hook before it builds JAVA_OPTS_CUSTOM, and setting
    # that variable there would skip the whole container-memory heap-sizing block.
    for candidate in \
            "${LUNA_CLIENT_DIR}"/jsp/64/libLunaAPI.so \
            "${LUNA_CLIENT_DIR}"/jsp/lib/libLunaAPI.so \
            "${LUNA_CLIENT_DIR}"/libs/64/libLunaAPI.so ; do
        if [ -f "${candidate}" ]; then
            LUNA_JSP_LIBDIR="$(dirname "${candidate}")"
            break
        fi
    done

    return 0
}

# One line describing what was found, for whichever logger the caller has.
luna_summary() {
    if [ "${LUNA_PRESENT:-0}" != "1" ]; then
        echo "Luna client not present (${LUNA_REASON:-not searched})."
        return 0
    fi
    local jsp="no JSP provider"
    if [ -n "${LUNA_JSP_JAR}" ] && [ -n "${LUNA_JSP_LIBDIR}" ]; then
        jsp="JSP ${LUNA_JSP_JAR} + JNI in ${LUNA_JSP_LIBDIR}"
    elif [ -n "${LUNA_JSP_JAR}" ]; then
        # The jar without the bridge is worse than neither: it loads and then throws
        # UnsatisfiedLinkError on first use, which reads like a code fault rather than a packaging one.
        jsp="JSP ${LUNA_JSP_JAR} but NO libLunaAPI.so — the provider will not initialise"
    fi
    echo "Luna client at ${LUNA_CLIENT_DIR}: PKCS#11 ${LUNA_CRYPTOKI}; ${jsp}; config ${ChrystokiConfigurationPath:-unset}."
}

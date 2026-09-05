#!/bin/bash
set -e

# Container entry point. Runs as root so it can fix the ownership of mounted volumes and link
# optional client files into place, then drops to the EJBCA app user and hands off to start.sh.
#
# Everything Luna-related here is conditional on a client tree having been mounted. With nothing
# mounted this behaves exactly as the SoftHSM-only script it grew out of.

TOKEN_DIR="/var/lib/softhsmv3/tokens"
SOFTHSM_CONF="/etc/softhsmv3.conf"
TOKEN_LABEL="${SOFTHSM_TOKEN_LABEL:-TestToken}"
TOKEN_PIN="${SOFTHSM_TOKEN_PIN:-1234}"
TOKEN_SO_PIN="${SOFTHSM_TOKEN_SO_PIN:-12345678}"
APP_UID=10001
CLIENT_TOOLBOX_LIB="/opt/keyfactor/ejbca/dist/clientToolBox/lib"

# Only when SoftHSM is actually in use. The Dockerfile sets SOFTHSM2_CONF image-wide so that an
# interactive `docker exec ... softhsm2-util` works, so on a Luna-only stack it has to be unset
# here — otherwise the variable survives the exec below and points anyone debugging at a token
# directory that was deliberately never created.
if [ "${SOFTHSM_ENABLED:-true}" = "true" ]; then
    export SOFTHSM2_CONF="${SOFTHSM_CONF}"
else
    unset SOFTHSM2_CONF
fi
export LD_LIBRARY_PATH=/opt/openssl/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

# ---- Thales Luna --------------------------------------------------------------------------------

source /opt/keyfactor/bin/luna-discover.sh
luna_discover

if [ "${LUNA_PRESENT}" = "1" ]; then
    # Derived here as well as in environment-hsm so this script's own log line is truthful about
    # where the config will be read from. Exporting it also carries it across the exec below.
    CHRYSTOKI_DIR="${LUNA_CHRYSTOKI_PATH:-${LUNA_CLIENT_DIR}/config}"
    export ChrystokiConfigurationPath="${CHRYSTOKI_DIR}"
fi
echo "[luna] $(luna_summary)"

if [ "${LUNA_PRESENT}" = "1" ]; then
    if [ -d "${CHRYSTOKI_DIR}" ]; then
        # The client writes into this directory — vtl createCert, and the client token file the
        # library keeps beside the certificates — so the app user needs more than read access.
        # Best effort: a read-only bind mount is a legitimate way to run this once the certificates
        # are registered, and failing the container over it would be wrong.
        chown -R "${APP_UID}:0" "${CHRYSTOKI_DIR}" 2>/dev/null \
            || echo "[luna] ${CHRYSTOKI_DIR} is not writable by uid ${APP_UID} (read-only mount?)."
    else
        echo "[luna] WARNING: no config directory at ${CHRYSTOKI_DIR}; nothing will connect."
    fi

    # ClientToolBox only, deliberately. EJBCA CE 9.3.7 has no crypto token backed by the Luna JSP
    # provider — CryptoTokenFactory knows Soft, PKCS11, Pkcs11Ng, Azure, AWS KMS, Fortanix,
    # Securosys and PrimeCAToken — so putting LunaProvider.jar on the EAR classpath would add a
    # JNI-loading jar that EJBCA cannot use and that throws on deploy when the .so is missing.
    # Here it is reachable for diagnostics and for the cross-check harness, and nothing else.
    if [ -n "${LUNA_JSP_JAR}" ] && [ -d "${CLIENT_TOOLBOX_LIB}" ]; then
        ln -sf "${LUNA_JSP_JAR}" "${CLIENT_TOOLBOX_LIB}/LunaProvider.jar"
        echo "[luna] Linked ${LUNA_JSP_JAR} into clientToolBox."
    fi
fi

# ---- SoftHSMv3 ----------------------------------------------------------------------------------

if [ "${SOFTHSM_ENABLED:-true}" != "true" ]; then
    echo "[softhsm] Disabled by SOFTHSM_ENABLED=${SOFTHSM_ENABLED}; skipping token initialization."
    exec gosu "${APP_UID}" /opt/keyfactor/bin/start.sh "$@"
fi

mkdir -p "${TOKEN_DIR}"

# Determine the correct CLI tool name (softhsmv3 may ship as softhsm2-util or softhsm3-util)
if command -v softhsm3-util &>/dev/null; then
    SOFTHSM_UTIL=softhsm3-util
elif command -v softhsm2-util &>/dev/null; then
    SOFTHSM_UTIL=softhsm2-util
else
    echo "ERROR: No softhsm utility found in PATH." >&2
    exit 1
fi

echo "[softhsm] Using utility: ${SOFTHSM_UTIL}"

# Fix volume ownership (may be root-owned from a previous build)
chown -R "${APP_UID}:0" "${TOKEN_DIR}" 2>/dev/null || true

# Check if the token is already initialized and valid
TOKEN_VALID=false
if [ -n "$(ls -A ${TOKEN_DIR} 2>/dev/null)" ]; then
    if "${SOFTHSM_UTIL}" --show-slots 2>/dev/null | grep -q "Label:.*${TOKEN_LABEL}"; then
        TOKEN_VALID=true
        echo "[softhsm] Token '${TOKEN_LABEL}' found and valid."
    else
        echo "[softhsm] Token directory has stale/invalid data — cleaning up."
        rm -rf "${TOKEN_DIR:?}"/* 2>/dev/null || true
    fi
fi

if [ "$TOKEN_VALID" = false ]; then
    echo "[softhsm] Initializing token '${TOKEN_LABEL}'..."
    "${SOFTHSM_UTIL}" \
        --init-token \
        --free \
        --label  "${TOKEN_LABEL}" \
        --pin    "${TOKEN_PIN}" \
        --so-pin "${TOKEN_SO_PIN}"
    # Ensure new token files are owned by the app user
    chown -R "${APP_UID}:0" "${TOKEN_DIR}" 2>/dev/null || true
    echo "[softhsm] Token '${TOKEN_LABEL}' initialized."
fi

"${SOFTHSM_UTIL}" --show-slots 2>/dev/null || true
echo "[softhsm] PKCS#11 library: $(ls /usr/local/lib/softhsm/libsofthsm*.so 2>/dev/null | head -1)"

# Drop to non-root app user and hand off to EJBCA
exec gosu "${APP_UID}" /opt/keyfactor/bin/start.sh "$@"

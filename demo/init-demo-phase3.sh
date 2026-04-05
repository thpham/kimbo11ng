#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# PQC TLS Demo — Phase 3 (runs inside EJBCA after second restart)
#
# Issues two server certificates and writes them to the shared volume:
#   1. Hybrid cert (RSA primary + ML-DSA-65 alt sig) from Hybrid-RootCA
#   2. Pure PQC cert (ML-DSA-65 primary) from PQC-RootCA
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

EJBCA_CLI="/opt/keyfactor/bin/ejbca.sh"
CERT_DIR="/demo/certs"
ADMIN_PASS="ejbca"

log() { echo "[demo-init] $*"; }

# ─── Idempotency check ──────────────────────────────────────────────────────
if [ -f "${CERT_DIR}/hybrid-server.p12" ] && [ -f "${CERT_DIR}/pqc-server.p12" ]; then
    log "Certificates already exist. Skipping."
    exit 0
fi

mkdir -p "${CERT_DIR}"

# ─── Helper: create end entity, generate P12, export cert + CA chain ─────────
issue_cert() {
    local USERNAME=$1
    local DN=$2
    local CA_NAME=$3
    local PREFIX=$4

    log "Creating end entity ${USERNAME} (CA: ${CA_NAME})..."
    ${EJBCA_CLI} ra addendentity \
        --username "${USERNAME}" \
        --dn "${DN}" \
        --caname "${CA_NAME}" \
        --type 1 --token P12 \
        --certprofile ENDUSER --eeprofile EMPTY \
        --password ${ADMIN_PASS} 2>&1 || true

    ${EJBCA_CLI} ra setclearpwd --username "${USERNAME}" --password ${ADMIN_PASS}
    ${EJBCA_CLI} ra setendentitystatus --username "${USERNAME}" -S 10

    log "Generating ${PREFIX} certificate via EJBCA batch..."
    mkdir -p /tmp/demo-p12
    ${EJBCA_CLI} batch --username "${USERNAME}" -dir /tmp/demo-p12

    # Copy P12 to shared volume
    cp "/tmp/demo-p12/${USERNAME}.p12" "${CERT_DIR}/${PREFIX}-server.p12"

    # Export server cert as PEM using keytool
    ALIAS=$(keytool -list -keystore "${CERT_DIR}/${PREFIX}-server.p12" -storetype PKCS12 \
        -storepass "${ADMIN_PASS}" 2>/dev/null | grep "PrivateKeyEntry" | head -1 | cut -d',' -f1)

    if [ -n "${ALIAS}" ]; then
        keytool -exportcert -keystore "${CERT_DIR}/${PREFIX}-server.p12" -storetype PKCS12 \
            -storepass "${ADMIN_PASS}" -alias "${ALIAS}" -rfc \
            -file "${CERT_DIR}/${PREFIX}-server.crt" 2>/dev/null
        log "Exported ${PREFIX} cert for alias: ${ALIAS}"
    else
        log "WARNING: Could not find private key alias in ${PREFIX} P12"
    fi

    # Export CA chain
    ${EJBCA_CLI} ca getcacert --caname "${CA_NAME}" -f "${CERT_DIR}/${PREFIX}-ca.pem"
}

# ─── 1. Issue Hybrid cert (RSA + ML-DSA-65 alt sig) ─────────────────────────
issue_cert "demo-hybrid-nginx" "CN=localhost,O=kimbo11ng Demo,C=CH" "Hybrid-RootCA" "hybrid"

# ─── 2. Issue Pure PQC cert (ML-DSA-65 primary) ─────────────────────────────
issue_cert "demo-pqc-nginx" "CN=localhost,O=kimbo11ng Demo,C=CH" "PQC-RootCA" "pqc"

# ─── 3. Verify ───────────────────────────────────────────────────────────────
log ""
log "=== Hybrid cert (RSA + ML-DSA-65 alt sig) ==="
keytool -printcert -file "${CERT_DIR}/hybrid-server.crt" 2>&1 | head -6 || true

log ""
log "=== Pure PQC cert (ML-DSA-65 primary) ==="
keytool -printcert -file "${CERT_DIR}/pqc-server.crt" 2>&1 | head -6 || true

log ""
log "=== Files written to ${CERT_DIR}/ ==="
ls -la "${CERT_DIR}/"
log ""
log "Phase 3 complete."

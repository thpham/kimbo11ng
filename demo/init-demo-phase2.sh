#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# PQC TLS Demo — Phase 2 (runs inside EJBCA container after first restart)
#
# Creates the Hybrid CA keys and initializes the CA via CLI.
# DB patching for alternativeSignatureAlgorithm is handled externally
# via the postgres container.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

EJBCA_CLI="/opt/keyfactor/bin/ejbca.sh"

log() { echo "[demo-init] $*"; }

# ─── 1. Generate Hybrid CA keys on TestHSM ──────────────────────────────────
log "Generating Hybrid CA keys on TestHSM..."
${EJBCA_CLI} cryptotoken generatekey \
    --token TestHSM --alias demo-hybridRSA --keyspec RSA2048 2>&1 || true
${EJBCA_CLI} cryptotoken generatekey \
    --token TestHSM --alias demo-hybridMLDSA --keyspec ML-DSA-65 2>&1 || true

# ─── 2. Initialize Hybrid Root CA ───────────────────────────────────────────
log "Initializing Hybrid-RootCA..."
printf 'certSignKey demo-hybridRSA\ncrlSignKey demo-hybridRSA\ndefaultKey demo-hybridRSA\ntestKey demo-hybridRSA\nalternativeCertSignKey demo-hybridMLDSA\n' \
    > /tmp/demo-hybrid-token.properties

${EJBCA_CLI} ca init \
    --caname Hybrid-RootCA \
    --dn "CN=Hybrid Root CA,O=kimbo11ng Demo,C=CH" \
    --tokenName TestHSM \
    --tokenPass 1234 \
    --tokenprop /tmp/demo-hybrid-token.properties \
    --keyspec 2048 \
    --keytype RSA \
    -v 3650 \
    --policy null \
    -s SHA256WithRSA 2>&1 || true

# ─── 3. Create Pure PQC Root CA (ML-DSA-65) ─────────────────────────────────
log "Generating PQC CA key on TestHSM..."
${EJBCA_CLI} cryptotoken generatekey \
    --token TestHSM --alias demo-pqcCA --keyspec ML-DSA-65 2>&1 || true

log "Initializing PQC-RootCA..."
printf 'certSignKey demo-pqcCA\ncrlSignKey demo-pqcCA\ndefaultKey demo-pqcCA\ntestKey demo-pqcCA\n' \
    > /tmp/demo-pqc-token.properties

${EJBCA_CLI} ca init \
    --caname PQC-RootCA \
    --dn "CN=PQC Root CA,O=kimbo11ng Demo,C=CH" \
    --tokenName TestHSM \
    --tokenPass 1234 \
    --tokenprop /tmp/demo-pqc-token.properties \
    --keyspec ML-DSA-65 \
    --keytype ML-DSA \
    -v 3650 \
    --policy null \
    -s ML-DSA-65 2>&1 || true

log "Phase 2 complete. Hybrid CA and PQC CA initialized."

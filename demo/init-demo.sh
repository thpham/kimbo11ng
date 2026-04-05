#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# PQC TLS Demo — Phase 1 (runs inside EJBCA container)
#
# Enables REST protocol, creates admin cert, imports ManagementCA into
# WildFly truststore. DB operations (token provisioning) are handled
# externally via the postgres container.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

EJBCA_CLI="/opt/keyfactor/bin/ejbca.sh"
ADMIN_PASS="ejbca"

log() { echo "[demo-init] $*"; }

# ─── 1. Enable REST protocol ────────────────────────────────────────────────
log "Enabling REST Certificate Management protocol..."
${EJBCA_CLI} config protocols enable --name "REST Certificate Management" 2>&1 || true

# ─── 2. Generate admin cert for mTLS ────────────────────────────────────────
log "Creating demo-admin end entity..."
${EJBCA_CLI} ra addendentity \
    --username demo-admin \
    --dn "CN=Demo Admin,O=ithings,C=CH" \
    --caname ManagementCA \
    --type 1 --token P12 \
    --certprofile ENDUSER --eeprofile EMPTY \
    --password ${ADMIN_PASS} 2>&1 || true

${EJBCA_CLI} ra setclearpwd --username demo-admin --password ${ADMIN_PASS}
${EJBCA_CLI} ra setendentitystatus --username demo-admin -S 10
${EJBCA_CLI} batch --username demo-admin -dir /opt/keyfactor/ejbca/p12

# Grant Super Administrator role
${EJBCA_CLI} roles addrolemember \
    --namespace "" --role "Super Administrator Role" \
    --caname ManagementCA \
    --with WITH_COMMONNAME --value "Demo Admin" 2>&1 || true

# ─── 3. Import ManagementCA into WildFly truststore ─────────────────────────
log "Importing ManagementCA into WildFly truststore..."
${EJBCA_CLI} ca getcacert --caname ManagementCA -f /tmp/managementca.pem

WF_DIR=$(ls /opt/keyfactor/ | grep wildfly | head -1)
CONFIG_DIR="/opt/keyfactor/${WF_DIR}/standalone/configuration"
TS_PASS=$(grep -A3 'name="httpsTS"' "${CONFIG_DIR}/standalone.xml" \
    | grep 'clear-text' | sed 's/.*clear-text="//;s/".*//')

keytool -import -noprompt \
    -keystore "${CONFIG_DIR}/truststore.jks" \
    -storepass "${TS_PASS}" \
    -alias managementca \
    -file /tmp/managementca.pem 2>&1 || true

log "Phase 1 complete."

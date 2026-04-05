#!/bin/bash
set -e

CERT_DIR="/etc/nginx/certs"
P12_PASS="ejbca"
MAX_WAIT=300
WAITED=0

echo "[nginx-pqc] Waiting for certificates in ${CERT_DIR}..."

# Wait for both P12 files
while [ ! -f "${CERT_DIR}/hybrid-server.p12" ] || [ ! -f "${CERT_DIR}/pqc-server.p12" ]; do
    if [ "$WAITED" -ge "$MAX_WAIT" ]; then
        echo "[nginx-pqc] ERROR: P12 files not found after ${MAX_WAIT}s"
        exit 1
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done

# Extract private keys from P12 files using openssl
for PREFIX in hybrid pqc; do
    if [ ! -f "${CERT_DIR}/${PREFIX}-server.key" ]; then
        echo "[nginx-pqc] Extracting ${PREFIX} private key from P12..."
        openssl pkcs12 -in "${CERT_DIR}/${PREFIX}-server.p12" -passin "pass:${P12_PASS}" \
            -nocerts -nodes -out "${CERT_DIR}/${PREFIX}-server.key" 2>&1
    fi
done

echo "[nginx-pqc] Certificates ready. Starting nginx..."
echo "[nginx-pqc] OpenSSL version: $(openssl version)"
exec nginx -g 'daemon off;'

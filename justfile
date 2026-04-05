# kimbo11ng — PKCS#11 NG CryptoToken for EJBCA CE
# https://github.com/thpham/kimbo11ng

set dotenv-load := false

# ─── Version matrix (single source of truth) ─────────────────────────────────
# Change these when upgrading EJBCA or its dependencies.

ejbca_version   := "9.3.7"
ejbca_image     := "keyfactor/ejbca-ce:" + ejbca_version
openssl_version := "3.6.0"

# EJBCA dependency JARs: "filename groupId artifactId version"
# Extracted from the base image and installed to local Maven repo.
# Update this list when EJBCA bumps dependency versions.
ejbca_deps := "cryptotokens-api-3.0.0.jar:com.keyfactor:cryptotokens-api:3.0.0 cryptotokens-impl-3.0.0.jar:com.keyfactor:cryptotokens-impl:3.0.0 jacknji11-1.3.1.jar:org.pkcs11:jacknji11:1.3.1 cesecore-common.jar:org.cesecore:cesecore-common:" + ejbca_version + " x509-common-util-5.3.5.jar:com.keyfactor:x509-common-util:5.3.5"

# Build configuration
module_dir := "."
artifact   := "kimbo11ng-1.0.0-SNAPSHOT-jar-with-dependencies.jar"
deps_dir   := "deps/ejbca"
ejbca_lib  := "/opt/keyfactor/ejbca/dist/ejbca.ear/lib"

# ─── Setup ────────────────────────────────────────────────────────────────────

# Extract dependency JARs from the EJBCA base image
extract-jars:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p {{deps_dir}}
    echo "Extracting JARs from {{ejbca_image}}..."
    for entry in {{ejbca_deps}}; do
        jar="${entry%%:*}"
        if [ -f "{{deps_dir}}/$jar" ]; then
            echo "  ok $jar"
        else
            docker run --rm {{ejbca_image}} cat "{{ejbca_lib}}/$jar" > "{{deps_dir}}/$jar"
            echo "  ++ $jar"
        fi
    done
    echo "Done. JARs in {{deps_dir}}/"

# Force re-extract all JARs (use after EJBCA version bump)
extract-jars-fresh:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf {{deps_dir}}
    mkdir -p {{deps_dir}}
    echo "Force-extracting JARs from {{ejbca_image}}..."
    for entry in {{ejbca_deps}}; do
        jar="${entry%%:*}"
        docker run --rm {{ejbca_image}} cat "{{ejbca_lib}}/$jar" > "{{deps_dir}}/$jar"
        echo "  ++ $jar"
    done
    echo "Done."

# Install extracted JARs into local Maven repository
install-deps: extract-jars
    #!/usr/bin/env bash
    set -euo pipefail
    DIR="$(cd "{{deps_dir}}" && pwd)"
    echo "Installing EJBCA JARs into local Maven repository..."
    for entry in {{ejbca_deps}}; do
        IFS=':' read -r jar groupId artifactId version <<< "$entry"
        mvn -q install:install-file \
            -Dfile="$DIR/$jar" \
            -DgroupId="$groupId" \
            -DartifactId="$artifactId" \
            -Dversion="$version" \
            -Dpackaging=jar
        echo "  ok $groupId:$artifactId:$version"
    done
    echo "Done."

# Full setup: extract + install + build
setup: install-deps build

# Show current version matrix
versions:
    #!/usr/bin/env bash
    echo "EJBCA:     {{ejbca_version}} ({{ejbca_image}})"
    echo "OpenSSL:   {{openssl_version}}"
    echo "Artifact:  {{artifact}}"
    echo ""
    echo "Dependencies:"
    for entry in {{ejbca_deps}}; do
        IFS=':' read -r jar groupId artifactId version <<< "$entry"
        echo "  $groupId:$artifactId:$version ($jar)"
    done

# ─── Build ────────────────────────────────────────────────────────────────────

# Build the kimbo11ng fat JAR
build:
    cd {{module_dir}} && mvn clean package -q
    @echo "Built: {{module_dir}}/target/{{artifact}}"

# Build without clean
build-quick:
    cd {{module_dir}} && mvn package -q
    @echo "Built: {{module_dir}}/target/{{artifact}}"

# ─── Docker ───────────────────────────────────────────────────────────────────

# Build the Docker image (EJBCA + softhsmv3 + kimbo11ng)
docker-build: build
    docker build -f docker/Dockerfile -t ghcr.io/thpham/ejbca-ce:latest \
        --build-arg OPENSSL_VERSION={{openssl_version}} .

# Build Docker image without cache
docker-build-nocache: build
    docker build -f docker/Dockerfile -t kimbo11ng-ejbca \
        --build-arg OPENSSL_VERSION={{openssl_version}} --no-cache .

# Start all services (EJBCA + MariaDB)
up:
    docker compose up -d
    @echo "Waiting for EJBCA to be healthy..."
    @docker compose exec ejbca sh -c 'until curl -sk https://localhost:8443/ejbca/publicweb/healthcheck/ejbcahealth > /dev/null 2>&1; do sleep 5; done' || true
    @echo "EJBCA is ready."

# Stop all services
down:
    docker compose down

# ─── Deploy (hot-reload JAR into running container) ──────────────────────────

# Deploy the fat JAR into a running EJBCA container and restart
deploy: build-quick
    #!/usr/bin/env bash
    set -euo pipefail
    CONTAINER=$(docker compose ps -q ejbca)
    if [ -z "$CONTAINER" ]; then
        echo "Error: EJBCA container is not running. Use 'just up' first."
        exit 1
    fi
    # Remove old JARs
    docker compose exec ejbca sh -c \
        "rm -f {{ejbca_lib}}/kimbo11ng-*.jar"
    # Copy new JAR
    docker compose cp \
        {{module_dir}}/target/{{artifact}} \
        ejbca:{{ejbca_lib}}/{{artifact}}
    # Restart EJBCA
    docker compose restart ejbca
    echo "Deployed {{artifact}} — waiting for EJBCA restart..."
    sleep 20
    echo "Ready."

# ─── Token provisioning ──────────────────────────────────────────────────────

# Create the TestHSM crypto token (Pkcs11NgCryptoToken) via DB insert
# The EJBCA CLI doesn't support creating p11ng tokens interactively,
# so we insert directly into the CryptoTokenData table.
create-token:
    #!/usr/bin/env bash
    set -euo pipefail
    # Check if token already exists
    EXISTS=$(docker compose exec -T postgres psql -U ejbca -d ejbca -tAc \
        "SELECT COUNT(*) FROM CryptoTokenData WHERE tokenName='TestHSM';")
    if [ "$EXISTS" -gt 0 ]; then
        echo "TestHSM token already exists, skipping."
        exit 0
    fi
    # Build tokenProps (Java properties, base64-encoded)
    PROPS=$(printf '%s\n' \
        "#$(date -u '+%a %b %d %H:%M:%S UTC %Y')" \
        "pin=ad2bc4c864d6463d07d7a4b0fe91a6c6" \
        "sharedLibrary=/usr/local/lib/softhsm/libsofthsmv3.so" \
        "slotLabelValue=TestToken" \
        "slotLabelType=SLOT_LABEL" \
        "tokenName=TestHSM" \
        "allow.extractable.privatekey=false")
    PROPS_B64=$(echo "$PROPS" | base64 | tr -d '\n')
    TOKEN_ID=1234567890
    docker compose exec -T postgres psql -U ejbca -d ejbca -c \
        "INSERT INTO CryptoTokenData (id, lastUpdate, rowProtection, rowVersion, tokenData, tokenName, tokenProps, tokenType) \
         VALUES ($TOKEN_ID, EXTRACT(EPOCH FROM NOW())::bigint * 1000, NULL, 0, NULL, 'TestHSM', '$PROPS_B64', 'Pkcs11NgCryptoToken');"
    echo "Created TestHSM (Pkcs11NgCryptoToken) with id=$TOKEN_ID"
    echo "Restarting EJBCA to pick up the new token..."
    docker compose restart ejbca
    sleep 20
    echo "Done."

# ─── CI helpers ───────────────────────────────────────────────────────────────

# Full CI pipeline: setup → docker build → integration tests
ci: setup docker-build
    cd {{module_dir}} && mvn verify -Pit
    @echo "CI pipeline completed successfully."

# Show project status
status:
    @echo "=== Versions ===" && just versions
    @echo ""
    @echo "=== Git ===" && git log --oneline -5
    @echo ""
    @echo "=== Docker ===" && docker compose ps 2>/dev/null || echo "(not running)"
    @echo ""
    @echo "=== Artifact ===" && ls -lh {{module_dir}}/target/{{artifact}} 2>/dev/null || echo "(not built)"

# Clean build artifacts and extracted JARs
clean:
    cd {{module_dir}} && mvn clean -q
    @echo "Cleaned build artifacts."

# Clean everything including extracted deps (forces re-extract on next setup)
clean-all: clean
    rm -rf {{deps_dir}}
    @echo "Cleaned deps. Run 'just setup' to re-extract."

# Show EJBCA logs
logs:
    docker compose logs -f ejbca

# ─── PQC TLS Demo ────────────────────────────────────────────────────────────

demo_compose := "demo/docker-compose.demo.yml"

# Run the PQC TLS demo (EJBCA + nginx with Hybrid CA certificate)
demo:
    #!/usr/bin/env bash
    set -euo pipefail

    DC="docker compose -f {{demo_compose}}"
    PSQL="$DC exec -T postgres psql -U ejbca -d ejbca -c"

    wait_ejbca() {
        $DC exec ejbca sh -c \
            'until curl -sk https://localhost:8443/ejbca/publicweb/healthcheck/ejbcahealth > /dev/null 2>&1; do sleep 5; done'
    }

    echo "=== PQC TLS Demo ==="
    echo ""

    # Start the stack
    echo "[1/8] Starting services..."
    $DC up -d

    # Wait for EJBCA to be healthy
    echo "[2/8] Waiting for EJBCA to be healthy..."
    wait_ejbca

    # Phase 1: enable protocol, create admin, import truststore
    echo "[3/8] Phase 1: provisioning admin + truststore..."
    $DC exec ejbca bash /demo/init-demo.sh

    # Provision TestHSM token via postgres container
    echo "       Provisioning TestHSM crypto token..."
    PROPS=$(printf '%s\n' \
        "pin=ad2bc4c864d6463d07d7a4b0fe91a6c6" \
        "sharedLibrary=/usr/local/lib/softhsm/libsofthsmv3.so" \
        "slotLabelValue=TestToken" \
        "slotLabelType=SLOT_LABEL" \
        "tokenName=TestHSM" \
        "allow.extractable.privatekey=false")
    PROPS_B64=$(echo "$PROPS" | base64 | tr -d '\n')
    $PSQL \
        "INSERT INTO CryptoTokenData \
         (id,lastUpdate,rowProtection,rowVersion,tokenData,tokenName,tokenProps,tokenType) \
         SELECT 1234567890,EXTRACT(EPOCH FROM NOW())::bigint*1000, \
         NULL,0,NULL,'TestHSM','${PROPS_B64}','Pkcs11NgCryptoToken' \
         WHERE NOT EXISTS (SELECT 1 FROM CryptoTokenData WHERE tokenName='TestHSM');" \
        || true

    # Restart EJBCA to pick up TestHSM token + truststore
    echo "[4/8] Restarting EJBCA (load TestHSM token)..."
    $DC restart ejbca
    sleep 5
    wait_ejbca

    # Phase 2: create Hybrid CA keys + init CA
    echo "[5/8] Phase 2: creating Hybrid Root CA..."
    $DC exec ejbca bash /demo/init-demo-phase2.sh

    # Patch CAData for alternativeSignatureAlgorithm via postgres
    echo "       Patching CAData for ML-DSA-65 alternative signature..."
    $PSQL \
        "UPDATE CAData SET data = replace(data,
         '<string>encryptionalgorithm</string>',
         E'<string>alternativeSignatureAlgorithm</string>\n    <string>ML-DSA-65</string>\n   </void>\n   <void method=\"put\">\n    <string>encryptionalgorithm</string>')
         WHERE name='Hybrid-RootCA'
         AND data NOT LIKE '%alternativeSignatureAlgorithm%';"

    $PSQL \
        "UPDATE CAData SET data = replace(data,
         E'defaultKey=demo-hybridRSA\n</string>',
         E'defaultKey=demo-hybridRSA\nalternativeCertSignKey=demo-hybridMLDSA\n</string>')
         WHERE name='Hybrid-RootCA'
         AND data NOT LIKE '%alternativeCertSignKey%';"

    # Restart EJBCA to pick up patched alternativeSignatureAlgorithm
    echo "[6/8] Restarting EJBCA (load Hybrid CA config)..."
    $DC restart ejbca
    sleep 5
    wait_ejbca

    # Phase 3: issue server cert + write to shared volume
    echo "[7/8] Phase 3: issuing server certificate..."
    $DC exec ejbca bash /demo/init-demo-phase3.sh

    # Restart nginx to pick up the new certs
    echo "[8/8] Starting nginx with PQC certificate..."
    $DC restart nginx
    sleep 3

    echo ""
    echo "============================================"
    echo "  PQC TLS Demo Ready!"
    echo "============================================"
    echo ""
    echo "  Hybrid (RSA + ML-DSA-65 alt sig):  https://localhost:4443/"
    echo "  Pure PQC (ML-DSA-65 primary):      https://localhost:4444/"
    echo ""
    echo "Inspect hybrid certificate:"
    echo "  docker compose -f {{demo_compose}} exec nginx openssl s_client -connect localhost:443 </dev/null 2>/dev/null | openssl x509 -text -noout"
    echo ""
    echo "Inspect PQC certificate:"
    echo "  docker compose -f {{demo_compose}} exec nginx openssl s_client -connect localhost:4444 </dev/null 2>/dev/null | openssl x509 -text -noout"
    echo ""
    echo "Teardown:"
    echo "  just demo-down"

# Stop the PQC TLS demo and clean up
demo-down:
    docker compose -f {{demo_compose}} down -v
    @echo "Demo stack removed."

# Show demo logs
demo-logs:
    docker compose -f {{demo_compose}} logs -f

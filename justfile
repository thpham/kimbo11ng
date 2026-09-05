# kimbo11ng — PKCS#11 NG CryptoToken for EJBCA CE
# https://github.com/thpham/kimbo11ng

set dotenv-load := false

# ─── Version matrix (single source of truth) ─────────────────────────────────
# Change these when upgrading EJBCA or its dependencies.

ejbca_version   := "9.3.7"
ejbca_image     := "keyfactor/ejbca-ce:" + ejbca_version
openssl_version := "3.6.0"
# softhsmv3 (now pqctoday-org/pqctoday-hsm) is built from source. Pinned to a release tag:
# upstream is under heavy development and building an unpinned HEAD makes the image
# unreproducible and breaks without warning — which it did, between the last published
# image and today.
# NOTE: v0.4.7 and v0.4.8 are unbuildable upstream (gitlinks without .gitmodules); moving to
# v0.5.0+ additionally requires --recurse-submodules in docker/Dockerfile. See that file.
softhsm_version := "v0.4.4"

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
    # 'verify', not 'package': the build gates (unit tests, artifact contents, SpotBugs,
    # coverage floor, duplicate classes, license headers) are all bound to the verify phase.
    cd {{module_dir}} && mvn clean verify -q
    @echo "Built: {{module_dir}}/target/{{artifact}}"

# Build without clean or gates — fast path for `just deploy` hot-reload iteration only.
build-quick:
    cd {{module_dir}} && mvn package -q -DskipTests
    @echo "Built (ungated): {{module_dir}}/target/{{artifact}}"

# Unit tests + all build gates, no Docker required
test:
    cd {{module_dir}} && mvn clean verify

# ─── Docker ───────────────────────────────────────────────────────────────────

# Build the Docker image (EJBCA + softhsmv3 + kimbo11ng)
docker-build: build
    docker build -f docker/Dockerfile -t ghcr.io/thpham/ejbca-ce:latest \
        --build-arg OPENSSL_VERSION={{openssl_version}} \
        --build-arg SOFTHSM_VERSION={{softhsm_version}} .

# Build Docker image without cache
docker-build-nocache: build
    docker build -f docker/Dockerfile -t kimbo11ng-ejbca \
        --build-arg OPENSSL_VERSION={{openssl_version}} \
        --build-arg SOFTHSM_VERSION={{softhsm_version}} --no-cache .

# Start all services (EJBCA + MariaDB)
up:
    docker compose up -d
    @echo "Waiting for EJBCA to be healthy..."
    @docker compose exec ejbca sh -c 'until curl -sk https://localhost:8443/ejbca/publicweb/healthcheck/ejbcahealth > /dev/null 2>&1; do sleep 5; done' || true
    @echo "EJBCA is ready."

# Stop all services
down:
    docker compose down

# ─── Thales Luna (optional) ──────────────────────────────────────────────────

# Compose files for a stack with a side-mounted Luna client. Nothing Thales-owned ships in the
# image; see docs/VENDOR_PROFILE_CHECKLIST.md for what to mount and how to register the client.
luna_compose := "-f docker-compose.yml -f docker-compose.luna.yml"

# LUNA_HOST_DIR is an extracted minimal client; LUNA_HOST_CONFIG holds Chrystoki.conf and the certs.
# Start the stack with a side-mounted Luna client
luna-up:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${LUNA_HOST_DIR:?set LUNA_HOST_DIR to an extracted Luna 10.9.2 minimal client}"
    : "${LUNA_HOST_CONFIG:?set LUNA_HOST_CONFIG to the directory holding Chrystoki.conf}"
    docker compose {{luna_compose}} up -d
    echo "Waiting for EJBCA to be healthy..."
    docker compose {{luna_compose}} exec ejbca sh -c 'until curl -sk https://localhost:8443/ejbca/publicweb/healthcheck/ejbcahealth > /dev/null 2>&1; do sleep 5; done' || true
    docker compose {{luna_compose}} logs ejbca 2>&1 | grep -i luna || true
    echo "EJBCA is ready."

# Report what the container makes of the mounted client — run this first when it will not connect
luna-status:
    docker compose {{luna_compose}} exec ejbca sh -c \
        'source /opt/keyfactor/bin/luna-discover.sh; luna_discover; luna_summary; \
         echo "ChrystokiConfigurationPath=${ChrystokiConfigurationPath:-unset}"; \
         command -v lunacm >/dev/null && lunacm -e "slot list" || echo "lunacm not on PATH"'

# Requires LUNA_PARTITION and LUNA_PIN; see create-token for why this is a DB insert.
# Create a Pkcs11NgCryptoToken bound to a Luna partition
create-luna-token:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${LUNA_PARTITION:?set LUNA_PARTITION to the partition label}"
    : "${LUNA_PIN:?set LUNA_PIN to the partition password}"
    TOKEN_NAME="${LUNA_TOKEN_NAME:-LunaHSM}"
    EXISTS=$(docker compose {{luna_compose}} exec -T postgres psql -U ejbca -d ejbca -tAc \
        "SELECT COUNT(*) FROM CryptoTokenData WHERE tokenName='${TOKEN_NAME}';")
    if [ "$EXISTS" -gt 0 ]; then
        echo "${TOKEN_NAME} token already exists, skipping."
        exit 0
    fi
    # EJBCA stores the PIN obfuscated, not encrypted. This inserts it in the clear, which is
    # acceptable for a test partition and is not acceptable for anything else — use the admin UI
    # for a real one.
    PROPS=$(printf '%s\n' \
        "#$(date -u '+%a %b %d %H:%M:%S UTC %Y')" \
        "pin=${LUNA_PIN}" \
        "sharedLibrary=/usr/local/luna/libs/64/libCryptoki2.so" \
        "slotLabelValue=${LUNA_PARTITION}" \
        "slotLabelType=SLOT_LABEL" \
        "tokenName=${TOKEN_NAME}" \
        "allow.extractable.privatekey=false")
    PROPS_B64=$(echo "$PROPS" | base64 | tr -d '\n')
    TOKEN_ID=1234567891
    docker compose {{luna_compose}} exec -T postgres psql -U ejbca -d ejbca -c \
        "INSERT INTO CryptoTokenData (id, lastUpdate, rowProtection, rowVersion, tokenData, tokenName, tokenProps, tokenType) \
         VALUES ($TOKEN_ID, EXTRACT(EPOCH FROM NOW())::bigint * 1000, NULL, 0, NULL, '${TOKEN_NAME}', '$PROPS_B64', 'Pkcs11NgCryptoToken');"
    echo "Created ${TOKEN_NAME} (Pkcs11NgCryptoToken) with id=$TOKEN_ID"
    docker compose {{luna_compose}} restart ejbca
    sleep 20
    echo "Done."

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

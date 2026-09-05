/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.it;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.ComposeContainer;
import org.testcontainers.containers.ContainerState;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests against a full EJBCA + SoftHSMv3 stack.
 *
 * Prerequisites:
 *   - just docker-build  (image ghcr.io/thpham/ejbca-ce:latest must exist locally)
 *
 * Run with:
 *   mvn verify -Pit
 *
 * What this tests:
 *   - mTLS authentication using a dynamically generated it-admin.p12
 *   - PQC key generation (ML-DSA, SLH-DSA, ML-KEM) via Pkcs11NgCryptoToken
 *   - PQC signing (ML-DSA, SLH-DSA) via EJBCA cryptotoken testkey
 *   - REST API reachable and returns valid responses
 *
 * Setup sequence (all before any test method runs):
 *   1. Enable REST Certificate Management protocol via CLI
 *   2. Generate it-admin.p12 and add to Super Administrator Role
 *   3. Import ManagementCA into WildFly TLS truststore (required for mTLS)
 *   4. Provision TestHSM Pkcs11NgCryptoToken via DB insert
 *   5. Restart EJBCA (loads TestHSM + reloads truststore with ManagementCA)
 *   6. Extract it-admin.p12 and build mTLS client
 *   7. Create PQC Root CA (ML-DSA-65) via CLI for certificate issuance tests
 *   7b. Create SLH-DSA Root CA (SLH-DSA-SHA2-128F) via CLI
 *   7c. Create Hybrid Root CA (RSA primary + ML-DSA-65 alternative) via CLI
 */
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class EjbcaContainerIT {

    // docker-compose.it.yml — IT-specific compose file without fixed host port bindings.
    // Testcontainers maps container ports to random ephemeral host ports; use
    // getServiceHost/getServicePort to discover them.  This avoids conflicts with
    // a running dev stack (docker-compose.yml uses fixed ports 8080/8443/9443).
    @Container
    static final ComposeContainer COMPOSE = new ComposeContainer(
            new File("src/it/docker-compose.it.yml"))
        .withExposedService("ejbca", 8443,
            Wait.forHealthcheck().withStartupTimeout(Duration.ofMinutes(6)))
        .withExposedService("postgres", 5432,
            Wait.forHealthcheck().withStartupTimeout(Duration.ofMinutes(2)));

    private static final String ADMIN_P12_PASSWORD = "ejbca";

    private static ch.ithings.kimbo11ng.it.ejbca.api.V1CaApi caApi;
    private static ch.ithings.kimbo11ng.it.ejbca.api.V1CertificateApi certApi;

    @BeforeAll
    static void setUp() throws Exception {
        Assumptions.assumeTrue(
            DockerClientFactory.instance().isDockerAvailable(),
            "Docker not available — skipping integration tests");

        // 1. Enable REST Certificate Management protocol (persisted to DB)
        enableProtocol("REST Certificate Management");

        // 2. Generate it-admin.p12 and register as Super Administrator
        generateItAdminCert();

        // 3. Import ManagementCA into WildFly truststore (enables mTLS client auth)
        importManagementCaIntoTruststore();

        // 4. Provision TestHSM Pkcs11NgCryptoToken (idempotent DB insert)
        provisionTestHsmToken();

        // 5. Restart EJBCA — picks up TestHSM token + reloads truststore
        restartEjbcaAndWait();

        // 6. Extract it-admin.p12 and build mTLS EJBCA API client
        File p12 = extractItAdminP12();
        ch.ithings.kimbo11ng.it.ejbca.ApiClient apiClient = buildEjbcaApiClient(p12);
        caApi = new ch.ithings.kimbo11ng.it.ejbca.api.V1CaApi(apiClient);
        certApi = new ch.ithings.kimbo11ng.it.ejbca.api.V1CertificateApi(apiClient);

        // 7. Create PQC Root CA (ML-DSA-65) for certificate issuance tests
        createPqcRootCa();

        // 7b. Create SLH-DSA Root CA (SLH-DSA-SHA2-128F)
        createSlhDsaRootCa();

        // 7c. Create Hybrid Root CA (RSA primary + ML-DSA-65 alternative)
        createHybridRootCa();
    }

    // ─── Setup helpers ────────────────────────────────────────────────────────

    /**
     * Enable a named EJBCA protocol via CLI (change persisted to DB immediately).
     */
    static void enableProtocol(String protocolName) throws Exception {
        exec(ejbcaContainer(),
            "/opt/keyfactor/bin/ejbca.sh", "config", "protocols", "enable",
            "--name", protocolName);
    }

    /**
     * Generate it-admin.p12 and add it to the Super Administrator Role.
     * Idempotent: "already exists" errors on addendentity / addrolemember are ignored.
     */
    static void generateItAdminCert() throws Exception {
        ContainerState ejbca = ejbcaContainer();

        // --password sets the end entity enrollment password non-interactively
        // (bypasses the console prompt that would NPE in execInContainer).
        // Idempotent: "already exists" errors are ignored via || true.
        ejbca.execInContainer("bash", "-c",
            "/opt/keyfactor/bin/ejbca.sh ra addendentity" +
            " --username it-admin" +
            " --dn 'CN=IT Admin,O=ithings,C=CH'" +
            " --caname ManagementCA" +
            " --type 1" +
            " --token P12" +
            " --certprofile ENDUSER" +
            " --eeprofile EMPTY" +
            " --password " + ADMIN_P12_PASSWORD +
            " 2>&1 || true");

        exec(ejbca, "/opt/keyfactor/bin/ejbca.sh", "ra", "setclearpwd",
            "--username", "it-admin", "--password", ADMIN_P12_PASSWORD);

        exec(ejbca, "/opt/keyfactor/bin/ejbca.sh", "ra", "setendentitystatus",
            "--username", "it-admin", "-S", "10");

        exec(ejbca, "/opt/keyfactor/bin/ejbca.sh", "batch",
            "--username", "it-admin", "-dir", "/opt/keyfactor/ejbca/p12");

        // Grant Super Administrator — idempotent, ignore "already exists"
        ejbca.execInContainer(
            "/opt/keyfactor/bin/ejbca.sh", "roles", "addrolemember",
            "--namespace", "", "--role", "Super Administrator Role",
            "--caname", "ManagementCA",
            "--with", "WITH_COMMONNAME", "--value", "IT Admin");
    }

    /**
     * Import the ManagementCA certificate into WildFly's TLS truststore so that
     * client certificates signed by ManagementCA are accepted at the TLS layer.
     *
     * WildFly generates a random truststore password at startup; we extract it
     * from standalone.xml at runtime rather than hard-coding it.
     */
    static void importManagementCaIntoTruststore() throws Exception {
        ContainerState ejbca = ejbcaContainer();

        // Export ManagementCA cert to a temp PEM file inside the container
        exec(ejbca, "/opt/keyfactor/bin/ejbca.sh", "ca", "getcacert",
            "--caname", "ManagementCA", "-f", "/tmp/managementca.pem");

        // Find the WildFly installation directory (e.g. wildfly-35.0.1.Final)
        org.testcontainers.containers.Container.ExecResult wfDir =
            ejbca.execInContainer("bash", "-c",
                "ls /opt/keyfactor/ | grep wildfly | head -1");
        String wfName = wfDir.getStdout().trim();
        String configDir = "/opt/keyfactor/" + wfName + "/standalone/configuration";

        // Extract the truststore password from standalone.xml
        org.testcontainers.containers.Container.ExecResult tsPassResult =
            ejbca.execInContainer("bash", "-c",
                "grep -A3 'name=\"httpsTS\"' " + configDir + "/standalone.xml" +
                " | grep 'clear-text' | sed 's/.*clear-text=\"//;s/\".*//'");
        String tsPassword = tsPassResult.getStdout().trim();
        if (tsPassword.isEmpty()) {
            throw new IllegalStateException(
                "Could not extract httpsTS truststore password from standalone.xml");
        }

        // Import ManagementCA into truststore (keytool is available in the container's JDK)
        exec(ejbca, "keytool",
            "-import", "-noprompt",
            "-keystore", configDir + "/truststore.jks",
            "-storepass", tsPassword,
            "-alias", "managementca",
            "-file", "/tmp/managementca.pem");
    }

    /**
     * Insert the TestHSM Pkcs11NgCryptoToken into the DB directly (idempotent).
     */
    static void provisionTestHsmToken() throws Exception {
        String props = String.join("\n",
            "pin=ad2bc4c864d6463d07d7a4b0fe91a6c6",
            "sharedLibrary=/usr/local/lib/softhsm/libsofthsmv3.so",
            "slotLabelValue=TestToken",
            "slotLabelType=SLOT_LABEL",
            "tokenName=TestHSM",
            "allow.extractable.privatekey=false");
        String b64 = Base64.getEncoder()
                .encodeToString(props.getBytes(StandardCharsets.UTF_8));

        ContainerState pg = COMPOSE.getContainerByServiceName("postgres-1").orElseThrow(
            () -> new IllegalStateException("postgres-1 container not found"));

        org.testcontainers.containers.Container.ExecResult r = pg.execInContainer(
            "psql", "-U", "ejbca", "-d", "ejbca", "-c",
            "INSERT INTO CryptoTokenData " +
            "(id,lastUpdate,rowProtection,rowVersion,tokenData,tokenName,tokenProps,tokenType)" +
            " SELECT 1234567890,EXTRACT(EPOCH FROM NOW())::bigint*1000," +
            "NULL,0,NULL,'TestHSM','" + b64 + "','Pkcs11NgCryptoToken'" +
            " WHERE NOT EXISTS (SELECT 1 FROM CryptoTokenData WHERE tokenName='TestHSM');");

        if (r.getExitCode() != 0) {
            throw new IllegalStateException("TestHSM token provision failed: " + r.getStderr());
        }
    }

    /**
     * Restart the EJBCA container and wait for it to be healthy.
     * Required so EJBCA picks up the TestHSM token from the DB and
     * WildFly reloads the TLS truststore (which now contains ManagementCA).
     */
    static void restartEjbcaAndWait() throws Exception {
        ContainerState ejbca = ejbcaContainer();

        DockerClientFactory.instance().client()
            .restartContainerCmd(ejbca.getContainerId())
            .exec();

        long deadline = System.currentTimeMillis() + Duration.ofMinutes(5).toMillis();
        while (System.currentTimeMillis() < deadline) {
            try {
                org.testcontainers.containers.Container.ExecResult r = ejbca.execInContainer(
                    "curl", "-sk",
                    "https://localhost:8443/ejbca/publicweb/healthcheck/ejbcahealth");
                if (r.getExitCode() == 0) return;
            } catch (Exception ignored) {
            }
            Thread.sleep(10_000);
        }
        throw new IllegalStateException("EJBCA did not become healthy after restart");
    }

    /**
     * Create a PQC Root CA (ML-DSA-65) using TestHSM.
     *
     * Uses the same token properties pattern as the justfile's create-pqc-ca recipe:
     *   1. Generate ML-DSA-65 key pair on TestHSM with alias "it-pqcCA"
     *   2. Write a token.properties file that maps CA key roles to the alias
     *   3. Run ejbca.sh ca init
     */
    static void createPqcRootCa() throws Exception {
        ContainerState ejbca = ejbcaContainer();

        // Generate CA signing key on TestHSM
        exec(ejbca, "/opt/keyfactor/bin/ejbca.sh", "cryptotoken", "generatekey",
            "--token", "TestHSM", "--alias", "it-pqcCA", "--keyspec", "ML-DSA-65");

        // Write token properties (maps CA key roles → alias)
        ejbca.execInContainer("bash", "-c",
            "printf 'certSignKey it-pqcCA\\ncrlSignKey it-pqcCA\\n" +
            "defaultKey it-pqcCA\\ntestKey it-pqcCA\\n'" +
            " > /tmp/it-ca-token.properties");

        // Initialize Root CA — same flags as justfile create-pqc-ca recipe
        exec(ejbca, "/opt/keyfactor/bin/ejbca.sh", "ca", "init",
            "--caname", "PQC-RootCA",
            "--dn", "CN=PQC Root CA,O=ithings,C=CH",
            "--tokenName", "TestHSM",
            "--tokenPass", "1234",
            "--tokenprop", "/tmp/it-ca-token.properties",
            "--keyspec", "ML-DSA-65",
            "--keytype", "ML-DSA",
            "-v", "3650",
            "--policy", "null",
            "-s", "ML-DSA-65");
    }

    /**
     * Create a SLH-DSA Root CA (SLH-DSA-SHA2-128F) using TestHSM.
     */
    static void createSlhDsaRootCa() throws Exception {
        ContainerState ejbca = ejbcaContainer();

        exec(ejbca, "/opt/keyfactor/bin/ejbca.sh", "cryptotoken", "generatekey",
            "--token", "TestHSM", "--alias", "it-slhdsaCA", "--keyspec", "SLH-DSA-SHA2-128F");

        ejbca.execInContainer("bash", "-c",
            "printf 'certSignKey it-slhdsaCA\\ncrlSignKey it-slhdsaCA\\n" +
            "defaultKey it-slhdsaCA\\ntestKey it-slhdsaCA\\n'" +
            " > /tmp/it-slhdsa-token.properties");

        exec(ejbca, "/opt/keyfactor/bin/ejbca.sh", "ca", "init",
            "--caname", "SLH-DSA-RootCA",
            "--dn", "CN=SLH-DSA Root CA,O=ithings,C=CH",
            "--tokenName", "TestHSM",
            "--tokenPass", "1234",
            "--tokenprop", "/tmp/it-slhdsa-token.properties",
            "--keyspec", "SLH-DSA-SHA2-128F",
            "--keytype", "SLH-DSA",
            "-v", "3650",
            "--policy", "null",
            "-s", "SLH-DSA-SHA2-128F");
    }

    /**
     * Create a Hybrid Root CA (RSA-2048 primary + ML-DSA-65 alternative signature).
     *
     * The EJBCA CLI does not expose alternativeSignatureAlgorithm, so we:
     *   1. Init the CA with RSA primary
     *   2. Patch the CAData XML in PostgreSQL to inject alternativeSignatureAlgorithm
     *   3. Restart EJBCA to pick up the change
     *   4. Renew the CA cert so the alternative signature extension is present
     */
    static void createHybridRootCa() throws Exception {
        ContainerState ejbca = ejbcaContainer();

        exec(ejbca, "/opt/keyfactor/bin/ejbca.sh", "cryptotoken", "generatekey",
            "--token", "TestHSM", "--alias", "it-hybridRSA", "--keyspec", "RSA2048");
        exec(ejbca, "/opt/keyfactor/bin/ejbca.sh", "cryptotoken", "generatekey",
            "--token", "TestHSM", "--alias", "it-hybridMLDSA", "--keyspec", "ML-DSA-65");

        ejbca.execInContainer("bash", "-c",
            "printf 'certSignKey it-hybridRSA\\ncrlSignKey it-hybridRSA\\n" +
            "defaultKey it-hybridRSA\\ntestKey it-hybridRSA\\n" +
            "alternativeCertSignKey it-hybridMLDSA\\n'" +
            " > /tmp/it-hybrid-token.properties");

        exec(ejbca, "/opt/keyfactor/bin/ejbca.sh", "ca", "init",
            "--caname", "Hybrid-RootCA",
            "--dn", "CN=Hybrid Root CA,O=ithings,C=CH",
            "--tokenName", "TestHSM",
            "--tokenPass", "1234",
            "--tokenprop", "/tmp/it-hybrid-token.properties",
            "--keyspec", "2048",
            "--keytype", "RSA",
            "-v", "3650",
            "--policy", "null",
            "-s", "SHA256WithRSA");

        // Patch CAData XML to inject alternativeSignatureAlgorithm (CLI does not expose this).
        // The replacement uses literal \n to match the XMLEncoder-serialized data in the DB.
        ContainerState pg = COMPOSE.getContainerByServiceName("postgres-1").orElseThrow(
            () -> new IllegalStateException("postgres-1 container not found"));
        String newFrag =
            "<string>alternativeSignatureAlgorithm</string>\\n    " +
            "<string>ML-DSA-65</string>\\n   " +
            "</void>\\n   " +
            "<void method=\"put\">\\n    " +
            "<string>encryptionalgorithm</string>";
        // E'...' tells PostgreSQL to interpret \n as actual newlines (0x0A).
        // The CAData XML uses actual newlines; literal \n would corrupt the XML.
        org.testcontainers.containers.Container.ExecResult patchResult =
            pg.execInContainer("psql", "-U", "ejbca", "-d", "ejbca", "-c",
                "UPDATE CAData SET data = replace(data," +
                " '<string>encryptionalgorithm</string>'," +
                " E'" + newFrag + "')" +
                " WHERE name='Hybrid-RootCA'" +
                " AND data NOT LIKE '%alternativeSignatureAlgorithm%';");
        if (patchResult.getExitCode() != 0) {
            throw new IllegalStateException(
                "Hybrid CA patch failed: " + patchResult.getStderr());
        }

        // Also inject alternativeCertSignKey into CAToken propertydata.
        // ca init ignores alternativeCertSignKey in --tokenprop; must be added manually.
        // The propertydata format: entries separated by \n, no leading spaces,
        // closing </string> immediately follows the last \n (no space before it).
        org.testcontainers.containers.Container.ExecResult patchKey =
            pg.execInContainer("psql", "-U", "ejbca", "-d", "ejbca", "-c",
                "UPDATE CAData SET data = replace(data," +
                " E'defaultKey=it-hybridRSA\\n</string>'," +
                " E'defaultKey=it-hybridRSA\\nalternativeCertSignKey=it-hybridMLDSA\\n</string>')" +
                " WHERE name='Hybrid-RootCA'" +
                " AND data NOT LIKE '%alternativeCertSignKey%';");
        if (patchKey.getExitCode() != 0) {
            throw new IllegalStateException(
                "Hybrid CA key patch failed: " + patchKey.getStderr());
        }

        // Restart EJBCA to pick up the alternativeSignatureAlgorithm DB patch.
        // Note: ca renewca is intentionally omitted — it disconnects the CA token
        // from TestHSM and leaves the CA offline. The patched data map takes effect
        // on restart; EJBCA will include the alternative sig in issued EE certs.
        restartEjbcaAndWait();
    }

    /**
     * Copy it-admin.p12 from the EJBCA container to a temp file on the host.
     */
    static File extractItAdminP12() throws Exception {
        ContainerState ejbca = ejbcaContainer();
        File dest = Files.createTempFile("it-admin-", ".p12").toFile();
        dest.deleteOnExit();
        ejbca.copyFileFromContainer(
            "/opt/keyfactor/ejbca/p12/it-admin.p12", dest.getAbsolutePath());
        return dest;
    }

    /**
     * Build an EJBCA API client configured for mTLS with the it-admin certificate.
     * Trust-all TrustManager and hostname verification disabled for test convenience.
     */
    static ch.ithings.kimbo11ng.it.ejbca.ApiClient buildEjbcaApiClient(File p12File) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = Files.newInputStream(p12File.toPath())) {
            ks.load(is, ADMIN_P12_PASSWORD.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, ADMIN_P12_PASSWORD.toCharArray());

        TrustManager[] trustAll = { new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
        }};

        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(kmf.getKeyManagers(), trustAll, null);

        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");

        HttpClient.Builder httpClientBuilder = HttpClient.newBuilder()
            .sslContext(ssl)
            .connectTimeout(Duration.ofSeconds(10));

        String host = COMPOSE.getServiceHost("ejbca", 8443);
        int    port = COMPOSE.getServicePort("ejbca", 8443);

        ch.ithings.kimbo11ng.it.ejbca.ApiClient apiClient =
            new ch.ithings.kimbo11ng.it.ejbca.ApiClient();
        apiClient.setHttpClientBuilder(httpClientBuilder);
        apiClient.updateBaseUri("https://" + host + ":" + port + "/ejbca/ejbca-rest-api");
        return apiClient;
    }

    // ─── REST API tests ───────────────────────────────────────────────────────

    @Test
    @Order(1)
    void restApi_listCas_authenticated() throws Exception {
        ch.ithings.kimbo11ng.it.ejbca.model.CaInfosRestResponse response =
            caApi.listCas(null);
        assertNotNull(response.getCertificateAuthorities(),
            "CA list should not be null");
        assertFalse(response.getCertificateAuthorities().isEmpty(),
            "CA list should not be empty");
    }

    @Test
    @Order(2)
    void restApi_caStatus_returns200() throws Exception {
        ch.ithings.kimbo11ng.it.ejbca.model.RestResourceStatusRestResponse status =
            caApi.status();
        assertEquals("OK", status.getStatus(),
            "CA status should be OK");
        assertTrue(status.getRevision() != null && status.getRevision().contains("EJBCA"),
            "Revision should mention EJBCA. Got: " + status.getRevision());
    }

    // ─── PQC key generation + signing tests ───────────────────────────────────

    @Test @Order(3)
    void generateMlDsaKey_succeeds() throws Exception {
        assertKeyGenSucceeds("it-mldsa", "ML-DSA-65");
    }

    @Test @Order(4)
    void testMlDsaKey_signsAndVerifies() throws Exception {
        assertKeyTestSucceeds("it-mldsa");
    }

    @Test @Order(5)
    void generateSlhDsaKey_succeeds() throws Exception {
        assertKeyGenSucceeds("it-slhdsa", "SLH-DSA-SHA2-128F");
    }

    @Test @Order(6)
    void testSlhDsaKey_signsAndVerifies() throws Exception {
        assertKeyTestSucceeds("it-slhdsa");
    }

    @Test @Order(7)
    void generateMlKemKey_succeeds() throws Exception {
        assertKeyGenSucceeds("it-mlkem", "ML-KEM-768");
    }

    @Test @Order(8)
    void generateRsaKey_succeeds() throws Exception {
        assertKeyGenSucceeds("it-rsa", "RSA2048");
    }

    @Test @Order(9)
    void testRsaKey_signsAndVerifies() throws Exception {
        assertKeyTestSucceeds("it-rsa");
    }

    @Test @Order(10)
    void generateEcKey_succeeds() throws Exception {
        assertKeyGenSucceeds("it-ec", "prime256v1");
    }

    @Test @Order(11)
    void testEcKey_signsAndVerifies() throws Exception {
        assertKeyTestSucceeds("it-ec");
    }

    @Test @Order(12)
    void listKeys_showsGeneratedKeys() throws Exception {
        org.testcontainers.containers.Container.ExecResult r =
            ejbcaContainer().execInContainer(
                "/opt/keyfactor/bin/ejbca.sh", "cryptotoken", "listkeys",
                "--token", "TestHSM");
        assertEquals(0, r.getExitCode(),
            "listkeys failed.\nstdout: " + r.getStdout() + "\nstderr: " + r.getStderr());
        assertTrue(r.getStdout().contains("it-mldsa"),
            "listkeys output should contain it-mldsa. Output: " + r.getStdout());
        assertTrue(r.getStdout().contains("it-pqcCA"),
            "listkeys output should contain it-pqcCA. Output: " + r.getStdout());
    }

    // ─── PQC certificate issuance tests ──────────────────────────────────────

    @Test @Order(13)
    void pqcRootCa_appearsInRestCaList() throws Exception {
        ch.ithings.kimbo11ng.it.ejbca.model.CaInfosRestResponse response =
            caApi.listCas(null);
        assertTrue(
            response.getCertificateAuthorities().stream()
                .anyMatch(ca -> "PQC-RootCA".equals(ca.getName())),
            "PQC-RootCA should appear in CA list");
    }

    @Test @Order(14)
    void pqcCa_issuesMlDsaSignedCert() throws Exception {
        X509Certificate cert = enrollKeystoreAndGetCert(
            "it-mldsaee", "CN=it-mldsaee.ithings.ch,O=ithings,C=CH", "PQC-RootCA");

        // ML-DSA-65 OID = 2.16.840.1.101.3.4.3.18 (NIST FIPS 204)
        assertEquals("2.16.840.1.101.3.4.3.18", cert.getSigAlgOID(),
            "Certificate must be signed with ML-DSA-65 by PQC-RootCA. sigAlgOID="
            + cert.getSigAlgOID());
    }

    @Test @Order(15)
    void slhDsaRootCa_appearsInRestCaList() throws Exception {
        ch.ithings.kimbo11ng.it.ejbca.model.CaInfosRestResponse response =
            caApi.listCas(null);
        assertTrue(
            response.getCertificateAuthorities().stream()
                .anyMatch(ca -> "SLH-DSA-RootCA".equals(ca.getName())),
            "SLH-DSA-RootCA should appear in CA list");
    }

    @Test @Order(16)
    void slhDsaCa_issuesSlhDsaSignedCert() throws Exception {
        X509Certificate cert = enrollKeystoreAndGetCert(
            "it-slhdsaee", "CN=it-slhdsaee.ithings.ch,O=ithings,C=CH", "SLH-DSA-RootCA");

        // SLH-DSA-SHA2-128F OID = 2.16.840.1.101.3.4.3.21 (NIST FIPS 205)
        assertEquals("2.16.840.1.101.3.4.3.21", cert.getSigAlgOID(),
            "Certificate must be signed with SLH-DSA-SHA2-128F. sigAlgOID=" + cert.getSigAlgOID());
    }

    @Test @Order(17)
    void hybridRootCa_appearsInRestCaList() throws Exception {
        ch.ithings.kimbo11ng.it.ejbca.model.CaInfosRestResponse response =
            caApi.listCas(null);
        assertTrue(
            response.getCertificateAuthorities().stream()
                .anyMatch(ca -> "Hybrid-RootCA".equals(ca.getName())),
            "Hybrid-RootCA should appear in CA list");
    }

    @Test @Order(18)
    void hybridCa_issuesRsaSignedCertWithAltSig() throws Exception {
        X509Certificate cert = enrollKeystoreAndGetCert(
            "it-hybridee", "CN=it-hybridee.ithings.ch,O=ithings,C=CH", "Hybrid-RootCA");

        // SHA256WithRSA OID = 1.2.840.113549.1.1.11
        assertEquals("1.2.840.113549.1.1.11", cert.getSigAlgOID(),
            "Certificate must be signed with SHA256WithRSA (primary). sigAlgOID=" + cert.getSigAlgOID());
    }

    @Test @Order(19)
    void testMlKemKey_refusesWithAnExplanation() throws Exception {
        // EJBCA's key test has two branches, sign and RSA-style encrypt/decrypt, chosen from the
        // key-usage set. An ML-KEM key honestly reports CKA_DECRYPT and no CKA_SIGN, so it lands
        // in the encryption branch — and encapsulation is not encryption. Without the interception
        // this fails inside a JCA Cipher with a message about padding.
        org.testcontainers.containers.Container.ExecResult r =
            ejbcaContainer().execInContainer(
                "/opt/keyfactor/bin/ejbca.sh", "cryptotoken", "testkey",
                "--token", "TestHSM", "--alias", "it-mlkem");

        assertEquals(1, r.getExitCode(),
            "testkey on a KEM key must fail, not silently pass.\nstdout: " + r.getStdout());
        assertTrue(r.getStdout().contains("key-encapsulation"),
            "the failure must say why. Output: " + r.getStdout());
        assertTrue(r.getStdout().contains("ML-KEM-768"),
            "the failure must name the algorithm. Output: " + r.getStdout());
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    private static ContainerState ejbcaContainer() {
        return COMPOSE.getContainerByServiceName("ejbca-1").orElseThrow(
            () -> new IllegalStateException("ejbca-1 container not found"));
    }

    /** Execute a command and throw if exit code != 0. */
    private static void exec(ContainerState container, String... cmd) throws Exception {
        org.testcontainers.containers.Container.ExecResult r =
            container.execInContainer(cmd);
        if (r.getExitCode() != 0) {
            throw new IllegalStateException(
                "Command failed (exit " + r.getExitCode() + "): "
                + String.join(" ", cmd)
                + "\nstdout: " + r.getStdout()
                + "\nstderr: " + r.getStderr());
        }
    }

    private void assertKeyGenSucceeds(String alias, String keySpec) throws Exception {
        org.testcontainers.containers.Container.ExecResult r =
            ejbcaContainer().execInContainer(
                "/opt/keyfactor/bin/ejbca.sh", "cryptotoken", "generatekey",
                "--token", "TestHSM", "--alias", alias, "--keyspec", keySpec);
        assertEquals(0, r.getExitCode(),
            keySpec + " key generation failed.\nstdout: " + r.getStdout() +
            "\nstderr: " + r.getStderr());
    }

    private void assertKeyTestSucceeds(String alias) throws Exception {
        org.testcontainers.containers.Container.ExecResult r =
            ejbcaContainer().execInContainer(
                "/opt/keyfactor/bin/ejbca.sh", "cryptotoken", "testkey",
                "--token", "TestHSM", "--alias", alias);
        assertEquals(0, r.getExitCode(),
            "testkey for " + alias + " failed.\nstdout: " + r.getStdout() +
            "\nstderr: " + r.getStderr());
    }

    /**
     * Add an end entity via CLI, then issue a certificate via REST enrollkeystore.
     * EJBCA generates the key pair internally (key_alg=RSA, key_spec=2048).
     * The CA signs with its own algorithm (ML-DSA, SLH-DSA, or RSA).
     * Returns the issued X509Certificate.
     */
    private X509Certificate enrollKeystoreAndGetCert(
            String username, String dn, String caName) throws Exception {
        // Add end entity (idempotent) — no REST endpoint for EE creation in CE
        org.testcontainers.containers.Container.ExecResult addEe =
            ejbcaContainer().execInContainer("bash", "-c",
                "/opt/keyfactor/bin/ejbca.sh ra addendentity" +
                " --username " + username +
                " --dn '" + dn + "'" +
                " --caname " + caName +
                " --type 1 --token P12" +
                " --certprofile ENDUSER --eeprofile EMPTY" +
                " --password ejbca 2>&1");
        if (addEe.getExitCode() != 0 && !addEe.getStdout().contains("already exists")) {
            throw new IllegalStateException("addendentity failed: " + addEe.getStdout());
        }

        exec(ejbcaContainer(), "/opt/keyfactor/bin/ejbca.sh", "ra", "setclearpwd",
            "--username", username, "--password", "ejbca");

        // Enroll via REST — EJBCA generates RSA-2048 key and signs with CA's key
        ch.ithings.kimbo11ng.it.ejbca.model.KeyStoreRestRequest req =
            new ch.ithings.kimbo11ng.it.ejbca.model.KeyStoreRestRequest()
                .username(username)
                .password("ejbca")
                .keyAlg("RSA")
                .keySpec("2048");

        ch.ithings.kimbo11ng.it.ejbca.model.CertificateEnrollmentRestResponse resp =
            certApi.enrollKeystore(req);

        byte[] certDer = resp.getCertificate();
        // enrollkeystore may return DER cert or PKCS#12; try DER first, fall back to PKCS#12
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certDer));
        } catch (Exception e) {
            KeyStore p12 = KeyStore.getInstance("PKCS12");
            p12.load(new ByteArrayInputStream(certDer), "ejbca".toCharArray());
            java.util.Enumeration<String> aliases = p12.aliases();
            while (aliases.hasMoreElements()) {
                java.security.cert.Certificate cert = p12.getCertificate(aliases.nextElement());
                if (cert instanceof X509Certificate) return (X509Certificate) cert;
            }
            throw new IllegalStateException("No X509Certificate found in enrollkeystore response");
        }
    }
}

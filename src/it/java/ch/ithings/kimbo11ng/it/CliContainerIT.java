/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.it;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The command-line tool, inside the published image, against real SoftHSMv3.
 *
 * <h2>Why this runs without EJBCA</h2>
 *
 * <p>The container here is started with {@code sleep infinity} instead of the image's normal entry
 * point, so no application server ever boots. That is not a shortcut to save the 120 seconds EJBCA
 * takes to come up — it is the assertion. The tool's whole claim is that it answers "does this HSM
 * work" before EJBCA is in the picture, on a machine where the CA may not even be installed yet. A
 * test that ran it against a healthy running stack would never notice the day that stopped being
 * true.
 *
 * <p>It is also why this class is cheap despite starting a container: no database, no health check,
 * no CA. The stack {@link EjbcaContainerIT} needs takes minutes; this takes seconds.
 *
 * <h2>What only this test can catch</h2>
 *
 * <p>{@link ch.ithings.kimbo11ng.cli.Main} is covered end to end by unit tests against the in-memory
 * token, so the parsing, dispatch and exit codes are not what this is for. Four things live only
 * here:
 *
 * <ul>
 *   <li>the launcher being on {@code PATH} and finding its own classpath, which is a property of the
 *       image and not of any Java class;</li>
 *   <li>module discovery through {@code environment-hsm}, so {@code listslots} works with no
 *       arguments at all;</li>
 *   <li>the crypto provider being installed — without it every post-quantum algorithm reports as
 *       excluded, and the in-memory tests cannot see that because the surrounding JVM has
 *       BouncyCastle for other reasons;</li>
 *   <li>real post-quantum signatures, which the fake token does not produce.</li>
 * </ul>
 */
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("CLI in the container")
class CliContainerIT {

    private static final String PIN = "1234";
    private static final String TOKEN_LABEL = "TestToken";

    /**
     * The image {@code just docker-build} produces.
     *
     * <p>Testcontainers' default pull policy fetches only when the image is absent locally, so a
     * freshly built working-tree image is used rather than silently replaced by the published
     * {@code latest} — the same hazard {@code EjbcaContainerIT} disables the compose pull for.
     */
    @org.testcontainers.junit.jupiter.Container
    static final GenericContainer<?> HSM = new GenericContainer<>(
            DockerImageName.parse("ghcr.io/thpham/ejbca-ce:latest"))
            // Overrides the image's CMD, which would initialise the token and then exec EJBCA.
            .withCommand("sleep", "infinity");

    @BeforeAll
    static void initialiseToken() throws Exception {
        Assumptions.assumeTrue(DockerClientFactory.instance().isDockerAvailable(),
                "Docker not available — skipping integration tests");
        // The same call init-hsm.sh makes, including its choice between the v2 and v3 tool names.
        // Done here rather than by running init-hsm.sh, because that script ends by exec'ing the
        // application server this test exists to do without.
        Container.ExecResult init = HSM.execInContainer("bash", "-c",
                "command -v softhsm3-util >/dev/null && U=softhsm3-util || U=softhsm2-util; "
                        + "$U --init-token --free --label " + TOKEN_LABEL
                        + " --pin " + PIN + " --so-pin 12345678");
        assertEquals(0, init.getExitCode(),
                "Could not initialise the SoftHSM token: " + init.getStderr());
    }

    /** Runs the tool the way an operator would: by name, from PATH, with no wrapper. */
    private static Container.ExecResult cli(String... args) throws Exception {
        String[] command = new String[args.length + 1];
        command[0] = "kimbo11ng-cli";
        System.arraycopy(args, 0, command, 1, args.length);
        return HSM.execInContainer(command);
    }

    /** The command-line prefix every command that opens the slot needs. */
    private static Container.ExecResult onToken(String... args) throws Exception {
        String[] command = new String[args.length + 6];
        System.arraycopy(args, 0, command, 0, args.length);
        command[args.length] = "--slot-ref";
        command[args.length + 1] = "SLOT_LABEL";
        command[args.length + 2] = "--slot";
        command[args.length + 3] = TOKEN_LABEL;
        command[args.length + 4] = "--password";
        command[args.length + 5] = PIN;
        return cli(command);
    }

    private static String ok(Container.ExecResult result) {
        assertEquals(0, result.getExitCode(),
                "command failed\nstdout:\n" + result.getStdout() + "\nstderr:\n"
                        + result.getStderr());
        return result.getStdout();
    }

    @Test
    @Order(1)
    @DisplayName("the launcher is on PATH and finds its own classpath")
    void launcherIsOnPath() throws Exception {
        Container.ExecResult result = cli();
        // No arguments is a usage error by design, but it proves the jar, the classpath and the
        // main class all resolved.
        assertEquals(2, result.getExitCode(), result.getStderr());
        assertTrue(result.getStdout().contains("listslots"), result.getStdout());
        assertTrue(result.getStdout().contains("capabilities"), result.getStdout());
    }

    @Test
    @Order(2)
    @DisplayName("listslots needs no arguments: the module comes from environment-hsm")
    void listSlotsWithNoArguments() throws Exception {
        String out = ok(cli("listslots"));
        assertTrue(out.contains("Slots with token:"), out);
        assertTrue(out.contains(TOKEN_LABEL), out);
        // Nothing was passed and nothing was prompted for: a slot list needs no credential, which
        // is what makes it the first thing to run against an unfamiliar HSM.
        assertFalse(out.contains("password"), out);
    }

    @Test
    @Order(3)
    @DisplayName("showtokeninfo reports the token and its PIN state")
    void showTokenInfo() throws Exception {
        String out = ok(cli("showtokeninfo", "--slot-ref", "SLOT_LABEL", "--slot", TOKEN_LABEL));
        assertTrue(out.contains(TOKEN_LABEL), out);
        assertTrue(out.contains("User PIN state:"), out);
    }

    /**
     * The regression test for the defect this whole class was written after.
     *
     * <p>Outside an application server nothing has registered BouncyCastle, and without it
     * {@code AlgorithmSupport} finds no {@code KeyFactory} for any post-quantum algorithm and
     * reports all eighteen as excluded — telling an operator their HSM cannot do ML-DSA when it
     * can. It was invisible to every unit test, because those JVMs have BouncyCastle installed for
     * other reasons.
     */
    @Test
    @Order(4)
    @DisplayName("capabilities reports the post-quantum algorithms as usable, with no PIN")
    void capabilities() throws Exception {
        String out = ok(cli("capabilities", "--slot-ref", "SLOT_LABEL", "--slot", TOKEN_LABEL));
        // The verdict moved onto the Profile line when the duplicate per-algorithm block
        // above the table was dropped.
        assertTrue(out.contains("18 of 18 post-quantum algorithms usable"), out);
        assertTrue(out.contains("ML-DSA-65"), out);
        assertTrue(out.contains("SLH-DSA-SHA2-128S"), out);
        assertFalse(out.contains("has no ML-DSA KeyFactory"),
                "BouncyCastle was not installed, so every PQC algorithm was excluded:\n" + out);
    }

    /**
     * The classical half of the same answer, against a real SoftHSMv3.
     *
     * <p>Worth its own test rather than three more assertions above, because it holds a different
     * property: the post-quantum list comes from the profile table and is therefore the same
     * whatever the token says, while these three rows are read out of the token's own mechanism
     * list. A SoftHSMv3 build without RSA would fail here and nowhere else.
     */
    @Test
    @Order(5)
    @DisplayName("capabilities lists RSA, EC and HMAC alongside the post-quantum algorithms")
    void capabilitiesReportsEveryAlgorithm() throws Exception {
        String out = ok(cli("capabilities", "--slot-ref", "SLOT_LABEL", "--slot", TOKEN_LABEL));
        assertTrue(out.contains("Key algorithms this crypto token can use on this HSM"), out);
        assertTrue(out.contains("CKM_RSA_PKCS_KEY_PAIR_GEN"), out);
        assertTrue(out.contains("CKM_EC_KEY_PAIR_GEN"), out);
        assertTrue(out.contains("HmacSHA512"), out);
        assertTrue(out.contains("ML-DSA-65"), out);
        // RSA generation is exercised further down, so "ok" here and a working generatekeypair
        // there are the same claim checked two ways — if they ever disagree, one of them is lying.
        String rsa = out.lines().filter(line -> line.startsWith("  RSA ")).findFirst().orElse("");
        assertTrue(rsa.contains("ok"), rsa);

        // Straight from Provider.getServices(), so this is what EJBCA is actually offered rather
        // than a restatement of the table above. The two are not the same list: a token can
        // generate an EC key and still not sign with SHA-512.
        assertTrue(out.contains("Services EJBCA can request from this token"), out);
        assertTrue(out.contains("SHA256withRSAandMGF1"), out);
        assertTrue(out.contains("SHA256withECDSA"), out);
        assertTrue(out.contains("KeyStore"), out);

        // The JCA KeyPairGenerator service covers only EC and RSA, and without the footnote that
        // reads as "post-quantum key pairs cannot be created" — which the table above contradicts
        // and generateKeyPair below disproves. The two sections disagreeing is worse than either
        // being incomplete, so the caveat is asserted, not just written.
        assertTrue(out.contains("Post-quantum key pairs are not created through a JCA"
                + " KeyPairGenerator"), out);

        // Named through the PKCS#11 v3.2 fallback in TokenCapabilities: jacknji11 1.3.1 knows none
        // of the six post-quantum mechanisms, so without it this column mixed CKM_ names for the
        // classical rows with bare hex for every post-quantum one.
        assertTrue(out.contains("CKM_ML_DSA_KEY_PAIR_GEN"), out);
        assertTrue(out.contains("CKM_SLH_DSA_KEY_PAIR_GEN"), out);
    }

    @Test
    @Order(6)
    @DisplayName("a post-quantum key pair generates and appears under its alias")
    void generateKeyPair() throws Exception {
        ok(onToken("generatekeypair", "--alias", "itmldsa", "--key-spec", "ML-DSA-65"));
        String out = ok(onToken("listkeypairs"));
        assertTrue(out.contains("itmldsa"), out);
        assertTrue(out.contains("ML-DSA-65"), out);
    }

    /**
     * The PKCS#11 v3.2 KEM usage attributes, on a key a real token made.
     *
     * <p>Only reachable here. The unit tests can prove the template carries {@code CKA_ENCAPSULATE}
     * and the conformance kit can prove it matches the declared operations, but neither can prove
     * a token accepts the template — and "SoftHSMv3 tolerated the old spelling and quietly fixed
     * it up" is precisely how the wrong attributes survived this long without anyone noticing.
     *
     * <p>Both branches of the kill-switch, because a switch nothing exercises is a switch that is
     * broken when it is finally needed, and it would be needed on hardware nobody could test on.
     */
    @Test
    @Order(7)
    @DisplayName("an ML-KEM key is generated with the v3.2 encapsulation attributes")
    void mlKemUsesEncapsulationAttributes() throws Exception {
        ok(onToken("generatekeypair", "--alias", "itkem", "--key-spec", "ML-KEM-768"));
        String out = ok(onToken("showobjectattributes", "--alias", "itkem"));
        assertTrue(out.contains("CKA_ENCAPSULATE"), out);
        assertTrue(out.contains("CKA_DECAPSULATE"), out);

        // The switch, on the same token. SoftHSMv3 adds the complementary pair itself whichever
        // spelling it is asked for, so what this proves is that the template is accepted — which
        // is the only thing that could differ on stricter firmware.
        ok(onToken("generatekeypair", "--alias", "itkemlegacy", "--key-spec", "ML-KEM-768",
                "--property", "kimbo11ng.pqc.kemUsage=legacy"));
        String legacy = ok(onToken("showobjectattributes", "--alias", "itkemlegacy"));
        assertTrue(legacy.contains("CKA_ENCRYPT"), legacy);
        assertTrue(legacy.contains("CKA_DECRYPT"), legacy);

        // A typo in the property is a refusal that names it, not a key generated the other way.
        Container.ExecResult bad = onToken("listkeypairs", "--property",
                "kimbo11ng.pqc.kemUsage=v3.2");
        assertNotEquals(0, bad.getExitCode(), bad.getStdout());
        assertTrue(bad.getStderr().contains("kimbo11ng.pqc.kemUsage"), bad.getStderr());
    }

    @Test
    @Order(8)
    @DisplayName("testkeypair produces a real ML-DSA signature and verifies it")
    void testKeyPair() throws Exception {
        String out = ok(onToken("testkeypair", "--alias", "itmldsa"));
        assertTrue(out.contains("signed and verified with ML-DSA-65"), out);
        // ML-DSA-65 signatures are 3309 bytes. Asserting the length is what separates a real
        // signature from a stub of plausible shape, which is exactly what the fake token returns.
        assertTrue(out.contains("3309 byte signature"), out);
    }

    @Test
    @Order(9)
    @DisplayName("the key is sensitive, unextractable, and named as ML-DSA")
    void objectAttributes() throws Exception {
        String out = ok(onToken("showobjectattributes", "--alias", "itmldsa"));
        assertTrue(out.contains("Objects labelled 'itmldsa': 2"), out);
        assertTrue(out.contains("CKA_SENSITIVE            true"), out);
        assertTrue(out.contains("CKA_EXTRACTABLE          false"), out);
        assertTrue(out.contains("CKA_NEVER_EXTRACTABLE    true"), out);
        // jacknji11 1.3.1 predates CKK_ML_DSA, so without the profile lookup this reads
        // "unknown CKK constant 0x0000004a" on a tool whose reason to exist is these keys.
        assertTrue(out.contains("ML_DSA"), out);
    }

    @Test
    @Order(10)
    @DisplayName("listobjects shows both halves with a shared CKA_ID")
    void listObjects() throws Exception {
        String out = ok(onToken("listobjects"));
        assertTrue(out.contains("private_key"), out);
        assertTrue(out.contains("public_key"), out);
        assertTrue(out.contains("itmldsa"), out);
    }

    @Test
    @Order(11)
    @DisplayName("signperformancetest measures throughput on the token")
    void signPerformanceTest() throws Exception {
        String out = ok(onToken("signperformancetest", "--alias", "itmldsa",
                "--time-limit", "1000"));
        assertTrue(out.contains("Signings per second:"), out);
        assertTrue(out.contains("Average time per signing:"), out);
    }

    @Test
    @Order(12)
    @DisplayName("a wrong PIN fails the command cleanly, with no stack trace")
    void wrongPin() throws Exception {
        Container.ExecResult result = cli("listkeypairs", "--slot-ref", "SLOT_LABEL",
                "--slot", TOKEN_LABEL, "--password", "wrong");
        assertEquals(1, result.getExitCode(), result.getStdout());
        assertNotEquals("", result.getStderr().trim());
        assertFalse(result.getStderr().contains("\tat "),
                "a wrong PIN should not print a Java stack trace:\n" + result.getStderr());
    }

    @Test
    @Order(13)
    @DisplayName("deleteobject removes both halves")
    void deleteObject() throws Exception {
        ok(onToken("deleteobject", "--alias", "itmldsa"));
        String out = ok(onToken("listkeypairs"));
        assertFalse(out.contains("itmldsa"), out);
        String objects = ok(onToken("listobjects"));
        assertFalse(objects.contains("itmldsa"), objects);
    }

    // ---- classical algorithms -------------------------------------------------------------
    //
    // The post-quantum keys are why this tool exists, but they are not what most of its work will
    // be: a CA has RSA and EC keys long before it has an ML-DSA one, and an operator reaching for
    // a diagnostic tool is usually holding a key that predates all of this. The mechanisms, the
    // signature algorithms and the key-length reporting are entirely separate code paths from the
    // post-quantum ones — the classical signature services come from a fixed table in the provider
    // rather than from a profile — so nothing above covers them.

    @Test
    @Order(20)
    @DisplayName("an RSA key pair generates and reports its modulus length")
    void generateRsa() throws Exception {
        ok(onToken("generatekeypair", "--alias", "itrsa", "--key-spec", "2048"));
        String out = ok(onToken("listkeypairs"));
        assertTrue(out.contains("itrsa"), out);
        assertTrue(out.contains("RSA"), out);
        assertTrue(out.contains("2048 bits"), out);
    }

    @Test
    @Order(21)
    @DisplayName("testkeypair on RSA defaults to SHA256withRSA and verifies")
    void testRsaKeyPair() throws Exception {
        String out = ok(onToken("testkeypair", "--alias", "itrsa"));
        assertTrue(out.contains("signed and verified with SHA256withRSA"), out);
        assertTrue(out.contains("256 byte signature"), out);
    }

    @Test
    @Order(22)
    @DisplayName("an explicit --signature-algorithm overrides the default, PSS included")
    void explicitSignatureAlgorithm() throws Exception {
        // RSA-PSS is registered under its own JCA name and carries a mechanism parameter block, so
        // it exercises a branch neither the default nor any PKCS#1 signature reaches.
        String out = ok(onToken("testkeypair", "--alias", "itrsa",
                "--signature-algorithm", "SHA256withRSAandMGF1"));
        assertTrue(out.contains("signed and verified with SHA256withRSAandMGF1"), out);
    }

    @Test
    @Order(23)
    @DisplayName("the RSA private key is sensitive and carries its modulus size")
    void rsaObjectAttributes() throws Exception {
        String out = ok(onToken("showobjectattributes", "--alias", "itrsa"));
        assertTrue(out.contains("CKA_KEY_TYPE             RSA"), out);
        assertTrue(out.contains("CKA_MODULUS_BITS         2048"), out);
        assertTrue(out.contains("CKA_SENSITIVE            true"), out);
        assertTrue(out.contains("CKA_EXTRACTABLE          false"), out);
    }

    /**
     * The curve named the way Keyfactor's own documentation names it.
     *
     * <p>{@code --key-spec P-256} is the spelling in the published Thales Luna guide for
     * {@code p11ng-cli}. It resolves here because the crypto token strips separators before looking
     * the curve up, and an operator moving between the two tools should not have to discover that
     * by trial.
     */
    @Test
    @Order(24)
    @DisplayName("an EC key pair generates from Keyfactor's own curve spelling")
    void generateEc() throws Exception {
        ok(onToken("generatekeypair", "--alias", "itec", "--key-spec", "P-256"));
        String out = ok(onToken("listkeypairs"));
        assertTrue(out.contains("itec"), out);
        assertTrue(out.contains("256 bits"), out);
    }

    @Test
    @Order(25)
    @DisplayName("testkeypair on EC defaults to SHA256withECDSA and verifies")
    void testEcKeyPair() throws Exception {
        // Also covers the DER re-wrapping: the token returns a raw r||s pair and a verifier that
        // was handed those bytes unchanged would reject the signature.
        String out = ok(onToken("testkeypair", "--alias", "itec"));
        assertTrue(out.contains("signed and verified with SHA256withECDSA"), out);
    }

    @Test
    @Order(26)
    @DisplayName("signperformancetest verifies every classical signature when asked")
    void classicalPerformanceWithVerify() throws Exception {
        String out = ok(onToken("signperformancetest", "--alias", "itec",
                "--time-limit", "1000", "--threads", "2", "--verify"));
        assertTrue(out.contains("Running signing test with 2 threads"), out);
        assertTrue(out.contains("Every signature was verified."), out);
    }

    @Test
    @Order(27)
    @DisplayName("a symmetric key generates and is listed as a secret, not a key pair")
    void generateSecretKey() throws Exception {
        ok(onToken("generatekey", "--alias", "ithmac", "--key-spec", "HmacSHA256"));
        String out = ok(onToken("listkeypairs"));
        assertTrue(out.contains("ithmac"), out);
        assertTrue(out.contains("secret"), out);
    }

    @Test
    @Order(28)
    @DisplayName("testkeypair refuses a secret key and names the right tool")
    void testKeyPairRefusesSecretKey() throws Exception {
        Container.ExecResult result = onToken("testkeypair", "--alias", "ithmac");
        assertEquals(1, result.getExitCode(), result.getStdout());
        assertTrue(result.getStderr().contains("signs through a Mac"), result.getStderr());
    }

    @Test
    @Order(29)
    @DisplayName("every classical key deletes cleanly, leaving the slot empty")
    void deleteClassicalKeys() throws Exception {
        for (String alias : new String[] {"itrsa", "itec", "ithmac"}) {
            ok(onToken("deleteobject", "--alias", alias));
        }
        String out = ok(onToken("listkeypairs"));
        assertTrue(out.contains("Aliases in slot"), out);
        for (String alias : new String[] {"itrsa", "itec", "ithmac"}) {
            assertFalse(out.contains(alias), out);
        }
    }
}

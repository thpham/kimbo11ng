/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import ch.ithings.kimbo11ng.profile.AlgorithmSupport;
import ch.ithings.kimbo11ng.profile.Pkcs11v32Profile;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.LongRef;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every classical signature algorithm this provider advertises, signed on the token and verified
 * with BouncyCastle.
 *
 * <p>Verification is the point. This provider never verifies — EJBCA does that through BC, from the
 * public key — so a mechanism mismatch, a wrong PSS salt length or a missing DER wrap produces a
 * signature that is well-formed, is accepted everywhere in our code, and fails only at the relying
 * party. Signing and then checking the result with a different implementation is the only way to
 * catch that here.
 */
@DisplayName("signature algorithms")
class SignatureAlgorithmTest {

    private TestSlot fixture;
    private Kimbo11ngProvider provider;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void openSlot() throws Exception {
        fixture = new TestSlot(new FakeToken()).loggedIn();
        provider = Kimbo11ngProvider.forToken(
                new TokenRuntime(fixture.slot(), new Pkcs11v32Profile()));
    }

    /** Generates a key pair on the token and returns {@code {publicHandle, privateHandle}}. */
    private long[] generate(KeyTemplates.Pair templates, long mechanism) throws Exception {
        return fixture.onSession((ce, session) -> {
            LongRef pub = new LongRef();
            LongRef priv = new LongRef();
            ce.GenerateKeyPair(session, new CKM(mechanism), templates.pub(), templates.priv(),
                    pub, priv);
            return new long[] {pub.value(), priv.value()};
        });
    }

    private long[] generateRsa(String alias, int bits) throws Exception {
        return generate(KeyTemplates.rsa(alias.getBytes(StandardCharsets.UTF_8),
                KeyTemplates.newKeyId(), bits), CKM.RSA_PKCS_KEY_PAIR_GEN);
    }

    private long[] generateEc(String alias, String curve) throws Exception {
        return generate(KeyTemplates.ec(alias.getBytes(StandardCharsets.UTF_8),
                KeyTemplates.newKeyId(), curve), CKM.EC_KEY_PAIR_GEN);
    }

    private PublicKey readRsa(long handle) throws Exception {
        return fixture.onSession((ce, s) -> PublicKeyReader.readRsaPublicKey(ce, s, handle));
    }

    private PublicKey readEc(long handle) throws Exception {
        return fixture.onSession((ce, s) -> PublicKeyReader.readEcPublicKey(ce, s, handle));
    }

    /** Signs through the provider and verifies the result with BouncyCastle. */
    private void signAndVerify(String jcaName, String algorithm, long privateHandle,
            PublicKey publicKey) throws Exception {
        byte[] message = "kimbo11ng signature round trip".getBytes(StandardCharsets.UTF_8);

        Kimbo11ngPrivateKey key = new Kimbo11ngPrivateKey(algorithm, fixture.slot(),
                new P11KeyRef(null, "sig-key", null), privateHandle);
        Signature signer = Signature.getInstance(jcaName, provider);
        signer.initSign(key);
        signer.update(message);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(jcaName, BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(message);
        assertTrue(verifier.verify(signature),
                jcaName + " produced a signature BouncyCastle will not verify");
    }

    @Nested
    @DisplayName("RSA PKCS#1 v1.5")
    class Pkcs1 {

        @ParameterizedTest
        @CsvSource({"SHA1withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA"})
        @DisplayName("signs and verifies")
        void roundTrip(String jcaName) throws Exception {
            long[] handles = generateRsa("rsa-" + jcaName, 2048);
            signAndVerify(jcaName, "RSA", handles[1], readRsa(handles[0]));
        }
    }

    @Nested
    @DisplayName("RSA-PSS")
    class Pss {

        @ParameterizedTest
        @CsvSource({"SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1"})
        @DisplayName("signs and verifies")
        void roundTrip(String jcaName) throws Exception {
            // The salt length in CK_RSA_PKCS_PSS_PARAMS has to match what the verifier expects, and
            // nothing but a verification catches a mismatch: a PSS signature with the wrong salt
            // length is the right size and the right shape, and only fails at the relying party.
            long[] handles = generateRsa("pss-" + jcaName, 2048);
            signAndVerify(jcaName, "RSA", handles[1], readRsa(handles[0]));
        }

        @Test
        @DisplayName("the mechanism parameter is three CK_ULONGs")
        void paramShape() {
            // CK_RSA_PKCS_PSS_PARAMS { hashAlg, mgf, sLen }. jacknji11 supplies no default for
            // these mechanisms, which is why the parameter is built here at all.
            int ulong = org.pkcs11.jacknji11.ULong.ULONG_SIZE.size();
            assertEquals(3 * ulong, RsaPssParams.sha256().length);
            assertEquals(3 * ulong, RsaPssParams.sha384().length);
            assertEquals(3 * ulong, RsaPssParams.sha512().length);
        }

        @Test
        @DisplayName("a token refuses PSS without the parameter, which is why it is sent")
        void tokenRefusesMissingParam() throws Exception {
            // Characterization of the failure this exists to avoid: new CKM(SHA256_RSA_PKCS_PSS)
            // carries no parameter, because CKM.DEFAULT_PARAMS covers only the CBC IVs and OAEP.
            long[] handles = generateRsa("pss-bare", 2048);
            Exception e = assertThrows(Exception.class, () -> fixture.onSession((ce, session) -> {
                ce.SignInit(session, new CKM(CKM.SHA256_RSA_PKCS_PSS), handles[1]);
                return null;
            }));
            assertTrue(ch.ithings.kimbo11ng.p11.Pkcs11Errors.is(e,
                            org.pkcs11.jacknji11.CKR.MECHANISM_PARAM_INVALID),
                    () -> "expected CKR_MECHANISM_PARAM_INVALID, got " + e);
        }
    }

    @Nested
    @DisplayName("ECDSA")
    class Ecdsa {

        @ParameterizedTest
        @CsvSource({
            "SHA256withECDSA, secp256r1",
            "SHA384withECDSA, secp384r1",
            "SHA512withECDSA, secp521r1"})
        @DisplayName("signs, DER-wraps and verifies")
        void roundTrip(String jcaName, String curve) throws Exception {
            // PKCS#11 returns the bare r||s pair; X.509 needs SEQUENCE{INTEGER r, INTEGER s}. The
            // conversion is only observably correct through a verifier.
            long[] handles = generateEc("ec-" + jcaName, curve);
            signAndVerify(jcaName, "EC", handles[1], readEc(handles[0]));
        }
    }

    @Nested
    @DisplayName("BouncyCastle content signer")
    class ContentSigner {

        /**
         * How EJBCA actually signs a certificate.
         *
         * <p>{@code CAAdminSessionBean.createCertificateChain} builds a
         * {@code JcaContentSignerBuilder} over this provider, and that resolves <em>every</em>
         * helper it needs from the provider it was handed. For PSS that includes a
         * {@code MessageDigest}, which a PKCS#11 provider has no obvious reason to offer — so CA
         * creation failed with "cannot create signer: no such algorithm: SHA256 for provider
         * Kimbo11ng-…", a message naming neither PSS nor the missing service. Signing through the
         * same builder is the only unit-level way to see that.
         */
        @ParameterizedTest
        @CsvSource({
            "SHA256withRSA,        1.2.840.113549.1.1.11",
            "SHA384withRSA,        1.2.840.113549.1.1.12",
            "SHA256withRSAandMGF1, 1.2.840.113549.1.1.10",
            "SHA384withRSAandMGF1, 1.2.840.113549.1.1.10",
            "SHA512withRSAandMGF1, 1.2.840.113549.1.1.10"})
        @DisplayName("builds, signs and stamps the right algorithm identifier")
        void buildsAndSigns(String jcaName, String expectedOid) throws Exception {
            long[] handles = generateRsa("cs-" + jcaName, 2048);
            Kimbo11ngPrivateKey key = new Kimbo11ngPrivateKey("RSA", fixture.slot(),
                    new P11KeyRef(null, "cs-key", null), handles[1]);
            byte[] message = "certificate to be signed".getBytes(StandardCharsets.UTF_8);

            org.bouncycastle.operator.ContentSigner signer =
                    new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(jcaName)
                            .setProvider(provider).build(key);
            signer.getOutputStream().write(message);
            signer.getOutputStream().close();

            assertEquals(expectedOid, signer.getAlgorithmIdentifier().getAlgorithm().getId(),
                    "the algorithm identifier written into the certificate");

            Signature verifier = Signature.getInstance(jcaName, BouncyCastleProvider.PROVIDER_NAME);
            verifier.initVerify(readRsa(handles[0]));
            verifier.update(message);
            assertTrue(verifier.verify(signer.getSignature()),
                    jcaName + " via ContentSigner produced an unverifiable signature");
        }

        @Test
        @DisplayName("offers the digests BouncyCastle looks up, under both spellings")
        void digestServices() throws Exception {
            for (String name : new String[] {"SHA-256", "SHA256", "SHA-384", "SHA384",
                    "SHA-512", "SHA512", "SHA-1", "SHA1"}) {
                assertNotNull(provider.getService("MessageDigest", name), name);
            }
            // And they must compute the real thing, not a stub.
            java.security.MessageDigest ours =
                    java.security.MessageDigest.getInstance("SHA-256", provider);
            assertArrayEquals(java.security.MessageDigest.getInstance("SHA-256").digest(),
                    ours.digest());
        }
    }

    @Nested
    @DisplayName("PSS parameters")
    class PssParameters {

        @Test
        @DisplayName("accepts the parameters the service already signs with")
        void matchingSpecIsAccepted() throws Exception {
            long[] handles = generateRsa("pss-spec-ok", 2048);
            Signature signature = Signature.getInstance("SHA256withRSAandMGF1", provider);
            signature.setParameter(new java.security.spec.PSSParameterSpec(
                    "SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, 32, 1));
            signature.initSign(new Kimbo11ngPrivateKey("RSA", fixture.slot(),
                    new P11KeyRef(null, "pss-spec-ok", null), handles[1]));
            signature.update(new byte[] {1, 2, 3});
            assertTrue(signature.sign().length > 0);
        }

        @Test
        @DisplayName("refuses a salt length the token will not be told about")
        void mismatchedSaltIsRefused() throws Exception {
            // The mechanism parameter is fixed when the Signature is created. Accepting a
            // different salt length would produce a signature of the right size that no verifier
            // expecting the requested parameters can check.
            Signature signature = Signature.getInstance("SHA256withRSAandMGF1", provider);
            java.security.InvalidAlgorithmParameterException e = assertThrows(
                    java.security.InvalidAlgorithmParameterException.class,
                    () -> signature.setParameter(new java.security.spec.PSSParameterSpec(
                            "SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, 20, 1)));
            assertTrue(e.getMessage().contains("salt=32"), e.getMessage());
            assertTrue(e.getMessage().contains("salt=20"), e.getMessage());
        }

        @Test
        @DisplayName("refuses PSS parameters on a mechanism that is not PSS")
        void pssSpecOnPkcs1IsRefused() throws Exception {
            Signature signature = Signature.getInstance("SHA256withRSA", provider);
            assertThrows(java.security.InvalidAlgorithmParameterException.class,
                    () -> signature.setParameter(new java.security.spec.PSSParameterSpec(
                            "SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, 32, 1)));
        }
    }

    @Nested
    @DisplayName("service registration")
    class Registration {

        @Test
        @DisplayName("advertises every classical algorithm the token can sign with")
        void classicalServices() {
            for (String jcaName : new String[] {
                    "SHA1withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA",
                    "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1",
                    "SHA1withECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA"}) {
                assertNotNull(provider.getService("Signature", jcaName),
                        jcaName + " is not registered");
            }
        }

        @Test
        @DisplayName("matches the JCA name case-insensitively, as EJBCA spells it")
        void caseInsensitive() {
            // AlgorithmConstants uses SHA256WithRSA; the provider registers SHA256withRSA.
            assertNotNull(provider.getService("Signature", "SHA256WithRSA"));
            assertNotNull(provider.getService("Signature", "SHA256WITHRSAANDMGF1"));
        }

        @Test
        @DisplayName("advertises every signing algorithm in the profile and no KEM")
        void postQuantumServices() {
            Pkcs11v32Profile profile = new Pkcs11v32Profile();
            for (var entry : profile.entries()) {
                var service = provider.getService("Signature", entry.canonicalName());
                if (entry.canSign()) {
                    assertNotNull(service, entry.canonicalName() + " is not registered");
                } else {
                    assertNull(service, entry.canonicalName()
                            + " is a KEM and must not be offered as a signature algorithm");
                }
            }
        }

        @Test
        @DisplayName("does not advertise an algorithm the token cannot sign with")
        void unsupportedAlgorithmIsNotAdvertised() throws Exception {
            // Signature.getInstance throwing NoSuchAlgorithmException is recoverable for EJBCA's
            // SignWithWorkingAlgorithm, which moves to the next candidate. A CKR_MECHANISM_INVALID
            // in the middle of signing is not.
            FakeToken noPss = new FakeToken().hideMechanism(
                    CKM.SHA256_RSA_PKCS_PSS, CKM.SHA384_RSA_PKCS_PSS, CKM.SHA512_RSA_PKCS_PSS);
            try (TestSlot limited = new TestSlot(noPss)) {
                TokenRuntime runtime = new TokenRuntime(limited.slot(),
                        AlgorithmSupport.compute(new Pkcs11v32Profile(),
                                limited.slot().capabilities(), true),
                        true, PublicKeyReader.Policy.LENIENT);
                Kimbo11ngProvider limitedProvider = Kimbo11ngProvider.forToken(runtime);

                assertNull(limitedProvider.getService("Signature", "SHA256withRSAandMGF1"));
                assertNotNull(limitedProvider.getService("Signature", "SHA256withRSA"));
            }
        }

        @Test
        @DisplayName("refuses to verify, pointing at BouncyCastle")
        void verificationIsRefused() throws Exception {
            // Refused at initVerify rather than at verify, so the caller finds out before it has
            // fed in the data. EJBCA never asks: KeyTools.testKey resolves the verifying provider
            // from the public key's algorithm, which is always BC.
            long[] handles = generateRsa("verify-check", 2048);
            Signature signature = Signature.getInstance("SHA256withRSA", provider);
            java.security.InvalidKeyException e = assertThrows(
                    java.security.InvalidKeyException.class,
                    () -> signature.initVerify(readRsa(handles[0])));
            assertTrue(e.getMessage().contains("BouncyCastle"), e.getMessage());
        }
    }
}

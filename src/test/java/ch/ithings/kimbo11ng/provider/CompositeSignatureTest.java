/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import ch.ithings.kimbo11ng.p11.Pkcs11v32;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.AlgorithmSupport;
import ch.ithings.kimbo11ng.profile.Pkcs11v32Profile;
import com.keyfactor.util.keys.KeyTools;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeIndex;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.LongRef;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Composite ML-DSA signatures (draft-ietf-lamps-pq-composite-sigs), the case of issue #12.
 *
 * <p>EJBCA's {@code CryptoTokenCompositeWrapper} hands this provider a BouncyCastle
 * {@code CompositePrivateKey} whose two halves are token keys, and asks for the composite algorithm
 * by name. Three things have to hold for that to produce a signature anyone can verify, and each is
 * tested on its own before the whole:
 *
 * <ol>
 *   <li>ML-DSA signs with the context string BouncyCastle sets. The composite construction binds
 *       its domain label into the ML-DSA half through that context; signing with an empty one gives
 *       a signature of the right length that does not verify — what the reporter of #12 saw.</li>
 *   <li>{@code RSASSA-PSS}, with the hash taken from a {@code PSSParameterSpec}, is what BC asks for
 *       as the RSA-PSS half.</li>
 *   <li>The composite service itself exists, under its name and its OID.</li>
 * </ol>
 *
 * <p>The provider under test is deliberately <b>not</b> installed in {@link Security}, except in the
 * one test that goes through EJBCA's own code, which looks providers up by name. The component
 * signatures must come from this provider because the composite service says so, not because the
 * JCA happened to find it.
 */
@DisplayName("composite signatures")
class CompositeSignatureTest {

    private static final byte[] MESSAGE =
            "kimbo11ng composite round trip".getBytes(StandardCharsets.UTF_8);

    private TestSlot fixture;
    private FakeToken fake;
    private Kimbo11ngProvider provider;
    private final Pkcs11v32Profile profile = new Pkcs11v32Profile();

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void openSlot() throws Exception {
        fake = new FakeToken();
        fixture = new TestSlot(fake).loggedIn();
        provider = Kimbo11ngProvider.forToken(new TokenRuntime(fixture.slot(), profile));
    }

    @AfterEach
    void closeSlot() {
        Security.removeProvider(provider.getName());
        fixture.close();
    }

    // ---------------------------------------------------------------- key helpers

    private long[] generate(KeyTemplates.Pair templates, long mechanism) throws Exception {
        return fixture.onSession((ce, session) -> {
            LongRef pub = new LongRef();
            LongRef priv = new LongRef();
            ce.GenerateKeyPair(session, new CKM(mechanism), templates.pub(), templates.priv(),
                    pub, priv);
            return new long[] {pub.value(), priv.value()};
        });
    }

    private static byte[] label(String alias) {
        return alias.getBytes(StandardCharsets.UTF_8);
    }

    /** An ML-DSA pair on the token: the public half as BC reads it, the private half as a handle. */
    private KeyPair mlDsa(String parameterSet) throws Exception {
        AlgorithmEntry entry = profile.lookup(parameterSet).orElseThrow();
        String alias = "mldsa-" + parameterSet;
        long[] h = generate(KeyTemplates.pqc(label(alias), KeyTemplates.newKeyId(), entry, profile),
                entry.ckmKeyPairGen());
        PublicKey pub = fixture.onSession(
                (ce, s) -> PublicKeyReader.readPqcPublicKey(ce, s, h[0], entry));
        return new KeyPair(pub, new Kimbo11ngPrivateKey(entry.canonicalName(), fixture.slot(),
                new P11KeyRef(null, alias, entry), h[1]));
    }

    private KeyPair rsa(int bits) throws Exception {
        String alias = "rsa-" + bits;
        long[] h = generate(KeyTemplates.rsa(label(alias), KeyTemplates.newKeyId(), bits),
                CKM.RSA_PKCS_KEY_PAIR_GEN);
        PublicKey pub = fixture.onSession((ce, s) -> PublicKeyReader.readRsaPublicKey(ce, s, h[0]));
        return new KeyPair(pub, new Kimbo11ngPrivateKey("RSA", fixture.slot(),
                new P11KeyRef(null, alias, null), h[1]));
    }

    private KeyPair ec(String curve) throws Exception {
        String alias = "ec-" + curve;
        long[] h = generate(KeyTemplates.ec(label(alias), KeyTemplates.newKeyId(), curve),
                CKM.EC_KEY_PAIR_GEN);
        PublicKey pub = fixture.onSession((ce, s) -> PublicKeyReader.readEcPublicKey(ce, s, h[0]));
        return new KeyPair(pub, new Kimbo11ngPrivateKey("EC", fixture.slot(),
                new P11KeyRef(null, alias, null), h[1]));
    }

    private KeyPair edwards(String curve) throws Exception {
        String alias = "ed-" + curve;
        long[] h = generate(KeyTemplates.edwards(label(alias), KeyTemplates.newKeyId(), curve),
                CKM.EC_EDWARDS_KEY_PAIR_GEN);
        PublicKey pub = fixture.onSession(
                (ce, s) -> PublicKeyReader.readEdwardsPublicKey(ce, s, h[0]));
        return new KeyPair(pub, new Kimbo11ngPrivateKey(curve, fixture.slot(),
                new P11KeyRef(null, alias, null), h[1]));
    }

    private KeyPair classical(String type, String parameter) throws Exception {
        return switch (type) {
            case "RSA" -> rsa(Integer.parseInt(parameter));
            case "EC" -> ec(parameter);
            case "EDWARDS" -> edwards(parameter);
            default -> throw new IllegalArgumentException(type);
        };
    }

    private static ASN1ObjectIdentifier oidOf(String compositeName) {
        return CompositeIndex.getSupportedIdentifiers().stream()
                .filter(oid -> CompositeIndex.getAlgorithmName(oid).equals(compositeName))
                .findFirst().orElseThrow(() -> new AssertionError("BC has no " + compositeName));
    }

    /** A composite pair built exactly as EJBCA's {@code CryptoTokenCompositeWrapper} builds it. */
    private KeyPair composite(String name, KeyPair pq, KeyPair classical) {
        ASN1ObjectIdentifier oid = oidOf(name);
        return new KeyPair(new CompositePublicKey(oid, pq.getPublic(), classical.getPublic()),
                new CompositePrivateKey(oid, pq.getPrivate(), classical.getPrivate()));
    }

    private static boolean verifiesWithBc(String algorithm, PublicKey pub, byte[] signature,
            java.security.spec.AlgorithmParameterSpec spec) throws Exception {
        Signature verifier = Signature.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(pub);
        if (spec != null) {
            verifier.setParameter(spec);
        }
        verifier.update(MESSAGE);
        return verifier.verify(signature);
    }

    // ---------------------------------------------------------------- the three building blocks

    @Nested
    @DisplayName("ML-DSA context string")
    class MlDsaContext {

        @Test
        @DisplayName("is sent to the token, so BC verifies under the same context")
        void contextIsBound() throws Exception {
            KeyPair pair = mlDsa("ML-DSA-44");
            byte[] context = "COMPSIG-MLDSA44-RSA2048-PSS-SHA256".getBytes(StandardCharsets.US_ASCII);

            Signature signer = Signature.getInstance("ML-DSA-44", provider);
            signer.initSign(pair.getPrivate());
            signer.setParameter(new ContextParameterSpec(context));
            signer.update(MESSAGE);
            byte[] signature = signer.sign();

            assertTrue(verifiesWithBc("ML-DSA", pair.getPublic(), signature,
                    new ContextParameterSpec(context)),
                    "the signature must verify under the context it was asked for");
            assertFalse(verifiesWithBc("ML-DSA", pair.getPublic(), signature, null),
                    "a signature that also verifies under the empty context means the context "
                            + "never reached the token");
        }

        @Test
        @DisplayName("an empty context sends no mechanism parameter, exactly as before")
        void emptyContextSendsNothing() throws Exception {
            KeyPair pair = mlDsa("ML-DSA-65");

            Signature signer = Signature.getInstance("ML-DSA-65", provider);
            signer.initSign(pair.getPrivate());
            signer.setParameter(ContextParameterSpec.EMPTY_CONTEXT_SPEC);
            signer.update(MESSAGE);
            byte[] signature = signer.sign();

            assertNull(fake.lastSignParameter(),
                    "plain ML-DSA must keep taking the token's default; see "
                            + "VENDOR_PROFILE_CHECKLIST, 'The ML-DSA signing parameters'");
            assertTrue(verifiesWithBc("ML-DSA", pair.getPublic(), signature, null));
        }

        @Test
        @DisplayName("a context of exactly 255 bytes, FIPS 204's maximum, is accepted")
        void maximumContextIsAccepted() throws Exception {
            KeyPair pair = mlDsa("ML-DSA-44");
            byte[] context = new byte[SignAdditionalContext.MAX_CONTEXT_LENGTH];
            java.util.Arrays.fill(context, (byte) 'k');

            Signature signer = Signature.getInstance("ML-DSA-44", provider);
            signer.initSign(pair.getPrivate());
            signer.setParameter(new ContextParameterSpec(context));
            signer.update(MESSAGE);

            assertTrue(verifiesWithBc("ML-DSA", pair.getPublic(), signer.sign(),
                    new ContextParameterSpec(context)));
        }

        @Test
        @DisplayName("sends CKH_HEDGE_PREFERRED, the value a token assumes when nothing is sent")
        void hedgeIsPreferred() throws Exception {
            // Records the value sent; it cannot prove the field was written. CKH_HEDGE_PREFERRED is
            // zero and freshly allocated memory often is too, so an unwritten field usually reads
            // the same. What would catch that is a token reading garbage — the fake refuses any
            // hedge outside 0..2, which catches it only when the allocator is not clean.
            KeyPair pair = mlDsa("ML-DSA-44");
            Signature signer = Signature.getInstance("ML-DSA-44", provider);
            signer.initSign(pair.getPrivate());
            signer.setParameter(new ContextParameterSpec(new byte[] {1, 2, 3}));
            signer.update(MESSAGE);
            signer.sign();

            assertEquals(Pkcs11v32.CKH_HEDGE_PREFERRED, fake.lastSignHedge());
        }

        @Test
        @DisplayName("a context longer than FIPS 204's 255 bytes is refused")
        void overlongContextIsRefused() throws Exception {
            KeyPair pair = mlDsa("ML-DSA-44");
            Signature signer = Signature.getInstance("ML-DSA-44", provider);
            signer.initSign(pair.getPrivate());
            assertThrows(java.security.InvalidAlgorithmParameterException.class,
                    () -> signer.setParameter(new ContextParameterSpec(new byte[256])));
        }

        @Test
        @DisplayName("is refused for a classical algorithm, which has no context")
        void classicalRefusesContext() throws Exception {
            KeyPair pair = rsa(2048);
            Signature signer = Signature.getInstance("SHA256withRSA", provider);
            signer.initSign(pair.getPrivate());
            assertThrows(java.security.InvalidAlgorithmParameterException.class,
                    () -> signer.setParameter(new ContextParameterSpec(new byte[] {1})));
        }
    }

    @Nested
    @DisplayName("RSASSA-PSS")
    class GenericPss {

        @ParameterizedTest
        @CsvSource({"SHA-256, 32", "SHA-384, 48", "SHA-512, 64", "SHA-256, 20"})
        @DisplayName("takes its hash and salt length from the PSSParameterSpec")
        void roundTrip(String digest, int salt) throws Exception {
            KeyPair pair = rsa(2048);
            PSSParameterSpec spec = new PSSParameterSpec(digest, "MGF1",
                    new MGF1ParameterSpec(digest), salt, PSSParameterSpec.TRAILER_FIELD_BC);

            Signature signer = Signature.getInstance("RSASSA-PSS", provider);
            signer.initSign(pair.getPrivate());
            signer.setParameter(spec);
            signer.update(MESSAGE);
            byte[] signature = signer.sign();

            assertTrue(verifiesWithBc("RSASSA-PSS", pair.getPublic(), signature, spec),
                    "RSASSA-PSS " + digest + "/salt=" + salt + " did not verify");
        }

        @Test
        @DisplayName("an MGF1 digest other than the message digest reaches the token as asked")
        void distinctMgfDigestIsNotReinterpreted() throws Exception {
            // RsaPssParams encodes the MGF from the spec's own MGF1 parameters. BouncyCastle — the
            // verifier EJBCA uses — refuses a mismatched MGF digest outright, so no signature here
            // can be checked; what is checked is that the block names MGF1-SHA512, and that the
            // fake refuses what it cannot honour rather than signing with MGF1-SHA256 instead.
            KeyPair pair = rsa(2048);
            Signature signer = Signature.getInstance("RSASSA-PSS", provider);
            signer.initSign(pair.getPrivate());
            signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA512,
                    32, PSSParameterSpec.TRAILER_FIELD_BC));
            signer.update(MESSAGE);

            assertThrows(SignatureException.class, signer::sign);
            assertEquals("SHA-256/MGF1-SHA-512/salt=32",
                    RsaPssParams.describe(fake.lastSignParameter()));
        }

        @Test
        @DisplayName("refuses a hash the token does not sign with, before asking the token")
        void unsupportedHashIsRefusedByName() throws Exception {
            // RSASSA-PSS is offered when the token has any PSS mechanism, and the hash only
            // arrives with the spec. A token with SHA-256 PSS and not SHA-512 must get a refusal
            // that names the mechanism, not a CKR_MECHANISM_INVALID from inside C_SignInit.
            fixture.close();
            fake = new FakeToken().hideMechanism(CKM.SHA512_RSA_PKCS_PSS);
            fixture = new TestSlot(fake).loggedIn();
            provider = Kimbo11ngProvider.forToken(new TokenRuntime(fixture.slot(),
                    AlgorithmSupport.compute(profile, fixture.slot().capabilities(), true),
                    true, PublicKeyReader.Policy.LENIENT));
            KeyPair pair = rsa(2048);

            Signature signer = Signature.getInstance("RSASSA-PSS", provider);
            signer.initSign(pair.getPrivate());
            signer.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512,
                    64, PSSParameterSpec.TRAILER_FIELD_BC));
            signer.update(MESSAGE);

            SignatureException e = assertThrows(SignatureException.class, signer::sign);
            assertTrue(e.getMessage().contains("CKM_SHA512_RSA_PKCS_PSS"), e.getMessage());
        }

        @Test
        @DisplayName("refuses to sign without parameters rather than picking a hash")
        void parametersAreRequired() throws Exception {
            KeyPair pair = rsa(2048);
            Signature signer = Signature.getInstance("RSASSA-PSS", provider);
            signer.initSign(pair.getPrivate());
            signer.update(MESSAGE);
            SignatureException e = assertThrows(SignatureException.class, signer::sign);
            assertTrue(e.getMessage().contains("PSSParameterSpec"), e.getMessage());
        }
    }

    @Nested
    @DisplayName("signature state")
    class State {

        @Test
        @DisplayName("a failed initSign forgets the previous key instead of signing with it")
        void failedInitForgetsPreviousKey() throws Exception {
            // java.security.Signature keeps its SIGN state when initSign throws, so if the SPI
            // kept its key too, the next sign() would quietly use the key from before.
            KeyPair pair = mlDsa("ML-DSA-44");
            Kimbo11ngPrivateKey noEntry = new Kimbo11ngPrivateKey("ML-DSA-44", fixture.slot(),
                    new P11KeyRef(null, "no-entry", null), 1L);

            Signature signer = Signature.getInstance("ML-DSA-44", provider);
            signer.initSign(pair.getPrivate());
            assertThrows(java.security.InvalidKeyException.class, () -> signer.initSign(noEntry));
            signer.update(MESSAGE);

            assertThrows(SignatureException.class, signer::sign,
                    "signed with the key from before the failed initSign");
        }

        @Test
        @DisplayName("a null composite parameter is ignored, as for the single-key services")
        void nullCompositeParameterIsIgnored() throws Exception {
            String name = "MLDSA44-RSA2048-PSS-SHA256";
            KeyPair pair = composite(name, mlDsa("ML-DSA-44"), rsa(2048));

            Signature signer = Signature.getInstance(name, provider);
            signer.initSign(pair.getPrivate());
            signer.setParameter(null);
            signer.update(MESSAGE);

            assertTrue(verifiesWithBc(name, pair.getPublic(), signer.sign(), null));
        }
    }

    // ---------------------------------------------------------------- the composite itself

    @Nested
    @DisplayName("composite ML-DSA")
    class Composite {

        @ParameterizedTest(name = "{0}")
        @CsvSource({
            "MLDSA44-RSA2048-PSS-SHA256,           ML-DSA-44, RSA,     2048",
            "MLDSA44-Ed25519-SHA512,               ML-DSA-44, EDWARDS, Ed25519",
            "MLDSA44-ECDSA-P256-SHA256,            ML-DSA-44, EC,      secp256r1",
            "MLDSA65-RSA3072-PSS-SHA512,           ML-DSA-65, RSA,     3072",
            "MLDSA65-RSA4096-PSS-SHA512,           ML-DSA-65, RSA,     4096",
            "MLDSA65-ECDSA-P256-SHA512,            ML-DSA-65, EC,      secp256r1",
            "MLDSA65-ECDSA-P384-SHA512,            ML-DSA-65, EC,      secp384r1",
            "MLDSA65-ECDSA-brainpoolP256r1-SHA512, ML-DSA-65, EC,      brainpoolP256r1",
            "MLDSA65-Ed25519-SHA512,               ML-DSA-65, EDWARDS, Ed25519",
            "MLDSA87-ECDSA-P384-SHA512,            ML-DSA-87, EC,      secp384r1",
            "MLDSA87-ECDSA-brainpoolP384r1-SHA512, ML-DSA-87, EC,      brainpoolP384r1",
            "MLDSA87-Ed448-SHAKE256,               ML-DSA-87, EDWARDS, Ed448",
            "MLDSA87-RSA3072-PSS-SHA512,           ML-DSA-87, RSA,     3072",
            "MLDSA87-RSA4096-PSS-SHA512,           ML-DSA-87, RSA,     4096",
            "MLDSA87-ECDSA-P521-SHA512,            ML-DSA-87, EC,      secp521r1"})
        @DisplayName("signs on the token and verifies under BouncyCastle")
        void roundTrip(String name, String mlDsa, String type, String parameter) throws Exception {
            KeyPair pair = composite(name, mlDsa(mlDsa), classical(type, parameter));

            Signature signer = Signature.getInstance(name, provider);
            signer.initSign(pair.getPrivate());
            signer.update(MESSAGE);
            byte[] signature = signer.sign();

            assertTrue(verifiesWithBc(name, pair.getPublic(), signature, null),
                    name + " produced a signature BouncyCastle will not verify");
        }

        @Test
        @DisplayName("answers to its OID, which is how BC's operator layer asks for it")
        void byOid() throws Exception {
            KeyPair pair = composite("MLDSA44-RSA2048-PSS-SHA256", mlDsa("ML-DSA-44"), rsa(2048));

            Signature signer = Signature.getInstance("1.3.6.1.5.5.7.6.37", provider);
            signer.initSign(pair.getPrivate());
            signer.update(MESSAGE);

            assertTrue(verifiesWithBc("MLDSA44-RSA2048-PSS-SHA256", pair.getPublic(),
                    signer.sign(), null));
        }

        @Test
        @DisplayName("carries the caller's composite context into the signature")
        void compositeContext() throws Exception {
            // Distinct from the ML-DSA context BouncyCastle sets on the inner half: this is the
            // application's ctx, which the draft puts into M' = Prefix || Label || len(ctx) || ctx.
            String name = "MLDSA44-RSA2048-PSS-SHA256";
            KeyPair pair = composite(name, mlDsa("ML-DSA-44"), rsa(2048));
            ContextParameterSpec ctx =
                    new ContextParameterSpec("kimbo11ng".getBytes(StandardCharsets.US_ASCII));

            Signature signer = Signature.getInstance(name, provider);
            signer.initSign(pair.getPrivate());
            signer.setParameter(ctx);
            signer.update(MESSAGE);
            byte[] signature = signer.sign();

            assertTrue(verifiesWithBc(name, pair.getPublic(), signature, ctx));
            assertFalse(verifiesWithBc(name, pair.getPublic(), signature, null),
                    "a signature that verifies without the context never carried it");
        }

        @Test
        @DisplayName("refuses a composite key of a different composite algorithm")
        void refusesOtherComposite() throws Exception {
            KeyPair pair = composite("MLDSA44-ECDSA-P256-SHA256", mlDsa("ML-DSA-44"),
                    ec("secp256r1"));
            Signature signer = Signature.getInstance("MLDSA44-RSA2048-PSS-SHA256", provider);
            java.security.InvalidKeyException e = assertThrows(
                    java.security.InvalidKeyException.class,
                    () -> signer.initSign(pair.getPrivate()));
            assertTrue(e.getMessage().contains("1.3.6.1.5.5.7.6.37"), e.getMessage());
        }

        @Test
        @DisplayName("refuses a key that is not composite at all")
        void refusesPlainKey() throws Exception {
            KeyPair rsa = rsa(2048);
            Signature signer = Signature.getInstance("MLDSA44-RSA2048-PSS-SHA256", provider);
            java.security.InvalidKeyException e = assertThrows(
                    java.security.InvalidKeyException.class,
                    () -> signer.initSign(rsa.getPrivate()));
            assertTrue(e.getMessage().contains(Kimbo11ngPrivateKey.class.getName()),
                    "the refusal must name what it was given: " + e.getMessage());
        }

        @Test
        @DisplayName("signs a certificate through JcaContentSignerBuilder, the CA-creation path")
        void signsCertificate() throws Exception {
            String name = "MLDSA44-RSA2048-PSS-SHA256";
            KeyPair pair = composite(name, mlDsa("ML-DSA-44"), rsa(2048));
            X500Name dn = new X500Name("CN=composite CA");

            X509CertificateHolder cert = new JcaX509v3CertificateBuilder(dn, BigInteger.ONE,
                    new Date(), new Date(System.currentTimeMillis() + 86_400_000L), dn,
                    pair.getPublic())
                    .build(new JcaContentSignerBuilder(name).setProvider(provider)
                            .build(pair.getPrivate()));

            assertTrue(cert.isSignatureValid(new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pair.getPublic())));
        }

        @Test
        @DisplayName("passes EJBCA's KeyTools.testKey, the call that failed in issue #12")
        void ejbcaTestKey() throws Exception {
            KeyPair pair = composite("MLDSA44-RSA2048-PSS-SHA256", mlDsa("ML-DSA-44"), rsa(2048));
            // EJBCA looks the provider up by name, so this is the one test that installs it.
            Security.addProvider(provider);

            KeyTools.testKey(pair.getPrivate(), pair.getPublic(), provider.getName());
        }

        /** Re-opens the slot on {@code token}, with the capability probe honoured, not assumed. */
        private void reopenProbed(FakeToken token) throws Exception {
            fixture.close();
            fake = token;
            fixture = new TestSlot(fake).loggedIn();
            provider = Kimbo11ngProvider.forToken(new TokenRuntime(fixture.slot(),
                    AlgorithmSupport.compute(profile, fixture.slot().capabilities(), true),
                    true, PublicKeyReader.Policy.LENIENT));
        }

        @Test
        @DisplayName("is not offered when the token cannot sign the classical half")
        void gatedOnComponents() throws Exception {
            reopenProbed(new FakeToken().hideMechanism(CKM.SHA256_RSA_PKCS_PSS,
                    CKM.SHA384_RSA_PKCS_PSS, CKM.SHA512_RSA_PKCS_PSS));

            assertNull(provider.getService("Signature", "RSASSA-PSS"),
                    "no PSS mechanism on the token, so no RSASSA-PSS");
            assertNull(provider.getService("Signature", "MLDSA44-RSA2048-PSS-SHA256"),
                    "no PSS on the token, so no PSS composite");
            assertNotNull(provider.getService("Signature", "MLDSA44-ECDSA-P256-SHA256"),
                    "ECDSA is still there, so its composite is too");
        }

        @Test
        @DisplayName("is not offered when the token cannot sign the ML-DSA half")
        void gatedOnMlDsa() throws Exception {
            reopenProbed(new FakeToken().hideMechanism(Pkcs11v32.CKM_ML_DSA,
                    Pkcs11v32.CKM_ML_DSA_KEY_PAIR_GEN));

            Set<String> composites = provider.getServices().stream()
                    .filter(s -> s.getType().equals("Signature"))
                    .map(java.security.Provider.Service::getAlgorithm)
                    .filter(a -> a.startsWith("MLDSA"))
                    .collect(Collectors.toSet());
            assertEquals(Set.of(), composites);
        }

        @Test
        @DisplayName("is withdrawn when the provider is re-pointed at a token without the halves")
        void withdrawnOnResync() throws Exception {
            // One provider object per (library, slot) lives for the JVM, so re-initialising the
            // slot against a narrower token re-points it rather than replacing it. Everything the
            // new token cannot sign has to stop being offered, composites included.
            assertNotNull(provider.getService("Signature", "RSASSA-PSS"));
            assertNotNull(provider.getService("Signature", "MLDSA44-ECDSA-P256-SHA256"));

            try (TestSlot narrow = new TestSlot(new FakeToken().hideMechanism(
                    CKM.SHA256_RSA_PKCS_PSS, CKM.SHA384_RSA_PKCS_PSS, CKM.SHA512_RSA_PKCS_PSS,
                    Pkcs11v32.CKM_ML_DSA, Pkcs11v32.CKM_ML_DSA_KEY_PAIR_GEN))) {
                Kimbo11ngProvider again = Kimbo11ngProvider.forToken(new TokenRuntime(
                        fixture.slot(),
                        AlgorithmSupport.compute(profile, narrow.slot().capabilities(), true),
                        true, PublicKeyReader.Policy.LENIENT));

                assertSame(provider, again);
                assertNull(again.getService("Signature", "RSASSA-PSS"),
                        "RSASSA-PSS outlived the PSS mechanisms behind it");
                assertNull(again.getService("Signature", "MLDSA44-ECDSA-P256-SHA256"),
                        "a composite outlived the ML-DSA half it needs");
                assertNotNull(again.getService("Signature", "SHA256withRSA"),
                        "what the narrower token still has must survive the swap");
            }
        }

        /** The composite signature services this provider offers. */
        private Set<String> offeredComposites() {
            return provider.getServices().stream()
                    .filter(s -> s.getType().equals("Signature"))
                    .map(java.security.Provider.Service::getAlgorithm)
                    .filter(a -> a.startsWith("MLDSA"))
                    .collect(Collectors.toCollection(TreeSet::new));
        }

        @Test
        @DisplayName("covers every pure composite BouncyCastle knows except PKCS#1 v1.5")
        void tableMatchesBouncyCastle() {
            Set<String> bc = CompositeIndex.getSupportedIdentifiers().stream()
                    .map(CompositeIndex::getAlgorithmName)
                    .filter(name -> !name.contains("-PKCS15-"))
                    .collect(Collectors.toCollection(TreeSet::new));
            // The fake advertises every mechanism, so every composite should be on offer. A BC
            // upgrade that adds one shows up here, rather than as a missing algorithm in EJBCA.
            assertEquals(bc, offeredComposites());
        }

        @Test
        @DisplayName("gates each composite on the halves BouncyCastle will actually ask for")
        void gatesMatchBouncyCastlePairings() throws Exception {
            // The classical column only decides whether a composite is offered — BouncyCastle
            // picks the component algorithm itself — so a wrong row signs perfectly on a token
            // that has everything, and is offered on one that cannot sign it. Only a comparison
            // with BC's own pairing table catches it. Both are package-private in BC 1.84; a BC
            // upgrade that moves them fails here, loudly, which is the point.
            java.lang.reflect.Method pairing = CompositeIndex.class
                    .getDeclaredMethod("getPairing", ASN1ObjectIdentifier.class);
            pairing.setAccessible(true);
            java.lang.reflect.Field pssSpecs = org.bouncycastle.jcajce.provider.asymmetric
                    .compositesignatures.SignatureSpi.class
                    .getDeclaredField("algorithmsParameterSpecs");
            pssSpecs.setAccessible(true);
            java.util.Map<?, ?> specs = (java.util.Map<?, ?>) pssSpecs.get(null);

            for (ASN1ObjectIdentifier oid : CompositeIndex.getSupportedIdentifiers()) {
                String name = CompositeIndex.getAlgorithmName(oid);
                if (name.contains("-PKCS15-")) {
                    continue;
                }
                String[] halves = (String[]) pairing.invoke(null, oid);
                String classical = halves[1];
                if ("RSASSA-PSS".equals(classical)) {
                    // BC asks for RSASSA-PSS; what the token has to have is the PSS mechanism
                    // for the hash in BC's spec for this composite.
                    PSSParameterSpec spec = (PSSParameterSpec) specs.get(oid);
                    classical = spec.getDigestAlgorithm().replace("-", "") + "withRSAandMGF1";
                }
                assertEquals(List.of(halves[0], classical), Kimbo11ngProvider.compositeHalves(name),
                        name + ": the provider gates on different halves from the ones BC signs with");
            }
        }

        @Test
        @DisplayName("does not offer the RSA PKCS#1 v1.5 composites, which EJBCA does not support")
        void noPkcs15Composites() {
            // Keyfactor: "EJBCA does not support the legacy PKCS#1 v1.5 signature scheme with
            // composite keys"; an RSA classical half always signs with PSS. Offering them would be
            // surface EJBCA never asks for and nothing here has exercised end to end.
            Set<String> pkcs15 = CompositeIndex.getSupportedIdentifiers().stream()
                    .map(CompositeIndex::getAlgorithmName)
                    .filter(name -> name.contains("-PKCS15-"))
                    .collect(Collectors.toCollection(TreeSet::new));
            assertEquals(Set.of("MLDSA44-RSA2048-PKCS15-SHA256", "MLDSA65-RSA3072-PKCS15-SHA512",
                    "MLDSA65-RSA4096-PKCS15-SHA512"), pkcs15,
                    "BouncyCastle's PKCS#1 v1.5 composites changed; review the exclusion");
            for (String name : pkcs15) {
                assertNull(provider.getService("Signature", name), name + " is offered");
            }
        }
    }
}

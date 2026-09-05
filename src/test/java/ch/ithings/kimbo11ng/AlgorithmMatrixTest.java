/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.Pkcs11v32Profile;
import ch.ithings.kimbo11ng.provider.KeyTemplates;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.CachingKeyStoreWrapper;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every algorithm the README claims, taken end to end: generated on the token, read back through a
 * fresh enumeration, and handed to EJBCA's own resolver.
 *
 * <p>The last step is what makes this more than a smoke test.
 * {@code AlgorithmTools.getSignatureAlgorithms} is the method EJBCA uses to decide what a key can
 * sign with, and it returns an empty list for anything it does not recognise — so a key that is
 * "correct bytes" but not a type EJBCA knows fails much later as "No valid signing algorithm
 * found", during CA creation rather than during key generation. Asking the real resolver here is
 * the difference between testing our code and testing the claim.
 *
 * <p>Re-enumeration rather than the freshly generated objects, because those two paths build the
 * key differently: generation passes the {@link AlgorithmEntry} it just used, while enumeration has
 * to recover it from {@code CKA_KEY_TYPE} plus the parameter-set attribute. Only the second is
 * exercised after a restart, and only the second can resolve the wrong parameter set.
 */
@DisplayName("algorithm matrix")
class AlgorithmMatrixTest {

    /** The parts of {@code BaseCryptoToken} that {@code CryptoTokenImpl} calls back into. */
    private static final class Bridge implements CryptoTokenBridge {
        private Properties properties = new Properties();
        private CachingKeyStoreWrapper keyStore;

        @Override
        public void bridgeSetKeyStore(KeyStore ks) throws KeyStoreException {
            this.keyStore = ks == null ? null : new CachingKeyStoreWrapper(ks, true);
        }

        @Override
        public CachingKeyStoreWrapper bridgeGetKeyStore() {
            return keyStore;
        }

        @Override
        public void bridgeSetJCAProvider(Provider provider) {
        }

        @Override
        public void bridgeSetProperties(Properties properties) {
            this.properties = properties;
        }

        @Override
        public Properties bridgeGetProperties() {
            return properties;
        }

        @Override
        public void bridgeSetTokenName(String name) {
        }

        @Override
        public void bridgeSetId(int id) {
        }
    }

    private static final Pkcs11v32Profile PROFILE = new Pkcs11v32Profile();

    private CryptoTokenImpl impl;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        Properties properties = new Properties();
        properties.setProperty(CryptoTokenImpl.SHLIB_LABEL_KEY, "/nonexistent/libfake.so");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_TYPE, "SLOT_INDEX");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_VALUE, "0");
        properties.setProperty(CryptoTokenImpl.DO_NOT_ADD_P11_PROVIDER, "true");
        impl = new CryptoTokenImpl(new Bridge(), new Pkcs11ModuleRegistry(path -> new FakeToken()));
        impl.init(properties, null, 70);
        impl.activate("1234".toCharArray());
    }

    /**
     * Generates {@code keySpec} under {@code alias}, then throws away every cached key and reads it
     * back off the token — the path a restart takes.
     */
    private PublicKey generateThenReEnumerate(String keySpec, String alias) throws Exception {
        impl.generateKeyPair(keySpec, alias);
        impl.getProvider().getKeyStoreSpi().clear();
        impl.getProvider().getKeyStoreSpi().engineLoad(null, "1234".toCharArray());

        assertTrue(impl.getProvider().getKeyStoreSpi().engineContainsAlias(alias),
                "'" + alias + "' did not survive re-enumeration");
        PublicKey pub = impl.getProvider().getKeyStoreSpi().getPublicKey(alias);
        assertNotNull(pub, "no public key was recovered for '" + alias + "'");
        return pub;
    }

    /** EJBCA must be able to name at least one signature algorithm for a signing key. */
    private static void assertEjbcaCanSignWith(PublicKey key, String keySpec) {
        List<String> algorithms = AlgorithmTools.getSignatureAlgorithms(key);
        assertFalse(algorithms.isEmpty(),
                () -> "EJBCA resolved no signature algorithm for a " + keySpec + " key ("
                        + key.getAlgorithm() + "). AlgorithmTools returns an empty list for a key"
                        + " type it does not recognise, and CA creation then fails with 'No valid"
                        + " signing algorithm found'.");
    }

    @Nested
    @DisplayName("post-quantum")
    class PostQuantum {

        static Stream<String> everyPqcAlgorithm() {
            return PROFILE.entries().stream().map(AlgorithmEntry::canonicalName);
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("everyPqcAlgorithm")
        @DisplayName("generates, re-enumerates, and carries the right OID and length")
        void roundTrip(String keySpec) throws Exception {
            AlgorithmEntry entry = PROFILE.lookup(keySpec).orElseThrow();
            PublicKey pub = generateThenReEnumerate(keySpec, "m-" + keySpec);

            // BouncyCastle names a post-quantum key by its parameter set, not its family: a key
            // built through KeyFactory("ML-DSA") reports "ML-DSA-44". Worth asserting exactly,
            // because it means getAlgorithm() alone is enough to catch a parameter-set mix-up.
            assertEquals(keySpec, pub.getAlgorithm(),
                    "the key does not report the parameter set it was generated as");
            assertTrue(pub.getAlgorithm().startsWith(entry.family().jcaName()));

            // The OID in the encoding is what lands in the certificate's SubjectPublicKeyInfo, and
            // the length is what proves the parameter set was not merely assumed.
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pub.getEncoded());
            assertEquals(entry.oid(), spki.getAlgorithm().getAlgorithm(),
                    keySpec + " came back under the wrong OID");
            assertEquals(entry.publicKeyLength(), spki.getPublicKeyData().getOctets().length,
                    keySpec + " came back the wrong size");

            if (entry.canSign()) {
                assertEjbcaCanSignWith(pub, keySpec);
            }
        }

        @Test
        @DisplayName("the matrix covers the whole profile table, not a chosen subset")
        void matrixIsComplete() {
            // 3 ML-DSA + 3 ML-KEM + 12 SLH-DSA. If a profile row is added without a test, the
            // count changes and this fails rather than the row going unexercised.
            assertEquals(18, everyPqcAlgorithm().count());
        }
    }

    @Nested
    @DisplayName("RSA")
    class Rsa {

        @ParameterizedTest(name = "RSA-{0}")
        @ValueSource(ints = {2048, 3072, 4096})
        @DisplayName("generates, re-enumerates, and reports the right modulus size")
        void roundTrip(int bits) throws Exception {
            PublicKey pub = generateThenReEnumerate("RSA" + bits, "m-rsa" + bits);

            assertEquals("RSA", pub.getAlgorithm());
            assertEquals(bits, ((RSAPublicKey) pub).getModulus().bitLength());
            assertEquals(String.valueOf(bits), AlgorithmTools.getKeySpecification(pub));
            assertEjbcaCanSignWith(pub, "RSA" + bits);
        }

        @Test
        @DisplayName("a bare key size means RSA, as EJBCA writes it")
        void bareKeySize() throws Exception {
            assertEquals("RSA", generateThenReEnumerate("2048", "m-bare").getAlgorithm());
        }
    }

    @Nested
    @DisplayName("EC")
    class Ec {

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1", "secp256k1",
                "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"})
        @DisplayName("generates, re-enumerates, and lands on the right curve")
        void roundTrip(String curve) throws Exception {
            PublicKey pub = generateThenReEnumerate(curve, "m-" + curve);

            assertEquals("EC", pub.getAlgorithm());
            // Compared as OIDs, not as names: EJBCA reports the X9.62 spelling, so a key generated
            // as secp256r1 comes back as prime256v1. Same curve, different word for it — and a
            // name comparison would fail on that while missing an actual curve mix-up between two
            // curves that share a spelling convention.
            String reported = AlgorithmTools.getKeySpecification(pub);
            assertEquals(KeyTemplates.resolveCurveOid(curve), KeyTemplates.resolveCurveOid(reported),
                    () -> "generated on " + curve + " but EJBCA reads it as " + reported);
            assertTrue(((ECPublicKey) pub).getW().getAffineX().signum() > 0,
                    "a point of all zeroes means the encoding was misread");
            assertEjbcaCanSignWith(pub, curve);
        }

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {"P-256", "P-384", "P-521", "prime256v1"})
        @DisplayName("accepts the alternative spellings EJBCA emits")
        void curveAliases(String spelling) throws Exception {
            assertEquals("EC", generateThenReEnumerate(spelling, "m-alias-" + spelling)
                    .getAlgorithm());
        }
    }
}

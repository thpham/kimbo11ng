/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestBridge;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKA;

import java.security.InvalidKeyException;
import java.security.Security;
import java.util.Properties;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What a key on the token says it may be used for.
 *
 * <p>EJBCA reads this in exactly two places, and both were established by reading the bytecode in
 * {@code deps/ejbca}, not from documentation:
 *
 * <ul>
 *   <li>{@code BaseCryptoToken.testKeyPair} computes
 *       {@code contains(261) && !contains(264)} and runs an encrypt/decrypt test if true, a signing
 *       test otherwise. Note what this means for the empty set every EJBCA CE token returns today,
 *       including {@code PKCS11CryptoToken}: the predicate is false, so <em>everything</em> gets
 *       the signing test.
 *   <li>{@code CryptoTokenManagementSessionBean.getKeyUsageStringForKeyPairInfo} compares the set
 *       for equality against {@code {261}}, {@code {264}} and {@code {261,264}}, mapping them to
 *       {@code KeyPairInfo.KeyUsage.ENCRYPT}, {@code SIGN} and {@code SIGN_ENCRYPT}, and to
 *       {@code null} for anything else. This is what the admin UI shows per key.
 * </ul>
 */
@DisplayName("key usages")
class KeyUsageTest {

    /** {@code CKA_DECRYPT}, the constant EJBCA hardcodes as 261. */
    private static final long DECRYPT = 261L;
    /** {@code CKA_SIGN}, the constant EJBCA hardcodes as 264. */
    private static final long SIGN = 264L;

    private FakeToken token;
    private CryptoTokenImpl impl;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        token = new FakeToken();
        Properties properties = new Properties();
        properties.setProperty(CryptoTokenImpl.SHLIB_LABEL_KEY, "/nonexistent/libfake.so");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_TYPE, "SLOT_INDEX");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_VALUE, "0");
        properties.setProperty(CryptoTokenImpl.DO_NOT_ADD_P11_PROVIDER, "true");
        impl = new CryptoTokenImpl(new TestBridge(), new Pkcs11ModuleRegistry(path -> token));
        impl.init(properties, null, 60);
        impl.activate("1234".toCharArray());
    }

    /** EJBCA's own predicate, so the tests below assert the decision rather than describing it. */
    private static boolean picksEncryptionTest(Set<Long> usages) {
        return usages.contains(DECRYPT) && !usages.contains(SIGN);
    }

    @Nested
    @DisplayName("private keys")
    class Private {

        @Test
        @DisplayName("an RSA key reports sign and decrypt, which EJBCA renders as SIGN_ENCRYPT")
        void rsa() throws Exception {
            impl.generateKeyPair("2048", "rsaKey");
            Set<Long> usages = impl.getKeyUsagesFromPrivateKey("rsaKey");

            assertEquals(Set.of(DECRYPT, SIGN), usages);
            assertFalse(picksEncryptionTest(usages), "an RSA CA key must get the signing test");
        }

        @Test
        @DisplayName("an EC key reports sign only")
        void ec() throws Exception {
            impl.generateKeyPair("secp256r1", "ecKey");
            Set<Long> usages = impl.getKeyUsagesFromPrivateKey("ecKey");

            assertEquals(Set.of(SIGN), usages);
            assertFalse(picksEncryptionTest(usages));
        }

        @Test
        @DisplayName("an ML-DSA key reports sign and not decrypt")
        void mlDsa() throws Exception {
            impl.generateKeyPair("ML-DSA-65", "pqcKey");
            Set<Long> usages = impl.getKeyUsagesFromPrivateKey("pqcKey");

            assertEquals(Set.of(SIGN), usages);
            assertFalse(picksEncryptionTest(usages),
                    "an ML-DSA key run through an RSA encryption test fails inside a Cipher");
        }

        @Test
        @DisplayName("an ML-KEM key reports decrypt and not sign")
        void mlKem() throws Exception {
            // Honest, and it is what puts the key in EJBCA's encryption branch — which is why
            // testKeyPair is intercepted for it. See the KemKeys nested class below.
            impl.generateKeyPair("ML-KEM-768", "kemKey");
            Set<Long> usages = impl.getKeyUsagesFromPrivateKey("kemKey");

            assertEquals(Set.of(DECRYPT), usages);
            assertTrue(picksEncryptionTest(usages));
        }

        @Test
        @DisplayName("the answer is restricted to the two constants EJBCA compares against")
        void restrictedVocabulary() throws Exception {
            // The RSA private template also sets CKA_UNWRAP. Returning it would make
            // getKeyUsageStringForKeyPairInfo's set-equality miss, and the admin UI would show no
            // key usage at all — worse than the empty set this replaces.
            impl.generateKeyPair("2048", "rsaKey");
            assertFalse(impl.getKeyUsagesFromPrivateKey("rsaKey").contains(CKA.UNWRAP));
            assertTrue(impl.getKeyUsagesFromKey("rsaKey", true).contains(CKA.UNWRAP),
                    "asking for everything explicitly does report it");
        }
    }

    @Nested
    @DisplayName("public keys")
    class Public {

        @Test
        @DisplayName("an RSA public key reports encrypt and verify")
        void rsa() throws Exception {
            impl.generateKeyPair("2048", "rsaKey");
            assertEquals(Set.of(CKA.ENCRYPT, CKA.VERIFY),
                    impl.getKeyUsagesFromPublicKey("rsaKey"));
        }

        @Test
        @DisplayName("an EC public key reports verify only")
        void ec() throws Exception {
            impl.generateKeyPair("secp256r1", "ecKey");
            assertEquals(Set.of(CKA.VERIFY), impl.getKeyUsagesFromPublicKey("ecKey"));
        }

        @Test
        @DisplayName("the full public set includes CKA_WRAP for RSA")
        void fullSet() throws Exception {
            impl.generateKeyPair("2048", "rsaKey");
            assertEquals(Set.of(CKA.ENCRYPT, CKA.VERIFY, CKA.WRAP),
                    impl.getKeyUsagesFromKey("rsaKey", false));
        }
    }

    @Nested
    @DisplayName("reading attributes")
    class Reading {

        @Test
        @DisplayName("asks for exactly the attributes named")
        void explicitAttributes() throws Exception {
            impl.generateKeyPair("2048", "rsaKey");
            assertEquals(Set.of(CKA.UNWRAP),
                    impl.getKeyUsagesFromKey("rsaKey", true, CKA.UNWRAP, CKA.DERIVE));
        }

        @Test
        @DisplayName("one unsupported attribute does not lose the others")
        void unsupportedAttributeIsIsolated() throws Exception {
            // A bulk C_GetAttributeValue returns non-zero if any requested type is invalid for the
            // object, and jacknji11 turns that into an exception — so a single attribute the token
            // does not implement would take the whole answer with it.
            impl.generateKeyPair("2048", "rsaKey");
            token.omitAttribute(CKA.DECRYPT);

            assertEquals(Set.of(SIGN), impl.getKeyUsagesFromPrivateKey("rsaKey"));
        }

        @Test
        @DisplayName("an alias the token does not hold reports nothing rather than failing")
        void unknownAlias() throws Exception {
            // EJBCA asks per alias while building its key list; a missing object is not an error.
            assertEquals(Set.of(), impl.getKeyUsagesFromPrivateKey("neverGenerated"));
        }

        @Test
        @DisplayName("finds the key by CKA_ID, so a relabelled half is still found")
        void resolvesByKeyId() throws Exception {
            impl.generateKeyPair("2048", "rsaKey");
            // Rename only the public half on the token, behind this instance's back.
            byte[] renamed = "someoneElse".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            var ref = impl.getProvider().getKeyStoreSpi().referenceFor("rsaKey");
            try (var lease = impl.getSlot().borrow()) {
                for (long h : ref.findAll(impl.getSlot().ce(), lease.session(),
                        org.pkcs11.jacknji11.CKO.PUBLIC_KEY, true)) {
                    impl.getSlot().ce().SetAttributeValue(lease.session(), h,
                            new CKA(CKA.LABEL, renamed));
                }
            }

            assertEquals(Set.of(CKA.ENCRYPT, CKA.VERIFY),
                    impl.getKeyUsagesFromPublicKey("rsaKey"),
                    "a label search would have found nothing");
        }
    }

    @Nested
    @DisplayName("key-encapsulation keys")
    class KemKeys {

        @Test
        @DisplayName("refuses a key test that would run a Cipher against an ML-KEM key")
        void kemKeyPairIsNotTestable() throws Exception {
            impl.generateKeyPair("ML-KEM-768", "kemKey");

            InvalidKeyException e = assertThrows(InvalidKeyException.class,
                    () -> impl.requireTestableKeyPair("kemKey"));
            assertTrue(e.getMessage().contains("ML-KEM-768"), e.getMessage());
            assertTrue(e.getMessage().contains("key-encapsulation"), e.getMessage());
        }

        @Test
        @DisplayName("lets every signing key through")
        void signingKeysAreTestable() throws Exception {
            impl.generateKeyPair("ML-DSA-65", "pqcKey");
            impl.generateKeyPair("2048", "rsaKey");
            impl.generateKeyPair("secp256r1", "ecKey");

            for (String alias : new String[] {"pqcKey", "rsaKey", "ecKey"}) {
                impl.requireTestableKeyPair(alias);
            }
            // And an alias that does not exist is EJBCA's problem to report, not this check's.
            impl.requireTestableKeyPair("neverGenerated");
        }
    }
}

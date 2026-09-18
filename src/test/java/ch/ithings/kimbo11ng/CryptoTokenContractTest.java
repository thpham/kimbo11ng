/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The token as EJBCA holds it, rather than as {@link CryptoTokenImpl} implements it.
 *
 * <p>Every other unit test drives {@code CryptoTokenImpl} through {@code TestBridge}, which is the
 * useful seam but skips the half of the behaviour that lives in the overrides here and in
 * {@code BaseCryptoToken} underneath them. That half is where the consequences are: what EJBCA
 * stores as {@code tokenType}, which branch {@code testKeyPair} picks, and what escapes
 * {@code getPrivateKey} when an alias is not the kind of key the caller assumed. Those were covered
 * only by the container integration tests, which is minutes per assertion and unavailable offline.
 *
 * <p>The class under test is the alias, {@code Pkcs11NgCryptoToken}, and not its parent: that FQN
 * is the one EJBCA's registry names and instantiates.
 */
@DisplayName("the CryptoToken EJBCA sees")
class CryptoTokenContractTest {

    /** {@code CKA_DECRYPT} and {@code CKA_SIGN}, the constants EJBCA hardcodes. */
    private static final long DECRYPT = 261L;
    private static final long SIGN = 264L;

    private FakeToken token;
    private Pkcs11NgCryptoToken cryptoToken;
    private String registeredProvider;

    /** Reaches the protected test constructor, which is the only way to substitute the fake. */
    private static final class Alias extends Pkcs11NgCryptoToken {
        private static final long serialVersionUID = 1L;

        Alias(Pkcs11ModuleRegistry modules) throws InstantiationException {
            super(modules);
        }
    }

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        token = new FakeToken();
        cryptoToken = new Alias(new Pkcs11ModuleRegistry(path -> token));
        Properties properties = new Properties();
        properties.setProperty(CryptoTokenImpl.SHLIB_LABEL_KEY, "/nonexistent/libfake.so");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_TYPE, "SLOT_INDEX");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_VALUE, "0");
        // Deliberately NOT doNotAddP11Provider, which every other unit test sets. BaseCryptoToken
        // resolves the signing provider by NAME out of java.security.Security, so the real
        // testKeyPair path is unreachable unless the provider is actually registered. That is
        // global JVM state, hence the removal in tearDown.
        cryptoToken.init(properties, null, 4711);
        registeredProvider = cryptoToken.getSignProviderName();
    }

    @AfterEach
    void tearDown() {
        if (registeredProvider != null) {
            Security.removeProvider(registeredProvider);
        }
    }

    private void activate() throws Exception {
        cryptoToken.activate("1234".toCharArray());
    }

    @Nested
    @DisplayName("identity")
    class Identity {

        @Test
        @DisplayName("the class EJBCA instantiates names itself Pkcs11NgCryptoToken")
        void simpleNameIsTheStoredTokenType() throws Exception {
            // CryptoTokenSessionBean.mergeCryptoToken stores getConcreteClass().getSimpleName() as
            // the tokenType column, and CryptoTokenSessionBean.getClassNameForType resolves it back
            // by scanning the registry for a registered class path that endsWith it. A rename here
            // is silent: the row resolves to null and EJBCA substitutes a NullCryptoToken. On CE 9.6
            // it is worse than silent — any type outside {Soft, Null} is what the startup check
            // refuses to boot with. See docs/EJBCA_UPSTREAM_WATCH.md, W1 and W2.
            assertEquals("Pkcs11NgCryptoToken", new Pkcs11NgCryptoToken().getClass().getSimpleName());
            assertEquals("org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken",
                    Pkcs11NgCryptoToken.class.getName());
        }

        @Test
        @DisplayName("is a BaseCryptoToken and a P11SlotUser, which is what EJBCA casts it to")
        void satisfiesTheContracts() {
            assertTrue(cryptoToken instanceof CryptoToken);
            assertTrue(cryptoToken
                    instanceof com.keyfactor.util.keys.token.pkcs11.P11SlotUser);
        }

        @Test
        @DisplayName("never permits an extractable private key, and carries no token data")
        void refusesExtractableKeys() {
            // EJBCA asks before it offers key export in the admin UI. The answer is fixed: a key
            // generated by this token is CKA_EXTRACTABLE=false and there is nothing to export.
            assertFalse(cryptoToken.permitExtractablePrivateKeyForTest());
            assertFalse(cryptoToken.doPermitExtractablePrivateKey());
            // Soft tokens return a serialized keystore here. A PKCS#11 token has none: the key
            // material never leaves the HSM, so there is nothing to persist in the database.
            assertNull(cryptoToken.getTokenData());
        }
    }

    @Nested
    @DisplayName("activation")
    class Activation {

        @Test
        @DisplayName("is offline until activated and after deactivation")
        void statusFollowsActivation() throws Exception {
            // isActive is P11SlotUser's method, and the slot-list wrapper calls it to decide whether
            // a slot is still in use. It must agree with the status EJBCA reads, or a slot is
            // released while a CA is still signing through it.
            assertFalse(cryptoToken.isActive());
            assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());

            activate();
            assertTrue(cryptoToken.isActive());
            assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());

            cryptoToken.deactivate();
            assertFalse(cryptoToken.isActive());
            assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
        }

        @Test
        @DisplayName("activating again after deactivation brings the same token back")
        void reactivates() throws Exception {
            activate();
            cryptoToken.generateKeyPair("secp256r1", "ecKey");
            cryptoToken.deactivate();

            activate();
            assertTrue(cryptoToken.isActive());
            assertNotNull(cryptoToken.getPublicKey("ecKey"),
                    "the key is on the token, not in the session");
        }
    }

    @Nested
    @DisplayName("keys through the EJBCA surface")
    class Keys {

        @Test
        @DisplayName("generates a key pair and hands back both halves")
        void generatesAndReadsBack() throws Exception {
            activate();
            cryptoToken.generateKeyPair("2048", "rsaKey");

            PublicKey pub = cryptoToken.getPublicKey("rsaKey");
            PrivateKey priv = cryptoToken.getPrivateKey("rsaKey");
            assertEquals("RSA", pub.getAlgorithm());
            assertNotNull(priv);
            assertTrue(cryptoToken.doesPrivateKeyExist("rsaKey"));
            assertTrue(cryptoToken.getAliases().contains("rsaKey"));
        }

        @Test
        @DisplayName("reports the key usages EJBCA renders in the admin UI")
        void keyUsagesReachTheSurface() throws Exception {
            activate();
            cryptoToken.generateKeyPair("2048", "rsaKey");

            // getKeyUsageStringForKeyPairInfo compares this set for equality against {261},
            // {264} and {261,264}; anything else shows as no key usage at all.
            assertEquals(java.util.Set.of(DECRYPT, SIGN),
                    cryptoToken.getKeyUsagesFromPrivateKey("rsaKey"));
        }

        @Test
        @DisplayName("generates from KeyGenParams, the overload the admin UI calls")
        void generatesFromKeyGenParams() throws Exception {
            activate();
            cryptoToken.generateKeyPair(
                    com.keyfactor.util.keys.token.KeyGenParams.builder("2048").build(), "rsaKey");

            assertTrue(cryptoToken.doesPrivateKeyExist("rsaKey"));
            assertEquals("RSA", cryptoToken.getPublicKey("rsaKey").getAlgorithm());
        }

        @Test
        @DisplayName("reports public-key and explicit-attribute usages too")
        void theOtherKeyUsageOverloads() throws Exception {
            activate();
            cryptoToken.generateKeyPair("2048", "rsaKey");

            assertEquals(java.util.Set.of(org.pkcs11.jacknji11.CKA.ENCRYPT,
                            org.pkcs11.jacknji11.CKA.VERIFY),
                    cryptoToken.getKeyUsagesFromPublicKey("rsaKey"));
            assertEquals(java.util.Set.of(org.pkcs11.jacknji11.CKA.UNWRAP),
                    cryptoToken.getKeyUsagesFromKey("rsaKey", true, org.pkcs11.jacknji11.CKA.UNWRAP));
        }

        @Test
        @DisplayName("reset drops the token back to offline")
        void resetTakesItOffline() throws Exception {
            activate();
            cryptoToken.generateKeyPair("secp256r1", "ecKey");
            assertTrue(cryptoToken.isActive());

            // EJBCA calls reset when it re-reads a token's configuration. It has to leave the token
            // needing activation again, or a stale session survives a credential change.
            cryptoToken.reset();
            assertFalse(cryptoToken.isActive());
        }

        @Test
        @DisplayName("deletes a key pair through the alias EJBCA knows it by")
        void deletes() throws Exception {
            activate();
            cryptoToken.generateKeyPair("secp256r1", "ecKey");
            assertTrue(cryptoToken.doesPrivateKeyExist("ecKey"));

            cryptoToken.deleteEntry("ecKey");
            assertFalse(cryptoToken.doesPrivateKeyExist("ecKey"));
            assertFalse(cryptoToken.getAliases().contains("ecKey"));
        }
    }

    @Nested
    @DisplayName("testKeyPair")
    class KeyTest {

        @Test
        @DisplayName("signs and verifies a signing key, through BaseCryptoToken's own path")
        void signingKeysPass() throws Exception {
            activate();
            cryptoToken.generateKeyPair("2048", "rsaKey");
            cryptoToken.generateKeyPair("secp256r1", "ecKey");
            cryptoToken.generateKeyPair("ML-DSA-65", "pqcKey");

            // This is the whole of BaseCryptoToken.testKeyPair: pick a branch from the key usages,
            // then sign and verify for real. It is what the admin UI's "Test" button runs and what
            // HsmKeepAliveWorker runs on a schedule.
            for (String alias : new String[] {"rsaKey", "ecKey", "pqcKey"}) {
                cryptoToken.testKeyPair(alias);
            }
        }

        @Test
        @DisplayName("actually runs BaseCryptoToken's test, rather than silently passing")
        void theTestIsReallyPerformed() throws Exception {
            activate();
            cryptoToken.generateKeyPair("secp256r1", "ecKey");

            // The guard in the override is only half the behaviour; the other half is delegating to
            // super, and an override that forgot to would report every key healthy — including the
            // one whose HSM has stopped answering, which is the single thing testKeyPair exists to
            // notice. Failing the token's next call is the cheapest way to prove the signature is
            // genuinely attempted.
            token.failNextWith(org.pkcs11.jacknji11.CKR.FUNCTION_FAILED);
            assertThrows(Exception.class, () -> cryptoToken.testKeyPair("ecKey"),
                    "a token that will not sign must not pass its own key test");
        }

        @Test
        @DisplayName("refuses an ML-KEM key before BaseCryptoToken can pick the encryption branch")
        void kemKeysAreRefusedWithAnExplanation() throws Exception {
            activate();
            cryptoToken.generateKeyPair("ML-KEM-768", "kemKey");

            // The key honestly reports CKA_DECRYPT and no CKA_SIGN, which selects the RSA-style
            // encrypt/decrypt branch. Key encapsulation is not encryption, so without this override
            // the failure is a padding error from inside a JCA Cipher, which names neither the
            // algorithm nor the reason.
            InvalidKeyException e = assertThrows(InvalidKeyException.class,
                    () -> cryptoToken.testKeyPair("kemKey"));
            assertTrue(e.getMessage().contains("ML-KEM-768"), e.getMessage());
            assertTrue(e.getMessage().contains("key-encapsulation"), e.getMessage());
        }
    }

    @Nested
    @DisplayName("a secret key under an alias")
    class SecretKeys {

        @Test
        @DisplayName("getPrivateKey reports it as absent rather than letting a cast escape")
        void getPrivateKeyRefusesASecretKey() throws Exception {
            activate();
            cryptoToken.generateKey("HmacSHA256", 256, "dbProtectionKey");

            // BaseCryptoToken.getPrivateKey is an unguarded (PrivateKey) cast whose catch does not
            // cover ClassCastException. HsmKeepAliveWorker walks every alias and calls testKeyPair
            // on each, catching only InvalidKeyException, CryptoTokenOfflineException and
            // KeyStoreException — so one secret key on the token would take the keep-alive service
            // down on a schedule.
            CryptoTokenOfflineException e = assertThrows(CryptoTokenOfflineException.class,
                    () -> cryptoToken.getPrivateKey("dbProtectionKey"));
            assertTrue(e.getMessage().contains("dbProtectionKey"), e.getMessage());
            assertTrue(e.getMessage().contains("secret key"), e.getMessage());
        }

        @Test
        @DisplayName("doesPrivateKeyExist answers false for it, which is the truth")
        void doesPrivateKeyExistIsFalse() throws Exception {
            activate();
            cryptoToken.generateKey("HmacSHA256", 256, "dbProtectionKey");

            assertFalse(cryptoToken.doesPrivateKeyExist("dbProtectionKey"));
            assertTrue(cryptoToken.getAliases().contains("dbProtectionKey"),
                    "it is still on the token, and still listed");
        }

        @Test
        @DisplayName("testKeyPair refuses it by name, so the keep-alive sweep survives it")
        void testKeyPairSurvivesASecretKey() throws Exception {
            activate();
            cryptoToken.generateKey("HmacSHA256", 256, "dbProtectionKey");

            // Any of the three exceptions the worker catches would do; what must not happen is an
            // unchecked one.
            assertThrows(Exception.class, () -> cryptoToken.testKeyPair("dbProtectionKey"));
            try {
                cryptoToken.testKeyPair("dbProtectionKey");
            } catch (InvalidKeyException | CryptoTokenOfflineException expected) {
                return;
            }
            throw new AssertionError("testKeyPair on a secret key must fail, and checked");
        }
    }
}

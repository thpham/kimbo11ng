/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestBridge;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import ch.ithings.kimbo11ng.provider.Kimbo11ngSecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Symmetric keys: {@code C_GenerateKey}, and the MAC that makes the result worth having.
 *
 * <p>This is the {@code CryptoToken.generateKey} path, which is not the {@code generateKeyPair} one:
 * PKCS#11 has a separate call for a single secret key, and EJBCA reaches it through the JCA — a
 * {@code KeyGenerator} from this provider, then {@code setKeyEntry} to name the result. Both halves
 * are exercised here, because either alone leaves the key invisible or nameless.
 *
 * <p>In EJBCA CE nothing calls this: the only call site in the deployed EAR is a pass-through in
 * {@code org.cesecore.dbprotection.CachedCryptoToken}, which CE never constructs. The tests are
 * therefore the only consumer today, and they are written to hold the contract for the day database
 * protection becomes one.
 */
@DisplayName("symmetric keys")
class SymmetricKeyTest {

    private FakeToken token;
    private TestBridge bridge;
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
        bridge = new TestBridge();
        Properties properties = new Properties();
        properties.setProperty(CryptoTokenImpl.SHLIB_LABEL_KEY, "/nonexistent/libfake.so");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_TYPE, "SLOT_INDEX");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_VALUE, "0");
        properties.setProperty(CryptoTokenImpl.DO_NOT_ADD_P11_PROVIDER, "true");
        impl = new CryptoTokenImpl(bridge, new Pkcs11ModuleRegistry(path -> token));
        impl.init(properties, null, 77);
        impl.activate("1234".toCharArray());
    }

    private List<String> aliases() throws Exception {
        return Collections.list(bridge.bridgeGetKeyStore().aliases());
    }

    @Test
    @DisplayName("generates an HMAC key and gives it the requested alias")
    void generatesAndNames() throws Exception {
        impl.generateKey("HmacSHA256", 256, "dbProtectionKey");

        assertTrue(aliases().contains("dbProtectionKey"),
                "the alias has to reach the CachingKeyStoreWrapper, or EJBCA reports it absent");
        Key key = bridge.bridgeGetKeyStore().getKey("dbProtectionKey", null);
        assertInstanceOf(Kimbo11ngSecretKey.class, key);
        assertEquals("HmacSHA256", key.getAlgorithm());
    }

    @Test
    @DisplayName("the key material never leaves the token")
    void keyIsNotExtractable() throws Exception {
        impl.generateKey("HmacSHA256", 256, "sealed");

        Key key = bridge.bridgeGetKeyStore().getKey("sealed", null);
        assertNull(key.getEncoded(),
                "a CKA_SENSITIVE key must not pretend to expose its bytes");
        assertEquals("PKCS#11", key.getFormat());
    }

    @Test
    @DisplayName("MACs through the token, and the answer matches the key the token actually holds")
    void macRoundTrip() throws Exception {
        impl.generateKey("HmacSHA256", 256, "macKey");
        Key key = bridge.bridgeGetKeyStore().getKey("macKey", null);

        Mac mac = Mac.getInstance("HmacSHA256", impl.getProvider());
        mac.init(key);
        byte[] first = mac.doFinal("protected row".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        assertEquals(32, first.length, "HmacSHA256 is 32 bytes");
        // Deterministic across invocations: the second MAC of the same input under the same key
        // must be identical, which a per-call random would not be and a wrong key would not be.
        mac.init(key);
        byte[] second = mac.doFinal("protected row".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertArrayEquals(first, second);

        mac.init(key);
        byte[] other = mac.doFinal("a different row".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertFalse(java.util.Arrays.equals(first, other));
    }

    @Test
    @DisplayName("the three HMAC sizes each produce their own digest length")
    void macLengths() throws Exception {
        record Case(String algorithm, int bits, int macBytes) {
        }
        List<Case> cases = List.of(
                new Case("HmacSHA256", 256, 32),
                new Case("HmacSHA384", 384, 48),
                new Case("HmacSHA512", 512, 64));
        List<Integer> lengths = new ArrayList<>();
        for (Case c : cases) {
            impl.generateKey(c.algorithm(), c.bits(), "key-" + c.algorithm());
            Mac mac = Mac.getInstance(c.algorithm(), impl.getProvider());
            mac.init(bridge.bridgeGetKeyStore().getKey("key-" + c.algorithm(), null));
            lengths.add(mac.doFinal(new byte[] {1, 2, 3}).length);
        }
        assertEquals(List.of(32, 48, 64), lengths);
    }

    @Test
    @DisplayName("survives a re-enumeration, which is what a restart does")
    void survivesReload() throws Exception {
        impl.generateKey("HmacSHA256", 256, "persistent");
        assertTrue(aliases().contains("persistent"));

        // deactivate + activate re-runs engineLoad, which clears the maps and reads the token
        // again. A secret key that was only in memory would vanish here — which is what happened
        // before enumerateSecretKeys existed.
        impl.deactivate();
        impl.activate("1234".toCharArray());

        assertTrue(aliases().contains("persistent"),
                "a token-resident key must come back from the token, not from a Java map");
        Key reloaded = bridge.bridgeGetKeyStore().getKey("persistent", null);
        assertNotNull(reloaded);
        // The key type is what the token records; the MAC it will serve is not, so the enumerated
        // name is the key type rather than a guess at HmacSHA256.
        assertEquals("GenericSecret", reloaded.getAlgorithm());

        Mac mac = Mac.getInstance("HmacSHA256", impl.getProvider());
        mac.init(reloaded);
        assertEquals(32, mac.doFinal(new byte[] {9}).length,
                "the reloaded key must still be usable");
    }

    @Test
    @DisplayName("deleting removes the object from the token")
    void deleteRemovesTheObject() throws Exception {
        impl.generateKey("HmacSHA256", 256, "temporary");
        int before = token.handles().size();

        bridge.bridgeGetKeyStore().deleteEntry("temporary");

        assertFalse(aliases().contains("temporary"));
        assertEquals(before - 1, token.handles().size(),
                "the secret key object itself must be destroyed, not merely forgotten");
    }

    @Test
    @DisplayName("refuses an alias the token already uses")
    void refusesDuplicateAlias() throws Exception {
        impl.generateKey("HmacSHA256", 256, "taken");

        KeyStoreException e = assertThrows(KeyStoreException.class,
                () -> impl.generateKey("HmacSHA256", 256, "taken"));
        assertTrue(e.getMessage().contains("already holds a key"), e.getMessage());
    }

    @Test
    @DisplayName("refuses an alias already used by a key pair")
    void refusesAliasOfAKeyPair() throws Exception {
        impl.generateKeyPair("2048", "caKey");

        KeyStoreException e = assertThrows(KeyStoreException.class,
                () -> impl.generateKey("HmacSHA256", 256, "caKey"));
        assertTrue(e.getMessage().contains("already holds a key"), e.getMessage());
    }

    @Test
    @DisplayName("names the supported algorithms when asked for one it does not have")
    void unknownAlgorithmIsNamed() {
        NoSuchAlgorithmException e = assertThrows(NoSuchAlgorithmException.class,
                () -> impl.generateKey("Blowfish", 128, "nope"));
        assertTrue(e.getMessage().contains("HmacSHA256"), e.getMessage());
    }

    @Test
    @DisplayName("refuses AES, because a key it cannot use is worse than no key")
    void aesIsRefusedWithAReason() {
        // The token would generate it happily. The provider registers no Cipher, and the key is
        // not extractable, so the result would be an object nothing in this JVM could use.
        NoSuchAlgorithmException e = assertThrows(NoSuchAlgorithmException.class,
                () -> impl.generateKey("AES", 256, "aesKey"));
        assertTrue(e.getMessage().contains("Cipher"), e.getMessage());
        assertTrue(e.getMessage().contains("HmacSHA256"), e.getMessage());
    }

    @Test
    @DisplayName("refuses an HMAC key shorter than its own digest, and blames the size not the token")
    void refusesAShortKey() {
        KeyStoreException e = assertThrows(KeyStoreException.class,
                () -> impl.generateKey("HmacSHA512", 128, "weak"));
        assertTrue(e.getMessage().startsWith("HmacSHA512 keys must be at least 512 bits"),
                e.getMessage());
    }

    @Test
    @DisplayName("an offline token says so rather than 'not implemented'")
    void offlineTokenIsNamedOffline() throws Exception {
        impl.deactivate();

        assertThrows(com.keyfactor.util.keys.token.CryptoTokenOfflineException.class,
                () -> impl.generateKey("HmacSHA256", 256, "whenever"));
    }

    @Test
    @DisplayName("a secret alias is not a PrivateKey, which is the cast BaseCryptoToken makes")
    void aSecretAliasWouldBreakTheUnguardedCast() throws Exception {
        impl.generateKey("HmacSHA256", 256, "hmacKey");
        impl.generateKeyPair("2048", "caKey");

        // BaseCryptoToken.getPrivateKey is (PrivateKey) getKeyStore().getKey(alias, pin), and its
        // catch block covers KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException
        // and ProviderException — not ClassCastException. This asserts the fact that makes that a
        // hazard, so that a future change to engineGetKey cannot quietly remove the reason for the
        // getPrivateKey override in Kimbo11ngCryptoToken.
        Key secret = bridge.bridgeGetKeyStore().getKey("hmacKey", null);
        assertFalse(secret instanceof java.security.PrivateKey,
                "if this ever becomes true, the override in Kimbo11ngCryptoToken is obsolete —"
                        + " and if it is false, that override is what stops HsmKeepAliveWorker from"
                        + " dying on a ClassCastException");
        assertTrue(bridge.bridgeGetKeyStore().getKey("caKey", null)
                instanceof java.security.PrivateKey);

        assertTrue(impl.isSecretKey("hmacKey"));
        assertFalse(impl.isSecretKey("caKey"));
        assertFalse(impl.isSecretKey("neverHeardOf"));
    }

    @Test
    @DisplayName("refuses to run a key-pair test on a secret key")
    void refusesAKeyPairTestOnASecretKey() throws Exception {
        impl.generateKey("HmacSHA256", 256, "hmacKey");

        java.security.InvalidKeyException e = assertThrows(java.security.InvalidKeyException.class,
                () -> impl.requireTestableKeyPair("hmacKey"));
        assertTrue(e.getMessage().contains("no public half"), e.getMessage());
    }

    @Test
    @DisplayName("the MAC refuses a key that is not on this token")
    void macRefusesASoftwareKey() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256", impl.getProvider());
        // Falling back to a software HMAC over the supplied bytes would silently defeat the point
        // of the HSM, so this must be a refusal rather than a convenience.
        assertThrows(java.security.InvalidKeyException.class,
                () -> mac.init(new javax.crypto.spec.SecretKeySpec(new byte[32], "HmacSHA256")));
    }

    @Test
    @DisplayName("symmetric services are absent when the token does not offer the mechanism")
    void servicesFollowTheToken() throws Exception {
        FakeToken plain = new FakeToken();
        plain.hideMechanism(org.pkcs11.jacknji11.CKM.GENERIC_SECRET_KEY_GEN);
        CryptoTokenImpl restricted = new CryptoTokenImpl(new TestBridge(),
                new Pkcs11ModuleRegistry(path -> plain));
        Properties properties = new Properties();
        properties.setProperty(CryptoTokenImpl.SHLIB_LABEL_KEY, "/nonexistent/other.so");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_TYPE, "SLOT_INDEX");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_VALUE, "0");
        properties.setProperty(CryptoTokenImpl.DO_NOT_ADD_P11_PROVIDER, "true");
        restricted.init(properties, null, 78);

        assertNull(restricted.getProvider().getService("KeyGenerator", "HmacSHA256"),
                "a mechanism the token does not advertise must not be offered as a service");
        // The Mac stays: CKM_SHA256_HMAC is still advertised, and a key created elsewhere on this
        // token would still be usable with it.
        assertNotNull(restricted.getProvider().getService("Mac", "HmacSHA256"));
    }
}

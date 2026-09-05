/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import ch.ithings.kimbo11ng.p11.SessionPoolConfig;
import com.keyfactor.util.keys.CachingKeyStoreWrapper;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKR;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Token lifecycle: init, activate, generate, deactivate, reset.
 *
 * <p>The states have to be honest, because EJBCA acts on them. A token that reports itself active
 * while its login has been dropped produces signature failures on whatever request happens to
 * arrive next, attributed to that request rather than to the token.
 */
@DisplayName("crypto token lifecycle")
class CryptoTokenLifecycleTest {

    /** The parts of {@code BaseCryptoToken} that {@code CryptoTokenImpl} reaches back into. */
    private static final class RecordingBridge implements CryptoTokenBridge {

        private Properties properties = new Properties();
        private CachingKeyStoreWrapper keyStore;
        private Provider provider;
        private String tokenName;
        private int id;
        private final AtomicInteger keyStoreSets = new AtomicInteger();

        @Override
        public void bridgeSetKeyStore(KeyStore ks) throws KeyStoreException {
            keyStoreSets.incrementAndGet();
            // Mirrors BaseCryptoToken: a null keystore is what "offline" means to EJBCA, and a
            // non-null one is wrapped in the cache whose alias list is built once.
            this.keyStore = ks == null ? null : new CachingKeyStoreWrapper(ks, true);
        }

        @Override
        public CachingKeyStoreWrapper bridgeGetKeyStore() {
            return keyStore;
        }

        @Override
        public void bridgeSetJCAProvider(Provider provider) {
            this.provider = provider;
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
            this.tokenName = name;
        }

        @Override
        public void bridgeSetId(int id) {
            this.id = id;
        }
    }

    private FakeToken token;
    private RecordingBridge bridge;
    private CryptoTokenImpl impl;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static Properties tokenProperties() {
        Properties p = new Properties();
        p.setProperty(CryptoTokenImpl.SHLIB_LABEL_KEY, "/nonexistent/libfake.so");
        p.setProperty(CryptoTokenImpl.SLOT_LABEL_TYPE, "SLOT_INDEX");
        p.setProperty(CryptoTokenImpl.SLOT_LABEL_VALUE, "0");
        p.setProperty(CryptoTokenImpl.DO_NOT_ADD_P11_PROVIDER, "true");
        return p;
    }

    @BeforeEach
    void setUp() throws Exception {
        token = new FakeToken();
        bridge = new RecordingBridge();
        impl = new CryptoTokenImpl(bridge, new Pkcs11ModuleRegistry(path -> token));
        impl.init(tokenProperties(), null, 42);
    }

    @Test
    @DisplayName("resolves the slot and the provider through one library initialization")
    void initResolvesSlotOnce() {
        assertNotNull(impl.getProvider());
        assertNotNull(impl.getSlot());
        assertEquals(0L, impl.getSlot().slotId());
        // Slot resolution and the token's own slot used to initialize the library separately.
        assertEquals(1, token.initializeCalls());
    }

    @Test
    @DisplayName("activating logs in and publishes a keystore")
    void activatePublishesKeyStore() throws Exception {
        impl.activate("1234".toCharArray());

        assertTrue(impl.getSlot().isLoggedIn());
        assertNotNull(bridge.bridgeGetKeyStore(), "EJBCA reads 'online' as a non-null keystore");
        assertEquals(1, token.loginCalls());
    }

    @Test
    @DisplayName("reports a wrong PIN as an authentication failure")
    void wrongPinIsAuthenticationFailure() {
        assertThrows(CryptoTokenAuthenticationFailedException.class,
                () -> impl.activate("wrong".toCharArray()));
        assertNull(bridge.bridgeGetKeyStore());
    }

    @Test
    @DisplayName("reports a missing token as offline, not as a bad PIN")
    void missingTokenIsOffline() {
        // Previously every activation failure was reported as CryptoTokenAuthenticationFailedException,
        // so an operator whose HSM was unplugged spent their time checking the PIN.
        token.failNextWith(CKR.TOKEN_NOT_PRESENT);
        CryptoTokenOfflineException e = assertThrows(CryptoTokenOfflineException.class,
                () -> impl.activate("1234".toCharArray()));
        assertTrue(e.getMessage().contains("TOKEN_NOT_PRESENT"), e.getMessage());
    }

    @Test
    @DisplayName("deactivating clears the keystore, the cached keys and the login")
    void deactivateIsTruthful() throws Exception {
        impl.activate("1234".toCharArray());
        impl.generateKeyPair("2048", "signKey");
        assertTrue(impl.getProvider().getKeyStoreSpi().engineContainsAlias("signKey"));

        impl.deactivate();

        assertNull(bridge.bridgeGetKeyStore(), "a deactivated token must read as offline");
        assertFalse(impl.getSlot().isLoggedIn(), "the token must actually be logged out");
        assertEquals(0, impl.getProvider().getKeyStoreSpi().engineSize(),
                "cached handles must go: otherwise a deactivated token keeps handing out keys "
                        + "whose session is no longer authenticated");
    }

    @Test
    @DisplayName("resetting also drains the session pool")
    void resetDrainsSessions() throws Exception {
        impl.activate("1234".toCharArray());
        impl.generateKeyPair("2048", "signKey");
        assertTrue(token.openSessionCount() > 0);

        impl.reset();

        assertEquals(0, token.openSessionCount(), "reset must release the sessions");
        assertEquals(0, token.finalizeCalls(),
                "but never finalize the library: another component may be using it");
    }

    @Test
    @DisplayName("a token can be activated again after being reset")
    void reactivationWorksAfterReset() throws Exception {
        impl.activate("1234".toCharArray());
        impl.generateKeyPair("2048", "signKey");
        impl.reset();

        impl.activate("1234".toCharArray());
        assertNotNull(bridge.bridgeGetKeyStore());
        // The key is still on the token, so enumeration must find it again without regenerating.
        assertTrue(impl.getProvider().getKeyStoreSpi().engineContainsAlias("signKey"),
                "keys survive a reset; only sessions do not");
    }

    @Test
    @DisplayName("generating a key makes it visible to EJBCA immediately")
    void generatedKeyIsVisibleThroughTheCache() throws Exception {
        impl.activate("1234".toCharArray());
        impl.generateKeyPair("ML-DSA-65", "pqcKey");

        // The CachingKeyStoreWrapper builds its alias list once, and a key generated on the token
        // never passes through KeyStore.setKeyEntry, so without an explicit refresh EJBCA reports
        // "No key with alias" for a key that demonstrably exists.
        assertTrue(java.util.Collections.list(bridge.bridgeGetKeyStore().aliases())
                .contains("pqcKey"));
    }

    @Test
    @DisplayName("honours a configured session ceiling")
    void sessionCeilingComesFromProperties() throws Exception {
        Properties properties = tokenProperties();
        properties.setProperty(SessionPoolConfig.MAX_SESSIONS, "2");
        CryptoTokenImpl configured = new CryptoTokenImpl(new RecordingBridge(),
                new Pkcs11ModuleRegistry(path -> new FakeToken()));
        configured.init(properties, null, 43);
        configured.activate("1234".toCharArray());

        try (var a = configured.getSlot().borrow(); var b = configured.getSlot().borrow()) {
            assertNotNull(a);
            assertNotNull(b);
            assertThrows(CryptoTokenOfflineException.class, () -> configured.getSlot().borrow());
        }
    }

    @Test
    @DisplayName("refuses to initialize without a library path")
    void libraryPathIsRequired() {
        Properties empty = new Properties();
        CryptoTokenImpl bare = new CryptoTokenImpl(new RecordingBridge(),
                new Pkcs11ModuleRegistry(path -> new FakeToken()));
        CryptoTokenOfflineException e = assertThrows(CryptoTokenOfflineException.class,
                () -> bare.init(empty, null, 44));
        assertTrue(e.getMessage().contains(CryptoTokenImpl.SHLIB_LABEL_KEY), e.getMessage());
    }
}

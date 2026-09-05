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

import java.security.InvalidAlgorithmParameterException;
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
    @DisplayName("refuses to generate a second key under an alias the token already uses")
    void duplicateAliasIsRejected() throws Exception {
        impl.activate("1234".toCharArray());
        impl.generateKeyPair("2048", "signKey");

        // PKCS#11 does not constrain CKA_LABEL, so without this check the token ends up holding
        // two keys with one name. Everything appears to work — enumeration picks one arbitrarily —
        // until a restart picks the other and the CA signs with a key its certificate does not match.
        InvalidAlgorithmParameterException e = assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> impl.generateKeyPair("2048", "signKey"));
        assertTrue(e.getMessage().contains("signKey"), e.getMessage());

        assertEquals(1, impl.getProvider().getKeyStoreSpi().engineSize());
    }

    @Test
    @DisplayName("checks the token, not just its own cache, for the alias")
    void duplicateAliasIsCheckedOnTheToken() throws Exception {
        impl.activate("1234".toCharArray());
        // Created behind this instance's back, as another node or a vendor tool would.
        var templates = ch.ithings.kimbo11ng.provider.KeyTemplates.rsa(
                "external".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                ch.ithings.kimbo11ng.provider.KeyTemplates.newKeyId(), 2048);
        try (var lease = impl.getSlot().borrow()) {
            impl.getSlot().ce().GenerateKeyPair(lease.session(),
                    new org.pkcs11.jacknji11.CKM(org.pkcs11.jacknji11.CKM.RSA_PKCS_KEY_PAIR_GEN),
                    templates.pub(), templates.priv(),
                    new org.pkcs11.jacknji11.LongRef(), new org.pkcs11.jacknji11.LongRef());
        }

        assertThrows(InvalidAlgorithmParameterException.class,
                () -> impl.generateKeyPair("2048", "external"));
    }

    @Test
    @DisplayName("goes offline when the signing path reports the token gone")
    void offlineReportClearsTheKeyStore() throws Exception {
        impl.activate("1234".toCharArray());
        impl.generateKeyPair("2048", "signKey");
        assertNotNull(bridge.bridgeGetKeyStore());

        // The seam the signing path uses when it sees CKR_TOKEN_NOT_PRESENT: it can detect the
        // failure but cannot act on it, because clearing EJBCA's keystore is not reachable there.
        impl.getSlot().reportOffline("token removed", null);

        assertNull(bridge.bridgeGetKeyStore(), "EJBCA reads a null keystore as offline");
        assertEquals(0, impl.getProvider().getKeyStoreSpi().engineSize(),
                "cached handles must not outlive the token they point into");
    }

    @Test
    @DisplayName("enumerates leniently by default and strictly when asked")
    void publicKeyPolicyComesFromProperties() throws Exception {
        // Generation is always strict; this governs only reading keys that already exist, where a
        // token using a pre-standard OID should not stop a CA from starting.
        assertEquals(ch.ithings.kimbo11ng.provider.PublicKeyReader.Policy.LENIENT,
                impl.getProvider().runtime().publicKeyPolicy());

        Properties strict = tokenProperties();
        strict.setProperty(
                ch.ithings.kimbo11ng.provider.PublicKeyReader.STRICT_PUBLIC_KEY, "true");
        CryptoTokenImpl configured = new CryptoTokenImpl(new RecordingBridge(),
                new Pkcs11ModuleRegistry(path -> new FakeToken()));
        configured.init(strict, null, 45);
        assertEquals(ch.ithings.kimbo11ng.provider.PublicKeyReader.Policy.STRICT,
                configured.getProvider().runtime().publicKeyPolicy());
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

    // ---- capability probing ----

    /** A token initialised through the fixture's bridge, so each case can vary the fake. */
    private CryptoTokenImpl tokenWith(FakeToken fake, Properties properties) throws Exception {
        CryptoTokenImpl configured = new CryptoTokenImpl(new RecordingBridge(),
                new Pkcs11ModuleRegistry(path -> fake));
        configured.init(properties, null, 46);
        configured.activate("1234".toCharArray());
        return configured;
    }

    @Test
    @DisplayName("refuses an algorithm whose mechanism the token does not advertise")
    void unsupportedAlgorithmIsRefusedByName() throws Exception {
        // What this replaces: CKR_MECHANISM_INVALID from inside C_GenerateKeyPair, naming neither
        // the mechanism nor the algorithm nor the fifteen others that would have worked.
        CryptoTokenImpl configured = tokenWith(
                new FakeToken().hideMechanism(FakeToken.CKM_ML_DSA_KEY_PAIR_GEN),
                tokenProperties());

        InvalidAlgorithmParameterException e = assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> configured.generateKeyPair("ML-DSA-65", "pqcKey"));
        assertTrue(e.getMessage().contains("ML-DSA-65"), e.getMessage());
        assertTrue(e.getMessage().contains("0x0000001c"), e.getMessage());

        // And the rest of the table still works, which is the other half of the claim.
        configured.generateKeyPair("SLH-DSA-SHA2-128S", "slhKey");
        assertTrue(configured.getProvider().getKeyStoreSpi().engineContainsAlias("slhKey"));
    }

    @Test
    @DisplayName("refuses RSA and EC too when their generation mechanism is missing")
    void unsupportedClassicalAlgorithmIsRefused() throws Exception {
        CryptoTokenImpl configured = tokenWith(
                new FakeToken().hideMechanism(org.pkcs11.jacknji11.CKM.EC_KEY_PAIR_GEN),
                tokenProperties());

        InvalidAlgorithmParameterException e = assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> configured.generateKeyPair("secp256r1", "ecKey"));
        assertTrue(e.getMessage().contains("CKM_EC_KEY_PAIR_GEN"), e.getMessage());
        configured.generateKeyPair("2048", "rsaKey");
    }

    @Test
    @DisplayName("attempts it anyway when fail-fast is turned off")
    void failFastKillSwitch() throws Exception {
        // The case the switch exists for: the probe is wrong, not the token. A mechanism gated by
        // a partition policy can be usable and unlisted, and then refusing on the list is refusing
        // on bad evidence.
        Properties properties = tokenProperties();
        properties.setProperty(
                ch.ithings.kimbo11ng.p11.TokenCapabilities.PROBE_FAIL_FAST, "false");
        FakeToken underReporting =
                new FakeToken().underReportMechanism(FakeToken.CKM_ML_DSA_KEY_PAIR_GEN);
        CryptoTokenImpl configured = tokenWith(underReporting, properties);

        assertTrue(configured.getProvider().runtime().algorithms().excluded()
                        .containsKey("ML-DSA-65"),
                "the probe still says it is unsupported");
        configured.generateKeyPair("ML-DSA-65", "pqcKey");
        assertTrue(configured.getProvider().getKeyStoreSpi().engineContainsAlias("pqcKey"),
                "but the token honours it, and the operator has said to try");
    }

    @Test
    @DisplayName("a token that will not answer the probe keeps working")
    void unprobedTokenIsNotCrippled() throws Exception {
        CryptoTokenImpl configured = tokenWith(
                new FakeToken().failMechanismList(CKR.FUNCTION_NOT_SUPPORTED), tokenProperties());
        var algorithms = configured.getProvider().runtime().algorithms();

        // An unanswered question is not evidence of absence. Refusing everything because the probe
        // failed would take a working HSM out of service over a mechanism list it declined to give.
        assertFalse(algorithms.capabilities().probed());
        assertEquals(18, algorithms.supported().size());
        configured.generateKeyPair("ML-DSA-65", "pqcKey");
        assertTrue(configured.getProvider().getKeyStoreSpi().engineContainsAlias("pqcKey"));
    }

    @Test
    @DisplayName("names the profile that would have known an algorithm the active one does not")
    void wrongProfilePointsAtTheRightOne() throws Exception {
        // The misconfiguration an operator following the vendor-profile path will actually make.
        // Everything not RSA and not in the profile falls through to the EC branch, which used to
        // answer "string ML-DSA-65 is not an OID" — true of that branch, useless about the mistake.
        Properties properties = tokenProperties();
        properties.setProperty(ch.ithings.kimbo11ng.profile.ProfileResolver.PROFILE_PROPERTY,
                "thales-luna");
        CryptoTokenImpl configured = tokenWith(new FakeToken(), properties);

        InvalidAlgorithmParameterException e = assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> configured.generateKeyPair("ML-DSA-65", "pqcKey"));
        assertTrue(e.getMessage().contains("thales-luna"), e.getMessage());
        assertTrue(e.getMessage().contains("pkcs11v32"), e.getMessage());
        assertTrue(e.getMessage().contains(
                ch.ithings.kimbo11ng.profile.ProfileResolver.PROFILE_PROPERTY), e.getMessage());
        // Every profile that knows it, not the first one ServiceLoader happened to return.
        assertTrue(e.getMessage().contains("vendor-test"), e.getMessage());
    }

    @Test
    @DisplayName("rejects a key specification no profile and no curve table knows")
    void nonsenseKeySpec() throws Exception {
        CryptoTokenImpl configured = tokenWith(new FakeToken(), tokenProperties());
        InvalidAlgorithmParameterException e = assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> configured.generateKeyPair("not-an-algorithm", "key"));
        assertTrue(e.getMessage().contains("not-an-algorithm"), e.getMessage());
    }

    @Test
    @DisplayName("logs the effective algorithm table at init")
    void effectiveTableIsAvailable() throws Exception {
        CryptoTokenImpl configured = tokenWith(
                new FakeToken().hideMechanism(FakeToken.CKM_SLH_DSA), tokenProperties());
        var algorithms = configured.getProvider().runtime().algorithms();

        assertEquals(6, algorithms.supported().size(), "three ML-DSA and three ML-KEM");
        assertEquals(12, algorithms.excluded().size(), "the SLH-DSA variants cannot sign");
        assertTrue(algorithms.describe().contains("6/18 usable"), algorithms.describe());
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

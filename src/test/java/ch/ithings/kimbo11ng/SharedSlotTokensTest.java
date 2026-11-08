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
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Two crypto tokens on one slot of one library, as EJBCA allows: two tokens configured against the
 * same HSM partition, or one created next to another. They share the library, its session pool and
 * its login state — PKCS#11 logs in per application and slot — and one JCA provider per
 * (library, slot). Each must still see its keys after the other does anything.
 */
@DisplayName("two crypto tokens on one slot")
class SharedSlotTokensTest {

    private static final AtomicInteger LIBRARIES = new AtomicInteger();
    private static final char[] PIN = "1234".toCharArray();

    private FakeToken fake;
    private Pkcs11ModuleRegistry registry;
    private String library;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void oneLibrary() {
        fake = new FakeToken();
        registry = new Pkcs11ModuleRegistry(path -> fake);
        library = "/nonexistent/libshared-" + LIBRARIES.incrementAndGet() + ".so";
    }

    /** A crypto token on slot 0 of the shared library, initialised and activated. */
    private CryptoTokenImpl token(int id, TestBridge bridge) throws Exception {
        Properties properties = new Properties();
        properties.setProperty(CryptoTokenImpl.SHLIB_LABEL_KEY, library);
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_TYPE, "SLOT_INDEX");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_VALUE, "0");
        properties.setProperty(CryptoTokenImpl.DO_NOT_ADD_P11_PROVIDER, "true");
        CryptoTokenImpl token = new CryptoTokenImpl(bridge, registry);
        token.init(properties, null, id);
        token.activate(PIN.clone());
        return token;
    }

    private static List<String> aliases(TestBridge bridge) throws Exception {
        return Collections.list(bridge.bridgeGetKeyStore().aliases());
    }

    @Test
    @DisplayName("a token reactivated after a second one opened on its slot still sees its keys")
    void reactivationAfterASecondToken() throws Exception {
        TestBridge firstBridge = new TestBridge();
        CryptoTokenImpl first = token(1, firstBridge);
        first.generateKeyPair("2048", "firstKey");

        TestBridge secondBridge = new TestBridge();
        CryptoTokenImpl second = token(2, secondBridge);
        second.generateKeyPair("2048", "secondKey");

        // EJBCA's deactivate, then the auto-activation that follows it.
        first.deactivate();
        first.activate(PIN.clone());

        assertTrue(aliases(firstBridge).contains("firstKey"),
                "the first token lost its keys: " + aliases(firstBridge));
        assertTrue(aliases(secondBridge).contains("secondKey"),
                "the second token lost its keys: " + aliases(secondBridge));
        // What EJBCA's listkeys needs for each alias, and what it drops the alias without. The
        // alias list alone passed while EJBCA showed "does not contain any key pairs".
        assertNotNull(first.readPublicKey("firstKey", true),
                "the first token lists firstKey but has no public key for it");
        assertNotNull(second.readPublicKey("secondKey", true),
                "the second token lists secondKey but has no public key for it");
    }

    /** Signs once with {@code alias} through {@code token}'s keystore and provider. */
    private static void sign(CryptoTokenImpl token, TestBridge bridge, String alias)
            throws Exception {
        java.security.PrivateKey key =
                (java.security.PrivateKey) bridge.bridgeGetKeyStore().getKey(alias, null);
        java.security.Signature signer =
                java.security.Signature.getInstance("SHA256withRSA", token.getProvider());
        signer.initSign(key);
        signer.update(new byte[] {1, 2, 3});
        assertNotNull(signer.sign());
    }

    @Test
    @DisplayName("deactivating one token leaves the other able to sign")
    void deactivationLeavesTheOtherTokenSigning() throws Exception {
        // PKCS#11 logs in per application and slot: one token's C_Logout is every token's.
        fake.enforceLogin();
        CryptoTokenImpl first = token(1, new TestBridge());
        TestBridge secondBridge = new TestBridge();
        CryptoTokenImpl second = token(2, secondBridge);
        second.generateKeyPair("2048", "secondKey");

        first.deactivate();

        sign(second, secondBridge, "secondKey");
    }

    @Test
    @DisplayName("the last token to deactivate on a slot does log the slot out")
    void lastDeactivationLogsOut() throws Exception {
        // The other half: sharing the login must not keep a slot logged in once nothing holds it,
        // or deactivate stops meaning what it says.
        fake.enforceLogin();
        CryptoTokenImpl first = token(1, new TestBridge());
        CryptoTokenImpl second = token(2, new TestBridge());

        first.deactivate();
        assertTrue(fake.isLoggedIn(), "the second token still holds the login");
        second.deactivate();
        org.junit.jupiter.api.Assertions.assertFalse(fake.isLoggedIn(),
                "no token holds the login any more, so the slot must be logged out");
    }

    @Test
    @DisplayName("a token that went offline and logged in again still logs the slot out once")
    void offlineReleasesTheLogin() throws Exception {
        // The offline path drops the token's login without a C_Logout — the token is gone. If it
        // kept its hold, the reconnected token would count twice and deactivate would never log
        // the slot out.
        fake.enforceLogin();
        CryptoTokenImpl token = token(1, new TestBridge());

        token.getSlot().reportOffline("test: the HSM went away", null);
        token.activate(PIN.clone());
        token.deactivate();

        org.junit.jupiter.api.Assertions.assertFalse(fake.isLoggedIn(),
                "deactivate after a reconnection must log the slot out");
    }

    @Test
    @DisplayName("resetting one token leaves the other able to sign")
    void resetLeavesTheOtherTokenSigning() throws Exception {
        // reset() drains the session pool, and the pool is the slot's, not the token's. Closing
        // the application's last session logs the slot out, and the other token with it.
        fake.enforceLogin();
        CryptoTokenImpl first = token(1, new TestBridge());
        TestBridge secondBridge = new TestBridge();
        CryptoTokenImpl second = token(2, secondBridge);
        second.generateKeyPair("2048", "secondKey");

        first.reset();

        sign(second, secondBridge, "secondKey");
    }

    @Test
    @DisplayName("resetting the last token on a slot still releases its sessions")
    void lastResetReleasesTheSessions() throws Exception {
        // The other half: keeping the pool for the other tokens must not keep it once none is
        // left, or reset stops releasing anything.
        fake.enforceLogin();
        CryptoTokenImpl first = token(1, new TestBridge());
        CryptoTokenImpl second = token(2, new TestBridge());

        first.reset();
        assertTrue(fake.openSessionCount() > 0, "the second token still uses the slot's sessions");
        second.reset();

        org.junit.jupiter.api.Assertions.assertEquals(0, fake.openSessionCount(),
                "no token uses the slot any more, so its sessions must be closed");
        org.junit.jupiter.api.Assertions.assertFalse(fake.isLoggedIn());
    }

    @Test
    @DisplayName("a token generates a secret key it can use after a second token initialised")
    void secretKeyAfterASecondToken() throws Exception {
        // A guard, not a regression test: the generator used to take the second token's slot,
        // which shares everything generation needs. It must keep working through the first's own.
        TestBridge bridge = new TestBridge();
        CryptoTokenImpl first = token(1, bridge);
        token(2, new TestBridge());

        first.generateKey("HmacSHA256", 256, "firstMac");

        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256", first.getProvider());
        mac.init((javax.crypto.SecretKey) bridge.bridgeGetKeyStore().getKey("firstMac", null));
        org.junit.jupiter.api.Assertions.assertEquals(32, mac.doFinal(new byte[] {1, 2, 3}).length);
    }

    @Test
    @DisplayName("a token reactivated after EJBCA's throwaway instances of it still sees its keys")
    void reactivationAfterThrowawayInstances() throws Exception {
        // EJBCA instantiates and inits a token more than once — two short-lived copies with id -1
        // per token it creates — and every init re-points the provider shared by the slot.
        TestBridge bridge = new TestBridge();
        CryptoTokenImpl token = token(1, bridge);
        token.generateKeyPair("2048", "key");
        token(-1, new TestBridge());

        token.deactivate();
        token.activate(PIN.clone());

        assertNotNull(token.readPublicKey("key", true),
                "the token lists its key but has no public key for it");
    }
}

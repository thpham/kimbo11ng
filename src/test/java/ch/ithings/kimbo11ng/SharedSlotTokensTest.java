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

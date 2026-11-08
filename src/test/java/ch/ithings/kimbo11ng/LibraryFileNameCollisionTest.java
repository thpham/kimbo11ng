/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestBridge;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKM;

import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Two different PKCS#11 libraries that happen to share a file name — {@code libpkcs11.so} from
 * two vendors, or two versions of one client installed side by side during a migration — each on
 * the same slot number. The provider is shared per (library, slot), so the two must not be taken
 * for one library: each provider has to serve its own HSM.
 */
@DisplayName("two libraries with one file name")
class LibraryFileNameCollisionTest {

    private static final AtomicInteger NAMES = new AtomicInteger();
    private static final char[] PIN = "1234".toCharArray();

    private FakeToken vendorA;
    private FakeToken vendorB;
    private Pkcs11ModuleRegistry registry;
    private String fileName;

    @BeforeEach
    void twoLibraries() {
        vendorA = new FakeToken();
        vendorB = new FakeToken();
        registry = new Pkcs11ModuleRegistry(path -> path.contains("/vendor-a/") ? vendorA : vendorB);
        // A fresh file name per test: providers live for the life of the JVM.
        fileName = "libsame-" + NAMES.incrementAndGet() + ".so";
    }

    private CryptoTokenImpl token(String vendorDir, int id) throws Exception {
        Properties properties = new Properties();
        properties.setProperty(CryptoTokenImpl.SHLIB_LABEL_KEY,
                "/nonexistent/" + vendorDir + "/" + fileName);
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_TYPE, "SLOT_INDEX");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_VALUE, "0");
        properties.setProperty(CryptoTokenImpl.DO_NOT_ADD_P11_PROVIDER, "true");
        CryptoTokenImpl token = new CryptoTokenImpl(new TestBridge(), registry);
        token.init(properties, null, id);
        token.activate(PIN.clone());
        return token;
    }

    @Test
    @DisplayName("each library gets its own provider, under its own name")
    void eachLibraryHasItsOwnProvider() throws Exception {
        CryptoTokenImpl a = token("vendor-a", 1);
        CryptoTokenImpl b = token("vendor-b", 2);

        assertNotEquals(a.getProvider().getName(), b.getProvider().getName(),
                "one provider name for two HSMs: whichever initialised last serves both");
        assertTrue(b.getProvider().getName().matches("Kimbo11ng-"
                        + java.util.regex.Pattern.quote(fileName.replace('.', '_'))
                        + "-[0-9a-f]{8}-slot" + b.getSlot().slotId()),
                "the second library's name says which library and slot it is, plus its path tag: "
                        + b.getProvider().getName());
        assertSame(a.getSlot(), a.getProvider().getSlot(),
                "the provider of vendor A's library serves vendor B's");
        // EJBCA registers a provider name once and resolves it from then on, so the second
        // library's qualified name must find the same provider on every init.
        assertSame(b.getProvider(), token("vendor-b", 3).getProvider());
    }

    @Test
    @DisplayName("a provider offers only what its own HSM does")
    void servicesFollowTheirOwnLibrary() throws Exception {
        vendorA.hideMechanism(CKM.GENERIC_SECRET_KEY_GEN);
        CryptoTokenImpl a = token("vendor-a", 1);
        token("vendor-b", 2);

        assertNull(a.getProvider().getService("KeyGenerator", "HmacSHA256"),
                "vendor A's provider advertises what only vendor B's HSM does");
        assertNotNull(a.getProvider().getService("Mac", "HmacSHA256"));
    }

    @Test
    @DisplayName("the first library keeps the name it always had")
    void firstLibraryKeepsItsName() throws Exception {
        CryptoTokenImpl a = token("vendor-a", 1);
        String before = a.getProvider().getName();
        token("vendor-b", 2);

        // Nothing changes for an installation with one library per file name, which is all of them
        // until the second one arrives; and the first keeps its name when it does.
        assertEquals("Kimbo11ng-" + fileName.replace('.', '_') + "-slot" + a.getSlot().slotId(),
                before);
        assertEquals(before, token("vendor-a", 3).getProvider().getName());
    }
}

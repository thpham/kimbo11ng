/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.UnsupportedNativeProvider;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CK_C_INITIALIZE_ARGS;
import org.pkcs11.jacknji11.NativePointer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Library lifetime: initialised once, never finalised, and failures never remembered.
 */
@DisplayName("Pkcs11ModuleRegistry")
class Pkcs11ModuleRegistryTest {

    private static final String LIB = "/nonexistent/libfake.so";

    @Test
    @DisplayName("initializes a library once no matter how many slots use it")
    void oneInitializePerLibrary() throws Exception {
        FakeToken token = new FakeToken();
        Pkcs11ModuleRegistry registry = new Pkcs11ModuleRegistry(path -> token);

        Pkcs11Module module = registry.get(LIB);
        // Three slots, and the slot-list wrapper EJBCA asks for separately, all on one library.
        module.slot(0L, new Properties());
        module.slot(0L, new Properties());
        registry.get(LIB).slotList();
        assertSame(module, registry.get(LIB));

        // Previously each CryptokiDevice and each SlotListWrapper called C_Initialize itself, so
        // opening one token initialised the same library two or three times. PKCS#11 allows one.
        assertEquals(1, token.initializeCalls());
    }

    @Test
    @DisplayName("never finalizes a library")
    void neverFinalizes() throws Exception {
        FakeToken token = new FakeToken();
        Pkcs11ModuleRegistry registry = new Pkcs11ModuleRegistry(path -> token);
        Pkcs11Module module = registry.get(LIB);
        P11Slot slot = module.slot(0L, new Properties());

        slot.login("1234".toCharArray());
        slot.close();
        module.releaseSlot(0L);

        // EJBCA's classic PKCS11CryptoToken resolves its slots through our ServiceLoader factory,
        // so SunPKCS11 may be using any library we have loaded. C_Finalize would pull the state
        // out from under it and the damage would appear somewhere else entirely.
        assertEquals(0, token.finalizeCalls());
    }

    @Test
    @DisplayName("recognises the same library reached by a different path")
    void canonicalizesPaths() throws Exception {
        // A symlinked library initialised twice is the same bug as no deduplication at all, and
        // deployments do reach an HSM library through both /usr/lib and a versioned path.
        Path dir = Files.createTempDirectory("kimbo11ng-lib");
        Path real = Files.createFile(dir.resolve("libfake.so"));
        Path link = dir.resolve("liblink.so");
        Files.createSymbolicLink(link, real);

        FakeToken token = new FakeToken();
        Pkcs11ModuleRegistry registry = new Pkcs11ModuleRegistry(path -> token);
        assertSame(registry.get(real.toString()), registry.get(link.toString()));
        assertEquals(1, token.initializeCalls());
    }

    @Test
    @DisplayName("reports a library that will not initialize instead of carrying on")
    void initializationFailureIsFatal() {
        // The old code logged this at debug and continued, so a library that could not load
        // produced "no slots found" much later with nothing pointing at the real cause.
        Pkcs11ModuleRegistry registry = new Pkcs11ModuleRegistry(path -> new UnsupportedNativeProvider() {
            @Override
            public long C_Initialize(CK_C_INITIALIZE_ARGS args) {
                return CKR.GENERAL_ERROR;
            }
        });
        CryptoTokenOfflineException e = assertThrows(CryptoTokenOfflineException.class,
                () -> registry.get(LIB));
        assertTrue(e.getMessage().contains(LIB), e.getMessage());
        assertTrue(e.getMessage().contains("GENERAL_ERROR"), e.getMessage());
        assertFalse(registry.isLoaded(LIB), "a failed load must not be cached as loaded");
    }

    @Test
    @DisplayName("accepts a library another component already initialized")
    void alreadyInitializedIsFine() throws Exception {
        Pkcs11ModuleRegistry registry = new Pkcs11ModuleRegistry(path -> new UnsupportedNativeProvider() {
            @Override
            public long C_Initialize(CK_C_INITIALIZE_ARGS args) {
                return CKR.CRYPTOKI_ALREADY_INITIALIZED;
            }

            @Override
            public long C_Finalize(NativePointer reserved) {
                return CKR.OK;
            }
        });
        // SunPKCS11 getting there first is the normal case in a mixed deployment, not an error.
        assertTrue(registry.get(LIB).path().endsWith("libfake.so"));
    }

    @Test
    @DisplayName("retries a slot list that failed rather than remembering the failure")
    void slotListFailureIsNotCached() throws Exception {
        FakeToken token = new FakeToken();
        Pkcs11Module module = new Pkcs11ModuleRegistry(path -> token).get(LIB);

        token.failNextWith(CKR.DEVICE_ERROR);
        assertThrows(CryptoTokenOfflineException.class, module::slotList);

        // The previous implementation stored an empty array on failure, so one transient error at
        // startup — a Luna client not yet connected — made the library permanently slotless until
        // the application server was restarted.
        assertEquals(1, module.slotList().length);
    }

    @Test
    @DisplayName("re-reads the slot list after invalidate")
    void invalidateForgetsCaches() throws Exception {
        FakeToken token = new FakeToken();
        Pkcs11Module module = new Pkcs11ModuleRegistry(path -> token).get(LIB);
        assertEquals(1, module.slotList().length);
        assertEquals("FakeToken", new String(module.tokenLabel(0L)));

        module.invalidate();
        assertEquals(1, module.slotList().length);
    }

    @Test
    @DisplayName("initializes once when several threads ask for the library at the same time")
    void concurrentGetInitializesOnce() throws Exception {
        FakeToken token = new FakeToken();
        Pkcs11ModuleRegistry registry = new Pkcs11ModuleRegistry(path -> token);

        int threads = 16;
        CountDownLatch start = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        registry.get(LIB);
                    } catch (Throwable t) {
                        failure.compareAndSet(null, t);
                    }
                });
            }
            start.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
        if (failure.get() != null) {
            throw new AssertionError("a thread failed to get the module", failure.get());
        }
        // EJBCA activates crypto tokens in parallel at startup. Two C_Initialize calls racing is
        // exactly the case the registry exists to prevent.
        assertEquals(1, token.initializeCalls());
        assertEquals(1, registry.loaded().size());
    }
}

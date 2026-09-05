/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.p11.Pkcs11Module;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.NativeProvider;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.ProviderException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What the MAC path does when the retry — not the first attempt — is the one that finds the token
 * gone.
 *
 * <p>The database-protection HMAC key lives on the same network HSM as everything else, so the
 * sequence a dropped connection produces is: first attempt {@code CKR_SESSION_HANDLE_INVALID}
 * (retryable, the handle went stale), retry {@code CKR_DEVICE_ERROR} (the token really is gone).
 * If the second failure is not reported, {@code CryptoTokenImpl} never clears EJBCA's keystore and
 * {@code autoActivate()} is never given the chance to log in again: the token stays "online" with
 * a dead HSM behind it.
 *
 * <p>{@link FakeToken}'s own fault knobs are one-shot, so this scripts the failures at the
 * {@code NativeProvider} seam instead — one CKR per {@code C_SignInit}, which is exactly one per
 * MAC attempt.
 */
@DisplayName("MAC offline reporting")
class MacOfflineReportingTest {

    /** Distinct per fixture so two fixtures never canonicalize to the same registry key. */
    private static final AtomicInteger PATHS = new AtomicInteger();

    private final List<P11Slot> slots = new ArrayList<>();

    @AfterEach
    void closeSlots() {
        slots.forEach(P11Slot::close);
    }

    /**
     * A logged-in slot over a token whose {@code C_SignInit} answers {@code script} — one CKR per
     * call, in order — before behaving normally again.
     */
    private P11Slot slotFailingSignInitWith(long... script) throws Exception {
        Deque<Long> scripted = new ArrayDeque<>();
        for (long ckr : script) {
            scripted.addLast(ckr);
        }
        NativeProvider provider = scriptedSignInit(new FakeToken(), scripted);
        Pkcs11ModuleRegistry registry = new Pkcs11ModuleRegistry(path -> provider);
        Pkcs11Module module = registry.get("/nonexistent/libmacoffline-"
                + PATHS.incrementAndGet() + ".so");
        P11Slot slot = module.slot(0L, new Properties());
        slots.add(slot);
        slot.login("1234".toCharArray());
        return slot;
    }

    private static NativeProvider scriptedSignInit(FakeToken token, Deque<Long> script) {
        return (NativeProvider) Proxy.newProxyInstance(
                NativeProvider.class.getClassLoader(),
                new Class<?>[] {NativeProvider.class},
                (proxy, method, args) -> {
                    if ("C_SignInit".equals(method.getName()) && !script.isEmpty()) {
                        return script.removeFirst();
                    }
                    try {
                        return method.invoke(token, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
    }

    private static SecretKeyType hmac256() {
        return SecretKeyType.lookup("HmacSHA256").orElseThrow();
    }

    private static Kimbo11ngSecretKey generate(P11Slot slot) {
        return (Kimbo11ngSecretKey) new Kimbo11ngKeyGeneratorSpi(slot, hmac256())
                .engineGenerateKey();
    }

    private static Kimbo11ngMacSpi macOver(Kimbo11ngSecretKey key) throws Exception {
        Kimbo11ngMacSpi mac = new Kimbo11ngMacSpi(hmac256());
        mac.engineInit(key, null);
        byte[] row = "protected row".getBytes(StandardCharsets.UTF_8);
        mac.engineUpdate(row, 0, row.length);
        return mac;
    }

    @Test
    @DisplayName("a retry that fails with an offline CKR takes the token offline")
    void retryFailingOfflineIsReported() throws Exception {
        P11Slot slot = slotFailingSignInitWith(CKR.SESSION_HANDLE_INVALID, CKR.DEVICE_ERROR);
        Kimbo11ngSecretKey key = generate(slot);
        AtomicReference<String> reported = new AtomicReference<>();
        slot.onOffline((reason, cause) -> reported.set(reason));

        ProviderException e = assertThrows(ProviderException.class, macOver(key)::engineDoFinal);

        assertTrue(e.getMessage().contains("DEVICE_ERROR"), e.getMessage());
        assertNotNull(reported.get(), "the retry found the token gone and nothing told the crypto"
                + " token, so EJBCA would keep using a keystore backed by a dead HSM");
        assertTrue(reported.get().contains(key.getAlias()), reported.get());
    }

    @Test
    @DisplayName("a retry that fails for any other reason leaves the token online")
    void retryFailingFatalIsNotReported() throws Exception {
        P11Slot slot = slotFailingSignInitWith(CKR.SESSION_HANDLE_INVALID, CKR.FUNCTION_FAILED);
        Kimbo11ngSecretKey key = generate(slot);
        AtomicReference<String> reported = new AtomicReference<>();
        slot.onOffline((reason, cause) -> reported.set(reason));

        ProviderException e = assertThrows(ProviderException.class, macOver(key)::engineDoFinal);

        assertTrue(e.getMessage().contains("FUNCTION_FAILED"), e.getMessage());
        assertNull(reported.get(), "a token that answered is still there; taking it offline would"
                + " clear a keystore that is perfectly good");
    }

    @Test
    @DisplayName("a retry that succeeds leaves the token online")
    void successfulRetryIsNotReported() throws Exception {
        P11Slot slot = slotFailingSignInitWith(CKR.SESSION_HANDLE_INVALID);
        Kimbo11ngSecretKey key = generate(slot);
        AtomicReference<String> reported = new AtomicReference<>();
        slot.onOffline((reason, cause) -> reported.set(reason));

        assertNotNull(macOver(key).engineDoFinal());
        assertNull(reported.get());
    }
}

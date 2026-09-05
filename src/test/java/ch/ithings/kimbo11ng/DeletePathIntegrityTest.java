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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.NativeProvider;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What has to be true when the token says no.
 *
 * <p>Every case here is a token that refuses one operation while answering the rest normally — a
 * partition whose policy forbids deleting a key, or one that will not let an attribute be rewritten.
 * The failure mode under test is never the refusal itself: it is kimbo11ng reporting success anyway,
 * so that EJBCA's alias cache and the objects on the HSM stop agreeing. Once they disagree, the
 * next operator action is taken against a picture of the token that is not true.
 */
@DisplayName("delete and alias integrity when the token refuses")
class DeletePathIntegrityTest {

    /**
     * {@code CKR_ACTION_PROHIBITED}, which jacknji11 1.3.1 does not define. It is what a token
     * answers when the object exists and a policy — key-deletion audit, a Luna partition rule —
     * forbids the operation being asked of it.
     */
    private static final long CKR_ACTION_PROHIBITED = 0x0000001BL;

    private TestBridge bridge;
    private CryptoTokenImpl impl;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** Brings up a token on {@code provider} and activates it, as EJBCA would. */
    private void start(NativeProvider provider) throws Exception {
        bridge = new TestBridge();
        Properties properties = new Properties();
        properties.setProperty(CryptoTokenImpl.SHLIB_LABEL_KEY, "/nonexistent/libfake.so");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_TYPE, "SLOT_INDEX");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_VALUE, "0");
        properties.setProperty(CryptoTokenImpl.DO_NOT_ADD_P11_PROVIDER, "true");
        impl = new CryptoTokenImpl(bridge, new Pkcs11ModuleRegistry(path -> provider));
        impl.init(properties, null, 91);
        impl.activate("1234".toCharArray());
    }

    private List<String> aliases() throws Exception {
        return Collections.list(bridge.bridgeGetKeyStore().aliases());
    }

    /**
     * The same token with {@code C_DestroyObject} refused.
     *
     * <p>A proxy rather than a knob on {@link FakeToken}: the refusal has to be selective — every
     * other call must succeed, or the test would be about an unreachable token instead of about a
     * policy that forbids exactly one operation.
     */
    private static NativeProvider refusesDestroy(FakeToken token) {
        return (NativeProvider) Proxy.newProxyInstance(
                NativeProvider.class.getClassLoader(),
                new Class<?>[] {NativeProvider.class},
                (proxy, method, args) -> {
                    if ("C_DestroyObject".equals(method.getName())) {
                        return CKR_ACTION_PROHIBITED;
                    }
                    try {
                        return method.invoke(token, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
    }

    private static long[] find(FakeToken token, long objectClass, String label) {
        return token.handles().stream()
                .filter(h -> java.util.Arrays.equals(token.attribute(h, CKA.CLASS),
                        org.pkcs11.jacknji11.ULong.ulong2b(objectClass)))
                .filter(h -> java.util.Arrays.equals(token.attribute(h, CKA.LABEL),
                        label.getBytes(StandardCharsets.UTF_8)))
                .mapToLong(Long::longValue)
                .toArray();
    }

    // ---------------------------------------------------------------- the delete path

    @Test
    @DisplayName("a refused destroy reaches the caller, and the alias is kept")
    void refusedDestroyIsNotSilent() throws Exception {
        FakeToken token = new FakeToken();
        start(refusesDestroy(token));
        impl.generateKeyPair("2048", "caKey");
        int before = token.handles().size();

        KeyStoreException e = assertThrows(KeyStoreException.class,
                () -> impl.deleteEntry("caKey"),
                "a delete the token refused must not be reported as a delete that happened");
        assertTrue(e.getMessage().contains("caKey"), e.getMessage());

        assertEquals(before, token.handles().size(),
                "nothing was destroyed, so the key pair is still on the token");
        assertTrue(aliases().contains("caKey"),
                "EJBCA dropped the alias for a key the HSM still holds, so nothing will ever"
                        + " delete it and the next generation under this name makes a twin");
    }

    @Test
    @DisplayName("the secret-key half of delete behaves the same way")
    void refusedSecretDestroyIsNotSilent() throws Exception {
        FakeToken token = new FakeToken();
        start(refusesDestroy(token));
        impl.generateKey("HmacSHA256", 256, "dbProtectionKey");
        int before = token.handles().size();

        KeyStoreException e = assertThrows(KeyStoreException.class,
                () -> impl.deleteEntry("dbProtectionKey"));
        assertTrue(e.getMessage().contains("dbProtectionKey"), e.getMessage());

        assertEquals(before, token.handles().size());
        assertTrue(aliases().contains("dbProtectionKey"));
    }

    // ---------------------------------------------------------------- alias uniqueness

    @Test
    @DisplayName("a key pair is refused an alias a secret key already holds")
    void keyPairRefusesAnAliasHeldByASecretKey() throws Exception {
        FakeToken token = new FakeToken();
        start(token);
        impl.generateKey("HmacSHA256", 256, "shared");

        // The mirror of SymmetricKeyTest.refusesAliasOfAKeyPair, which pins the other direction.
        // One alias must not name two kinds of key: engineAliases returns a set and engineSize a
        // sum, so the moment both maps hold 'shared' EJBCA is told the keystore has two entries
        // and can enumerate only one of them.
        InvalidAlgorithmParameterException e = assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> impl.generateKeyPair("2048", "shared"));
        assertTrue(e.getMessage().contains("shared"), e.getMessage());

        assertEquals(List.of("shared"), aliases());
        assertEquals(0, find(token, CKO.PRIVATE_KEY, "shared").length,
                "the key pair must not have been generated at all");
    }

    // ---------------------------------------------------------------- naming a secret key

    @Test
    @DisplayName("secret generation fails when the token will not accept the alias")
    void secretGenerationFailsWhenTheLabelCannotBeWritten() throws Exception {
        // A token that refuses attribute writes: the object is created under the generator's
        // provisional 'generated-<uuid>' label and can never be given the caller's alias.
        FakeToken token = new FakeToken().readOnlyAttributes(CKA.LABEL);
        start(token);

        KeyStoreException e = assertThrows(KeyStoreException.class,
                () -> impl.generateKey("HmacSHA256", 256, "dbProtectionKey"),
                "the caller was told the alias exists while the token holds no key under it");
        assertTrue(e.getMessage().contains("dbProtectionKey"), e.getMessage());

        assertFalse(aliases().contains("dbProtectionKey"),
                "CachingKeyStoreWrapper.setKeyEntry caches the alias once the delegate returns,"
                        + " so a silent return is exactly what leaves EJBCA holding a name for a"
                        + " key that is not there");
        assertTrue(token.handles().isEmpty(),
                "the unusable object must not be left on the token under its provisional label");
    }
}

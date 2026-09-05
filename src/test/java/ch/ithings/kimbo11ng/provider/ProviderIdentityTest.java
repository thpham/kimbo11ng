/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import ch.ithings.kimbo11ng.profile.Pkcs11v32Profile;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.LongRef;

import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The provider object survives re-initialisation; only the runtime behind it changes.
 *
 * <p>This is the property the whole facade design exists for, and it is not tidiness.
 * {@code BaseCryptoToken.setProvider} calls {@code Security.addProvider} itself, and
 * {@code Security.addProvider} is a no-op when the name is already registered. So a fresh provider
 * per {@code init} would leave the <em>previous</em> instance in {@code java.security.Security} —
 * still pointing at a released slot — and {@code KeyTools.getProvider(name)} and
 * {@code SignWithWorkingAlgorithm}, which both resolve providers by name, would keep signing
 * through it. EJBCA never notices; the CA simply stops working after a token is re-saved.
 *
 * <p>EJBCA CE has no way to trigger an in-JVM re-init from the CLI or the REST API — only the admin
 * UI's Save button reaches {@code saveCryptoToken} — so this cannot be an integration test. It is
 * asserted here instead, against the same code path.
 */
@DisplayName("provider identity")
class ProviderIdentityTest {

    private final List<TestSlot> fixtures = new ArrayList<>();
    private final Pkcs11v32Profile profile = new Pkcs11v32Profile();

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @AfterEach
    void closeSlots() {
        fixtures.forEach(TestSlot::close);
    }

    /**
     * A slot on its own library path, as a distinct crypto token would be.
     *
     * <p>{@code TestSlot} gives each fixture a unique path, which is what makes "same provider for
     * the same slot" and "different providers for different slots" both testable.
     */
    private TestSlot newSlot() throws Exception {
        TestSlot fixture = new TestSlot(new FakeToken()).loggedIn();
        fixtures.add(fixture);
        return fixture;
    }

    @Test
    @DisplayName("ten init cycles on one slot yield one provider object")
    void identityIsStableAcrossReinit() throws Exception {
        TestSlot fixture = newSlot();
        Kimbo11ngProvider first = Kimbo11ngProvider.forToken(
                new TokenRuntime(fixture.slot(), profile));

        for (int i = 0; i < 10; i++) {
            // What CryptoTokenImpl.initDevice does on every re-initialisation: a new runtime over
            // the same slot, handed to forToken.
            TokenRuntime runtime = new TokenRuntime(fixture.slot(), profile);
            Kimbo11ngProvider again = Kimbo11ngProvider.forToken(runtime);

            assertSame(first, again, "re-initialising must not create a second provider object");
            assertEquals(first.getName(), again.getName());
            assertSame(runtime, again.runtime(),
                    "the provider must be pointing at the runtime it was just given");
        }
    }

    @Test
    @DisplayName("resolving the provider by name finds the live object, not a zombie")
    void nameResolvesToTheLiveProvider() throws Exception {
        // The failure mode in full: Security.addProvider ignores a name that is already present,
        // so if init produced a new object the name would still resolve to the old one.
        TestSlot fixture = newSlot();
        Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                new TokenRuntime(fixture.slot(), profile));
        String name = provider.getName();
        try {
            Security.addProvider(provider);

            TokenRuntime swapped = new TokenRuntime(fixture.slot(), profile);
            Kimbo11ngProvider afterReinit = Kimbo11ngProvider.forToken(swapped);
            Security.addProvider(afterReinit);

            Provider resolved = Security.getProvider(name);
            assertSame(afterReinit, resolved,
                    "EJBCA resolves providers by name; the name must find the current object");
            assertSame(swapped, ((Kimbo11ngProvider) resolved).runtime());
        } finally {
            Security.removeProvider(name);
        }
    }

    @Test
    @DisplayName("signing keeps working through the same provider after a swap")
    void signingSurvivesASwap() throws Exception {
        TestSlot fixture = newSlot();
        Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                new TokenRuntime(fixture.slot(), profile));
        long privateHandle = generateRsa(fixture, "swap-key");

        signOnce(provider, fixture, privateHandle);
        Kimbo11ngProvider.forToken(new TokenRuntime(fixture.slot(), profile));
        signOnce(provider, fixture, privateHandle);
    }

    @Test
    @DisplayName("two slots get two providers with different names")
    void differentSlotsAreDifferentProviders() throws Exception {
        Kimbo11ngProvider a = Kimbo11ngProvider.forToken(
                new TokenRuntime(newSlot().slot(), profile));
        Kimbo11ngProvider b = Kimbo11ngProvider.forToken(
                new TokenRuntime(newSlot().slot(), profile));

        assertNotSame(a, b);
        assertNotEquals(a.getName(), b.getName(),
                "two tokens sharing a provider name would collide in java.security.Security");
    }

    @Test
    @DisplayName("the provider name is derived only from the library and slot")
    void nameIsDerivedFromTheSlot() throws Exception {
        TestSlot fixture = newSlot();
        Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                new TokenRuntime(fixture.slot(), profile));

        // Stable across restarts is the requirement: EJBCA stores the name nowhere, it recomputes
        // it, so anything time- or instance-dependent in here would break resolution after a
        // restart rather than at the point of the mistake.
        assertTrue(provider.getName().contains(fixture.slot().libraryName()),
                provider.getName());
        assertTrue(provider.getName().endsWith("slot" + fixture.slot().slotId()),
                provider.getName());
    }

    private long generateRsa(TestSlot fixture, String alias) throws Exception {
        KeyTemplates.Pair templates = KeyTemplates.rsa(
                alias.getBytes(StandardCharsets.UTF_8), KeyTemplates.newKeyId(), 2048);
        return fixture.onSession((ce, session) -> {
            LongRef pub = new LongRef();
            LongRef priv = new LongRef();
            ce.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN),
                    templates.pub(), templates.priv(), pub, priv);
            return priv.value();
        });
    }

    private void signOnce(Kimbo11ngProvider provider, TestSlot fixture, long handle)
            throws Exception {
        Kimbo11ngPrivateKey key = new Kimbo11ngPrivateKey("RSA", fixture.slot(),
                new P11KeyRef(null, "swap-key", null), handle);
        Signature signer = Signature.getInstance("SHA256withRSA", provider);
        signer.initSign(key);
        signer.update("after the swap".getBytes(StandardCharsets.UTF_8));
        assertTrue(signer.sign().length > 0);
    }
}

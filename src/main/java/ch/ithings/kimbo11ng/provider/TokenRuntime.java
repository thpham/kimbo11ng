/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.profile.PqcMechanismProfile;

import java.util.Objects;

/**
 * The live state one crypto token instance works against: its slot and its algorithm profile.
 *
 * <p>Separated from {@link Kimbo11ngProvider} so that re-initialising a token swaps the runtime
 * while the provider object stays the same. That matters because EJBCA registers the provider
 * globally and then resolves it <em>by name</em> — {@code KeyTools.getProvider} and
 * {@code SignWithWorkingAlgorithm} both do — and only registers a name once. A fresh provider per
 * init would leave the previously registered instance in {@code java.security.Security}, still
 * pointing at a released slot, and EJBCA would keep signing through it.
 */
public final class TokenRuntime {

    private final P11Slot slot;
    private final PqcMechanismProfile profile;
    private volatile Kimbo11ngKeyStoreSpi keyStoreSpi;

    public TokenRuntime(P11Slot slot, PqcMechanismProfile profile) {
        this.slot = Objects.requireNonNull(slot, "slot");
        this.profile = Objects.requireNonNull(profile, "profile");
    }

    public P11Slot slot() {
        return slot;
    }

    public PqcMechanismProfile profile() {
        return profile;
    }

    /** The keystore SPI for this token, or {@code null} before a KeyStore has been created. */
    public Kimbo11ngKeyStoreSpi keyStoreSpi() {
        return keyStoreSpi;
    }

    void adoptKeyStoreSpi(Kimbo11ngKeyStoreSpi spi) {
        this.keyStoreSpi = spi;
    }

    @Override
    public String toString() {
        return "TokenRuntime{lib=" + slot.libPath() + " slot=" + slot.slotId()
                + " profile=" + profile.name() + "}";
    }
}

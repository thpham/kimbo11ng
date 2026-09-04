/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.profile.AlgorithmSupport;
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

    /**
     * Whether a legacy key found without a {@code CKA_ID} should have one written onto it.
     *
     * <p>On by default: it is what lets keys generated before kimbo11ng wrote ids stop depending on
     * their label, which is an EJBCA alias an operator can change. Turn it off for a token whose
     * objects must not be modified at all — an audited partition, say — and those keys keep
     * resolving by label.
     */
    public static final String BACKFILL_KEY_IDS = "kimbo11ng.keyid.backfill";

    private final P11Slot slot;
    private final AlgorithmSupport algorithms;
    private final boolean backfillKeyIds;
    private final PublicKeyReader.Policy publicKeyPolicy;
    private volatile Kimbo11ngKeyStoreSpi keyStoreSpi;

    public TokenRuntime(P11Slot slot, PqcMechanismProfile profile) {
        this(slot, profile, true, PublicKeyReader.Policy.LENIENT);
    }

    public TokenRuntime(P11Slot slot, PqcMechanismProfile profile, boolean backfillKeyIds) {
        this(slot, profile, backfillKeyIds, PublicKeyReader.Policy.LENIENT);
    }

    public TokenRuntime(P11Slot slot, PqcMechanismProfile profile, boolean backfillKeyIds,
            PublicKeyReader.Policy publicKeyPolicy) {
        this(slot, AlgorithmSupport.unchecked(profile), backfillKeyIds, publicKeyPolicy);
    }

    public TokenRuntime(P11Slot slot, AlgorithmSupport algorithms, boolean backfillKeyIds,
            PublicKeyReader.Policy publicKeyPolicy) {
        this.slot = Objects.requireNonNull(slot, "slot");
        this.algorithms = Objects.requireNonNull(algorithms, "algorithms");
        this.backfillKeyIds = backfillKeyIds;
        this.publicKeyPolicy = Objects.requireNonNull(publicKeyPolicy, "publicKeyPolicy");
    }

    /**
     * How strictly to read public keys that already exist on the token.
     *
     * <p>Generation is always strict — see {@link PublicKeyReader.Policy}. This governs only
     * enumeration, where the keys may predate kimbo11ng and a cosmetic disagreement should not stop
     * a CA from starting.
     */
    public PublicKeyReader.Policy publicKeyPolicy() {
        return publicKeyPolicy;
    }

    /** @see #BACKFILL_KEY_IDS */
    public boolean backfillKeyIds() {
        return backfillKeyIds;
    }

    public P11Slot slot() {
        return slot;
    }

    public PqcMechanismProfile profile() {
        return algorithms.profile();
    }

    /**
     * The profile intersected with what this token and this BouncyCastle can do.
     *
     * <p>Distinct from {@link #profile()}: the profile is what the vendor is claimed to support,
     * this is what was confirmed. Generation goes through here so that asking for an algorithm the
     * token does not have is refused by name rather than by {@code CKR_MECHANISM_INVALID}.
     */
    public AlgorithmSupport algorithms() {
        return algorithms;
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
                + " profile=" + algorithms.profile().name()
                + " (" + algorithms.supported().size() + " usable algorithms)}";
    }
}

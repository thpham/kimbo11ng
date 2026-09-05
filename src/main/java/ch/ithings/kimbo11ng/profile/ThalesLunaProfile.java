/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import java.util.List;

/**
 * Thales Luna, awaiting vendor constants.
 *
 * <p>The table below is empty, so this profile currently supports nothing and reports so honestly
 * rather than throwing from ten methods. Populating it is the entire task — no logic is needed,
 * because {@link AbstractTableProfile} supplies every lookup.
 *
 * <p><b>What to fill in.</b> For each algorithm the firmware supports, add one row giving:
 *
 * <ul>
 *   <li>{@code ckkKeyType} — Luna's {@code CKK_*} for the key type. Vendor-defined values live at
 *       or above {@code CKK_VENDOR_DEFINED} (0x80000000) and will not match the v3.2 numbers in
 *       {@link Pkcs11v32Profile}.
 *   <li>{@code ckmKeyPairGen} and {@code ckmOperation} — the generation and signing mechanisms.
 *       These are separate fields precisely because a vendor may shift one and not the other.
 *   <li>{@code ckpParameterSet} — {@code OptionalLong.empty()} if Luna encodes the parameter set
 *       in the mechanism rather than an attribute, which is the likelier arrangement on firmware
 *       predating v3.2. An empty value is fully supported.
 *   <li>{@code oid} and {@code publicKeyLength} — these are FIPS-defined, so copy them from
 *       {@link Pkcs11v32Profile}; they do not vary by vendor. The length is what lets a
 *       misresolved parameter set be caught before it reaches a certificate.
 * </ul>
 *
 * <p>Override {@link #ckaParameterSet()} if the attribute id differs from v3.2's {@code 0x61D}.
 *
 * <p>Once populated, the profile must pass the same conformance suite as
 * {@link Pkcs11v32Profile} — that suite is the acceptance criterion, and it runs against the
 * in-memory fake token, so it can be satisfied before hardware is available.
 */
public final class ThalesLunaProfile extends AbstractTableProfile {

    public ThalesLunaProfile() {
        super(List.of());
    }

    @Override
    public String name() {
        return "thales-luna";
    }

    @Override
    public long ckaParameterSet() {
        return Pkcs11v32Profile.CKA_PARAMETER_SET;
    }

    @Override
    public String toString() {
        return name() + " (no algorithms — vendor constants not yet supplied)";
    }
}

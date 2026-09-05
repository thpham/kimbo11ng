/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import java.util.Arrays;
import java.util.Locale;

/**
 * Which usage attributes a key-encapsulation key is generated with.
 *
 * <p>Two pairs describe the same thing and two different readers understand only one each.
 *
 * <ul>
 *   <li>{@code CKA_ENCAPSULATE} (0x633) and {@code CKA_DECAPSULATE} (0x634) are what PKCS#11 v3.2
 *       defines for a KEM, and what a v3.2-aware token gates {@code C_EncapsulateKey} and
 *       {@code C_DecapsulateKey} on.
 *   <li>{@code CKA_ENCRYPT} and {@code CKA_DECRYPT} are what <em>EJBCA</em> reads.
 *       {@code BaseCryptoToken.testKeyPair} branches on {@code contains(261) && !contains(264)},
 *       and {@code CryptoTokenManagementSessionBean.getKeyUsageStringForKeyPairInfo} compares the
 *       usage set for equality against {@code {261}} to decide the admin UI shows ENCRYPT. Neither
 *       knows 0x634.
 * </ul>
 *
 * <p>Which is right therefore depends on the token, which is why the choice lives on the profile
 * rather than in {@code KeyTemplates}: see {@link PqcMechanismProfile#defaultKemUsage()}.
 * {@link #PROPERTY} overrides whatever the profile says, for the token that turns out to disagree
 * with its own documentation.
 */
public enum KemUsage {

    /**
     * Both pairs. The default for a token described by the bare v3.2 profile.
     *
     * <p>Not indecision — it is the only setting under which a key is both correct per the
     * specification and legible to EJBCA. Measured on SoftHSMv3 on 2026-09-05: it accepts either
     * pair and then sets the other itself, so on that token the three settings converge on the
     * same object and only differ in what was asked for.
     */
    BOTH,

    /**
     * The v3.2 pair alone, for a token that models a KEM key as a KEM key and nothing else.
     *
     * <p>The cost is EJBCA's side: no key usage shown in the admin UI for these keys, and
     * {@code testKeyPair} routing them to the signing branch. That is a reporting loss on an
     * algorithm EJBCA CE cannot use for anything anyway — there is no key-encapsulation path in
     * Community Edition — and it is preferable to a template the token refuses outright.
     */
    V32,

    /**
     * The encryption pair alone, which is what this project sent before the v3.2 attributes were
     * wired up. For a token that refuses the attribute numbers it has never heard of.
     */
    LEGACY;

    /** Token property overriding the profile's choice: {@code both}, {@code v32} or {@code legacy}. */
    public static final String PROPERTY = "kimbo11ng.pqc.kemUsage";

    /**
     * Parses the property value, case-insensitively.
     *
     * @param value the configured value, or null/blank for the profile's own default
     * @param fallback what an unset property means, from {@link PqcMechanismProfile}
     * @throws IllegalArgumentException on a value that is not one of the three. Deliberately not a
     *     silent default: a typo would otherwise generate every ML-KEM key with a spelling the
     *     operator did not choose and say nothing about it.
     */
    public static KemUsage parse(String value, KemUsage fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        String wanted = value.trim().toUpperCase(Locale.ROOT);
        for (KemUsage candidate : values()) {
            if (candidate.name().equals(wanted)) {
                return candidate;
            }
        }
        throw new IllegalArgumentException(PROPERTY + "='" + value + "' is not one of "
                + Arrays.toString(values()) + ".");
    }

    /** True if this setting sends {@code CKA_ENCAPSULATE} and {@code CKA_DECAPSULATE}. */
    public boolean sendsV32() {
        return this != LEGACY;
    }

    /** True if this setting sends {@code CKA_ENCRYPT} and {@code CKA_DECRYPT}. */
    public boolean sendsEncryption() {
        return this != V32;
    }
}

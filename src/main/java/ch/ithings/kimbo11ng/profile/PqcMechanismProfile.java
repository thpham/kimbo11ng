/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import java.util.Collection;
import java.util.Optional;
import java.util.OptionalLong;

/**
 * A vendor's description of how post-quantum algorithms appear over PKCS#11.
 *
 * <p>An implementation supplies a table of {@link AlgorithmEntry} and the attribute its token uses
 * for parameter sets; {@link AbstractTableProfile} provides every lookup on top of that. Adding a
 * vendor should require no logic — if it does, the missing variation belongs in
 * {@code AlgorithmEntry}, not in an override here.
 *
 * <p>Implementations are discovered with {@link java.util.ServiceLoader}, so a vendor profile can
 * ship as a separate jar without touching this project.
 */
public interface PqcMechanismProfile {

    /**
     * Stable identifier, matched case-insensitively against the
     * {@code kimbo11ng.pqc.profile} token property.
     */
    String name();

    /** Every algorithm this profile describes. */
    Collection<AlgorithmEntry> entries();

    /**
     * Attribute holding the parameter set, {@code CKA_PARAMETER_SET} (0x61D) in PKCS#11 v3.2.
     * Vendors that predate the attribute may use a different id, or none — see
     * {@link AlgorithmEntry#ckpParameterSet()}.
     */
    long ckaParameterSet();

    /**
     * Resolve a key specification such as {@code "ML-DSA-65"}, tolerating separator and case
     * differences.
     */
    Optional<AlgorithmEntry> lookup(String keySpec);

    /**
     * Reverse lookup for a key already on the token.
     *
     * @param ckk the key type read from {@code CKA_KEY_TYPE}
     * @param ckp the parameter set read from the profile's parameter-set attribute, or empty when
     *            the token did not report one
     * @return the single matching entry, or empty when the pair is ambiguous or unknown. Ambiguity
     *         is deliberately not resolved by guessing: a wrong parameter set means a wrong OID in
     *         an issued certificate.
     */
    Optional<AlgorithmEntry> lookupByKeyType(long ckk, OptionalLong ckp);

    /** True if {@link #lookup(String)} would resolve this key specification. */
    default boolean supports(String keySpec) {
        return lookup(keySpec).isPresent();
    }
}

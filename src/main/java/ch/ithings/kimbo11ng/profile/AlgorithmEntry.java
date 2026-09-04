/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.Objects;
import java.util.OptionalLong;
import java.util.Set;

/**
 * Everything kimbo11ng needs to know about one post-quantum algorithm, in one immutable row.
 *
 * <p>This exists so that adding an HSM vendor is a data change rather than a code change. Before
 * it, the same algorithm was described in four places — the key-generation mechanism in the
 * profile, the signing mechanism hardcoded in the signature SPI, the key type hardcoded in the
 * keystore SPI, and the OID hardcoded in the public-key reader — and a vendor profile that
 * overrode only the first would generate a key correctly and then sign it with the wrong
 * mechanism.
 *
 * @param canonicalName  the name EJBCA uses, e.g. {@code "ML-DSA-65"}; matches an
 *                       {@code AlgorithmConstants.KEYALGORITHM_*} value
 * @param family         the algorithm family
 * @param ckkKeyType     {@code CKK_*} value for keys of this algorithm
 * @param ckmKeyPairGen  {@code CKM_*} value for key-pair generation
 * @param ckmOperation   {@code CKM_*} value for the primary operation: signing for ML-DSA and
 *                       SLH-DSA, key encapsulation for ML-KEM
 * @param ckpParameterSet {@code CKP_*} value written to {@code CKA_PARAMETER_SET}, or empty when
 *                       the vendor distinguishes parameter sets by mechanism instead. Empty is a
 *                       supported configuration, not a gap: it is how a token that predates the
 *                       v3.2 attribute is expected to be described.
 * @param oid            the NIST OID for this exact parameter set, used to build the
 *                       {@code SubjectPublicKeyInfo}
 * @param publicKeyLength the FIPS public-key size in bytes, used to cross-check what the token
 *                       returns; a mismatch means the parameter set was resolved wrongly and the
 *                       certificate would carry a lie
 * @param ops            operations a key of this algorithm may perform
 */
public record AlgorithmEntry(
        String canonicalName,
        PqcFamily family,
        long ckkKeyType,
        long ckmKeyPairGen,
        long ckmOperation,
        OptionalLong ckpParameterSet,
        ASN1ObjectIdentifier oid,
        int publicKeyLength,
        Set<KeyOp> ops) {

    /** Operations a key may be generated for. */
    public enum KeyOp {
        SIGN, VERIFY, ENCAPSULATE, DECAPSULATE
    }

    public AlgorithmEntry {
        Objects.requireNonNull(canonicalName, "canonicalName");
        Objects.requireNonNull(family, "family");
        Objects.requireNonNull(ckpParameterSet, "ckpParameterSet");
        Objects.requireNonNull(oid, "oid");
        ops = Set.copyOf(Objects.requireNonNull(ops, "ops"));
        if (publicKeyLength <= 0) {
            throw new IllegalArgumentException(
                    canonicalName + ": publicKeyLength must be positive, got " + publicKeyLength);
        }
    }

    /** True if a key of this algorithm can produce signatures. */
    public boolean canSign() {
        return ops.contains(KeyOp.SIGN);
    }

    /**
     * Normalised form of a key specification, so that {@code ML-DSA-65}, {@code MLDSA65} and
     * {@code ml_dsa_65} all resolve to the same entry.
     */
    public static String normalize(String keySpec) {
        return keySpec == null ? "" : keySpec.toUpperCase(java.util.Locale.ROOT)
                .replace("-", "")
                .replace("_", "");
    }

    /** The normalised form of this entry's canonical name. */
    public String normalizedName() {
        return normalize(canonicalName);
    }
}

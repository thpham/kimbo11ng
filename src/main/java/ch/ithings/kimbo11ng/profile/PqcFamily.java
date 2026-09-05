/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

/**
 * The post-quantum algorithm families this token can hold keys for.
 *
 * <p>The JCA name is the one BouncyCastle registers its {@code KeyFactory} under, and the one
 * {@code AlgorithmConstants.KEYALGORITHM_*} uses for the family.
 *
 * <p>It is <em>not</em> what the resulting key reports from {@code getAlgorithm()}: a key built
 * through {@code KeyFactory.getInstance("ML-DSA")} names its parameter set, so an ML-DSA-44 key
 * answers {@code "ML-DSA-44"}. Nothing depends on the family name matching — EJBCA's
 * {@code AlgorithmTools.getSignatureAlgorithms} dispatches on {@code instanceof MLDSAKey} /
 * {@code SLHDSAKey} / {@code MLKEMKey}, never on the string. Measured, and asserted in
 * {@code AlgorithmMatrixTest}.
 */
public enum PqcFamily {

    /** FIPS 204. */
    ML_DSA("ML-DSA"),
    /** FIPS 203. Key establishment, not signing. */
    ML_KEM("ML-KEM"),
    /** FIPS 205. */
    SLH_DSA("SLH-DSA");

    private final String jcaName;

    PqcFamily(String jcaName) {
        this.jcaName = jcaName;
    }

    /** The JCA / EJBCA algorithm name, e.g. {@code "ML-DSA"}. */
    public String jcaName() {
        return jcaName;
    }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

/**
 * The post-quantum algorithm families this token can hold keys for.
 *
 * <p>The JCA name is the one BouncyCastle registers its {@code KeyFactory} under and the one
 * EJBCA's {@code AlgorithmConstants.KEYALGORITHM_*} uses, so it is what a {@code PublicKey} must
 * report from {@code getAlgorithm()} for EJBCA to resolve signature algorithms for it.
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

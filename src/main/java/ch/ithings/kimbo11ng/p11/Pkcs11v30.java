/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

/**
 * The PKCS#11 v3.0 SHA-3 mechanisms Keyfactor's jacknji11 1.3.1 does not define.
 *
 * <h2>Why this class exists</h2>
 *
 * <p>Same reason as {@link Pkcs11v32}, and deliberately a separate class rather than more entries
 * there: one value, one place, named after the specification that fixes it. SHA-3 arrived in v3.0,
 * five years before the post-quantum mechanisms, and a reader who wants to check a number needs to
 * know which document to open.
 *
 * <h2>Why these are needed at all</h2>
 *
 * <p>EJBCA offers them. {@code AlgorithmTools.getSignatureAlgorithms} returns
 * {@code SHA3-256withRSA}, {@code SHA3-384withRSA} and {@code SHA3-512withRSA} for any RSA key, and
 * the three ECDSA equivalents plus {@code SHA224withECDSA} for any EC key — so they appear in the
 * list an administrator picks a CA's signature algorithm from. Without these, a CA configured with
 * one of them would fail at its first signature, on a token that supports the mechanism perfectly
 * well. SoftHSMv3 advertises all seven.
 *
 * <h2>Provenance</h2>
 *
 * <p>Hand-entered, because the bindings predate v3.0's additions. Checked on 2026-09-19 against the
 * OASIS PKCS#11 v3.0 mechanisms specification and cross-checked against the mechanism list
 * SoftHSMv3 reports, where the unnamed values appear at exactly these numbers and with
 * {@code CKF_SIGN} set.
 *
 * <p>Only the mechanisms this project registers a service for are declared. The SHA3-224 and
 * SHA3-PSS variants exist in the specification and are advertised by SoftHSMv3, but EJBCA has no
 * signature algorithm for them, so a constant here would name something nothing can ask for.
 */
public final class Pkcs11v30 {

    private Pkcs11v30() {
    }

    // ---- RSA PKCS#1 v1.5 over SHA-3 ----

    /** {@code CKM_SHA3_256_RSA_PKCS}. */
    public static final long CKM_SHA3_256_RSA_PKCS = 0x00000060L;
    /** {@code CKM_SHA3_384_RSA_PKCS}. */
    public static final long CKM_SHA3_384_RSA_PKCS = 0x00000061L;
    /** {@code CKM_SHA3_512_RSA_PKCS}. */
    public static final long CKM_SHA3_512_RSA_PKCS = 0x00000062L;

    // ---- ECDSA over SHA-3 ----

    /** {@code CKM_ECDSA_SHA3_256}. */
    public static final long CKM_ECDSA_SHA3_256 = 0x00001048L;
    /** {@code CKM_ECDSA_SHA3_384}. */
    public static final long CKM_ECDSA_SHA3_384 = 0x00001049L;
    /** {@code CKM_ECDSA_SHA3_512}. */
    public static final long CKM_ECDSA_SHA3_512 = 0x0000104AL;

    // ---- Digests ----

    /**
     * {@code CKM_SHA3_256}, and the two below it.
     *
     * <p>Declared for naming in a mechanism dump, not because this provider digests on the token:
     * every signature here hands the whole message to {@code C_Sign} under a combined mechanism.
     * The software digest services the provider registers are a separate thing — see
     * {@code DelegatingMessageDigestSpi}.
     */
    public static final long CKM_SHA3_256 = 0x000002B0L;
    /** {@code CKM_SHA3_384}. */
    public static final long CKM_SHA3_384 = 0x000002C0L;
    /** {@code CKM_SHA3_512}. */
    public static final long CKM_SHA3_512 = 0x000002D0L;
}

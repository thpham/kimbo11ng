/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

/**
 * The PKCS#11 v3.2 constants Keyfactor's jacknji11 1.3.1 does not define.
 *
 * <h2>Why this class exists</h2>
 *
 * <p>These are specification values, not vendor data, and they were living in
 * {@code Pkcs11v32Profile} — a profile, which is a table describing one vendor's tokens. Two
 * consequences followed, both of them the drift this project keeps closing elsewhere. Six of them
 * were declared a second time, verbatim, in {@code ThalesLunaProfile}, whose own javadoc says
 * "all identical to v3.2" — a sentence that has to stay true by inspection. And a vendor profile
 * reached into another vendor profile for {@code CKA_PARAMETER_SET}, as did {@code KeyTemplates}
 * from a different package, which reads as a dependency on Luna's competitor rather than on the
 * standard both implement.
 *
 * <p>One value, one place, named after the specification that fixes it. A profile still chooses
 * <em>which</em> of these its tokens use — that is what a profile is for — but no longer owns what
 * the numbers are.
 *
 * <h2>Provenance</h2>
 *
 * <p>Every value here is hand-entered, because the bindings predate v3.2. Hand-entered is not the
 * same as guessed: all of them were checked on 2026-09-05 against the OASIS working header
 * (oasis-tcs/pkcs11, {@code working/headers/pkcs11t.h}) and against jacknji11 upstream, which took
 * the same values from that header in PR #65. The two KEM usage attributes were cross-checked
 * against NSS ({@code lib/util/pkcs11t.h}) and p11-kit ({@code common/pkcs11.h}), which carry
 * 0x633 and 0x634. Zero divergences.
 *
 * <p>What none of that establishes is whether a given token implements any of it. The mechanism
 * probe is for that half of the question: a correct table and an absent mechanism look identical
 * until something asks the token.
 */
public final class Pkcs11v32 {

    private Pkcs11v32() {
    }

    // ---- Key types ----

    /** {@code CKK_ML_DSA} (FIPS 204). */
    public static final long CKK_ML_DSA = 0x0000004AL;

    /** {@code CKK_ML_KEM} (FIPS 203). */
    public static final long CKK_ML_KEM = 0x00000049L;

    /** {@code CKK_SLH_DSA} (FIPS 205). */
    public static final long CKK_SLH_DSA = 0x0000004BL;

    // ---- Mechanisms ----

    /** {@code CKM_ML_DSA_KEY_PAIR_GEN}. */
    public static final long CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001CL;

    /** {@code CKM_ML_DSA}, the signing mechanism. */
    public static final long CKM_ML_DSA = 0x0000001DL;

    /** {@code CKM_ML_KEM_KEY_PAIR_GEN}. */
    public static final long CKM_ML_KEM_KEY_PAIR_GEN = 0x0000000FL;

    /** {@code CKM_ML_KEM}, usable only with {@code C_EncapsulateKey}/{@code C_DecapsulateKey}. */
    public static final long CKM_ML_KEM = 0x00000017L;

    /** {@code CKM_SLH_DSA_KEY_PAIR_GEN}. */
    public static final long CKM_SLH_DSA_KEY_PAIR_GEN = 0x0000002DL;

    /** {@code CKM_SLH_DSA}, the signing mechanism. */
    public static final long CKM_SLH_DSA = 0x0000002EL;

    // ---- Attributes ----

    /** {@code CKA_PARAMETER_SET}, holding the {@code CKP_*} value that names the parameter set. */
    public static final long CKA_PARAMETER_SET = 0x0000061DL;

    /**
     * {@code CKA_ENCAPSULATE}, the public-key usage attribute for a KEM.
     *
     * <p>The counterpart of {@code CKA_ENCRYPT}, gating {@code C_EncapsulateKey} rather than
     * {@code C_Encrypt}. A KEM has no {@code C_Encrypt}, which is why the distinction matters and
     * why a token is entitled to refuse a template that confuses them.
     */
    public static final long CKA_ENCAPSULATE = 0x00000633L;

    /** {@code CKA_DECAPSULATE}, the private-key counterpart of {@link #CKA_ENCAPSULATE}. */
    public static final long CKA_DECAPSULATE = 0x00000634L;
}

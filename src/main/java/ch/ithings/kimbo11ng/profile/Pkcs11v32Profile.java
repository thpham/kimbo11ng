/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import ch.ithings.kimbo11ng.profile.AlgorithmEntry.KeyOp;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.List;
import java.util.OptionalLong;
import java.util.Set;

/**
 * Post-quantum algorithms as described by OASIS PKCS#11 v3.2. Works with softhsmv3 and any token
 * that implements the specification as written.
 *
 * <p>Every constant below is hand-entered, because jacknji11 1.3.1 predates v3.2 and defines none
 * of these in {@code CKA}, {@code CKK} or {@code CKM}. Hand-entered is not the same as guessed:
 * all 28 of them — three {@code CKK_*}, six {@code CKM_*}, {@code CKA_PARAMETER_SET} and the
 * eighteen {@code CKP_*} parameter sets — were checked on 2026-09-05 against the OASIS working
 * header (oasis-tcs/pkcs11, {@code working/headers/pkcs11t.h}) and against jacknji11 upstream,
 * which took the same values from that header in PR #65. Zero divergences.
 *
 * <p>What the probe is still for is the other half of the question: the spec says what a mechanism
 * is <em>numbered</em>, never whether a given token implements it. A correct table and an absent
 * mechanism look identical until something asks the token.
 */
public final class Pkcs11v32Profile extends AbstractTableProfile {

    /** Attribute id for the parameter set (PKCS#11 v3.2). */
    public static final long CKA_PARAMETER_SET = 0x0000061DL;

    // Key types
    private static final long CKK_ML_DSA = 0x0000004AL;
    private static final long CKK_ML_KEM = 0x00000049L;
    private static final long CKK_SLH_DSA = 0x0000004BL;

    // Mechanisms
    private static final long CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001CL;
    private static final long CKM_ML_DSA = 0x0000001DL;
    private static final long CKM_ML_KEM_KEY_PAIR_GEN = 0x0000000FL;
    private static final long CKM_ML_KEM = 0x00000017L;
    private static final long CKM_SLH_DSA_KEY_PAIR_GEN = 0x0000002DL;
    private static final long CKM_SLH_DSA = 0x0000002EL;

    // NIST OID arcs
    private static final String SIG_ARC = "2.16.840.1.101.3.4.3.";
    private static final String KEM_ARC = "2.16.840.1.101.3.4.4.";

    private static final Set<KeyOp> SIGNING = Set.of(KeyOp.SIGN, KeyOp.VERIFY);
    private static final Set<KeyOp> KEM = Set.of(KeyOp.ENCAPSULATE, KeyOp.DECAPSULATE);

    public Pkcs11v32Profile() {
        super(table());
    }

    private static List<AlgorithmEntry> table() {
        return List.of(
            // ---- ML-DSA (FIPS 204). Public key 1312 / 1952 / 2592 bytes. ----
            mlDsa("ML-DSA-44", 1L, SIG_ARC + "17", 1312),
            mlDsa("ML-DSA-65", 2L, SIG_ARC + "18", 1952),
            mlDsa("ML-DSA-87", 3L, SIG_ARC + "19", 2592),

            // ---- ML-KEM (FIPS 203). Public key 800 / 1184 / 1568 bytes. ----
            mlKem("ML-KEM-512",  1L, KEM_ARC + "1", 800),
            mlKem("ML-KEM-768",  2L, KEM_ARC + "2", 1184),
            mlKem("ML-KEM-1024", 3L, KEM_ARC + "3", 1568),

            // ---- SLH-DSA (FIPS 205). Public key is 2n bytes: 32 / 48 / 64. ----
            // CKP values run s-before-f and SHA2-before-SHAKE within each level; the NIST OID arc
            // groups all SHA2 variants (.20-.25) before all SHAKE ones (.26-.31). The two orders
            // do not line up, which is exactly the sort of mismatch a table makes safe.
            slhDsa("SLH-DSA-SHA2-128S",   1L, SIG_ARC + "20", 32),
            slhDsa("SLH-DSA-SHAKE-128S",  2L, SIG_ARC + "26", 32),
            slhDsa("SLH-DSA-SHA2-128F",   3L, SIG_ARC + "21", 32),
            slhDsa("SLH-DSA-SHAKE-128F",  4L, SIG_ARC + "27", 32),
            slhDsa("SLH-DSA-SHA2-192S",   5L, SIG_ARC + "22", 48),
            slhDsa("SLH-DSA-SHAKE-192S",  6L, SIG_ARC + "28", 48),
            slhDsa("SLH-DSA-SHA2-192F",   7L, SIG_ARC + "23", 48),
            slhDsa("SLH-DSA-SHAKE-192F",  8L, SIG_ARC + "29", 48),
            slhDsa("SLH-DSA-SHA2-256S",   9L, SIG_ARC + "24", 64),
            slhDsa("SLH-DSA-SHAKE-256S", 10L, SIG_ARC + "30", 64),
            slhDsa("SLH-DSA-SHA2-256F",  11L, SIG_ARC + "25", 64),
            slhDsa("SLH-DSA-SHAKE-256F", 12L, SIG_ARC + "31", 64));
    }

    private static AlgorithmEntry mlDsa(String name, long ckp, String oid, int pubLen) {
        return new AlgorithmEntry(name, PqcFamily.ML_DSA, CKK_ML_DSA, CKM_ML_DSA_KEY_PAIR_GEN,
                CKM_ML_DSA, OptionalLong.of(ckp), new ASN1ObjectIdentifier(oid), pubLen, SIGNING);
    }

    private static AlgorithmEntry mlKem(String name, long ckp, String oid, int pubLen) {
        return new AlgorithmEntry(name, PqcFamily.ML_KEM, CKK_ML_KEM, CKM_ML_KEM_KEY_PAIR_GEN,
                CKM_ML_KEM, OptionalLong.of(ckp), new ASN1ObjectIdentifier(oid), pubLen, KEM);
    }

    private static AlgorithmEntry slhDsa(String name, long ckp, String oid, int pubLen) {
        return new AlgorithmEntry(name, PqcFamily.SLH_DSA, CKK_SLH_DSA, CKM_SLH_DSA_KEY_PAIR_GEN,
                CKM_SLH_DSA, OptionalLong.of(ckp), new ASN1ObjectIdentifier(oid), pubLen, SIGNING);
    }

    @Override
    public String name() {
        return "pkcs11v32";
    }

    @Override
    public long ckaParameterSet() {
        return CKA_PARAMETER_SET;
    }
}

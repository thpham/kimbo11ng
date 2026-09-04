/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.fake;

import ch.ithings.kimbo11ng.profile.AbstractTableProfile;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry.KeyOp;
import ch.ithings.kimbo11ng.profile.PqcFamily;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.List;
import java.util.OptionalLong;
import java.util.Set;

/**
 * A stand-in for the vendor profile that does not exist yet, discovered through
 * {@code META-INF/services} on the test classpath.
 *
 * <p>It is here so profile auto-detection is tested against two profiles that genuinely disagree,
 * rather than against one. Everything about it is chosen to be the awkward case a real vendor is
 * expected to be:
 *
 * <ul>
 *   <li>Vendor-defined mechanisms and key type, all above {@code 0x80000000}, so the values come
 *       back from jacknji11 sign-extended — see {@link ch.ithings.kimbo11ng.p11.CkULong}.
 *   <li>Generation and signing mechanisms shifted independently, which is why
 *       {@link AlgorithmEntry} keeps them as separate fields.
 *   <li>No {@code CKA_PARAMETER_SET}: the parameter set is encoded in the mechanism, which is the
 *       likelier arrangement on firmware predating PKCS#11 v3.2.
 * </ul>
 *
 * <p>OIDs and public-key lengths are FIPS-defined and therefore identical to the v3.2 profile's:
 * those do not vary by vendor, and a profile that changed them would be wrong.
 */
public final class VendorTestProfile extends AbstractTableProfile {

    /** Distinct generation mechanism per parameter set, the way a pre-v3.2 vendor would do it. */
    public static final long CKM_VENDOR_MLDSA44_KEY_PAIR_GEN = 0x80000100L;
    public static final long CKM_VENDOR_MLDSA65_KEY_PAIR_GEN = 0x80000101L;
    public static final long CKM_VENDOR_MLDSA87_KEY_PAIR_GEN = 0x80000102L;
    public static final long CKM_VENDOR_MLDSA = 0x80000110L;

    /** Every mechanism this profile needs, for a test that has to advertise them all. */
    public static final long[] MECHANISMS = {
            CKM_VENDOR_MLDSA44_KEY_PAIR_GEN, CKM_VENDOR_MLDSA65_KEY_PAIR_GEN,
            CKM_VENDOR_MLDSA87_KEY_PAIR_GEN, CKM_VENDOR_MLDSA};

    private static final long CKK_VENDOR_ML_DSA = 0x80000200L;

    public VendorTestProfile() {
        super(List.of(
                mlDsa("ML-DSA-44", CKM_VENDOR_MLDSA44_KEY_PAIR_GEN, 1L,
                        "2.16.840.1.101.3.4.3.17", 1312),
                mlDsa("ML-DSA-65", CKM_VENDOR_MLDSA65_KEY_PAIR_GEN, 2L,
                        "2.16.840.1.101.3.4.3.18", 1952),
                mlDsa("ML-DSA-87", CKM_VENDOR_MLDSA87_KEY_PAIR_GEN, 3L,
                        "2.16.840.1.101.3.4.3.19", 2592)));
    }

    private static AlgorithmEntry mlDsa(String name, long keygen, long distinguisher, String oid,
            int pubLen) {
        // The key type is shared, so the entries would be indistinguishable on the token without
        // something to tell them apart; a real vendor of this shape distinguishes by mechanism.
        // AbstractTableProfile enforces that, which is the point of borrowing the CKP slot here.
        return new AlgorithmEntry(name, PqcFamily.ML_DSA, CKK_VENDOR_ML_DSA, keygen,
                CKM_VENDOR_MLDSA, OptionalLong.of(distinguisher), new ASN1ObjectIdentifier(oid),
                pubLen, Set.of(KeyOp.SIGN, KeyOp.VERIFY));
    }

    @Override
    public String name() {
        return "vendor-test";
    }

    @Override
    public long ckaParameterSet() {
        return 0x80000300L;
    }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import ch.ithings.kimbo11ng.p11.Pkcs11v32;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry.KeyOp;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.List;
import java.util.OptionalLong;
import java.util.Set;

/**
 * Thales Luna Network/PCIe HSM, firmware 7.9.0 or later with Luna HSM Client 10.9.0 or later.
 *
 * <p><b>This profile is optional.</b> Luna 7.9.0 implements post-quantum keys with the standard
 * PKCS#11 v3.2 numbering — the same key types, mechanisms, parameter-set attribute and {@code CKP_*}
 * values as {@link Pkcs11v32Profile} — so a Luna token works correctly under the default profile,
 * with the capability probe narrowing the algorithm table to what the firmware actually advertises.
 * The profile exists so that Luna can be named explicitly (<code>kimbo11ng.pqc.profile=thales-luna</code>)
 * and so that the difference from a v3.2 token is stated in code rather than discovered at runtime:
 * Luna supports ML-DSA and ML-KEM but <b>not SLH-DSA</b>, so the twelve SLH-DSA rows are absent
 * here. Under the default profile the same twelve rows are excluded by the probe instead.
 *
 * <p><b>Constants.</b> All identical to v3.2: {@code Pkcs11v32.CKK_ML_DSA} 0x4A, {@code Pkcs11v32.CKK_ML_KEM} 0x49,
 * {@code Pkcs11v32.CKM_ML_DSA_KEY_PAIR_GEN} 0x1C, {@code Pkcs11v32.CKM_ML_DSA} 0x1D, {@code Pkcs11v32.CKM_ML_KEM_KEY_PAIR_GEN}
 * 0x0F, {@code Pkcs11v32.CKM_ML_KEM} 0x17, {@code CKA_PARAMETER_SET} 0x61D with {@code CKP_*} 1/2/3 per
 * family. Luna adds one vendor mechanism, {@code CKM_EXTMU_ML_DSA} (0x80000175) for external-mu
 * signing, which kimbo11ng does not use; its proprietary surface for ML-KEM is the
 * {@code CA_EncapsulateKey}/{@code CA_DecapsulateKey} functions rather than different constants,
 * and kimbo11ng does not encapsulate.
 *
 * <p><b>Known firmware limits (7.9.x).</b> ML-DSA private keys cannot be wrapped or unwrapped, and
 * there is no SLH-DSA support or published roadmap for it. Neither affects certificate signing.
 *
 * <p>Sources: Luna HSM Firmware 7.9.0 Customer Release Notes; the ML-DSA and ML-KEM programming
 * guides in the Luna SDK documentation. See {@code docs/VENDOR_PROFILE_CHECKLIST.md}.
 */
public final class ThalesLunaProfile extends AbstractTableProfile {

    // Firmware 7.9.0 uses the v3.2 values verbatim; they are repeated rather than imported so that
    // a future divergence is a one-line edit here and not a change to the v3.2 profile.


    private static final String SIG_ARC = "2.16.840.1.101.3.4.3.";
    private static final String KEM_ARC = "2.16.840.1.101.3.4.4.";

    private static final Set<KeyOp> SIGNING = Set.of(KeyOp.SIGN, KeyOp.VERIFY);
    private static final Set<KeyOp> KEM = Set.of(KeyOp.ENCAPSULATE, KeyOp.DECAPSULATE);

    public ThalesLunaProfile() {
        super(table());
    }

    private static List<AlgorithmEntry> table() {
        return List.of(
            mlDsa("ML-DSA-44", 1L, SIG_ARC + "17", 1312),
            mlDsa("ML-DSA-65", 2L, SIG_ARC + "18", 1952),
            mlDsa("ML-DSA-87", 3L, SIG_ARC + "19", 2592),

            mlKem("ML-KEM-512",  1L, KEM_ARC + "1", 800),
            mlKem("ML-KEM-768",  2L, KEM_ARC + "2", 1184),
            mlKem("ML-KEM-1024", 3L, KEM_ARC + "3", 1568));
    }

    private static AlgorithmEntry mlDsa(String name, long ckp, String oid, int pubLen) {
        return new AlgorithmEntry(name, PqcFamily.ML_DSA, Pkcs11v32.CKK_ML_DSA, Pkcs11v32.CKM_ML_DSA_KEY_PAIR_GEN,
                Pkcs11v32.CKM_ML_DSA, OptionalLong.of(ckp), new ASN1ObjectIdentifier(oid), pubLen, SIGNING);
    }

    private static AlgorithmEntry mlKem(String name, long ckp, String oid, int pubLen) {
        return new AlgorithmEntry(name, PqcFamily.ML_KEM, Pkcs11v32.CKK_ML_KEM, Pkcs11v32.CKM_ML_KEM_KEY_PAIR_GEN,
                Pkcs11v32.CKM_ML_KEM, OptionalLong.of(ckp), new ASN1ObjectIdentifier(oid), pubLen, KEM);
    }

    @Override
    public String name() {
        return "thales-luna";
    }

    /**
     * The v3.2 pair alone, no {@code CKA_ENCRYPT}.
     *
     * <p>Luna's ML-KEM programming guide gives the generation templates explicitly:
     * {@code CKA_ENCAPSULATE} on the public half and {@code CKA_DECAPSULATE} on the private one,
     * both defaulting to true, alongside {@code CKA_CLASS}, {@code CKA_KEY_TYPE},
     * {@code CKA_PARAMETER_SET}, {@code CKA_SENSITIVE} and {@code CKA_EXTRACTABLE}. Neither
     * {@code CKA_ENCRYPT} nor {@code CKA_DECRYPT} appears in either list. Sending them anyway would
     * be asking a token that models a KEM correctly to accept a claim about an operation ML-KEM
     * does not have — the exact template a firmware entitled to answer
     * {@code CKR_TEMPLATE_INCONSISTENT} would answer it to.
     *
     * <p>The cost, and it is real: EJBCA reads {@code CKA_DECRYPT} by number, so an ML-KEM key made
     * on Luna will show no key usage in the admin UI. That is a reporting gap on an algorithm
     * EJBCA CE has no path for anyway, and it is recoverable with
     * {@code kimbo11ng.pqc.kemUsage=both} on a partition that turns out to accept the wider
     * template. Unverified against hardware — there is none here — which is why it is a profile
     * default rather than something hard-coded.
     *
     * <p>Retrieved 2026-09-05 from the Luna 7 SDK documentation, ML-KEM Programming Guide.
     */
    @Override
    public KemUsage defaultKemUsage() {
        return KemUsage.V32;
    }

    @Override
    public long ckaParameterSet() {
        return Pkcs11v32.CKA_PARAMETER_SET;
    }
}

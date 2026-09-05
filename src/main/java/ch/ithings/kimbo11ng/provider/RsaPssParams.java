/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import org.pkcs11.jacknji11.ULong;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * The {@code CK_RSA_PKCS_PSS_PARAMS} block a PSS mechanism will not sign without.
 *
 * <p>Unlike every other mechanism this provider uses, {@code CKM_SHA*_RSA_PKCS_PSS} takes a
 * parameter, and jacknji11 supplies none: {@code CKM.DEFAULT_PARAMS} covers the CBC IVs and
 * {@code CKM_RSA_PKCS_OAEP} and nothing else, so {@code new CKM(CKM.SHA256_RSA_PKCS_PSS)} produces
 * a mechanism with a null parameter and the token answers {@code CKR_MECHANISM_PARAM_INVALID}.
 * That is why PSS was not simply added to the classical signature table with the others.
 *
 * <p>The struct is three {@code CK_ULONG}s — hash algorithm, mask generation function, salt length
 * — laid out at the platform's {@code CK_ULONG} width, which is what {@link ULong#ulong2b} encodes.
 * It is the same shape jacknji11 uses for its own OAEP default.
 *
 * <h2>Salt length</h2>
 *
 * <p>Equal to the digest length. That is what BouncyCastle's {@code SHA256withRSAandMGF1} produces
 * and therefore what a verifier of an EJBCA-issued certificate expects; a token signing with a
 * different salt length yields a signature no relying party can check, and nothing on our side
 * would notice, because this provider never verifies.
 */
final class RsaPssParams {

    /** {@code CKM_SHA256} — the digest mechanism, not the signature mechanism. */
    private static final long CKM_SHA256 = 0x00000250L;
    private static final long CKM_SHA384 = 0x00000260L;
    private static final long CKM_SHA512 = 0x00000270L;

    /** {@code CKG_MGF1_*}, the mask generation functions from PKCS#11 §2.1.16. */
    private static final long CKG_MGF1_SHA256 = 0x00000002L;
    private static final long CKG_MGF1_SHA384 = 0x00000003L;
    private static final long CKG_MGF1_SHA512 = 0x00000004L;

    private RsaPssParams() {
    }

    /** Encoded parameters for SHA-256 PSS: MGF1-SHA256, 32-byte salt. */
    static byte[] sha256() {
        return encode(CKM_SHA256, CKG_MGF1_SHA256, 32);
    }

    /** Encoded parameters for SHA-384 PSS: MGF1-SHA384, 48-byte salt. */
    static byte[] sha384() {
        return encode(CKM_SHA384, CKG_MGF1_SHA384, 48);
    }

    /** Encoded parameters for SHA-512 PSS: MGF1-SHA512, 64-byte salt. */
    static byte[] sha512() {
        return encode(CKM_SHA512, CKG_MGF1_SHA512, 64);
    }

    private static byte[] encode(long hashAlg, long mgf, long saltLength) {
        return ULong.ulong2b(hashAlg, mgf, saltLength);
    }

    /**
     * The encoding a {@link PSSParameterSpec} asks for, so a caller-supplied spec can be compared
     * against what the service will actually send.
     *
     * @throws InvalidAlgorithmParameterException if the spec names anything this cannot express —
     *         a digest with no PKCS#11 mechanism, a mask function other than MGF1, or a trailer
     *         field other than the single byte PKCS#1 defines
     */
    static byte[] forSpec(PSSParameterSpec spec) throws InvalidAlgorithmParameterException {
        if (!"MGF1".equalsIgnoreCase(spec.getMGFAlgorithm())) {
            throw new InvalidAlgorithmParameterException(
                    "Only MGF1 is supported, got " + spec.getMGFAlgorithm());
        }
        if (spec.getTrailerField() != PSSParameterSpec.TRAILER_FIELD_BC) {
            throw new InvalidAlgorithmParameterException(
                    "Only trailer field 1 is supported, got " + spec.getTrailerField());
        }
        String mgfDigest = spec.getMGFParameters() instanceof MGF1ParameterSpec mgf1
                ? mgf1.getDigestAlgorithm()
                : spec.getDigestAlgorithm();
        return encode(digestMechanism(spec.getDigestAlgorithm()), mgf(mgfDigest),
                spec.getSaltLength());
    }

    /** {@code "SHA-256/MGF1-SHA-256/salt=32"}, for a message that has to name both sides. */
    static String describe(byte[] encoded) {
        int width = ULong.ULONG_SIZE.size();
        if (encoded == null || encoded.length != 3 * width) {
            return "<not a CK_RSA_PKCS_PSS_PARAMS>";
        }
        return name(field(encoded, 0)) + "/MGF1-" + mgfName(field(encoded, 1))
                + "/salt=" + field(encoded, 2);
    }

    /** One {@code CK_ULONG} out of the struct; {@code ULong.b2ulong} decodes a single value. */
    private static long field(byte[] encoded, int index) {
        int width = ULong.ULONG_SIZE.size();
        byte[] slice = new byte[width];
        System.arraycopy(encoded, index * width, slice, 0, width);
        return ULong.b2ulong(slice);
    }

    /** JCA digest name to the {@code CKM_*} the PSS parameter block names as its hash. */
    private static long digestMechanism(String algorithmName)
            throws InvalidAlgorithmParameterException {
        return switch (normalize(algorithmName)) {
            case "SHA256" -> CKM_SHA256;
            case "SHA384" -> CKM_SHA384;
            case "SHA512" -> CKM_SHA512;
            default -> throw new InvalidAlgorithmParameterException(
                    "No PSS mechanism is registered for digest " + algorithmName);
        };
    }

    /** JCA digest name to the {@code CKG_MGF1_*} mask generation function over it. */
    private static long mgf(String algorithmName) throws InvalidAlgorithmParameterException {
        return switch (normalize(algorithmName)) {
            case "SHA256" -> CKG_MGF1_SHA256;
            case "SHA384" -> CKG_MGF1_SHA384;
            case "SHA512" -> CKG_MGF1_SHA512;
            default -> throw new InvalidAlgorithmParameterException(
                    "No MGF1 variant is registered for digest " + algorithmName);
        };
    }

    /** {@code "SHA-256"} and {@code "SHA256"} are the same algorithm to every caller here. */
    private static String normalize(String algorithmName) {
        return algorithmName == null ? ""
                : algorithmName.toUpperCase(java.util.Locale.ROOT).replace("-", "");
    }

    private static String name(long mechanism) {
        if (mechanism == CKM_SHA256) {
            return "SHA-256";
        }
        if (mechanism == CKM_SHA384) {
            return "SHA-384";
        }
        if (mechanism == CKM_SHA512) {
            return "SHA-512";
        }
        return "0x" + Long.toHexString(mechanism);
    }

    private static String mgfName(long mgf) {
        if (mgf == CKG_MGF1_SHA256) {
            return "SHA-256";
        }
        if (mgf == CKG_MGF1_SHA384) {
            return "SHA-384";
        }
        if (mgf == CKG_MGF1_SHA512) {
            return "SHA-512";
        }
        return "0x" + Long.toHexString(mgf);
    }
}

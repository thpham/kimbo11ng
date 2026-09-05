/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CryptokiE;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Builds {@link PublicKey} objects from PKCS#11 object attributes.
 *
 * <p>The result must be a real BouncyCastle key, never an opaque wrapper: EJBCA's
 * {@code AlgorithmTools.getSignatureAlgorithms} decides what a key can sign with using
 * {@code instanceof MLDSAKey} / {@code SLHDSAKey} / {@code MLKEMKey}, and returns an empty list for
 * anything else. A key it cannot recognise is a key no CA can use, so failing loudly here is
 * strictly better than handing back something that fails later as "no valid signing algorithm".
 *
 * <p>Nothing in here guesses. Every branch is decided by a length or an OID that the token itself
 * reported, and a disagreement is an error rather than a default — because the failure mode of
 * guessing is not a broken key but a working key with the wrong algorithm in its certificate.
 */
public final class PublicKeyReader {

    private static final Logger log = Logger.getLogger(PublicKeyReader.class);

    /** How hard to fail when the token's answers disagree with what was asked for. */
    public enum Policy {
        /**
         * Any disagreement is an error. Used when generating: we know exactly what was requested,
         * so a mismatch means the key on the token is not the key that was asked for, and issuing
         * a certificate for it would state the wrong algorithm.
         */
        STRICT,
        /**
         * A disagreement that cannot produce a wrong OID is logged rather than thrown. Used when
         * enumerating keys that already exist and may have been created by other software: a CA
         * that has been running for years should not fail to start over a cosmetic mismatch. A
         * genuine length mismatch still fails, under either policy.
         */
        LENIENT
    }

    private PublicKeyReader() {
    }

    /** Read an RSA public key from {@code CKA_MODULUS} and {@code CKA_PUBLIC_EXPONENT}. */
    public static PublicKey readRsaPublicKey(CryptokiE ce, long session, long handle)
            throws Exception {
        CKA[] attrs = ce.GetAttributeValue(session, handle, CKA.MODULUS, CKA.PUBLIC_EXPONENT);
        byte[] modulusBytes = attrs[0].getValue();
        byte[] exponentBytes = attrs[1].getValue();
        if (modulusBytes == null || modulusBytes.length == 0
                || exponentBytes == null || exponentBytes.length == 0) {
            throw new InvalidKeyException("The token did not report CKA_MODULUS and "
                    + "CKA_PUBLIC_EXPONENT for RSA public key handle " + handle);
        }
        BigInteger modulus = new BigInteger(1, modulusBytes);
        BigInteger publicExponent = new BigInteger(1, exponentBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePublic(new java.security.spec.RSAPublicKeySpec(modulus, publicExponent));
    }

    /**
     * Read an EC public key from {@code CKA_EC_PARAMS} and {@code CKA_EC_POINT}.
     *
     * <p>Both encodings modules use for the point are accepted, decided by length and prefix rather
     * than by inspecting one byte — see {@link EcPointCodec} for why the previous heuristic was
     * wrong for about a quarter of all keys.
     */
    public static PublicKey readEcPublicKey(CryptokiE ce, long session, long handle)
            throws Exception {
        CKA[] attrs = ce.GetAttributeValue(session, handle, CKA.EC_PARAMS, CKA.EC_POINT);
        ECParameterSpec spec = EcPointCodec.parseCurve(attrs[0].getValue());
        ECPoint point = EcPointCodec.decodePoint(attrs[1].getValue(), spec);

        KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePublic(new ECPublicKeySpec(point, spec));
    }

    /**
     * Read a post-quantum public key, using {@code entry} for the algorithm and OID.
     *
     * <p>The OID comes from the resolved {@link AlgorithmEntry} — which the caller either knows
     * because it just generated the key, or resolved from {@code CKA_KEY_TYPE} plus the token's
     * parameter-set attribute — and never from a default. A token that does not report its
     * parameter set makes the key unresolvable, which is reported; it does not make it ML-DSA-65.
     *
     * @param policy {@link Policy#STRICT} when generating, {@link Policy#LENIENT} when enumerating
     */
    public static PublicKey readPqcPublicKey(CryptokiE ce, long session, long handle,
            AlgorithmEntry entry, Policy policy) throws Exception {
        CKA valueAttr = ce.GetAttributeValue(session, handle, CKA.VALUE);
        byte[] keyBytes = valueAttr.getValue();
        if (keyBytes == null || keyBytes.length == 0) {
            throw new InvalidKeyException("CKA_VALUE is empty for " + entry.canonicalName()
                    + " public key (handle " + handle + ")");
        }

        byte[] spkiBytes;
        SubjectPublicKeyInfo fromToken = asSubjectPublicKeyInfo(keyBytes);
        if (fromToken != null) {
            requireOidMatches(fromToken, entry, policy);
            requireLengthMatches(fromToken.getPublicKeyData().getOctets().length, entry);
            spkiBytes = keyBytes;
        } else {
            requireLengthMatches(keyBytes.length, entry);
            spkiBytes = new SubjectPublicKeyInfo(new AlgorithmIdentifier(entry.oid()), keyBytes)
                    .getEncoded();
        }

        String jcaName = entry.family().jcaName();
        try {
            KeyFactory kf = KeyFactory.getInstance(jcaName, BouncyCastleProvider.PROVIDER_NAME);
            return kf.generatePublic(new java.security.spec.X509EncodedKeySpec(spkiBytes));
        } catch (Exception e) {
            // No opaque fallback on purpose: EJBCA cannot sign with a key it does not recognise,
            // so a wrapper would only defer this failure to certificate issuance.
            throw new InvalidKeyException("BouncyCastle could not materialise a " + jcaName
                    + " public key for " + entry.canonicalName() + " (OID " + entry.oid().getId()
                    + ", " + keyBytes.length + " bytes of CKA_VALUE). The deployed BouncyCastle may"
                    + " predate this algorithm.", e);
        }
    }

    /** Overload for the generation path, where any disagreement is fatal. */
    public static PublicKey readPqcPublicKey(CryptokiE ce, long session, long handle,
            AlgorithmEntry entry) throws Exception {
        return readPqcPublicKey(ce, session, handle, entry, Policy.STRICT);
    }

    /**
     * Rejects key material whose length does not match the parameter set it is being labelled as.
     *
     * <p>This is the only check there is, under either policy. Measured against the deployed
     * BouncyCastle: 1312 bytes of ML-DSA-44 material presented under the ML-DSA-87 OID is accepted
     * without complaint, and the resulting key reports
     * {@code getParameterSpec().getName() == "ML-DSA-87"}. EJBCA would write that OID into the
     * certificate's SubjectPublicKeyInfo, and the mislabelling would only ever surface as
     * signatures no relying party can verify.
     *
     * <p>FIPS 203 and 204 give every ML-KEM and ML-DSA parameter set a distinct public-key length,
     * so for those this resolves the parameter set outright. FIPS 205 gives SLH-DSA four variants
     * per length (s/f × SHA2/SHAKE), so there it confirms the security level and no more —
     * ML-DSA-44 read as ML-DSA-87 is caught; SLH-DSA-SHA2-128S read as SLH-DSA-SHAKE-128F is not.
     */
    private static void requireLengthMatches(int actual, AlgorithmEntry entry)
            throws InvalidKeyException {
        if (actual != entry.publicKeyLength()) {
            throw new InvalidKeyException("Refusing to label a " + actual + "-byte public key as "
                    + entry.canonicalName() + ", whose public key is " + entry.publicKeyLength()
                    + " bytes (" + entry.family().jcaName() + ", OID " + entry.oid().getId()
                    + "). The token holds a key of a different parameter set than the one"
                    + " requested; issuing a certificate for it would state the wrong algorithm.");
        }
    }

    /**
     * Rejects a token-supplied SubjectPublicKeyInfo that names a different algorithm.
     *
     * <p>Under {@link Policy#LENIENT} this is a warning instead: the length check below it is what
     * prevents a wrong OID reaching a certificate, and an existing CA whose token labels its own
     * keys slightly differently should not fail to start over it. Under {@link Policy#STRICT} —
     * generation — there is no such excuse: we asked for a specific algorithm.
     */
    private static void requireOidMatches(SubjectPublicKeyInfo spki, AlgorithmEntry entry,
            Policy policy) throws InvalidKeyException {
        ASN1ObjectIdentifier actual = spki.getAlgorithm().getAlgorithm();
        if (entry.oid().equals(actual)) {
            return;
        }
        String message = "The token reports this key as OID " + actual.getId()
                + " but it was resolved as " + entry.canonicalName() + " (OID "
                + entry.oid().getId() + ").";
        if (policy == Policy.STRICT) {
            throw new InvalidKeyException(message + " Refusing to guess which is right.");
        }
        log.warn(message + " Continuing with the token's own encoding: its length is checked"
                + " below, so a key of the wrong parameter set is still refused. This is usually a"
                + " token that predates the final OID assignments. Set " + STRICT_PUBLIC_KEY
                + "=true on the crypto token to make it fatal instead.");
    }

    /** @see Policy */
    public static final String STRICT_PUBLIC_KEY = "kimbo11ng.strict.publickey";

    /**
     * The bytes as a {@code SubjectPublicKeyInfo}, or {@code null} if they are raw key material.
     *
     * <p>Parse and consume, then re-encode and compare. PKCS#11 v3.2 does not settle which of the
     * two a token reports and implementations differ, so this has to be decided from the bytes —
     * and "starts with 0x30" is not a decision, it is a guess that a key whose first byte happens
     * to be 0x30 would lose.
     */
    private static SubjectPublicKeyInfo asSubjectPublicKeyInfo(byte[] b) {
        if (b.length <= 2 || b[0] != 0x30) {
            return null;
        }
        try {
            ASN1Primitive parsed = ASN1Primitive.fromByteArray(b);
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(parsed);
            if (!Arrays.equals(b, spki.getEncoded())) {
                return null;
            }
            return spki;
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("CKA_VALUE starts as a SEQUENCE but is not a SubjectPublicKeyInfo; "
                        + "treating it as raw key material: " + e.getMessage());
            }
            return null;
        }
    }
}

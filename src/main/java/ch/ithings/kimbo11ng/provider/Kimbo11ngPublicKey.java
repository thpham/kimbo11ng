/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CryptokiE;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Builds {@link PublicKey} objects from PKCS#11 object attributes.
 *
 * <p>The result must be a real BouncyCastle key, never an opaque wrapper: EJBCA's
 * {@code AlgorithmTools.getSignatureAlgorithms} decides what a key can sign with using
 * {@code instanceof MLDSAKey} / {@code SLHDSAKey} / {@code MLKEMKey}, and returns an empty list
 * for anything else. A key it cannot recognise is a key no CA can use, so failing loudly here is
 * strictly better than handing back something that fails later as "no valid signing algorithm".
 */
public final class Kimbo11ngPublicKey {

    private static final Logger log = Logger.getLogger(Kimbo11ngPublicKey.class);

    private Kimbo11ngPublicKey() {
    }

    /** Read an RSA public key from {@code CKA_MODULUS} and {@code CKA_PUBLIC_EXPONENT}. */
    public static PublicKey readRsaPublicKey(CryptokiE ce, long session, long handle)
            throws Exception {
        CKA[] attrs = ce.GetAttributeValue(session, handle, CKA.MODULUS, CKA.PUBLIC_EXPONENT);
        BigInteger modulus = new BigInteger(1, attrs[0].getValue());
        BigInteger publicExponent = new BigInteger(1, attrs[1].getValue());
        KeyFactory kf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
    }

    /**
     * Read an EC public key from {@code CKA_EC_PARAMS} and {@code CKA_EC_POINT}.
     *
     * <p>TODO(phase-4): the OCTET STRING unwrap below is unsound. Byte 0 is {@code 0x04} both as
     * the DER tag and as the uncompressed-point prefix, so for a module that reports a raw point
     * this misreads X[0] as a length; measured at 23.2% failure over 2,000 P-256 keys. Phase 4
     * replaces it with a parse-and-consume check plus a field-size assertion.
     */
    public static PublicKey readEcPublicKey(CryptokiE ce, long session, long handle)
            throws Exception {
        CKA[] attrs = ce.GetAttributeValue(session, handle, CKA.EC_PARAMS, CKA.EC_POINT);
        byte[] ecParamsBytes = attrs[0].getValue();
        byte[] ecPointBytes = attrs[1].getValue();

        ASN1ObjectIdentifier oid;
        try (ASN1InputStream ais = new ASN1InputStream(ecParamsBytes)) {
            oid = (ASN1ObjectIdentifier) ais.readObject();
        }
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(oid.getId());
        if (spec == null) {
            throw new InvalidKeyException("Unknown EC curve OID: " + oid.getId());
        }

        byte[] pointBytes = ecPointBytes;
        if (ecPointBytes.length > 1 && ecPointBytes[0] == 0x04 && ecPointBytes[1] != 0x04) {
            try (ASN1InputStream ais = new ASN1InputStream(ecPointBytes)) {
                ASN1Encodable obj = ais.readObject();
                if (obj instanceof DEROctetString der) {
                    pointBytes = der.getOctets();
                } else if (obj instanceof ASN1OctetString octets) {
                    pointBytes = octets.getOctets();
                }
            } catch (Exception e) {
                pointBytes = ecPointBytes;
            }
        }

        ECPoint point = spec.getCurve().decodePoint(pointBytes);
        KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePublic(new ECPublicKeySpec(point, spec));
    }

    /**
     * Read a post-quantum public key, using {@code entry} for the algorithm and OID.
     *
     * <p>The OID is taken from the resolved {@link AlgorithmEntry} rather than guessed from the
     * token's parameter-set attribute, so a token that does not report that attribute cannot cause
     * a key to be labelled as a different parameter set than it is.
     *
     * @param entry the algorithm this key was generated as, already resolved by the caller
     */
    public static PublicKey readPqcPublicKey(CryptokiE ce, long session, long handle,
            AlgorithmEntry entry) throws Exception {
        CKA valueAttr = ce.GetAttributeValue(session, handle, CKA.VALUE);
        byte[] keyBytes = valueAttr.getValue();
        if (keyBytes == null || keyBytes.length == 0) {
            throw new InvalidKeyException("CKA_VALUE is empty for " + entry.canonicalName()
                    + " public key (handle " + handle + ")");
        }

        byte[] spkiBytes;
        if (looksLikeSpki(keyBytes)) {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(keyBytes);
            requireOidMatches(spki, entry);
            requireLengthMatches(spki.getPublicKeyData().getOctets().length, entry);
            spkiBytes = keyBytes;
        } else {
            requireLengthMatches(keyBytes.length, entry);
            spkiBytes = new SubjectPublicKeyInfo(new AlgorithmIdentifier(entry.oid()), keyBytes)
                    .getEncoded();
        }

        String jcaName = entry.family().jcaName();
        try {
            KeyFactory kf = KeyFactory.getInstance(jcaName, BouncyCastleProvider.PROVIDER_NAME);
            return kf.generatePublic(new X509EncodedKeySpec(spkiBytes));
        } catch (Exception e) {
            // No opaque fallback on purpose: EJBCA cannot sign with a key it does not recognise,
            // so a wrapper would only defer this failure to certificate issuance.
            throw new InvalidKeyException("BouncyCastle could not materialise a " + jcaName
                    + " public key for " + entry.canonicalName() + " (OID " + entry.oid().getId()
                    + ", " + keyBytes.length + " bytes of CKA_VALUE). The deployed BouncyCastle may"
                    + " predate this algorithm.", e);
        }
    }

    /**
     * Rejects key material whose length does not match the parameter set it is being labelled as.
     *
     * <p>This is the only check there is. Measured against the deployed BouncyCastle: 1312 bytes of
     * ML-DSA-44 material presented under the ML-DSA-87 OID is accepted without complaint, and the
     * resulting key reports {@code getParameterSpec().getName() == "ML-DSA-87"}. EJBCA would then
     * write that OID into the certificate's SubjectPublicKeyInfo, and the mislabelling would only
     * ever surface as signatures no relying party can verify.
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

    /** Rejects a token-supplied SubjectPublicKeyInfo that names a different algorithm. */
    private static void requireOidMatches(SubjectPublicKeyInfo spki, AlgorithmEntry entry)
            throws InvalidKeyException {
        ASN1ObjectIdentifier actual = spki.getAlgorithm().getAlgorithm();
        if (!entry.oid().equals(actual)) {
            throw new InvalidKeyException("The token reports this key as OID " + actual.getId()
                    + " but it was resolved as " + entry.canonicalName() + " (OID "
                    + entry.oid().getId() + "). Refusing to guess which is right.");
        }
    }

    /** True if the bytes parse as a DER SEQUENCE, i.e. are already a SubjectPublicKeyInfo. */
    private static boolean looksLikeSpki(byte[] b) {
        if (b.length <= 2 || b[0] != 0x30) {
            return false;
        }
        try {
            SubjectPublicKeyInfo.getInstance(b);
            return true;
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("CKA_VALUE starts as a SEQUENCE but is not a SubjectPublicKeyInfo; "
                        + "treating it as raw key material: " + e.getMessage());
            }
            return false;
        }
    }
}

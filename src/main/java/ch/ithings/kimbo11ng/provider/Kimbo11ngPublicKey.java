/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

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
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Utility class for constructing PublicKey objects from PKCS#11 object attributes.
 */
public class Kimbo11ngPublicKey {

    private static final Logger log = Logger.getLogger(Kimbo11ngPublicKey.class);

    // NIST PQC OIDs (PKCS#11 v3.2 / NIST FIPS)
    // ML-DSA (FIPS 204)
    private static final ASN1ObjectIdentifier OID_ML_DSA_44 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.17");
    private static final ASN1ObjectIdentifier OID_ML_DSA_65 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.18");
    private static final ASN1ObjectIdentifier OID_ML_DSA_87 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.19");
    // ML-KEM (FIPS 203)
    private static final ASN1ObjectIdentifier OID_ML_KEM_512  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.4.1");
    private static final ASN1ObjectIdentifier OID_ML_KEM_768  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.4.2");
    private static final ASN1ObjectIdentifier OID_ML_KEM_1024 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.4.3");
    // SLH-DSA (FIPS 205) — OIDs per NIST: SHA2 group (.20-.25), SHAKE group (.26-.31)
    private static final ASN1ObjectIdentifier OID_SLH_DSA_SHA2_128S  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.20");
    private static final ASN1ObjectIdentifier OID_SLH_DSA_SHA2_128F  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.21");
    private static final ASN1ObjectIdentifier OID_SLH_DSA_SHA2_192S  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.22");
    private static final ASN1ObjectIdentifier OID_SLH_DSA_SHA2_192F  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.23");
    private static final ASN1ObjectIdentifier OID_SLH_DSA_SHA2_256S  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.24");
    private static final ASN1ObjectIdentifier OID_SLH_DSA_SHA2_256F  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.25");
    private static final ASN1ObjectIdentifier OID_SLH_DSA_SHAKE_128S = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.26");
    private static final ASN1ObjectIdentifier OID_SLH_DSA_SHAKE_128F = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.27");
    private static final ASN1ObjectIdentifier OID_SLH_DSA_SHAKE_192S = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.28");
    private static final ASN1ObjectIdentifier OID_SLH_DSA_SHAKE_192F = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.29");
    private static final ASN1ObjectIdentifier OID_SLH_DSA_SHAKE_256S = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.30");
    private static final ASN1ObjectIdentifier OID_SLH_DSA_SHAKE_256F = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.31");

    private Kimbo11ngPublicKey() {
    }

    /**
     * Read an RSA public key from a PKCS#11 object handle.
     */
    public static PublicKey readRsaPublicKey(CryptokiE ce, long session, long handle)
            throws Exception {
        CKA[] attrs = ce.GetAttributeValue(session, handle, CKA.MODULUS, CKA.PUBLIC_EXPONENT);
        byte[] modBytes = attrs[0].getValue();
        byte[] expBytes = attrs[1].getValue();

        BigInteger modulus = new BigInteger(1, modBytes);
        BigInteger publicExponent = new BigInteger(1, expBytes);

        KeyFactory kf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
    }

    /**
     * Read an EC public key from a PKCS#11 object handle.
     * CKA_EC_PARAMS contains DER-encoded OID.
     * CKA_EC_POINT contains DER-encoded uncompressed point (04 || X || Y).
     */
    public static PublicKey readEcPublicKey(CryptokiE ce, long session, long handle)
            throws Exception {
        CKA[] attrs = ce.GetAttributeValue(session, handle, CKA.EC_PARAMS, CKA.EC_POINT);
        byte[] ecParamsBytes = attrs[0].getValue();
        byte[] ecPointBytes = attrs[1].getValue();

        // Parse OID from DER-encoded EC_PARAMS
        ASN1ObjectIdentifier oid;
        try (ASN1InputStream ais = new ASN1InputStream(ecParamsBytes)) {
            oid = (ASN1ObjectIdentifier) ais.readObject();
        }

        // Get named curve parameters
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(oid.getId());
        if (spec == null) {
            throw new IllegalArgumentException("Unknown EC curve OID: " + oid.getId());
        }

        // EC_POINT may be wrapped in an OCTET STRING (DER encoding per PKCS#11 spec)
        byte[] pointBytes = ecPointBytes;
        if (ecPointBytes.length > 0 && ecPointBytes[0] == 0x04 &&
                ecPointBytes[1] != 0x04) {
            // Might be wrapped in DER OCTET STRING - try to unwrap
            try (ASN1InputStream ais = new ASN1InputStream(ecPointBytes)) {
                ASN1Encodable obj = ais.readObject();
                if (obj instanceof DEROctetString) {
                    pointBytes = ((DEROctetString) obj).getOctets();
                } else if (obj instanceof ASN1OctetString) {
                    pointBytes = ((ASN1OctetString) obj).getOctets();
                }
            } catch (Exception e) {
                // Not wrapped, use as-is
                pointBytes = ecPointBytes;
            }
        }

        // Decode the EC point
        ECPoint point = spec.getCurve().decodePoint(pointBytes);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, spec);

        KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePublic(pubSpec);
    }

    /**
     * Read a PQC public key (ML-DSA, ML-KEM) from a PKCS#11 object handle.
     * CKA_VALUE holds raw key bytes; we wrap them in SubjectPublicKeyInfo using the
     * correct NIST OID derived from CKA_PARAMETER_SET so EJBCA's KeyTools can hash them.
     *
     * @param keySpec human-readable spec string like "ML-DSA-65" or "ML-KEM" (for enumeration path)
     */
    public static PublicKey readPqcPublicKey(CryptokiE ce, long session, long handle,
            String keySpec) throws Exception {
        CKA valueAttr = ce.GetAttributeValue(session, handle, CKA.VALUE);
        byte[] keyBytes = valueAttr.getValue();
        if (keyBytes == null || keyBytes.length == 0) {
            throw new IllegalStateException("CKA_VALUE is empty for PQC public key handle " + handle);
        }

        if (log.isDebugEnabled()) {
            log.debug("readPqcPublicKey: keySpec=" + keySpec + " handle=" + handle +
                    " valueLen=" + keyBytes.length + " firstByte=0x" + String.format("%02X", keyBytes[0]));
        }

        // Try X509-encoded first — OpenSSL 3.6 may already produce SubjectPublicKeyInfo
        if (isSpki(keyBytes)) {
            try {
                SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(keyBytes);
                ASN1ObjectIdentifier spkiOid = spki.getAlgorithm().getAlgorithm();
                String jcaAlg = spkiAlgorithm(spkiOid);
                if (log.isDebugEnabled()) {
                    log.debug("readPqcPublicKey: SPKI detected, OID=" + spkiOid.getId() + " jcaAlg=" + jcaAlg);
                }
                if (jcaAlg != null) {
                    KeyFactory kf = KeyFactory.getInstance(jcaAlg, BouncyCastleProvider.PROVIDER_NAME);
                    return kf.generatePublic(new X509EncodedKeySpec(keyBytes));
                }
                // Unknown OID but valid SPKI — return opaque wrapper
                return new RawPqcPublicKey(keySpec, keyBytes);
            } catch (Exception e) {
                log.debug("SPKI parse/KeyFactory failed for " + keySpec + ": " + e.getMessage());
            }
        }

        // Raw bytes: determine OID from CKA_PARAMETER_SET + algorithm family
        long paramSet = 0L;
        try {
            CKA psAttr = ce.GetAttributeValue(session, handle, 0x0000061DL); // CKA_PARAMETER_SET
            Long psVal = psAttr.getValueLong();
            if (psVal != null) paramSet = psVal;
        } catch (Exception e) {
            log.debug("Could not read CKA_PARAMETER_SET: " + e.getMessage());
        }

        String normalized = keySpec.toUpperCase().replace("-", "").replace("_", "");
        ASN1ObjectIdentifier oid;
        String jcaAlg;
        if (normalized.startsWith("MLDSA")) {
            jcaAlg = "ML-DSA";
            if (paramSet == 1L)      oid = OID_ML_DSA_44;
            else if (paramSet == 3L) oid = OID_ML_DSA_87;
            else                     oid = OID_ML_DSA_65; // default / paramSet==2
        } else if (normalized.startsWith("MLKEM")) {
            jcaAlg = "ML-KEM";
            if (paramSet == 1L)      oid = OID_ML_KEM_512;
            else if (paramSet == 3L) oid = OID_ML_KEM_1024;
            else                     oid = OID_ML_KEM_768; // default / paramSet==2
        } else if (normalized.startsWith("SLHDSA")) {
            jcaAlg = "SLH-DSA";
            // CKP_SLH_DSA values (1-12) from pkcs11t.h → NIST OIDs
            if (paramSet == 1L)       oid = OID_SLH_DSA_SHA2_128S;   // CKP_SLH_DSA_SHA2_128S
            else if (paramSet == 2L)  oid = OID_SLH_DSA_SHAKE_128S;  // CKP_SLH_DSA_SHAKE_128S
            else if (paramSet == 3L)  oid = OID_SLH_DSA_SHA2_128F;   // CKP_SLH_DSA_SHA2_128F
            else if (paramSet == 4L)  oid = OID_SLH_DSA_SHAKE_128F;  // CKP_SLH_DSA_SHAKE_128F
            else if (paramSet == 5L)  oid = OID_SLH_DSA_SHA2_192S;   // CKP_SLH_DSA_SHA2_192S
            else if (paramSet == 6L)  oid = OID_SLH_DSA_SHAKE_192S;  // CKP_SLH_DSA_SHAKE_192S
            else if (paramSet == 7L)  oid = OID_SLH_DSA_SHA2_192F;   // CKP_SLH_DSA_SHA2_192F
            else if (paramSet == 8L)  oid = OID_SLH_DSA_SHAKE_192F;  // CKP_SLH_DSA_SHAKE_192F
            else if (paramSet == 9L)  oid = OID_SLH_DSA_SHA2_256S;   // CKP_SLH_DSA_SHA2_256S
            else if (paramSet == 10L) oid = OID_SLH_DSA_SHAKE_256S;  // CKP_SLH_DSA_SHAKE_256S
            else if (paramSet == 11L) oid = OID_SLH_DSA_SHA2_256F;   // CKP_SLH_DSA_SHA2_256F
            else if (paramSet == 12L) oid = OID_SLH_DSA_SHAKE_256F;  // CKP_SLH_DSA_SHAKE_256F
            else                      oid = OID_SLH_DSA_SHA2_128S;   // default
        } else {
            return new RawPqcPublicKey(keySpec, keyBytes);
        }

        // Wrap raw bytes into SubjectPublicKeyInfo
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(oid), keyBytes);
        byte[] spkiBytes = spki.getEncoded();

        try {
            KeyFactory kf = KeyFactory.getInstance(jcaAlg, BouncyCastleProvider.PROVIDER_NAME);
            return kf.generatePublic(new X509EncodedKeySpec(spkiBytes));
        } catch (Exception e) {
            log.debug("KeyFactory for " + jcaAlg + " unavailable, using opaque key: " + e.getMessage());
            return new RawPqcPublicKey(keySpec, spkiBytes);
        }
    }

    /** True if bytes look like a DER SEQUENCE (SubjectPublicKeyInfo). */
    private static boolean isSpki(byte[] b) {
        return b != null && b.length > 2 && b[0] == 0x30;
    }

    /** Map known PQC OIDs to JCA algorithm names. */
    private static String spkiAlgorithm(ASN1ObjectIdentifier oid) {
        String id = oid.getId();
        if (id.startsWith("2.16.840.1.101.3.4.4."))  return "ML-KEM";  // .1/.2/.3
        // Under 2.16.840.1.101.3.4.3: ML-DSA=.17-.19, SLH-DSA=.20-.31
        if (id.startsWith("2.16.840.1.101.3.4.3.")) {
            String suffix = id.substring("2.16.840.1.101.3.4.3.".length());
            try {
                int n = Integer.parseInt(suffix);
                if (n >= 17 && n <= 19) return "ML-DSA";
                if (n >= 20 && n <= 31) return "SLH-DSA";
            } catch (NumberFormatException e) { /* fall through */ }
        }
        return null;
    }

    /**
     * Opaque wrapper for PQC public keys when the JCA provider doesn't support the algorithm.
     * {@code encoded} is always SubjectPublicKeyInfo-format so EJBCA can hash it for SubjectKeyId.
     */
    public static final class RawPqcPublicKey implements PublicKey {
        private static final long serialVersionUID = 1L;

        private final String keySpec;
        private final byte[] encoded;

        public RawPqcPublicKey(String keySpec, byte[] encoded) {
            this.keySpec = keySpec;
            this.encoded = encoded;
        }

        @Override public String getAlgorithm() {
            String n = keySpec.toUpperCase().replace("-","").replace("_","");
            if (n.startsWith("MLDSA"))  return "ML-DSA";
            if (n.startsWith("MLKEM"))  return "ML-KEM";
            if (n.startsWith("SLHDSA")) return "SLH-DSA";
            return keySpec;
        }
        @Override public String getFormat() { return "X.509"; }
        @Override public byte[] getEncoded() { return encoded; }
        @Override public String toString() { return getAlgorithm() + "/" + keySpec + "[" + encoded.length + " bytes]"; }
    }
}

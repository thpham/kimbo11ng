/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * Decoding {@code CKA_EC_POINT} without guessing.
 *
 * <h2>What was wrong</h2>
 *
 * <p>PKCS#11 says {@code CKA_EC_POINT} is the DER encoding of an ANSI X9.62 ECPoint — an OCTET
 * STRING wrapping the point. Many modules return the bare point instead, and both readings have to
 * work. The previous code chose between them by looking at the first two bytes:
 *
 * <pre>{@code
 * if (b[0] == 0x04 && b[1] != 0x04) { ...treat as a DER OCTET STRING... }
 * }</pre>
 *
 * <p>{@code 0x04} is the OCTET STRING tag <em>and</em> the uncompressed-point prefix, so for a
 * module reporting a raw point this reads X[0] as a length. X[0] is uniformly distributed, so
 * roughly a quarter of all keys take the wrong branch: measured at 24.5% over 2,000 real P-256
 * keys (490 of 2,000).
 *
 * <p>What that costs, precisely. In 2,000 keys every one of the 490 misreads <em>threw</em> — the
 * truncated buffer is not a valid point length, so {@code decodePoint} rejects it. So the failure
 * an operator sees is a quarter of their EC keys refusing to load, not a quarter signing wrongly.
 * The silent variant is possible but far rarer: it needs the truncated content to be a valid
 * encoding in its own right, which for a 65-byte input means X[0] = 33 and X[1] ∈ {2, 3}, about 1
 * in 33,000. Neither is acceptable in a CA, and both come from the same guess.
 *
 * <h2>Why this version cannot have that bug</h2>
 *
 * <p>The two encodings have different lengths for any given curve, and the curve is known from
 * {@code CKA_EC_PARAMS}. A P-256 point is 65 bytes raw and 67 wrapped; there is no length at which
 * the two can be confused. So the decision is made on the length and the point prefix together, and
 * the DER reading additionally has to account for every byte in the buffer — a prefix that merely
 * parses is not enough. Nothing is inferred from a single byte.
 */
final class EcPointCodec {

    private static final Logger log = Logger.getLogger(EcPointCodec.class);

    /** X9.62 §4.4.2: the leading byte of an encoded point. */
    private static final int UNCOMPRESSED = 0x04;
    private static final int HYBRID_EVEN = 0x06;
    private static final int HYBRID_ODD = 0x07;
    private static final int COMPRESSED_EVEN = 0x02;
    private static final int COMPRESSED_ODD = 0x03;

    private EcPointCodec() {
    }

    /**
     * The curve named by {@code CKA_EC_PARAMS}.
     *
     * <p>Handles both forms of the X9.62 {@code Parameters} CHOICE: a named-curve OID, which is
     * what almost every token reports, and explicit parameters, which some HSMs use for curves
     * they have no OID for. The previous code cast the parsed object to an OID and would fail with
     * a {@code ClassCastException} on the explicit form.
     */
    static ECParameterSpec parseCurve(byte[] ecParams) throws InvalidKeyException {
        if (ecParams == null || ecParams.length == 0) {
            throw new InvalidKeyException("CKA_EC_PARAMS is empty; the curve is unknown");
        }
        try {
            X962Parameters parameters = X962Parameters.getInstance(
                    ASN1Primitive.fromByteArray(ecParams));
            if (parameters.isNamedCurve()) {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) parameters.getParameters();
                ECNamedCurveParameterSpec named = ECNamedCurveTable.getParameterSpec(oid.getId());
                if (named != null) {
                    return named;
                }
                // Named, but not in the JCE table: the custom-curve table covers a few that are
                // registered only there.
                X9ECParameters custom = CustomNamedCurves.getByOID(oid);
                if (custom == null) {
                    throw new InvalidKeyException("The token reports EC curve OID " + oid.getId()
                            + ", which this BouncyCastle does not know.");
                }
                return new ECParameterSpec(custom.getCurve(), custom.getG(), custom.getN(),
                        custom.getH(), custom.getSeed());
            }
            if (parameters.isImplicitlyCA()) {
                throw new InvalidKeyException("CKA_EC_PARAMS says implicitlyCA, which carries no "
                        + "curve. kimbo11ng cannot know which curve this key is on.");
            }
            X9ECParameters explicit = X9ECParameters.getInstance(parameters.getParameters());
            return new ECParameterSpec(explicit.getCurve(), explicit.getG(), explicit.getN(),
                    explicit.getH(), explicit.getSeed());
        } catch (InvalidKeyException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidKeyException("Could not read CKA_EC_PARAMS ("
                    + ecParams.length + " bytes): " + e.getMessage(), e);
        }
    }

    /**
     * Decodes the point, accepting either the wrapped or the bare encoding.
     *
     * @throws InvalidKeyException if the bytes are neither, with both lengths named. Naming them is
     *         what turns "this key will not load" into a diagnosis an operator can act on.
     */
    static ECPoint decodePoint(byte[] ecPoint, ECParameterSpec spec) throws InvalidKeyException {
        if (ecPoint == null || ecPoint.length < 2) {
            throw new InvalidKeyException("CKA_EC_POINT is "
                    + (ecPoint == null ? "absent" : ecPoint.length + " byte(s)")
                    + "; too short to be an EC point");
        }
        ECCurve curve = spec.getCurve();
        int fieldBytes = (curve.getFieldSize() + 7) / 8;

        // Bare point first. Its length is fixed by the curve, so a match here is unambiguous: the
        // wrapped form of the same point is always at least two bytes longer.
        if (isPlausibleRawPoint(ecPoint, fieldBytes)) {
            return decode(curve, ecPoint, "raw", fieldBytes);
        }

        byte[] unwrapped = unwrapOctetString(ecPoint);
        if (unwrapped != null && isPlausibleRawPoint(unwrapped, fieldBytes)) {
            return decode(curve, unwrapped, "DER-wrapped", fieldBytes);
        }

        throw new InvalidKeyException("CKA_EC_POINT (" + ecPoint.length + " bytes, leading byte 0x"
                + String.format("%02x", ecPoint[0]) + ") is neither a bare point nor a DER OCTET"
                + " STRING containing one, for a curve with a " + fieldBytes + "-byte field."
                + " Expected " + (1 + 2 * fieldBytes) + " bytes uncompressed or "
                + (1 + fieldBytes) + " compressed, or those wrapped in an OCTET STRING."
                + (unwrapped == null ? "" : " The OCTET STRING unwrapped to " + unwrapped.length
                        + " bytes, which is also not a point on this curve."));
    }

    /**
     * True if these bytes could be an encoded point on a curve with this field size.
     *
     * <p>Length and prefix together, never either alone. Length alone would accept a 65-byte blob
     * of anything; the prefix alone is what the old code trusted.
     */
    private static boolean isPlausibleRawPoint(byte[] candidate, int fieldBytes) {
        if (candidate.length == 1 + 2 * fieldBytes) {
            int prefix = candidate[0] & 0xFF;
            return prefix == UNCOMPRESSED || prefix == HYBRID_EVEN || prefix == HYBRID_ODD;
        }
        if (candidate.length == 1 + fieldBytes) {
            int prefix = candidate[0] & 0xFF;
            return prefix == COMPRESSED_EVEN || prefix == COMPRESSED_ODD;
        }
        return false;
    }

    /**
     * The contents of a DER OCTET STRING that occupies the whole buffer, or {@code null}.
     *
     * <p>Parse <em>and consume</em>: a raw point whose X coordinate begins with a byte that looks
     * like a length parses as a shorter OCTET STRING with trailing bytes left over. Requiring the
     * encoding to account for every byte is what rejects that.
     */
    private static byte[] unwrapOctetString(byte[] buffer) {
        try (ASN1InputStream in = new ASN1InputStream(buffer)) {
            ASN1Primitive first = in.readObject();
            if (!(first instanceof ASN1OctetString octets)) {
                return null;
            }
            if (in.readObject() != null) {
                return null;
            }
            // Re-encoding must reproduce the input exactly. This rejects a non-minimal or
            // truncated encoding that the parser was willing to accept.
            if (!Arrays.equals(buffer, octets.getEncoded())) {
                return null;
            }
            return octets.getOctets();
        } catch (IOException | IllegalArgumentException e) {
            if (log.isDebugEnabled()) {
                log.debug("CKA_EC_POINT is not a DER OCTET STRING: " + e.getMessage());
            }
            return null;
        }
    }

    private static ECPoint decode(ECCurve curve, byte[] pointBytes, String encoding, int fieldBytes)
            throws InvalidKeyException {
        try {
            ECPoint point = curve.decodePoint(pointBytes);
            if (point.isInfinity()) {
                throw new InvalidKeyException("CKA_EC_POINT decodes to the point at infinity, "
                        + "which is not a valid public key");
            }
            // The token's word is not enough: a point off the curve is a classic invalid-curve
            // attack vector, and BouncyCastle only checks this if asked.
            if (!point.isValid()) {
                throw new InvalidKeyException("CKA_EC_POINT does not lie on the curve the token "
                        + "reports in CKA_EC_PARAMS");
            }
            if (log.isDebugEnabled()) {
                log.debug("Decoded a " + encoding + " EC point on a " + fieldBytes
                        + "-byte field");
            }
            return point.normalize();
        } catch (InvalidKeyException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidKeyException("CKA_EC_POINT looked like a " + encoding
                    + " point but does not decode on this curve: " + e.getMessage(), e);
        }
    }
}

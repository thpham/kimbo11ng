/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.KemUsage;
import ch.ithings.kimbo11ng.p11.Pkcs11v32;
import ch.ithings.kimbo11ng.profile.PqcMechanismProfile;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKO;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Builds the {@code CKA} templates for key-pair generation.
 *
 * <p>One place, because these templates were previously copied verbatim between
 * {@code CryptoTokenImpl} and {@code Kimbo11ngKeyPairGeneratorSpi} and had already drifted — the
 * EC public template set {@code CKA_ENCRYPT} in one copy and not the other.
 *
 * <p>Every private key is generated {@code CKA_SENSITIVE} and not {@code CKA_EXTRACTABLE}: key
 * material must not leave the token, and EJBCA independently refuses to use a key it can extract.
 */
public final class KeyTemplates {

    /** Bytes of {@code CKA_ID}. Random rather than derived, so no second call is needed. */
    private static final int KEY_ID_BYTES = 16;

    private static final SecureRandom RANDOM = new SecureRandom();

    private KeyTemplates() {
    }

    /**
     * A fresh {@code CKA_ID}, placed in both halves of a key pair at generation time.
     *
     * <p>Random rather than a hash of the public key: the public key is not known until after
     * generation, and setting the id afterwards needs {@code C_SetAttributeValue}, which some HSM
     * policies refuse on token objects.
     */
    public static byte[] newKeyId() {
        byte[] id = new byte[KEY_ID_BYTES];
        RANDOM.nextBytes(id);
        return id;
    }

    /** Templates for an RSA key pair of {@code modulusBits}. */
    public static Pair rsa(byte[] label, byte[] keyId, int modulusBits) {
        List<CKA> pub = new ArrayList<>(List.of(
                new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
                new CKA(CKA.KEY_TYPE, CKK.RSA),
                new CKA(CKA.LABEL, label),
                new CKA(CKA.ID, keyId),
                new CKA(CKA.MODULUS_BITS, (long) modulusBits),
                new CKA(CKA.PUBLIC_EXPONENT, BigInteger.valueOf(65537).toByteArray()),
                new CKA(CKA.TOKEN, true),
                new CKA(CKA.VERIFY, true),
                new CKA(CKA.ENCRYPT, true),
                new CKA(CKA.WRAP, true)));
        List<CKA> priv = new ArrayList<>(privateBase(label, keyId, CKK.RSA));
        priv.add(new CKA(CKA.DECRYPT, true));
        priv.add(new CKA(CKA.UNWRAP, true));
        return new Pair(pub, priv);
    }

    /** Templates for an EC key pair on the named curve. */
    public static Pair ec(byte[] label, byte[] keyId, String curveName) throws IOException {
        byte[] ecParams = encodeCurve(curveName);
        List<CKA> pub = new ArrayList<>(List.of(
                new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
                new CKA(CKA.KEY_TYPE, CKK.EC),
                new CKA(CKA.LABEL, label),
                new CKA(CKA.ID, keyId),
                new CKA(CKA.EC_PARAMS, ecParams),
                new CKA(CKA.TOKEN, true),
                new CKA(CKA.VERIFY, true)));
        // No CKA_EC_PARAMS on the private template. It is tempting — it would let the curve be
        // recovered without the public object — but for CKM_EC_KEY_PAIR_GEN the curve is an input
        // to the public template only, and the token derives the private key's copy. Supplying it
        // is an attempt to set a read-only attribute: SoftHSMv3 answers CKR_ATTRIBUTE_READ_ONLY
        // and the whole generation fails.
        List<CKA> priv = new ArrayList<>(privateBase(label, keyId, CKK.EC));
        return new Pair(pub, priv);
    }

    /**
     * Templates for a post-quantum key pair described by {@code entry}, with the default KEM
     * spelling.
     *
     * <p>Kept so that the many callers which do not configure a token — tests, and the CLI's
     * capability table — need not thread a setting they have no opinion about. The one production
     * caller passes the token's own, resolved from the profile and the property.
     */
    public static Pair pqc(byte[] label, byte[] keyId, AlgorithmEntry entry,
            PqcMechanismProfile profile) {
        return pqc(label, keyId, entry, profile, profile.defaultKemUsage());
    }

    /**
     * Templates for a post-quantum key pair described by {@code entry}.
     *
     * <p>The ML-KEM branch now also asks for {@code CKA_ENCAPSULATE} and {@code CKA_DECAPSULATE},
     * the attributes PKCS#11 v3.2 defines for a key-encapsulation key. It previously asked only
     * for {@code CKA_ENCRYPT} and {@code CKA_DECRYPT}, which is a different claim: those gate
     * {@code C_Encrypt} and {@code C_Decrypt}, operations ML-KEM does not have. That went
     * unnoticed because SoftHSMv3 is permissive — measured on 2026-09-05, a key generated the old
     * way came back carrying 0x633 and 0x634 anyway, the token having set the correct pair itself.
     *
     * <p>Both pairs rather than a clean swap, and the reason is EJBCA rather than PKCS#11: it
     * reads {@code CKA_DECRYPT} by number and knows nothing of 0x634. {@link KemUsage} says which
     * consumer each pair serves and what is lost by dropping either.
     *
     * @param kemUsage which spelling to send; the profile chooses and
     *     {@link KemUsage#PROPERTY} overrides
     */
    public static Pair pqc(byte[] label, byte[] keyId, AlgorithmEntry entry,
            PqcMechanismProfile profile, KemUsage kemUsage) {
        List<CKA> pub = new ArrayList<>(List.of(
                new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
                new CKA(CKA.KEY_TYPE, entry.ckkKeyType()),
                new CKA(CKA.LABEL, label),
                new CKA(CKA.ID, keyId),
                new CKA(CKA.TOKEN, true)));
        List<CKA> priv = new ArrayList<>(privateBase(label, keyId, entry.ckkKeyType()));

        // Absent for a vendor that distinguishes parameter sets by mechanism instead; sending the
        // attribute anyway would be rejected as an unknown template item.
        entry.ckpParameterSet().ifPresent(ckp -> {
            pub.add(new CKA(profile.ckaParameterSet(), ckp));
            priv.add(new CKA(profile.ckaParameterSet(), ckp));
        });

        if (entry.canSign()) {
            pub.add(new CKA(CKA.VERIFY, true));
            priv.add(new CKA(CKA.SIGN, true));
        } else {
            // Encapsulation is a public-key operation, decapsulation a private-key one.
            if (kemUsage.sendsV32()) {
                pub.add(new CKA(Pkcs11v32.CKA_ENCAPSULATE, true));
                priv.add(new CKA(Pkcs11v32.CKA_DECAPSULATE, true));
            }
            if (kemUsage.sendsEncryption()) {
                pub.add(new CKA(CKA.ENCRYPT, true));
                priv.add(new CKA(CKA.DECRYPT, true));
            }
        }
        return new Pair(pub, priv);
    }

    /**
     * Template for a single secret key.
     *
     * <p>{@code CKA_PRIVATE} as well as {@code CKA_SENSITIVE}: a secret key readable without a
     * login is a secret key on a shared partition that anyone with a session can enumerate. The
     * asymmetric templates above set both for the same reason.
     *
     * <p>The usage attributes follow the key type rather than the caller's request. A generic
     * secret exists here to be an HMAC key, which PKCS#11 models as signing; an AES key exists to
     * encrypt and to wrap. Marking a key for everything would be simpler and would defeat
     * {@code CKA_*}-based policy on an HSM that enforces it.
     *
     * @param valueBits the key length, already validated by {@link SecretKeyType#validateBits(int)}
     */
    public static List<CKA> secret(byte[] label, byte[] keyId, SecretKeyType type, int valueBits) {
        List<CKA> template = new ArrayList<>(List.of(
                new CKA(CKA.CLASS, CKO.SECRET_KEY),
                new CKA(CKA.KEY_TYPE, type.ckk()),
                new CKA(CKA.LABEL, label),
                new CKA(CKA.ID, keyId),
                new CKA(CKA.VALUE_LEN, (long) (valueBits / 8)),
                new CKA(CKA.TOKEN, true),
                new CKA(CKA.PRIVATE, true),
                new CKA(CKA.SENSITIVE, true),
                new CKA(CKA.EXTRACTABLE, false)));
        if (type.isMac()) {
            template.add(new CKA(CKA.SIGN, true));
            template.add(new CKA(CKA.VERIFY, true));
        } else {
            template.add(new CKA(CKA.ENCRYPT, true));
            template.add(new CKA(CKA.DECRYPT, true));
            template.add(new CKA(CKA.WRAP, true));
            template.add(new CKA(CKA.UNWRAP, true));
        }
        return template;
    }

    private static List<CKA> privateBase(byte[] label, byte[] keyId, long keyType) {
        List<CKA> priv = new ArrayList<>(List.of(
                new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
                new CKA(CKA.KEY_TYPE, keyType),
                new CKA(CKA.LABEL, label),
                new CKA(CKA.ID, keyId),
                new CKA(CKA.TOKEN, true),
                new CKA(CKA.PRIVATE, true),
                new CKA(CKA.SENSITIVE, true),
                new CKA(CKA.EXTRACTABLE, false)));
        if (keyType != CKK.RSA && keyType != CKK.EC) {
            return priv;
        }
        priv.add(new CKA(CKA.SIGN, true));
        return priv;
    }

    /** DER-encoded OID for a curve name, accepting NIST, SEC and Brainpool spellings. */
    public static byte[] encodeCurve(String curveName) throws IOException {
        return new ASN1ObjectIdentifier(resolveCurveOid(curveName)).getEncoded();
    }

    /**
     * True if {@link #resolveCurveOid} can turn this name into an OID.
     *
     * <p>Worth asking before generating rather than after: {@code resolveCurveOid} hands back an
     * unrecognised name unchanged, so the failure otherwise happens inside
     * {@code new ASN1ObjectIdentifier(...)} as an {@code IllegalArgumentException} reading
     * "string not-a-curve not an OID" — accurate about the byte it choked on and silent about the
     * curve name the caller supplied.
     */
    public static boolean isKnownCurve(String curveName) {
        return curveName != null
                && ASN1ObjectIdentifier.tryFromID(resolveCurveOid(curveName)) != null;
    }

    /**
     * Curve name to OID. The explicit cases cover the spellings EJBCA emits that BouncyCastle's
     * table does not answer to; anything else is looked up, then accepted as an OID literal.
     */
    public static String resolveCurveOid(String name) {
        switch (name.toUpperCase(Locale.ROOT).replace("-", "").replace("_", "")) {
            case "P256": case "SECP256R1": case "PRIME256V1": return "1.2.840.10045.3.1.7";
            case "P384": case "SECP384R1": return "1.3.132.0.34";
            case "P521": case "SECP521R1": return "1.3.132.0.35";
            case "SECP256K1": return "1.3.132.0.10";
            case "BRAINPOOLP256R1": return "1.3.36.3.3.2.8.1.1.7";
            case "BRAINPOOLP384R1": return "1.3.36.3.3.2.8.1.1.11";
            case "BRAINPOOLP512R1": return "1.3.36.3.3.2.8.1.1.13";
            default:
                ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID(name);
                return oid != null ? oid.getId() : name;
        }
    }

    /** A public and private template pair. */
    public record Pair(List<CKA> publicTemplate, List<CKA> privateTemplate) {

        public Pair {
            publicTemplate = List.copyOf(publicTemplate);
            privateTemplate = List.copyOf(privateTemplate);
        }

        public CKA[] pub() {
            return publicTemplate.toArray(new CKA[0]);
        }

        public CKA[] priv() {
            return privateTemplate.toArray(new CKA[0]);
        }
    }
}

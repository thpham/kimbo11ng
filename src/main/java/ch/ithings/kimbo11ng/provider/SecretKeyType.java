/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * The secret-key algorithms this provider can create on a token.
 *
 * <p>Small and closed on purpose. A symmetric key is only worth putting on an HSM if the token can
 * also <em>use</em> it, and each row here names the one operation this provider implements for it:
 * {@link #ckmOperation()} is the mechanism a {@code Mac} or a {@code Cipher} would init with. A row
 * whose operation this provider does not implement would be a key nothing can consume.
 *
 * <h2>Why the HMAC rows are CKK_GENERIC_SECRET and not CKK_AES</h2>
 *
 * <p>PKCS#11 treats HMAC as a signing operation over a generic secret. A {@code CKK_AES} object is
 * not one, even when its template asks for {@code CKA_SIGN}: SoftHSMv3 accepts the generation and
 * then answers {@code CKR_KEY_TYPE_INCONSISTENT} (0x63) to {@code C_SignInit} with
 * {@code CKM_SHA256_HMAC} — measured, not assumed. A database-protection key generated as AES would
 * therefore pass generation and fail on first use. The key type follows the intended operation, not
 * the caller's spelling.
 *
 * @param jcaName the JCA algorithm name, which is what {@code KeyGenerator.getInstance} asks for
 * @param ckk the {@code CKK_*} key type written into the template
 * @param ckmKeyGen the {@code CKM_*} generation mechanism, gated by {@code CKF_GENERATE}
 * @param ckmOperation the {@code CKM_*} mechanism the key is used with, gated by {@code CKF_SIGN}
 * @param defaultBits the key length used when the caller does not name one
 */
public record SecretKeyType(String jcaName, long ckk, long ckmKeyGen, long ckmOperation,
        int defaultBits) {

    /**
     * AES, and the three HMAC sizes EJBCA's database protection can be configured with.
     *
     * <p>AES is here even though this provider offers no {@code Cipher}: it is the spelling EJBCA's
     * own {@code PKCS11CryptoToken} path uses, and refusing it at generation with a message that
     * names the missing {@code Cipher} is more useful than not recognising the algorithm at all.
     * See {@link #usableHere()}.
     */
    private static final List<SecretKeyType> TYPES = List.of(
            new SecretKeyType("AES", CKK.AES, CKM.AES_KEY_GEN, CKM.AES_CBC_PAD, 256),
            new SecretKeyType("HmacSHA256", CKK.GENERIC_SECRET, CKM.GENERIC_SECRET_KEY_GEN,
                    CKM.SHA256_HMAC, 256),
            new SecretKeyType("HmacSHA384", CKK.GENERIC_SECRET, CKM.GENERIC_SECRET_KEY_GEN,
                    CKM.SHA384_HMAC, 384),
            new SecretKeyType("HmacSHA512", CKK.GENERIC_SECRET, CKM.GENERIC_SECRET_KEY_GEN,
                    CKM.SHA512_HMAC, 512));

    /** Every algorithm in the table, in declaration order. */
    public static List<SecretKeyType> all() {
        return TYPES;
    }

    /** The row for a JCA algorithm name, case-insensitively; empty if there is none. */
    public static Optional<SecretKeyType> lookup(String jcaName) {
        if (jcaName == null) {
            return Optional.empty();
        }
        String wanted = jcaName.trim().toLowerCase(Locale.ROOT);
        return TYPES.stream()
                .filter(t -> t.jcaName().toLowerCase(Locale.ROOT).equals(wanted))
                .findFirst();
    }

    /** The names this table knows, for a message that has to list them. */
    public static List<String> names() {
        return TYPES.stream().map(SecretKeyType::jcaName).toList();
    }

    /** True for a key type whose operation this provider actually implements — HMAC only. */
    public boolean usableHere() {
        return ckk == CKK.GENERIC_SECRET;
    }

    /** True if this row is one of the HMAC sizes. */
    public boolean isMac() {
        return usableHere();
    }

    /**
     * The MAC length in bytes, which for the HMAC rows is the digest length.
     *
     * <p>{@code defaultBits} is the digest length for exactly that reason: an HMAC key shorter than
     * its own output buys nothing.
     */
    public int macLengthBytes() {
        if (!isMac()) {
            throw new IllegalStateException(jcaName + " is not a MAC algorithm");
        }
        return defaultBits / 8;
    }

    /**
     * Refuses a key length the algorithm cannot take.
     *
     * <p>PKCS#11 would answer {@code CKR_ATTRIBUTE_VALUE_INVALID} from inside {@code C_GenerateKey},
     * naming neither the attribute nor the value; this says which lengths exist.
     *
     * @param bits the requested length, or 0 to accept {@link #defaultBits()}
     * @return the length to put in {@code CKA_VALUE_LEN}, in bits
     */
    public int validateBits(int bits) {
        if (bits <= 0) {
            return defaultBits;
        }
        if (bits % 8 != 0) {
            throw new IllegalArgumentException(jcaName + " key length must be a whole number of"
                    + " bytes; " + bits + " bits is not.");
        }
        if (ckk == CKK.AES && bits != 128 && bits != 192 && bits != 256) {
            throw new IllegalArgumentException("AES keys are 128, 192 or 256 bits; " + bits
                    + " was requested.");
        }
        // A generic secret has no fixed size, but an HMAC key shorter than its digest weakens the
        // MAC without any error anywhere, so the floor is the digest length rather than 1 byte.
        if (ckk == CKK.GENERIC_SECRET && bits < defaultBits) {
            throw new IllegalArgumentException(jcaName + " keys must be at least " + defaultBits
                    + " bits — the digest length — and " + bits + " was requested. A shorter key"
                    + " weakens the MAC and no layer below here would report it.");
        }
        return bits;
    }

    @Override
    public String toString() {
        return jcaName;
    }
}

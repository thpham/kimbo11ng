/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import org.pkcs11.jacknji11.CKA;

/**
 * Reads {@code CK_ULONG}-valued attributes as the unsigned quantities PKCS#11 defines them to be.
 *
 * <h2>Why this exists</h2>
 *
 * <p>JackNJI11 1.3.1 decodes an 8-byte {@code CK_ULONG} with {@code int}-typed shifts
 * ({@code (buf[7] & 255) << 56}, where Java masks the shift distance to 5 bits), so the top four
 * bytes fold back over the bottom four and the 32-bit result is then sign-extended to {@code long}.
 * Measured on this exact dependency:
 *
 * <pre>
 *   0x0000004A -> 0x0000004A          (ok)
 *   0x7FFFFFFF -> 0x7FFFFFFF          (ok)
 *   0x80000000 -> 0xFFFFFFFF80000000  (sign-extended)
 *   0x80000100 -> 0xFFFFFFFF80000100  (sign-extended)
 *   0xFFFFFFFF -> -1
 * </pre>
 *
 * <p>Everything below {@code 0x80000000} is unaffected, which is why nothing has noticed: every
 * standard {@code CKK}, {@code CKM} and {@code CKA} value lives there. But
 * {@code CKK_VENDOR_DEFINED}, {@code CKM_VENDOR_DEFINED} and {@code CKA_VENDOR_DEFINED} are all
 * {@code 0x80000000}, so <em>every</em> vendor-defined constant has bit 31 set and comes back
 * negative. A vendor profile that writes {@code 0x80000100L} in its table would never match the
 * value read back from the token, and the key would be skipped as "profile does not describe CKK".
 * That is the Thales Luna case exactly, so it is fixed before the first vendor table is written
 * rather than after.
 *
 * <p>Not a workaround to remove later: PKCS#11 defines these type codes as 32-bit values even where
 * {@code CK_ULONG} is 64 bits wide, so masking to 32 bits is the correct reading regardless of what
 * the binding does.
 */
public final class CkULong {

    private CkULong() {
    }

    /**
     * The unsigned 32-bit value of a type code — a {@code CKK}, {@code CKM}, {@code CKA} or
     * {@code CKO} — however the binding sign-extended it.
     */
    public static long typeCode(long raw) {
        return raw & 0xFFFF_FFFFL;
    }

    /**
     * The unsigned type code held by {@code attr}, or {@code null} if the attribute carries no
     * value. Errors from the binding (a value that is not {@code CK_ULONG}-sized) propagate: a
     * token answering the wrong width for {@code CKA_KEY_TYPE} is a fault to report, not to guess
     * around.
     */
    public static Long typeCode(CKA attr) {
        Long value = attr.getValueLong();
        return value == null ? null : typeCode(value);
    }
}

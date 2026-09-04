/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;

import java.util.OptionalLong;

/**
 * Decides what a PKCS#11 return code means for the caller.
 *
 * <p>Every recovery decision in this codebase keys off {@link #classify}, so the rules live in one
 * place instead of being re-derived — sometimes differently — at each catch site. What this
 * replaces: {@code msg.contains("0x00000100")} for "already logged in", and a
 * {@code catch (Exception)} that threw away the cause and reported every failure as an
 * authentication failure, including a missing token.
 *
 * <p>Codes are normalised through {@link CkULong} before comparison. That is not defensive
 * padding: JackNJI11's own constant table stores vendor codes sign-extended
 * ({@code CKR.VENDOR_LUNA_ACCEL_DEVICE_ERROR} is {@code -2147483636}, i.e. {@code 0x8000000C}), so
 * a Luna error compared against an unnormalised literal silently matches nothing.
 */
public final class Pkcs11Errors {

    /** What the caller should do about a failure. */
    public enum Kind {
        /**
         * The session or object handle went stale but the token is still there. Reopen, re-resolve
         * and retry once. This is the ordinary consequence of a network HSM dropping a connection.
         */
        RETRYABLE,
        /**
         * The token is gone, or the login it was holding is gone. Go offline and let EJBCA's
         * {@code autoActivate()} log in again if a PIN is configured — we do not hold one.
         */
        OFFLINE,
        /** The PIN was wrong, expired or locked. Retrying with the same credential cannot help. */
        AUTH_FAILED,
        /** Anything else: a bug, a policy refusal, or a template the token will never accept. */
        FATAL
    }

    private Pkcs11Errors() {
    }

    /** The CKR carried by {@code t} or any of its causes, if one is. */
    public static OptionalLong ckrOf(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof CKRException ckr) {
                return OptionalLong.of(CkULong.typeCode(ckr.getCKR()));
            }
            if (c.getCause() == c) {
                break;
            }
        }
        return OptionalLong.empty();
    }

    /** True if {@code t} was caused by exactly this CKR. */
    public static boolean is(Throwable t, long ckr) {
        OptionalLong actual = ckrOf(t);
        return actual.isPresent() && actual.getAsLong() == CkULong.typeCode(ckr);
    }

    /** Classification of a throwable; {@link Kind#FATAL} when it carries no CKR at all. */
    public static Kind classify(Throwable t) {
        OptionalLong ckr = ckrOf(t);
        return ckr.isPresent() ? classify(ckr.getAsLong()) : Kind.FATAL;
    }

    public static Kind classify(long rawCkr) {
        long ckr = CkULong.typeCode(rawCkr);

        if (ckr == CKR.SESSION_HANDLE_INVALID || ckr == CKR.SESSION_CLOSED
                || ckr == CKR.OBJECT_HANDLE_INVALID) {
            return Kind.RETRYABLE;
        }
        if (ckr == CKR.DEVICE_ERROR || ckr == CKR.DEVICE_REMOVED
                || ckr == CKR.TOKEN_NOT_PRESENT || ckr == CKR.TOKEN_NOT_RECOGNIZED
                // Not an authentication failure: we were logged in and no longer are, which is
                // what a Luna does when its connection or HA group drops. Re-presenting a PIN we
                // do not hold cannot fix it; going offline lets EJBCA re-activate with one it has.
                || ckr == CKR.USER_NOT_LOGGED_IN) {
            return Kind.OFFLINE;
        }
        if (ckr == CKR.PIN_INCORRECT || ckr == CKR.PIN_INVALID || ckr == CKR.PIN_LEN_RANGE
                || ckr == CKR.PIN_EXPIRED || ckr == CKR.PIN_LOCKED) {
            return Kind.AUTH_FAILED;
        }
        return Kind.FATAL;
    }

    /**
     * True if the library was already initialised by someone else in this JVM — SunPKCS11, most
     * likely, since EJBCA's classic PKCS11CryptoToken resolves its slot list through our
     * ServiceLoader factory and can therefore share any library we touch.
     */
    public static boolean isAlreadyInitialized(Throwable t) {
        return is(t, CKR.CRYPTOKI_ALREADY_INITIALIZED);
    }

    /**
     * True if this token is already logged in. PKCS#11 login state is per application and token,
     * not per session, so a second {@code C_Login} on a slot we already authenticated answers this
     * and is not an error. Note it cannot be used to re-validate a PIN: the token answers before
     * looking at the credential.
     */
    public static boolean isAlreadyLoggedIn(Throwable t) {
        return is(t, CKR.USER_ALREADY_LOGGED_IN);
    }

    /** An offline exception naming the CKR, with the cause kept. */
    public static CryptoTokenOfflineException offline(String context, Throwable cause) {
        return new CryptoTokenOfflineException(context + describe(cause), cause);
    }

    /** {@code " (CKR_TOKEN_NOT_PRESENT)"}, or the message when there is no CKR to name. */
    public static String describe(Throwable t) {
        OptionalLong ckr = ckrOf(t);
        if (ckr.isEmpty()) {
            return t == null ? "" : ": " + t.getMessage();
        }
        return " (" + CKR.L2S(ckr.getAsLong()) + ")";
    }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * How a PKCS#11 return code is turned into a recovery decision.
 *
 * <p>These classifications decide whether a CA goes offline, retries, or reports a bad PIN, so each
 * one is asserted rather than left to the reader of a switch statement.
 */
@DisplayName("Pkcs11Errors")
class Pkcs11ErrorsTest {

    @Nested
    @DisplayName("classification")
    class Classification {

        @ParameterizedTest
        @ValueSource(longs = {CKR.SESSION_HANDLE_INVALID, CKR.SESSION_CLOSED,
                CKR.OBJECT_HANDLE_INVALID})
        @DisplayName("a stale handle is retryable")
        void retryable(long ckr) {
            assertEquals(Pkcs11Errors.Kind.RETRYABLE, Pkcs11Errors.classify(ckr));
        }

        @ParameterizedTest
        @ValueSource(longs = {CKR.DEVICE_ERROR, CKR.DEVICE_REMOVED, CKR.TOKEN_NOT_PRESENT,
                CKR.TOKEN_NOT_RECOGNIZED})
        @DisplayName("a missing or broken token means offline")
        void offline(long ckr) {
            assertEquals(Pkcs11Errors.Kind.OFFLINE, Pkcs11Errors.classify(ckr));
        }

        @Test
        @DisplayName("losing the login means offline, not an authentication failure")
        void notLoggedInIsOffline() {
            // The distinction matters: AUTH_FAILED tells EJBCA the credential is wrong and stops
            // it retrying, while OFFLINE lets autoActivate() log in again with the PIN it holds
            // and the CA recovers on its own. A dropped Luna connection produces this code.
            assertEquals(Pkcs11Errors.Kind.OFFLINE, Pkcs11Errors.classify(CKR.USER_NOT_LOGGED_IN));
        }

        @ParameterizedTest
        @ValueSource(longs = {CKR.PIN_INCORRECT, CKR.PIN_INVALID, CKR.PIN_LEN_RANGE,
                CKR.PIN_EXPIRED, CKR.PIN_LOCKED})
        @DisplayName("a rejected credential is an authentication failure")
        void authFailed(long ckr) {
            assertEquals(Pkcs11Errors.Kind.AUTH_FAILED, Pkcs11Errors.classify(ckr));
        }

        @ParameterizedTest
        @ValueSource(longs = {CKR.ATTRIBUTE_READ_ONLY, CKR.TEMPLATE_INCONSISTENT,
                CKR.MECHANISM_INVALID, CKR.OPERATION_ACTIVE})
        @DisplayName("a refused request is fatal, not something to retry")
        void fatal(long ckr) {
            // Retrying a template the token will never accept just fails again more slowly, and
            // going offline for it would take a CA down over a configuration mistake.
            assertEquals(Pkcs11Errors.Kind.FATAL, Pkcs11Errors.classify(ckr));
        }

        @Test
        @DisplayName("classifies a vendor code the binding reports as negative")
        void vendorCodeIsNormalised() {
            // jacknji11's own table stores this sign-extended: VENDOR_LUNA_ACCEL_DEVICE_ERROR is
            // -2147483636, i.e. 0x8000000C. Comparing raw would match nothing.
            assertEquals(Pkcs11Errors.Kind.FATAL,
                    Pkcs11Errors.classify(CKR.VENDOR_LUNA_ACCEL_DEVICE_ERROR));
            assertTrue(Pkcs11Errors.is(new CKRException(CKR.VENDOR_LUNA_ACCEL_DEVICE_ERROR),
                    CKR.VENDOR_LUNA_ACCEL_DEVICE_ERROR));
            // Both spellings of the same code must be recognised as the same code.
            assertTrue(Pkcs11Errors.is(new CKRException(0x8000_000CL),
                    CKR.VENDOR_LUNA_ACCEL_DEVICE_ERROR));
        }

        @Test
        @DisplayName("treats a throwable with no CKR as fatal")
        void noCkrIsFatal() {
            assertEquals(Pkcs11Errors.Kind.FATAL,
                    Pkcs11Errors.classify(new IllegalStateException("something else")));
            assertTrue(Pkcs11Errors.ckrOf(new IllegalStateException()).isEmpty());
        }
    }

    @Nested
    @DisplayName("finding the CKR")
    class Extraction {

        @Test
        @DisplayName("digs the CKR out of a wrapped exception")
        void walksTheCauseChain() {
            // Every layer between the token and the caller wraps: CryptokiE throws CKRException,
            // the SPI wraps it in SignatureException, EJBCA wraps that again. A classifier that
            // only looked at the outermost throwable would classify everything as fatal.
            Throwable wrapped = new IllegalStateException("outer",
                    new IOException("middle", new CKRException(CKR.TOKEN_NOT_PRESENT)));
            assertEquals(Pkcs11Errors.Kind.OFFLINE, Pkcs11Errors.classify(wrapped));
            assertEquals(CKR.TOKEN_NOT_PRESENT, Pkcs11Errors.ckrOf(wrapped).orElseThrow());
        }

        @Test
        @DisplayName("survives a self-referential cause chain")
        void selfReferentialCause() {
            // Not hypothetical: some frameworks initCause(this) to mark a throwable as unwrappable,
            // and a naive walk over the chain never terminates.
            Exception loop = new Exception("loop") {
                private static final long serialVersionUID = 1L;

                @Override
                public synchronized Throwable getCause() {
                    return this;
                }
            };
            assertEquals(Pkcs11Errors.Kind.FATAL, Pkcs11Errors.classify(loop));
        }

        @Test
        @DisplayName("recognises the two codes that are not failures")
        void nonFailures() {
            assertTrue(Pkcs11Errors.isAlreadyInitialized(
                    new CKRException(CKR.CRYPTOKI_ALREADY_INITIALIZED)));
            assertTrue(Pkcs11Errors.isAlreadyLoggedIn(
                    new CKRException(CKR.USER_ALREADY_LOGGED_IN)));
            // This is what replaced msg.contains("0x00000100"), which also matched any message
            // that happened to quote that number for another reason.
            assertFalse(Pkcs11Errors.isAlreadyLoggedIn(new CKRException(CKR.PIN_INCORRECT)));
        }
    }

    @Nested
    @DisplayName("reporting")
    class Reporting {

        @Test
        @DisplayName("keeps the cause and names the CKR")
        void offlineKeepsCause() {
            CKRException cause = new CKRException(CKR.TOKEN_NOT_PRESENT);
            CryptoTokenOfflineException e = Pkcs11Errors.offline("Could not open a session", cause);

            assertSame(cause, e.getCause(), "the cause must survive; it is the only diagnosis");
            assertTrue(e.getMessage().contains("Could not open a session"), e.getMessage());
            assertTrue(e.getMessage().contains("TOKEN_NOT_PRESENT"),
                    "an operator reading the log needs the CKR name: " + e.getMessage());
        }

        @Test
        @DisplayName("falls back to the message when there is no CKR")
        void describeWithoutCkr() {
            assertTrue(Pkcs11Errors.describe(new IllegalStateException("no token configured"))
                    .contains("no token configured"));
        }
    }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.fake;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.LongRef;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The double must be faithful before anything can be concluded from it. These tests pin the
 * protocol behaviours later phases rely on — especially the ones a real HSM enforces and SoftHSM
 * lets slide.
 */
@DisplayName("FakeToken")
class FakeTokenTest {

    private FakeToken token;
    private long session;

    @BeforeEach
    void openLoggedInSession() {
        token = new FakeToken();
        assertEquals(CKR.OK, token.C_Initialize(null));
        LongRef ref = new LongRef();
        assertEquals(CKR.OK, token.C_OpenSession(0L,
                CK_SESSION_INFO.CKF_SERIAL_SESSION | CK_SESSION_INFO.CKF_RW_SESSION, null, null, ref));
        session = ref.value();
        assertEquals(CKR.OK, token.C_Login(session, CKU.USER, "1234".getBytes(StandardCharsets.UTF_8), 4));
    }

    @Nested
    @DisplayName("protocol state")
    class ProtocolState {

        @Test
        @DisplayName("a second C_FindObjectsInit on a busy session is CKR_OPERATION_ACTIVE")
        void findIsSingleUsePerSession() {
            // This is the defect the shared-session design trips under concurrency: PKCS#11 find
            // is a per-session state machine, not a stateless query.
            assertEquals(CKR.OK, token.C_FindObjectsInit(session, new CKA[0], 0));
            assertEquals(CKR.OPERATION_ACTIVE, token.C_FindObjectsInit(session, new CKA[0], 0));
            assertEquals(CKR.OK, token.C_FindObjectsFinal(session));
            assertEquals(CKR.OK, token.C_FindObjectsInit(session, new CKA[0], 0));
        }

        @Test
        @DisplayName("C_FindObjects before init is CKR_OPERATION_NOT_INITIALIZED")
        void findRequiresInit() {
            assertEquals(CKR.OPERATION_NOT_INITIALIZED,
                    token.C_FindObjects(session, new long[8], 8, new LongRef()));
        }

        @Test
        @DisplayName("a second C_SignInit on a busy session is CKR_OPERATION_ACTIVE")
        void signIsSingleUsePerSession() {
            long key = generateRsa()[1];
            assertEquals(CKR.OK, token.C_SignInit(session, new CKM(CKM.SHA256_RSA_PKCS), key));
            assertEquals(CKR.OPERATION_ACTIVE,
                    token.C_SignInit(session, new CKM(CKM.SHA256_RSA_PKCS), key));
        }
    }

    @Nested
    @DisplayName("login")
    class Login {

        @Test
        @DisplayName("rejects a wrong PIN when logged out")
        void wrongPinRejected() {
            assertEquals(CKR.OK, token.C_Logout(session));
            assertEquals(CKR.PIN_INCORRECT,
                    token.C_Login(session, CKU.USER, "9999".getBytes(StandardCharsets.UTF_8), 4));
        }

        @Test
        @DisplayName("accepts ANY pin once already logged in, without checking it")
        void alreadyLoggedInDoesNotValidate() {
            // Faithful to the spec, and the reason kimbo11ng cannot "re-validate the PIN on
            // re-activation": C_Login short-circuits before looking at the credential. The fix
            // is a truthful deactivate(), not a re-check.
            assertEquals(CKR.USER_ALREADY_LOGGED_IN,
                    token.C_Login(session, CKU.USER, "totally-wrong".getBytes(StandardCharsets.UTF_8), 13));
            assertTrue(token.isLoggedIn());
        }
    }

    @Nested
    @DisplayName("attribute fetch")
    class Attributes {

        @Test
        @DisplayName("a null pValue is a length query, not a read")
        void nullPValueReturnsLength() {
            long publicKey = generateRsa()[0];
            CKA query = new CKA(CKA.MODULUS, (byte[]) null);
            assertEquals(CKR.OK, token.C_GetAttributeValue(session, publicKey, new CKA[] {query}, 1));
            assertEquals(256, query.ulValueLen, "RSA-2048 modulus is 256 bytes");
        }

        @Test
        @DisplayName("an undersized buffer is CKR_BUFFER_TOO_SMALL")
        void undersizedBuffer() {
            long publicKey = generateRsa()[0];
            CKA query = new CKA(CKA.MODULUS, new byte[8]);
            assertEquals(CKR.BUFFER_TOO_SMALL,
                    token.C_GetAttributeValue(session, publicKey, new CKA[] {query}, 1));
        }

        @Test
        @DisplayName("an attribute the object does not carry is CKR_ATTRIBUTE_TYPE_INVALID")
        void absentAttributeIsInvalid() {
            // The private key carries no CKA_MODULUS; a real token says so rather than
            // returning an empty value, and kimbo11ng must not read that as "length 0".
            long privateKey = generateRsa()[1];
            CKA query = new CKA(CKA.MODULUS, (byte[]) null);
            assertEquals(CKR.ATTRIBUTE_TYPE_INVALID,
                    token.C_GetAttributeValue(session, privateKey, new CKA[] {query}, 1));
            assertEquals(-1, query.ulValueLen);
        }

        @Test
        @DisplayName("omitAttribute hides an attribute the token would otherwise carry")
        void omittedAttributeIsInvalid() {
            // Simulates a vendor that does not implement CKA_PARAMETER_SET - the case that
            // currently makes every ML-DSA key silently default to the ML-DSA-65 OID.
            token.omitAttribute(CKA.MODULUS);
            long publicKey = generateRsa()[0];
            CKA query = new CKA(CKA.MODULUS, (byte[]) null);
            assertEquals(CKR.ATTRIBUTE_TYPE_INVALID,
                    token.C_GetAttributeValue(session, publicKey, new CKA[] {query}, 1));
        }

        @Test
        @DisplayName("readOnlyAttributes makes C_SetAttributeValue fail")
        void readOnlyAttributeRejectsWrite() {
            // Some HSM policies refuse attribute mutation on token objects, which is why the
            // CKA_ID backfill path must degrade rather than fail.
            token.readOnlyAttributes(CKA.ID);
            long privateKey = generateRsa()[1];
            CKA update = new CKA(CKA.ID, new byte[] {1, 2, 3});
            assertEquals(CKR.ATTRIBUTE_READ_ONLY,
                    token.C_SetAttributeValue(session, privateKey, new CKA[] {update}, 1));
        }
    }

    @Nested
    @DisplayName("fault injection")
    class Faults {

        @Test
        @DisplayName("failNextWith applies exactly once")
        void failNextIsOneShot() {
            token.failNextWith(CKR.DEVICE_ERROR);
            assertEquals(CKR.DEVICE_ERROR, token.C_FindObjectsInit(session, new CKA[0], 0));
            assertEquals(CKR.OK, token.C_FindObjectsInit(session, new CKA[0], 0));
        }

        @Test
        @DisplayName("killSessionsAfter invalidates open sessions mid-flight")
        void sessionDeath() {
            // A network HSM drops the link; every cached object handle dies with the session.
            token.killSessionsAfter(0);
            assertEquals(CKR.SESSION_HANDLE_INVALID, token.C_FindObjectsInit(session, new CKA[0], 0));
            assertEquals(0, token.openSessionCount());
        }
    }

    @Nested
    @DisplayName("EC point encoding")
    class EcPoint {

        @Test
        @DisplayName("DER wraps the point in an OCTET STRING, as PKCS#11 specifies")
        void derEncoding() {
            byte[] point = ecPointFrom(FakeToken.EcPointEncoding.DER);
            assertEquals(67, point.length, "65-byte point plus a 2-byte tag+length header");
            assertEquals(0x04, point[0] & 0xFF, "OCTET STRING tag");
            assertEquals(0x41, point[1] & 0xFF, "length 65");
        }

        @Test
        @DisplayName("RAW reports the bare uncompressed point, as several HSMs do")
        void rawEncoding() {
            // The ambiguity the current decoder trips over: byte 0 is 0x04 either way - once as
            // the OCTET STRING tag, once as the uncompressed-point prefix.
            byte[] point = ecPointFrom(FakeToken.EcPointEncoding.RAW);
            assertEquals(65, point.length, "P-256 uncompressed point is 04||X||Y");
            assertEquals(0x04, point[0] & 0xFF, "uncompressed-point prefix");
        }

        private byte[] ecPointFrom(FakeToken.EcPointEncoding encoding) {
            FakeToken t = freshToken(encoding);
            byte[] point = t.attribute(generateEc(t, loginTo(t)), CKA.EC_POINT);
            assertNotNull(point, "CKA_EC_POINT must be present on the public key");
            return point;
        }
    }

    // ---- helpers ----

    private static FakeToken freshToken(FakeToken.EcPointEncoding encoding) {
        FakeToken t = new FakeToken();
        t.ecPointEncoding(encoding);
        t.C_Initialize(null);
        return t;
    }

    private static long loginTo(FakeToken t) {
        LongRef ref = new LongRef();
        t.C_OpenSession(0L, CK_SESSION_INFO.CKF_SERIAL_SESSION | CK_SESSION_INFO.CKF_RW_SESSION,
                null, null, ref);
        t.C_Login(ref.value(), CKU.USER, "1234".getBytes(StandardCharsets.UTF_8), 4);
        return ref.value();
    }

    /** @return the public key handle */
    private static long generateEc(FakeToken t, long sess) {
        CKA[] pub = {
            new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
            // prime256v1
            new CKA(CKA.EC_PARAMS, new byte[] {0x06, 0x08, 0x2A, (byte) 0x86, 0x48,
                (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07}),
        };
        CKA[] priv = {new CKA(CKA.CLASS, CKO.PRIVATE_KEY)};
        LongRef pubRef = new LongRef();
        LongRef privRef = new LongRef();
        assertEquals(CKR.OK, t.C_GenerateKeyPair(sess, new CKM(CKM.EC_KEY_PAIR_GEN),
                pub, pub.length, priv, priv.length, pubRef, privRef));
        return pubRef.value();
    }

    /** @return {@code {publicHandle, privateHandle}} */
    private long[] generateRsa() {
        CKA[] pub = {
            new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
            new CKA(CKA.MODULUS_BITS, 2048L),
        };
        CKA[] priv = {new CKA(CKA.CLASS, CKO.PRIVATE_KEY)};
        LongRef pubRef = new LongRef();
        LongRef privRef = new LongRef();
        assertEquals(CKR.OK, token.C_GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN),
                pub, pub.length, priv, priv.length, pubRef, privRef));
        return new long[] {pubRef.value(), privRef.value()};
    }
}

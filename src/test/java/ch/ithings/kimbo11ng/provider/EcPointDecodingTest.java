/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.LongRef;

import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The measured defect this phase exists to fix.
 *
 * <p>{@code CKA_EC_POINT} is specified as a DER OCTET STRING wrapping the point, and many modules
 * report the bare point instead. The old code told them apart by looking at two bytes:
 * {@code b[0] == 0x04 && b[1] != 0x04}. {@code 0x04} is both the OCTET STRING tag and the
 * uncompressed-point prefix, so for a module reporting a raw point this reads X[0] as a length.
 * Measured against 2,000 real P-256 keys: 490 of them — 24.5% — took the wrong branch and failed
 * to load at all.
 *
 * <p>{@link #rawPointsAlwaysDecode} is the regression test: enough distinct keys that the old
 * heuristic could not pass it by luck.
 */
@DisplayName("CKA_EC_POINT decoding")
class EcPointDecodingTest {

    /**
     * Keys per curve. X[0] is uniform, so the old heuristic failed with p ≈ 0.25 per key; at 250
     * the chance of it passing by luck is about 10^-31.
     */
    private static final int KEYS_PER_CURVE = 250;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static long generateEc(TestSlot fixture, String curve) throws Exception {
        KeyTemplates.Pair t = KeyTemplates.ec("ecKey".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                KeyTemplates.newKeyId(), curve);
        return fixture.onSession((ce, session) -> {
            LongRef pub = new LongRef();
            LongRef priv = new LongRef();
            ce.GenerateKeyPair(session, new CKM(CKM.EC_KEY_PAIR_GEN), t.pub(), t.priv(), pub, priv);
            return pub.value();
        });
    }

    @Nested
    @DisplayName("the matrix")
    class Matrix {

        @ParameterizedTest
        @ValueSource(strings = {"P-256", "P-384", "P-521"})
        @DisplayName("decodes every raw point, on every curve")
        void rawPointsAlwaysDecode(String curve) throws Exception {
            // RAW is the encoding the old heuristic mishandled. One failure here is a regression.
            assertAllDecode(curve, FakeToken.EcPointEncoding.RAW);
        }

        @ParameterizedTest
        @ValueSource(strings = {"P-256", "P-384", "P-521"})
        @DisplayName("decodes every DER-wrapped point, on every curve")
        void derPointsAlwaysDecode(String curve) throws Exception {
            assertAllDecode(curve, FakeToken.EcPointEncoding.DER);
        }

        @ParameterizedTest
        @ValueSource(strings = {"secp256k1", "brainpoolP256r1", "brainpoolP384r1",
                "brainpoolP512r1"})
        @DisplayName("handles the non-NIST curves EJBCA offers")
        void otherCurves(String curve) throws Exception {
            for (FakeToken.EcPointEncoding encoding : FakeToken.EcPointEncoding.values()) {
                FakeToken token = new FakeToken().ecPointEncoding(encoding);
                try (TestSlot fixture = new TestSlot(token)) {
                    fixture.loggedIn();
                    long handle = generateEc(fixture, curve);
                    PublicKey key = fixture.onSession((ce, session) ->
                            PublicKeyReader.readEcPublicKey(ce, session, handle));
                    assertInstanceOf(ECPublicKey.class, key, curve + " / " + encoding);
                }
            }
        }

        private void assertAllDecode(String curve, FakeToken.EcPointEncoding encoding)
                throws Exception {
            FakeToken token = new FakeToken().ecPointEncoding(encoding);
            List<String> failures = new ArrayList<>();
            try (TestSlot fixture = new TestSlot(token)) {
                fixture.loggedIn();
                for (int i = 0; i < KEYS_PER_CURVE; i++) {
                    long handle = generateEc(fixture, curve);
                    try {
                        PublicKey key = fixture.onSession((ce, session) ->
                                PublicKeyReader.readEcPublicKey(ce, session, handle));
                        // Not merely "nothing was thrown": the rare bad case is a truncated buffer
                        // that happens to be a valid encoding of a different point, so check the
                        // key came back on the curve it was generated on.
                        ECPublicKey ec = (ECPublicKey) key;
                        int fieldSize = ec.getParams().getCurve().getField().getFieldSize();
                        assertNotNull(ec.getW());
                        if (fieldSize != expectedFieldSize(curve)) {
                            failures.add("key " + i + ": field size " + fieldSize);
                        }
                    } catch (Exception e) {
                        failures.add("key " + i + ": " + e);
                    }
                }
            }
            assertTrue(failures.isEmpty(), () -> curve + " / " + encoding + ": "
                    + failures.size() + " of " + KEYS_PER_CURVE + " keys failed ("
                    + (100.0 * failures.size() / KEYS_PER_CURVE) + "%). First few: "
                    + failures.subList(0, Math.min(3, failures.size())));
        }

        private int expectedFieldSize(String curve) {
            return switch (curve) {
                case "P-256" -> 256;
                case "P-384" -> 384;
                case "P-521" -> 521;
                default -> throw new IllegalArgumentException(curve);
            };
        }
    }

    @Nested
    @DisplayName("rejecting what it cannot read")
    class Rejection {

        private ECParameterSpec p256() throws Exception {
            return EcPointCodec.parseCurve(
                    new ASN1ObjectIdentifier("1.2.840.10045.3.1.7").getEncoded());
        }

        @Test
        @DisplayName("refuses a point of the wrong length rather than decoding part of it")
        void wrongLengthIsRejected() throws Exception {
            ECParameterSpec spec = p256();
            // 64 bytes: an uncompressed P-256 point missing its prefix, which is exactly the shape
            // a truncating bug produces. It must not be accepted as anything.
            byte[] truncated = new byte[64];
            truncated[0] = 0x04;

            Exception e = assertThrows(java.security.InvalidKeyException.class,
                    () -> EcPointCodec.decodePoint(truncated, spec));
            assertTrue(e.getMessage().contains("65"), () -> "the message should name the expected "
                    + "length: " + e.getMessage());
        }

        @Test
        @DisplayName("refuses an OCTET STRING with trailing bytes")
        void trailingBytesAreRejected() throws Exception {
            ECParameterSpec spec = p256();
            byte[] valid = new DEROctetString(new byte[65]).getEncoded();
            byte[] withJunk = java.util.Arrays.copyOf(valid, valid.length + 1);

            // Parse-and-consume: an encoding that only covers a prefix of the buffer is precisely
            // what the old code accepted when it misread X[0] as a length.
            assertThrows(java.security.InvalidKeyException.class,
                    () -> EcPointCodec.decodePoint(withJunk, spec));
        }

        @Test
        @DisplayName("refuses a point that is not on the curve")
        void pointOffTheCurveIsRejected() throws Exception {
            ECParameterSpec spec = p256();
            byte[] bogus = new byte[65];
            bogus[0] = 0x04;
            java.util.Arrays.fill(bogus, 1, 65, (byte) 0x11);

            // A point off the curve is the classic invalid-curve attack input, and BouncyCastle
            // only checks when asked.
            assertThrows(java.security.InvalidKeyException.class,
                    () -> EcPointCodec.decodePoint(bogus, spec));
        }

        @ParameterizedTest
        @ValueSource(ints = {0, 1})
        @DisplayName("refuses a buffer too short to be a point")
        void tooShortIsRejected(int length) throws Exception {
            assertThrows(java.security.InvalidKeyException.class,
                    () -> EcPointCodec.decodePoint(new byte[length], p256()));
        }

        @Test
        @DisplayName("refuses an absent point")
        void nullIsRejected() throws Exception {
            assertThrows(java.security.InvalidKeyException.class,
                    () -> EcPointCodec.decodePoint(null, p256()));
        }
    }

    @Nested
    @DisplayName("CKA_EC_PARAMS")
    class Curves {

        @ParameterizedTest
        @CsvSource({
            "1.2.840.10045.3.1.7, 256",
            "1.3.132.0.34,        384",
            "1.3.132.0.35,        521",
            "1.3.132.0.10,        256",
            "1.3.36.3.3.2.8.1.1.7, 256",
        })
        @DisplayName("reads a named curve")
        void namedCurve(String oid, int fieldSize) throws Exception {
            ECParameterSpec spec = EcPointCodec.parseCurve(new ASN1ObjectIdentifier(oid).getEncoded());
            assertEquals(fieldSize, spec.getCurve().getFieldSize());
        }

        @Test
        @DisplayName("reads explicit parameters, which some HSMs report instead of an OID")
        void explicitParameters() throws Exception {
            // The old code cast the parsed object straight to an OID and would have thrown
            // ClassCastException here.
            org.bouncycastle.asn1.x9.X9ECParameters p256 =
                    org.bouncycastle.asn1.nist.NISTNamedCurves.getByName("P-256");
            byte[] explicit = new org.bouncycastle.asn1.x9.X962Parameters(p256).toASN1Primitive()
                    .getEncoded();

            ECParameterSpec spec = EcPointCodec.parseCurve(explicit);
            assertEquals(256, spec.getCurve().getFieldSize());
        }

        @Test
        @DisplayName("says so when the curve is unknown rather than failing later")
        void unknownCurve() {
            Exception e = assertThrows(java.security.InvalidKeyException.class,
                    () -> EcPointCodec.parseCurve(
                            new ASN1ObjectIdentifier("1.2.3.4.5.6.7").getEncoded()));
            assertTrue(e.getMessage().contains("1.2.3.4.5.6.7"), e.getMessage());
        }

        @Test
        @DisplayName("rejects empty parameters")
        void emptyParameters() {
            assertThrows(java.security.InvalidKeyException.class,
                    () -> EcPointCodec.parseCurve(new byte[0]));
            assertThrows(java.security.InvalidKeyException.class,
                    () -> EcPointCodec.parseCurve(null));
        }
    }

    @Test
    @DisplayName("reads the same key back whichever encoding the token uses")
    void bothEncodingsYieldTheSameKey() throws Exception {
        // The two encodings must be interchangeable from the caller's point of view; a token that
        // switches between them across firmware versions must not change what a CA's key is.
        FakeToken raw = new FakeToken().ecPointEncoding(FakeToken.EcPointEncoding.RAW);
        FakeToken der = new FakeToken().ecPointEncoding(FakeToken.EcPointEncoding.DER);

        try (TestSlot rawSlot = new TestSlot(raw); TestSlot derSlot = new TestSlot(der)) {
            rawSlot.loggedIn();
            derSlot.loggedIn();

            long rawHandle = generateEc(rawSlot, "P-256");
            byte[] point = rawSlot.onSession((ce, session) ->
                    ce.GetAttributeValue(session, rawHandle, CKA.EC_POINT).getValue());
            byte[] params = rawSlot.onSession((ce, session) ->
                    ce.GetAttributeValue(session, rawHandle, CKA.EC_PARAMS).getValue());

            // The same point, wrapped, planted on the second token.
            long derHandle = derSlot.onSession((ce, session) -> {
                LongRef out = new LongRef();
                ce.CreateObject(session, new CKA[] {
                    new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
                    new CKA(CKA.KEY_TYPE, CKK.EC),
                    new CKA(CKA.EC_PARAMS, params),
                    new CKA(CKA.EC_POINT, new DEROctetString(point).getEncoded()),
                    new CKA(CKA.TOKEN, true),
                }, out);
                return out.value();
            });

            ECPublicKey fromRaw = (ECPublicKey) rawSlot.onSession((ce, session) ->
                    PublicKeyReader.readEcPublicKey(ce, session, rawHandle));
            ECPublicKey fromDer = (ECPublicKey) derSlot.onSession((ce, session) ->
                    PublicKeyReader.readEcPublicKey(ce, session, derHandle));

            assertEquals(fromRaw.getW(), fromDer.getW());
            assertNull(System.getProperty("never.set"));
        }
    }
}

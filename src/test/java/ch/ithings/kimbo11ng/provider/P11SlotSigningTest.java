/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import ch.ithings.kimbo11ng.profile.Pkcs11v32Profile;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.LongRef;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The signing path end to end against a fake token: generate on the token, read the public key
 * back, sign through the JCA provider, verify with BouncyCastle.
 *
 * <p>Pool mechanics live in {@code SessionPoolTest} and module lifecycle in
 * {@code Pkcs11ModuleRegistryTest}; what is checked here is that the pieces compose — that a
 * signature produced through a borrowed session verifies against the key the token reported.
 */
@DisplayName("signing through a slot")
class P11SlotSigningTest {

    private TestSlot fixture;

    @BeforeAll
    static void registerBouncyCastle() {
        // Kimbo11ngPublicKey resolves KeyFactory by provider NAME ("BC"), so BouncyCastle must be
        // registered in Security. In production EJBCA does this; nothing in kimbo11ng does, which
        // is an undocumented hard dependency worth pinning here.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void openSlot() throws Exception {
        fixture = new TestSlot(new FakeToken()).loggedIn();
    }

    @Test
    @DisplayName("initializes the library once and reuses pooled sessions")
    void initializesOnceAndPoolsSessions() throws Exception {
        assertEquals(1, fixture.token().initializeCalls(),
                "C_Initialize should be called once per library");

        long first = fixture.onSession((ce, session) -> session);
        long second = fixture.onSession((ce, session) -> session);
        assertEquals(first, second, "a returned session is handed out again rather than reopened");
        assertEquals(1, fixture.slot().pool().liveSessions());
    }

    @Test
    @DisplayName("closing the slot releases every session but never finalizes the library")
    void closeReleasesSessionsOnly() throws Exception {
        fixture.onSession((ce, session) -> session);
        fixture.slot().close();

        assertEquals(0, fixture.token().openSessionCount());
        assertEquals(0, fixture.token().finalizeCalls(),
                "C_Finalize must not be called: SunPKCS11 may be sharing this library");
    }

    @Test
    @DisplayName("derives the provider name from the library filename")
    void libraryNameIsSanitized() {
        assertTrue(fixture.slot().libraryName().startsWith("libfake-"),
                fixture.slot().libraryName());
        assertTrue(fixture.slot().libraryName().endsWith("_so"),
                "dots become underscores so the name is a legal JCA provider name: "
                        + fixture.slot().libraryName());
    }

    @Test
    @DisplayName("generates RSA on the token and reads the public key back")
    void rsaRoundTrip() throws Exception {
        long[] handles = generateRsa(2048);
        PublicKey pub = fixture.onSession((ce, session) ->
                Kimbo11ngPublicKey.readRsaPublicKey(ce, session, handles[0]));
        assertNotNull(pub);
        assertEquals("RSA", pub.getAlgorithm());
        assertEquals(2048, ((RSAPublicKey) pub).getModulus().bitLength());
    }

    @Test
    @DisplayName("signs RSA through the JCA provider and BouncyCastle verifies it")
    void rsaSignVerify() throws Exception {
        long[] handles = generateRsa(2048);
        PublicKey pub = fixture.onSession((ce, session) ->
                Kimbo11ngPublicKey.readRsaPublicKey(ce, session, handles[0]));

        byte[] data = "kimbo11ng".getBytes(StandardCharsets.UTF_8);
        byte[] signature = signWithProvider("SHA256withRSA", handles[1], "RSA", data);

        Signature verifier = Signature.getInstance("SHA256withRSA",
                BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(pub);
        verifier.update(data);
        assertTrue(verifier.verify(signature), "signature produced via PKCS#11 must verify");
    }

    @Test
    @DisplayName("converts the token's raw r||s ECDSA output into DER that verifies")
    void ecdsaSignatureIsReEncodedToDer() throws Exception {
        long[] handles = generateEc();
        PublicKey pub = fixture.onSession((ce, session) ->
                Kimbo11ngPublicKey.readEcPublicKey(ce, session, handles[0]));
        assertEquals("EC", pub.getAlgorithm());

        byte[] data = "kimbo11ng".getBytes(StandardCharsets.UTF_8);
        byte[] signature = signWithProvider("SHA256withECDSA", handles[1], "EC", data);

        // PKCS#11 hands back the bare r||s pair; the SPI must wrap it in an ASN.1 SEQUENCE
        // before anything in the JCA world can verify it.
        assertEquals(0x30, signature[0] & 0xFF, "DER SEQUENCE tag");
        Signature verifier = Signature.getInstance("SHA256withECDSA",
                BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(pub);
        verifier.update(data);
        assertTrue(verifier.verify(signature), "re-encoded ECDSA signature must verify");
    }

    @Test
    @DisplayName("returns the session to the pool after a successful signature")
    void signatureReturnsItsSession() throws Exception {
        long[] handles = generateRsa(2048);
        signWithProvider("SHA256withRSA", handles[1], "RSA", new byte[] {1, 2, 3});

        assertEquals(0, fixture.slot().pool().liveSessions() - fixture.slot().pool().idleSessions(),
                "no session may be left checked out after signing");
    }

    @Test
    @DisplayName("discards the session when signing fails, rather than pooling a live operation")
    void failedSignatureDiscardsItsSession() throws Exception {
        long[] handles = generateRsa(2048);
        // Warm the pool so there is a session to lose.
        fixture.onSession((ce, session) -> session);
        assertEquals(1, fixture.slot().pool().idleSessions());

        fixture.token().failNextWith(org.pkcs11.jacknji11.CKR.DEVICE_ERROR);
        try {
            signWithProvider("SHA256withRSA", handles[1], "RSA", new byte[] {1, 2, 3});
        } catch (Exception expected) {
            // The failure is the point; what matters is what happened to the session.
        }
        assertEquals(0, fixture.slot().pool().idleSessions(),
                "a session whose C_SignInit may have succeeded must not be reused: the next "
                        + "borrower's C_SignInit would answer CKR_OPERATION_ACTIVE");
    }

    @Test
    @DisplayName("returns the same provider instance for a slot across re-initialisation")
    void providerIsStableAcrossReinit() {
        // EJBCA registers the provider in java.security.Security under its name and only adds a
        // name once, so a second instance would leave the first registered and pointing at a
        // released slot. The facade must therefore be reused and merely re-pointed.
        TokenRuntime first = new TokenRuntime(fixture.slot(), new Pkcs11v32Profile());
        Kimbo11ngProvider a = Kimbo11ngProvider.forToken(first);

        TokenRuntime second = new TokenRuntime(fixture.slot(), new Pkcs11v32Profile());
        Kimbo11ngProvider b = Kimbo11ngProvider.forToken(second);

        assertSame(a, b, "one provider instance per (library, slot)");
        assertSame(second, b.runtime(), "the runtime behind it must be the newest one");
    }

    @Test
    @DisplayName("registers a Signature service for every signing algorithm in the profile")
    void registersProfileSignatureServices() {
        Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                new TokenRuntime(fixture.slot(), new Pkcs11v32Profile()));
        for (String algorithm : new String[] {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-256F", "SHA256withRSA", "SHA256withECDSA"}) {
            assertNotNull(provider.getService("Signature", algorithm),
                    () -> "missing Signature service for " + algorithm);
        }
        assertNull(provider.getService("Signature", "ML-KEM-768"),
                "ML-KEM is key establishment; registering it as a Signature would be wrong");
    }

    // ---- helpers ----

    private byte[] signWithProvider(String algorithm, long privateHandle, String keyAlgorithm,
            byte[] data) throws Exception {
        Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                new TokenRuntime(fixture.slot(), new Pkcs11v32Profile()));
        Kimbo11ngPrivateKey key = new Kimbo11ngPrivateKey(keyAlgorithm, fixture.slot(),
                new P11KeyRef(null, "test", null), privateHandle);
        Signature signer = Signature.getInstance(algorithm, provider);
        signer.initSign(key);
        signer.update(data);
        return signer.sign();
    }

    /** @return {@code {publicHandle, privateHandle}} */
    private long[] generateRsa(int bits) throws Exception {
        CKA[] pub = {
            new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
            new CKA(CKA.KEY_TYPE, CKK.RSA),
            new CKA(CKA.MODULUS_BITS, (long) bits),
            new CKA(CKA.TOKEN, true),
        };
        CKA[] priv = {
            new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
            new CKA(CKA.KEY_TYPE, CKK.RSA),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.SIGN, true),
        };
        return generatePair(CKM.RSA_PKCS_KEY_PAIR_GEN, pub, priv);
    }

    /** @return {@code {publicHandle, privateHandle}} for prime256v1 */
    private long[] generateEc() throws Exception {
        byte[] prime256v1 = new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.840.10045.3.1.7")
                .getEncoded();
        CKA[] pub = {
            new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
            new CKA(CKA.KEY_TYPE, CKK.EC),
            new CKA(CKA.EC_PARAMS, prime256v1),
            new CKA(CKA.TOKEN, true),
        };
        CKA[] priv = {
            new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
            new CKA(CKA.KEY_TYPE, CKK.EC),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.SIGN, true),
        };
        return generatePair(CKM.EC_KEY_PAIR_GEN, pub, priv);
    }

    private long[] generatePair(long mechanism, CKA[] pub, CKA[] priv) throws Exception {
        return fixture.onSession((ce, session) -> {
            LongRef pubRef = new LongRef();
            LongRef privRef = new LongRef();
            ce.GenerateKeyPair(session, new CKM(mechanism), pub, priv, pubRef, privRef);
            return new long[] {pubRef.value(), privRef.value()};
        });
    }
}

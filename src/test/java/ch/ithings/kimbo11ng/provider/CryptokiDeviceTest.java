/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.p11.NativeProviderFactory;
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
import org.pkcs11.jacknji11.CryptokiE;
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
 * Drives the production classes against {@link FakeToken} through the injection seam.
 *
 * <p>Until this existed, every class touching PKCS#11 sat at 0% coverage and could only be
 * exercised by booting EJBCA and SoftHSM under Docker. The round trips here — generate on the
 * token, read the public key back, sign through the JCA provider, verify with BouncyCastle —
 * are the ones the later phases rewrite, so they need a guard that runs in milliseconds.
 */
@DisplayName("CryptokiDevice against a fake token")
class CryptokiDeviceTest {

    private static final String LIB = "/nonexistent/libfake.so";

    private FakeToken fake;
    private CryptokiDevice device;

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
    void openDevice() throws Exception {
        fake = new FakeToken();
        NativeProviderFactory factory = path -> fake;
        device = new CryptokiDevice(LIB, 0L, factory);
        device.login("1234".toCharArray());
    }

    @Test
    @DisplayName("initializes the library and opens exactly one session")
    void initializesAndOpensSession() throws Exception {
        assertEquals(1, fake.initializeCalls(), "C_Initialize should be called once per device");
        assertTrue(device.isLoggedIn());
        long first = device.getOrOpenSession();
        long second = device.getOrOpenSession();
        assertEquals(first, second, "the device reuses its single session");
        assertEquals(1, fake.openSessionCount());
    }

    @Test
    @DisplayName("logout then close leaves no session behind")
    void closeReleasesSession() throws Exception {
        device.getOrOpenSession();
        device.close();
        assertEquals(0, fake.openSessionCount());
        assertEquals(0, fake.finalizeCalls(),
                "C_Finalize must not be called: SunPKCS11 may share this library");
    }

    @Test
    @DisplayName("derives the provider name from the library filename")
    void libraryNameIsSanitized() {
        assertEquals("libfake_so", device.getLibraryName());
    }

    @Test
    @DisplayName("generates RSA on the token and reads the public key back")
    void rsaRoundTrip() throws Exception {
        long[] handles = generateRsa(2048);
        PublicKey pub = Kimbo11ngPublicKey.readRsaPublicKey(
                device.getCe(), device.getOrOpenSession(), handles[0]);
        assertNotNull(pub);
        assertEquals("RSA", pub.getAlgorithm());
        assertEquals(2048, ((RSAPublicKey) pub).getModulus().bitLength());
    }

    @Test
    @DisplayName("signs RSA through the JCA provider and BouncyCastle verifies it")
    void rsaSignVerify() throws Exception {
        long[] handles = generateRsa(2048);
        PublicKey pub = Kimbo11ngPublicKey.readRsaPublicKey(
                device.getCe(), device.getOrOpenSession(), handles[0]);

        byte[] data = "kimbo11ng".getBytes(StandardCharsets.UTF_8);
        byte[] signature = signWithProvider("SHA256withRSA", handles[1], "RSA", data);

        Signature verifier = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(pub);
        verifier.update(data);
        assertTrue(verifier.verify(signature), "signature produced via PKCS#11 must verify");
    }

    @Test
    @DisplayName("converts the token's raw r||s ECDSA output into DER that verifies")
    void ecdsaSignatureIsReEncodedToDer() throws Exception {
        long[] handles = generateEc();
        PublicKey pub = Kimbo11ngPublicKey.readEcPublicKey(
                device.getCe(), device.getOrOpenSession(), handles[0]);
        assertEquals("EC", pub.getAlgorithm());

        byte[] data = "kimbo11ng".getBytes(StandardCharsets.UTF_8);
        byte[] signature = signWithProvider("SHA256withECDSA", handles[1], "EC", data);

        // PKCS#11 hands back the bare r||s pair; the SPI must wrap it in an ASN.1 SEQUENCE
        // before anything in the JCA world can verify it.
        assertEquals(0x30, signature[0] & 0xFF, "DER SEQUENCE tag");
        Signature verifier = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(pub);
        verifier.update(data);
        assertTrue(verifier.verify(signature), "re-encoded ECDSA signature must verify");
    }

    // ---- helpers ----

    private byte[] signWithProvider(String algorithm, long privateHandle, String keyAlgorithm,
            byte[] data) throws Exception {
        Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                new TokenRuntime(device, new Pkcs11v32Profile()));
        Kimbo11ngPrivateKey key = new Kimbo11ngPrivateKey(privateHandle, keyAlgorithm, "test", device);
        Signature signer = Signature.getInstance(algorithm, provider);
        signer.initSign(key);
        signer.update(data);
        return signer.sign();
    }

    @Test
    @DisplayName("returns the same provider instance for a slot across re-initialisation")
    void providerIsStableAcrossReinit() {
        // EJBCA registers the provider in java.security.Security under its name and only adds a
        // name once, so a second instance would leave the first registered and pointing at a
        // closed device. The facade must therefore be reused and merely re-pointed.
        TokenRuntime first = new TokenRuntime(device, new Pkcs11v32Profile());
        Kimbo11ngProvider a = Kimbo11ngProvider.forToken(first);

        TokenRuntime second = new TokenRuntime(device, new Pkcs11v32Profile());
        Kimbo11ngProvider b = Kimbo11ngProvider.forToken(second);

        assertSame(a, b, "one provider instance per (library, slot)");
        assertSame(second, b.runtime(), "the runtime behind it must be the newest one");
    }

    @Test
    @DisplayName("registers a Signature service for every signing algorithm in the profile")
    void registersProfileSignatureServices() {
        Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                new TokenRuntime(device, new Pkcs11v32Profile()));
        // 3 ML-DSA + 12 SLH-DSA sign; the 3 ML-KEM parameter sets must not appear.
        for (String algorithm : new String[] {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-256F", "SHA256withRSA", "SHA256withECDSA"}) {
            assertNotNull(provider.getService("Signature", algorithm),
                    () -> "missing Signature service for " + algorithm);
        }
        assertNull(provider.getService("Signature", "ML-KEM-768"),
                "ML-KEM is key establishment; registering it as a Signature would be wrong");
    }

    /** @return {@code {publicHandle, privateHandle}} */
    private long[] generateRsa(int bits) throws Exception {
        CryptokiE ce = device.getCe();
        long session = device.getOrOpenSession();
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
        LongRef pubRef = new LongRef();
        LongRef privRef = new LongRef();
        ce.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN),
                pub, priv, pubRef, privRef);
        return new long[] {pubRef.value(), privRef.value()};
    }

    /** @return {@code {publicHandle, privateHandle}} for prime256v1 */
    private long[] generateEc() throws Exception {
        CryptokiE ce = device.getCe();
        long session = device.getOrOpenSession();
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
        LongRef pubRef = new LongRef();
        LongRef privRef = new LongRef();
        ce.GenerateKeyPair(session, new CKM(CKM.EC_KEY_PAIR_GEN),
                pub, priv, pubRef, privRef);
        return new long[] {pubRef.value(), privRef.value()};
    }
}

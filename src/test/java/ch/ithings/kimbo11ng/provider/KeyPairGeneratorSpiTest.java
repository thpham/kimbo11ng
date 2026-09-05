/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import ch.ithings.kimbo11ng.profile.Pkcs11v32Profile;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.ProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The JCA {@code KeyPairGenerator} route into the token.
 *
 * <p>EJBCA does not use it — it generates through the CryptoToken API — which is exactly why it was
 * untested, and why an untested registered service is worth covering rather than leaving: the
 * provider advertises {@code KeyPairGenerator.RSA} and {@code KeyPairGenerator.EC}, so anything
 * resolving this provider by name can reach it, and a service that has never been executed is a
 * claim nobody has checked.
 *
 * <p>It shares {@link KeyTemplates} with the CryptoToken path, which is what stops the two drifting
 * as they had before — the EC public template used to set {@code CKA_ENCRYPT} in one copy and not
 * the other.
 */
@DisplayName("KeyPairGenerator SPI")
class KeyPairGeneratorSpiTest {

    private TestSlot fixture;
    private Kimbo11ngProvider provider;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void openSlot() throws Exception {
        fixture = new TestSlot(new FakeToken()).loggedIn();
        provider = Kimbo11ngProvider.forToken(
                new TokenRuntime(fixture.slot(), new Pkcs11v32Profile()));
    }

    @AfterEach
    void closeSlot() {
        fixture.close();
    }

    @Test
    @DisplayName("is reachable through the JCA, not only by direct construction")
    void resolvableThroughTheProvider() throws Exception {
        assertNotNull(KeyPairGenerator.getInstance("RSA", provider));
        assertNotNull(KeyPairGenerator.getInstance("EC", provider));
    }

    @ParameterizedTest
    @ValueSource(ints = {2048, 3072})
    @DisplayName("generates an RSA pair of the requested size, on the token")
    void rsa(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", provider);
        generator.initialize(bits);
        KeyPair pair = generator.generateKeyPair();

        assertEquals(bits, ((RSAPublicKey) pair.getPublic()).getModulus().bitLength());
        // The private half must stay in the token: a Kimbo11ngPrivateKey has no encoding, which is
        // also what makes EJBCA's isPrivateKeyExtractable check pass.
        Kimbo11ngPrivateKey privateKey = assertInstanceOf(
                Kimbo11ngPrivateKey.class, pair.getPrivate());
        assertEquals("PKCS#11", privateKey.getFormat());
        assertTrue(privateKey.ref().hasCkaId(), "generated keys must carry a CKA_ID");
    }

    @Test
    @DisplayName("the default RSA size is used when initialize is never called")
    void rsaDefaultSize() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA", provider).generateKeyPair();
        assertEquals(2048, ((RSAPublicKey) pair.getPublic()).getModulus().bitLength());
    }

    @Test
    @DisplayName("RSA refuses a parameter spec, pointing at initialize(int)")
    void rsaRejectsParameterSpec() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", provider);
        InvalidAlgorithmParameterException e = assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> generator.initialize(new RSAKeyGenParameterSpec(2048,
                        RSAKeyGenParameterSpec.F4)));
        assertTrue(e.getMessage().contains("initialize(int)"), e.getMessage());
    }

    @ParameterizedTest
    @CsvSource({"secp256r1, 256", "secp384r1, 384", "secp521r1, 521"})
    @DisplayName("generates an EC pair on the named curve")
    void ecByName(String curve, int fieldBits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", provider);
        generator.initialize(new ECGenParameterSpec(curve));
        KeyPair pair = generator.generateKeyPair();

        assertEquals(fieldBits,
                ((ECPublicKey) pair.getPublic()).getParams().getCurve().getField().getFieldSize());
        assertInstanceOf(Kimbo11ngPrivateKey.class, pair.getPrivate());
    }

    @ParameterizedTest
    @CsvSource({"256, 256", "384, 384", "521, 521", "999, 256"})
    @DisplayName("maps a key size to a NIST curve, defaulting to P-256")
    void ecBySize(int keysize, int expectedFieldBits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", provider);
        generator.initialize(keysize);
        KeyPair pair = generator.generateKeyPair();

        assertEquals(expectedFieldBits,
                ((ECPublicKey) pair.getPublic()).getParams().getCurve().getField().getFieldSize());
    }

    @Test
    @DisplayName("EC refuses a spec that is not an ECGenParameterSpec")
    void ecRejectsWrongSpec() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", provider);
        InvalidAlgorithmParameterException e = assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> generator.initialize(new RSAKeyGenParameterSpec(2048,
                        RSAKeyGenParameterSpec.F4)));
        assertTrue(e.getMessage().contains("ECGenParameterSpec"), e.getMessage());
    }

    @Test
    @DisplayName("an unknown curve is refused at initialize, where the caller can act on it")
    void unknownCurveIsRefusedEarly() throws Exception {
        // Found by writing this test: the name used to reach new ASN1ObjectIdentifier(...) and
        // escape generateKeyPair as a raw IllegalArgumentException reading "string not-a-curve not
        // an OID" — accurate about the byte it choked on, silent about the curve the caller named.
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", provider);
        InvalidAlgorithmParameterException e = assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> generator.initialize(new ECGenParameterSpec("not-a-curve")));
        assertTrue(e.getMessage().contains("not-a-curve"), e.getMessage());
    }

    @Test
    @DisplayName("a token failure surfaces as a ProviderException naming the algorithm")
    void tokenFailureIsWrapped() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", provider);
        fixture.token().failNextWith(org.pkcs11.jacknji11.CKR.DEVICE_ERROR);

        ProviderException e = assertThrows(ProviderException.class, generator::generateKeyPair);
        assertTrue(e.getMessage().contains("RSA"), e.getMessage());
    }

    @Test
    @DisplayName("the generated key signs through this provider")
    void generatedKeyIsUsable() throws Exception {
        // The whole point of generating on the token: the private key never leaves it, so the only
        // way to confirm the pair is a pair is to sign with one half and verify with the other.
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", provider);
        KeyPair pair = generator.generateKeyPair();
        byte[] message = "generated through the JCA".getBytes(
                java.nio.charset.StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("SHA256withRSA", provider);
        signer.initSign(pair.getPrivate());
        signer.update(message);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA",
                BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(pair.getPublic());
        verifier.update(message);
        assertTrue(verifier.verify(signature));
    }
}

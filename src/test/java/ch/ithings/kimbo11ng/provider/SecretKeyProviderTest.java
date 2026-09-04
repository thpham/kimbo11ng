/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyException;
import java.security.ProviderException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The provider-level pieces of symmetric support, below the crypto token.
 *
 * <p>{@code SymmetricKeyTest} exercises the EJBCA-facing path; this one covers what that path never
 * reaches — the argument refusals, the handle re-resolution and the identity rules that only matter
 * when something has already gone wrong.
 */
@DisplayName("secret keys in the provider")
class SecretKeyProviderTest {

    private final List<TestSlot> fixtures = new ArrayList<>();

    @AfterEach
    void closeSlots() {
        fixtures.forEach(TestSlot::close);
    }

    private TestSlot newSlot(FakeToken token) throws Exception {
        TestSlot fixture = new TestSlot(token).loggedIn();
        fixtures.add(fixture);
        return fixture;
    }

    private static SecretKeyType hmac256() {
        return SecretKeyType.lookup("HmacSHA256").orElseThrow();
    }

    private Kimbo11ngSecretKey generate(TestSlot slot, SecretKeyType type) {
        return (Kimbo11ngSecretKey) new Kimbo11ngKeyGeneratorSpiHarness(slot, type).generate();
    }

    /** {@code KeyGeneratorSpi}'s methods are protected, so a same-package harness calls them. */
    private static final class Kimbo11ngKeyGeneratorSpiHarness {
        private final Kimbo11ngKeyGeneratorSpi spi;

        Kimbo11ngKeyGeneratorSpiHarness(TestSlot slot, SecretKeyType type) {
            this.spi = new Kimbo11ngKeyGeneratorSpi(slot.slot(), type);
        }

        SecretKey generate() {
            return spi.engineGenerateKey();
        }

        void init(int bits) {
            spi.engineInit(bits, null);
        }

        void init(java.security.spec.AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            spi.engineInit(params, null);
        }

        void initDefault() {
            spi.engineInit((java.security.SecureRandom) null);
        }
    }

    // ---------------------------------------------------------------- the algorithm table

    @Test
    @DisplayName("looks algorithms up case-insensitively and refuses the unknown")
    void lookup() {
        assertEquals("HmacSHA256", SecretKeyType.lookup("hmacsha256").orElseThrow().jcaName());
        assertEquals("HmacSHA256", SecretKeyType.lookup("  HMACSHA256 ").orElseThrow().jcaName());
        assertTrue(SecretKeyType.lookup("Blowfish").isEmpty());
        assertTrue(SecretKeyType.lookup(null).isEmpty());
    }

    @Test
    @DisplayName("validates key lengths per algorithm")
    void keyLengths() {
        SecretKeyType aes = SecretKeyType.lookup("AES").orElseThrow();
        assertEquals(256, aes.validateBits(0), "0 means the algorithm's default");
        assertEquals(128, aes.validateBits(128));
        assertThrows(IllegalArgumentException.class, () -> aes.validateBits(512),
                "AES has three legal sizes and 512 is not one");
        assertThrows(IllegalArgumentException.class, () -> aes.validateBits(129),
                "a key that is not a whole number of bytes cannot exist on a token");

        SecretKeyType hmac = hmac256();
        assertEquals(256, hmac.validateBits(256));
        assertEquals(512, hmac.validateBits(512), "a longer HMAC key is allowed");
        assertThrows(IllegalArgumentException.class, () -> hmac.validateBits(128));
    }

    @Test
    @DisplayName("AES has no MAC length, and says so rather than inventing one")
    void aesHasNoMacLength() {
        SecretKeyType aes = SecretKeyType.lookup("AES").orElseThrow();
        assertFalse(aes.isMac());
        assertFalse(aes.usableHere());
        assertThrows(IllegalStateException.class, aes::macLengthBytes);
        assertEquals("AES", aes.toString());
    }

    // ---------------------------------------------------------------- generation

    @Test
    @DisplayName("refuses algorithm parameters, which none of these mechanisms take")
    void refusesParameters() throws Exception {
        TestSlot slot = newSlot(new FakeToken());
        Kimbo11ngKeyGeneratorSpiHarness harness =
                new Kimbo11ngKeyGeneratorSpiHarness(slot, hmac256());

        assertThrows(InvalidAlgorithmParameterException.class,
                () -> harness.init(new IvParameterSpec(new byte[16])));
    }

    @Test
    @DisplayName("reports a bad key size as an InvalidParameterException, per the JCA contract")
    void badKeySizeIsAJcaParameterError() throws Exception {
        TestSlot slot = newSlot(new FakeToken());
        Kimbo11ngKeyGeneratorSpiHarness harness =
                new Kimbo11ngKeyGeneratorSpiHarness(slot, hmac256());

        assertThrows(InvalidParameterException.class, () -> harness.init(64));
    }

    @Test
    @DisplayName("init(SecureRandom) resets the length to the algorithm's default")
    void initWithRandomResetsTheLength() throws Exception {
        TestSlot slot = newSlot(new FakeToken());
        Kimbo11ngKeyGeneratorSpiHarness harness =
                new Kimbo11ngKeyGeneratorSpiHarness(slot, hmac256());
        harness.init(512);
        harness.initDefault();

        Kimbo11ngSecretKey key = (Kimbo11ngSecretKey) harness.generate();
        assertEquals(32, valueLenOf(slot, key), "back to the 256-bit default");
    }

    @Test
    @DisplayName("refuses to generate when the token does not advertise CKF_GENERATE")
    void refusesAMechanismTheTokenLacks() throws Exception {
        FakeToken token = new FakeToken();
        token.hideMechanism(CKM.GENERIC_SECRET_KEY_GEN);
        TestSlot slot = newSlot(token);
        Kimbo11ngKeyGeneratorSpiHarness harness =
                new Kimbo11ngKeyGeneratorSpiHarness(slot, hmac256());

        ProviderException e = assertThrows(ProviderException.class, harness::generate);
        assertTrue(e.getMessage().contains("CKF_GENERATE"), e.getMessage());
    }

    @Test
    @DisplayName("the generated object is sensitive, non-extractable and marked for signing")
    void templateIsTheOneWeAskedFor() throws Exception {
        TestSlot slot = newSlot(new FakeToken());
        Kimbo11ngSecretKey key = generate(slot, hmac256());

        long handle = slot.onSession((ce, session) -> key.objectHandle(ce, session));
        assertTrue(booleanAttribute(slot, handle, CKA.SENSITIVE));
        assertFalse(booleanAttribute(slot, handle, CKA.EXTRACTABLE));
        assertTrue(booleanAttribute(slot, handle, CKA.SIGN));
        assertTrue(booleanAttribute(slot, handle, CKA.TOKEN));
    }

    private boolean booleanAttribute(TestSlot slot, long handle, long cka) throws Exception {
        return slot.onSession((ce, session) ->
                Boolean.TRUE.equals(ce.GetAttributeValue(session, handle, cka).getValueBool()));
    }

    private int valueLenOf(TestSlot slot, Kimbo11ngSecretKey key) {
        try {
            long handle = slot.onSession((ce, session) -> key.objectHandle(ce, session));
            return slot.onSession((ce, session) -> (int) (long) ce
                    .GetAttributeValue(session, handle, CKA.VALUE_LEN).getValueLong());
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    // ---------------------------------------------------------------- the key object

    @Test
    @DisplayName("re-resolves its handle after the slot invalidates them")
    void reResolvesItsHandle() throws Exception {
        TestSlot slot = newSlot(new FakeToken());
        Kimbo11ngSecretKey key = generate(slot, hmac256());
        long before = slot.onSession((ce, session) -> key.objectHandle(ce, session));

        slot.slot().invalidateHandles();

        long after = slot.onSession((ce, session) -> key.objectHandle(ce, session));
        assertEquals(before, after, "the fake keeps handles stable; the point is that it looked"
                + " the key up again rather than trusting a cached number");
    }

    @Test
    @DisplayName("says the key is gone rather than failing later with a handle error")
    void namesAMissingKey() throws Exception {
        TestSlot slot = newSlot(new FakeToken());
        Kimbo11ngSecretKey key = generate(slot, hmac256());
        long handle = slot.onSession((ce, session) -> key.objectHandle(ce, session));
        slot.onSession((ce, session) -> {
            ce.DestroyObject(session, handle);
            return null;
        });
        slot.slot().invalidateHandles();
        key.invalidateHandle();

        KeyException e = assertThrows(KeyException.class,
                () -> slot.onSession((ce, session) -> key.objectHandle(ce, session)));
        assertTrue(e.getMessage().contains("no longer holds a secret key"), e.getMessage());
    }

    @Test
    @DisplayName("identity is the key on the token, not the Java object")
    void identity() throws Exception {
        TestSlot slot = newSlot(new FakeToken());
        Kimbo11ngSecretKey key = generate(slot, hmac256());
        Kimbo11ngSecretKey same = new Kimbo11ngSecretKey(key.getAlgorithm(), key.slot(), key.ref());
        Kimbo11ngSecretKey other = generate(slot, hmac256());

        assertEquals(key, same);
        assertEquals(key.hashCode(), same.hashCode());
        assertNotEquals(key, other);
        assertNotEquals(key, "not a key");
        assertEquals(key, key);
        assertTrue(key.toString().contains(key.getAlias()));
    }

    @Test
    @DisplayName("refuses serialization, which would produce a key naming nothing")
    void refusesSerialization() throws Exception {
        TestSlot slot = newSlot(new FakeToken());
        Kimbo11ngSecretKey key = generate(slot, hmac256());

        assertThrows(java.io.NotSerializableException.class, () -> {
            try (ObjectOutputStream out =
                    new ObjectOutputStream(java.io.OutputStream.nullOutputStream())) {
                out.writeObject(key);
            }
        });
    }

    // ---------------------------------------------------------------- the MAC

    @Test
    @DisplayName("refuses to be built for an algorithm that is not a MAC")
    void macSpiRefusesAes() {
        SecretKeyType aes = SecretKeyType.lookup("AES").orElseThrow();
        assertThrows(IllegalArgumentException.class, () -> new Kimbo11ngMacSpi(aes));
    }

    @Test
    @DisplayName("refuses parameters and refuses a null key")
    void macRefusesBadInit() {
        Kimbo11ngMacSpi mac = new Kimbo11ngMacSpi(hmac256());
        assertThrows(InvalidAlgorithmParameterException.class,
                () -> mac.engineInit(null, new IvParameterSpec(new byte[16])));
        assertThrows(InvalidKeyException.class, () -> mac.engineInit(null, null));
    }

    @Test
    @DisplayName("refuses a key whose slot is gone, as a deserialized one would be")
    void macRefusesASlotlessKey() {
        Kimbo11ngMacSpi mac = new Kimbo11ngMacSpi(hmac256());
        Kimbo11ngSecretKey orphan = new Kimbo11ngSecretKey("HmacSHA256", null,
                new P11KeyRef(null, "orphan", null));

        InvalidKeyException e = assertThrows(InvalidKeyException.class,
                () -> mac.engineInit(orphan, null));
        assertTrue(e.getMessage().contains("no slot"), e.getMessage());
    }

    @Test
    @DisplayName("an uninitialized MAC says so instead of producing bytes")
    void macRefusesToFinishUninitialized() {
        Kimbo11ngMacSpi mac = new Kimbo11ngMacSpi(hmac256());
        assertEquals(32, mac.engineGetMacLength());
        assertThrows(IllegalStateException.class, mac::engineDoFinal);
    }

    @Test
    @DisplayName("byte-at-a-time updates and a reset agree with the bulk path")
    void macBuffersAndResets() throws Exception {
        TestSlot slot = newSlot(new FakeToken());
        Kimbo11ngSecretKey key = generate(slot, hmac256());
        byte[] message = "one two three".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        Mac bulk = Mac.getInstance("HmacSHA256", Kimbo11ngProvider.forToken(
                new TokenRuntime(slot.slot(), runtimeAlgorithms(slot), false,
                        PublicKeyReader.Policy.LENIENT)));
        bulk.init(key);
        byte[] expected = bulk.doFinal(message);

        Kimbo11ngMacSpi streamed = new Kimbo11ngMacSpi(hmac256());
        streamed.engineInit(key, null);
        // Discarded by the reset: what follows must not depend on it.
        streamed.engineUpdate((byte) 0x7F);
        streamed.engineReset();
        for (byte b : message) {
            streamed.engineUpdate(b);
        }
        assertEquals(java.util.Arrays.toString(expected),
                java.util.Arrays.toString(streamed.engineDoFinal()));

        // And the offset/length overload, which EJBCA's ProtectionStringBuilder path would use.
        streamed.engineInit(key, null);
        byte[] padded = new byte[message.length + 4];
        System.arraycopy(message, 0, padded, 2, message.length);
        streamed.engineUpdate(padded, 2, message.length);
        assertEquals(java.util.Arrays.toString(expected),
                java.util.Arrays.toString(streamed.engineDoFinal()));
    }

    @Test
    @DisplayName("reports a token failure as a ProviderException naming the mechanism")
    void macFailureIsNamed() throws Exception {
        FakeToken token = new FakeToken();
        TestSlot slot = newSlot(token);
        Kimbo11ngSecretKey key = generate(slot, hmac256());

        Kimbo11ngMacSpi mac = new Kimbo11ngMacSpi(hmac256());
        mac.engineInit(key, null);
        mac.engineUpdate(new byte[] {1}, 0, 1);
        token.failNextWith(org.pkcs11.jacknji11.CKR.FUNCTION_FAILED);

        ProviderException e = assertThrows(ProviderException.class, mac::engineDoFinal);
        assertTrue(e.getMessage().contains(Long.toHexString(CKM.SHA256_HMAC)), e.getMessage());
    }

    /** The algorithm support a runtime needs; the profile content is irrelevant here. */
    private static ch.ithings.kimbo11ng.profile.AlgorithmSupport runtimeAlgorithms(TestSlot slot) {
        return ch.ithings.kimbo11ng.profile.AlgorithmSupport.compute(
                new ch.ithings.kimbo11ng.profile.Pkcs11v32Profile(),
                slot.slot().capabilities(), true);
    }

    @Test
    @DisplayName("a secret key is found by its own object class, not the private-key one")
    void resolvesByObjectClass() throws Exception {
        TestSlot slot = newSlot(new FakeToken());
        Kimbo11ngSecretKey key = generate(slot, hmac256());
        P11KeyRef ref = key.ref();

        long asSecret = slot.onSession((ce, session) -> ref.resolve(ce, session, CKO.SECRET_KEY));
        long asPrivate = slot.onSession((ce, session) -> ref.resolve(ce, session, CKO.PRIVATE_KEY));

        assertTrue(asSecret >= 0);
        assertEquals(-1L, asPrivate,
                "searching the wrong class must find nothing rather than the secret key");
    }
}

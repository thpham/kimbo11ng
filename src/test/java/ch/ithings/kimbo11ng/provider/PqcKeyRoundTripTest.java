/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.p11.NativeProviderFactory;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.Pkcs11v32Profile;
import org.bouncycastle.jcajce.interfaces.MLDSAKey;
import org.bouncycastle.jcajce.interfaces.MLKEMKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.LongRef;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Generating a post-quantum key on the token and reading its public key back.
 *
 * <p>The property under test is the one EJBCA depends on and nothing else checks: the returned
 * object must be a BouncyCastle {@code MLDSAKey} / {@code SLHDSAKey} / {@code MLKEMKey}. EJBCA's
 * {@code AlgorithmTools.getSignatureAlgorithms} decides what a key can sign with by
 * {@code instanceof} against exactly those interfaces and returns an empty list otherwise, so a
 * key that is merely "correct bytes" fails much later as "No valid signing algorithm found".
 *
 * <p>Which is why there is no opaque-wrapper fallback anywhere in this path — see the deleted
 * {@code RawPqcPublicKey}.
 */
@DisplayName("PQC key round trip")
class PqcKeyRoundTripTest {

    private FakeToken fake;
    private CryptokiDevice device;
    private final Pkcs11v32Profile profile = new Pkcs11v32Profile();

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void openDevice() throws Exception {
        fake = new FakeToken();
        NativeProviderFactory factory = path -> fake;
        device = new CryptokiDevice("/nonexistent/libfake.so", 0L, factory);
        device.login("1234".toCharArray());
    }

    /** Generates through the production templates and returns the public handle. */
    private long generate(AlgorithmEntry entry) throws Exception {
        KeyTemplates.Pair templates = KeyTemplates.pqc(
                entry.canonicalName().getBytes(StandardCharsets.UTF_8),
                KeyTemplates.newKeyId(), entry, profile);
        LongRef pub = new LongRef();
        LongRef priv = new LongRef();
        device.getCe().GenerateKeyPair(device.getOrOpenSession(),
                new CKM(entry.ckmKeyPairGen()), templates.pub(), templates.priv(), pub, priv);
        return pub.value();
    }

    @ParameterizedTest
    @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    @DisplayName("materialises an ML-DSA key BouncyCastle recognises")
    void mlDsa(String keySpec) throws Exception {
        AlgorithmEntry entry = profile.lookup(keySpec).orElseThrow();
        PublicKey key = Kimbo11ngPublicKey.readPqcPublicKey(
                device.getCe(), device.getOrOpenSession(), generate(entry), entry);

        assertInstanceOf(MLDSAKey.class, key,
                "EJBCA resolves signature algorithms by instanceof MLDSAKey");
        // The OID in the encoding is what ends up in the certificate's SubjectPublicKeyInfo, so a
        // key generated as ML-DSA-44 must not come back labelled ML-DSA-65.
        assertTrue(new String(key.getEncoded(), StandardCharsets.ISO_8859_1).length() > 0);
        assertEquals(keySpec, ((MLDSAKey) key).getParameterSpec().getName()
                .toUpperCase(java.util.Locale.ROOT));
    }

    @ParameterizedTest
    @ValueSource(strings = {"SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-128F",
            "SLH-DSA-SHAKE-256S"})
    @DisplayName("materialises an SLH-DSA key BouncyCastle recognises")
    void slhDsa(String keySpec) throws Exception {
        AlgorithmEntry entry = profile.lookup(keySpec).orElseThrow();
        PublicKey key = Kimbo11ngPublicKey.readPqcPublicKey(
                device.getCe(), device.getOrOpenSession(), generate(entry), entry);
        assertInstanceOf(SLHDSAKey.class, key);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    @DisplayName("materialises an ML-KEM key BouncyCastle recognises")
    void mlKem(String keySpec) throws Exception {
        AlgorithmEntry entry = profile.lookup(keySpec).orElseThrow();
        PublicKey key = Kimbo11ngPublicKey.readPqcPublicKey(
                device.getCe(), device.getOrOpenSession(), generate(entry), entry);
        assertInstanceOf(MLKEMKey.class, key);
    }

    @Test
    @DisplayName("refuses to label an ML-DSA-44 key as ML-DSA-87")
    void mismatchedParameterSetIsRejected() throws Exception {
        long handle = generate(profile.lookup("ML-DSA-44").orElseThrow());
        AlgorithmEntry wrong = profile.lookup("ML-DSA-87").orElseThrow();

        InvalidKeyException e = assertThrows(InvalidKeyException.class, () ->
                Kimbo11ngPublicKey.readPqcPublicKey(device.getCe(), device.getOrOpenSession(),
                        handle, wrong));
        assertTrue(e.getMessage().contains("1312"), () -> "message: " + e.getMessage());
        assertTrue(e.getMessage().contains("ML-DSA-87"), () -> "message: " + e.getMessage());
    }

    @Test
    @DisplayName("BouncyCastle does not catch this, which is why the check above exists")
    void bouncyCastleAcceptsAMislabelledKey() throws Exception {
        // Characterization, not aspiration. Feed BC 1312 bytes of ML-DSA-44 material under the
        // ML-DSA-87 OID and it returns a key that reports itself as ML-DSA-87. EJBCA would put
        // that OID in the certificate. If a future BouncyCastle starts rejecting this, this test
        // fails and the length check can be reconsidered — until then it is load-bearing.
        byte[] material = new byte[1312];
        new java.security.SecureRandom().nextBytes(material);
        byte[] spki = new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        profile.lookup("ML-DSA-87").orElseThrow().oid()), material).getEncoded();

        PublicKey key = java.security.KeyFactory
                .getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME)
                .generatePublic(new java.security.spec.X509EncodedKeySpec(spki));
        assertEquals("ML-DSA-87", ((MLDSAKey) key).getParameterSpec().getName()
                .toUpperCase(java.util.Locale.ROOT));
    }

    @Test
    @DisplayName("refuses a token SubjectPublicKeyInfo that names a different algorithm")
    void mismatchedSpkiOidIsRejected() throws Exception {
        AlgorithmEntry entry = profile.lookup("ML-DSA-65").orElseThrow();
        fake.pqcSpkiOid(profile.lookup("ML-DSA-44").orElseThrow().oid().getId());
        long handle = generate(entry);

        InvalidKeyException e = assertThrows(InvalidKeyException.class, () ->
                Kimbo11ngPublicKey.readPqcPublicKey(device.getCe(), device.getOrOpenSession(),
                        handle, entry));
        assertTrue(e.getMessage().contains("Refusing to guess"), () -> "message: " + e.getMessage());
    }

    @Test
    @DisplayName("reads a SubjectPublicKeyInfo already wrapped by the token")
    void acceptsSpkiFromTheToken() throws Exception {
        // PKCS#11 v3.2 leaves it open whether CKA_VALUE holds raw key material or a full SPKI, and
        // tokens differ. Both must work without configuration.
        AlgorithmEntry entry = profile.lookup("ML-DSA-65").orElseThrow();
        long rawHandle = generate(entry);
        PublicKey fromRaw = Kimbo11ngPublicKey.readPqcPublicKey(
                device.getCe(), device.getOrOpenSession(), rawHandle, entry);

        fake.pqcSpkiOid(entry.oid().getId());
        long spkiHandle = generate(entry);
        PublicKey fromSpki = Kimbo11ngPublicKey.readPqcPublicKey(
                device.getCe(), device.getOrOpenSession(), spkiHandle, entry);

        assertInstanceOf(MLDSAKey.class, fromSpki);
        assertEquals(fromRaw.getAlgorithm(), fromSpki.getAlgorithm());
        assertEquals(fromRaw.getEncoded().length, fromSpki.getEncoded().length,
                "both paths must produce the same encoding shape");
    }

    @Test
    @DisplayName("rejects an empty CKA_VALUE rather than building an empty key")
    void emptyValueIsRejected() throws Exception {
        AlgorithmEntry entry = profile.lookup("ML-DSA-65").orElseThrow();
        long handle = generate(entry);
        fake.emptyAttribute(org.pkcs11.jacknji11.CKA.VALUE);

        InvalidKeyException e = assertThrows(InvalidKeyException.class, () ->
                Kimbo11ngPublicKey.readPqcPublicKey(device.getCe(), device.getOrOpenSession(),
                        handle, entry));
        assertTrue(e.getMessage().contains("CKA_VALUE is empty"), () -> "message: " + e.getMessage());
    }
}

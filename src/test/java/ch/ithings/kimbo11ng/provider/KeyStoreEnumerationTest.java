/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.p11.NativeProviderFactory;
import ch.ithings.kimbo11ng.profile.AbstractTableProfile;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.Pkcs11v32Profile;
import ch.ithings.kimbo11ng.profile.PqcFamily;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.interfaces.MLDSAKey;
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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Loading the keystore: reading whatever keys are already on a token and working out what each one
 * is.
 *
 * <p>This is the path that runs on every EJBCA restart against keys someone else's software may
 * have generated, so it has to resolve a key from its attributes alone. Getting it wrong is not a
 * missing key — it is a key loaded under the wrong algorithm.
 */
@DisplayName("keystore enumeration")
class KeyStoreEnumerationTest {

    /** A profile whose ML-DSA entries use vendor-range constants, as a Luna table would. */
    private static final class VendorProfile extends AbstractTableProfile {

        static final long VENDOR_CKK_ML_DSA = 0x8000_0100L;
        static final long VENDOR_CKM_ML_DSA_KEYGEN = 0x8000_0200L;

        VendorProfile() {
            super(List.of(new AlgorithmEntry("ML-DSA-65", PqcFamily.ML_DSA,
                    VENDOR_CKK_ML_DSA, VENDOR_CKM_ML_DSA_KEYGEN, 0x8000_0201L,
                    OptionalLong.of(2L), new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.18"),
                    1952, Set.of(AlgorithmEntry.KeyOp.SIGN, AlgorithmEntry.KeyOp.VERIFY))));
        }

        @Override
        public String name() {
            return "test-vendor";
        }

        @Override
        public long ckaParameterSet() {
            return 0x0000_061DL;
        }
    }

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

    private Kimbo11ngKeyStoreSpi load() throws Exception {
        return load(profile);
    }

    private Kimbo11ngKeyStoreSpi load(ch.ithings.kimbo11ng.profile.PqcMechanismProfile p)
            throws Exception {
        Kimbo11ngKeyStoreSpi spi = new Kimbo11ngKeyStoreSpi(new TokenRuntime(device, p));
        spi.engineLoad(null, null);
        return spi;
    }

    private void generateRsa(String alias) throws Exception {
        KeyTemplates.Pair t = KeyTemplates.rsa(alias.getBytes(StandardCharsets.UTF_8),
                KeyTemplates.newKeyId(), 2048);
        device.getCe().GenerateKeyPair(device.getOrOpenSession(),
                new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), t.pub(), t.priv(),
                new LongRef(), new LongRef());
    }

    private void generateEc(String alias, String curve) throws Exception {
        KeyTemplates.Pair t = KeyTemplates.ec(alias.getBytes(StandardCharsets.UTF_8),
                KeyTemplates.newKeyId(), curve);
        device.getCe().GenerateKeyPair(device.getOrOpenSession(), new CKM(CKM.EC_KEY_PAIR_GEN),
                t.pub(), t.priv(), new LongRef(), new LongRef());
    }

    private void generatePqc(String alias, AlgorithmEntry entry,
            ch.ithings.kimbo11ng.profile.PqcMechanismProfile p, long ckmKeyGen) throws Exception {
        KeyTemplates.Pair t = KeyTemplates.pqc(alias.getBytes(StandardCharsets.UTF_8),
                KeyTemplates.newKeyId(), entry, p);
        device.getCe().GenerateKeyPair(device.getOrOpenSession(), new CKM(ckmKeyGen),
                t.pub(), t.priv(), new LongRef(), new LongRef());
    }

    @Test
    @DisplayName("loads every key on the token under its alias")
    void loadsAllAlgorithms() throws Exception {
        generateRsa("rsaKey");
        generateEc("ecKey", "P-256");
        generatePqc("mldsaKey", profile.lookup("ML-DSA-65").orElseThrow(), profile,
                profile.lookup("ML-DSA-65").orElseThrow().ckmKeyPairGen());

        Kimbo11ngKeyStoreSpi spi = load();

        assertEquals(3, spi.engineSize());
        assertEquals(Set.of("rsaKey", "ecKey", "mldsaKey"),
                Set.copyOf(Collections.list(spi.engineAliases())));
        for (String alias : new String[] {"rsaKey", "ecKey", "mldsaKey"}) {
            assertTrue(spi.engineContainsAlias(alias), alias);
            assertTrue(spi.engineIsKeyEntry(alias), alias);
            assertFalse(spi.engineIsCertificateEntry(alias), alias);
            assertNotNull(spi.engineGetKey(alias, null), alias);
            assertNotNull(spi.getPublicKey(alias), () -> "public key for " + alias);
        }
    }

    @Test
    @DisplayName("gives each key the algorithm its attributes say it is")
    void resolvesAlgorithms() throws Exception {
        generateRsa("rsaKey");
        generateEc("ecKey", "P-384");
        generatePqc("mldsaKey", profile.lookup("ML-DSA-87").orElseThrow(), profile,
                profile.lookup("ML-DSA-87").orElseThrow().ckmKeyPairGen());

        Kimbo11ngKeyStoreSpi spi = load();

        assertEquals("RSA", spi.engineGetKey("rsaKey", null).getAlgorithm());
        assertEquals("EC", spi.engineGetKey("ecKey", null).getAlgorithm());
        assertEquals("ML-DSA", spi.engineGetKey("mldsaKey", null).getAlgorithm());
        // Resolved from CKA_KEY_TYPE plus CKA_PARAMETER_SET, with no help from the caller: this is
        // the restart path, where nothing remembers what the key was generated as.
        assertInstanceOf(MLDSAKey.class, spi.getPublicKey("mldsaKey"));
        assertEquals("ML-DSA-87", ((MLDSAKey) spi.getPublicKey("mldsaKey"))
                .getParameterSpec().getName().toUpperCase(java.util.Locale.ROOT));
    }

    @Test
    @DisplayName("resolves a key whose vendor key type the binding reports as negative")
    void vendorKeyTypeResolves() throws Exception {
        // The end-to-end form of the CkULong problem: 0x80000100 comes back from CKA_KEY_TYPE
        // sign-extended, and without normalisation this key is skipped as an unknown CKK.
        VendorProfile vendor = new VendorProfile();
        AlgorithmEntry entry = vendor.lookup("ML-DSA-65").orElseThrow();
        // The fake generates by mechanism, so ask it for ML-DSA material under the standard CKM
        // while the templates carry the vendor key type the profile declares.
        generatePqc("vendorKey", entry, vendor,
                profile.lookup("ML-DSA-65").orElseThrow().ckmKeyPairGen());

        Kimbo11ngKeyStoreSpi spi = load(vendor);

        assertTrue(spi.engineContainsAlias("vendorKey"),
                "a vendor-key-type key must not be skipped as unknown");
        assertEquals("ML-DSA", spi.engineGetKey("vendorKey", null).getAlgorithm());
    }

    @Test
    @DisplayName("skips a key the profile cannot describe rather than guessing")
    void unknownKeyTypeIsSkipped() throws Exception {
        generateRsa("rsaKey");
        // A key type no profile entry claims. Loading it under some default algorithm is how a
        // key ends up signing with the wrong mechanism, so it must be left out entirely.
        long session = device.getOrOpenSession();
        CKA[] pub = {
            new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
            new CKA(CKA.KEY_TYPE, 0x0000_00FFL),
            new CKA(CKA.LABEL, "mysteryKey".getBytes(StandardCharsets.UTF_8)),
            new CKA(CKA.VALUE, new byte[32]),
            new CKA(CKA.TOKEN, true),
        };
        CKA[] priv = {
            new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
            new CKA(CKA.KEY_TYPE, 0x0000_00FFL),
            new CKA(CKA.LABEL, "mysteryKey".getBytes(StandardCharsets.UTF_8)),
            new CKA(CKA.TOKEN, true),
        };
        device.getCe().CreateObject(session, pub);
        device.getCe().CreateObject(session, priv);

        Kimbo11ngKeyStoreSpi spi = load();

        assertFalse(spi.engineContainsAlias("mysteryKey"));
        assertNull(spi.engineGetKey("mysteryKey", null));
        assertTrue(spi.engineContainsAlias("rsaKey"),
                "one unreadable key must not stop the others loading");
    }

    @Test
    @DisplayName("loads a PQC key even when the token hides CKA_PARAMETER_SET, if unambiguous")
    void missingParameterSetOnASingleEntryProfile() throws Exception {
        VendorProfile vendor = new VendorProfile();
        generatePqc("vendorKey", vendor.lookup("ML-DSA-65").orElseThrow(), vendor,
                profile.lookup("ML-DSA-65").orElseThrow().ckmKeyPairGen());
        fake.omitAttribute(vendor.ckaParameterSet());

        // One entry has this key type, so there is exactly one answer and no guessing involved.
        assertTrue(load(vendor).engineContainsAlias("vendorKey"));
    }

    @Test
    @DisplayName("skips a PQC key when the parameter set is missing and the type is ambiguous")
    void missingParameterSetWhenAmbiguous() throws Exception {
        generatePqc("mldsaKey", profile.lookup("ML-DSA-65").orElseThrow(), profile,
                profile.lookup("ML-DSA-65").orElseThrow().ckmKeyPairGen());
        fake.omitAttribute(profile.ckaParameterSet());

        // Three ML-DSA parameter sets share CKK_ML_DSA. Picking one would mean a certificate
        // asserting an algorithm the key is not.
        assertFalse(load().engineContainsAlias("mldsaKey"),
                "an unresolvable parameter set must not fall back to a default");
    }

    @Test
    @DisplayName("reloading replaces the previous contents instead of accumulating")
    void reloadIsIdempotent() throws Exception {
        generateRsa("rsaKey");
        Kimbo11ngKeyStoreSpi spi = load();
        assertEquals(1, spi.engineSize());

        spi.engineLoad(null, null);
        assertEquals(1, spi.engineSize(), "a second load must not double the aliases");

        spi.clear();
        assertEquals(0, spi.engineSize());
    }

    @Test
    @DisplayName("has no certificates and no creation dates to report")
    void noCertificateEntries() throws Exception {
        generateRsa("rsaKey");
        Kimbo11ngKeyStoreSpi spi = load();

        // EJBCA stores certificates in its own database, not on the token. Returning null here is
        // the contract; the previous code did an HSM round-trip and discarded the result.
        assertNull(spi.engineGetCertificate("rsaKey"));
        assertNull(spi.engineGetCertificateChain("rsaKey"));
        assertNull(spi.engineGetCreationDate("rsaKey"));
        assertNull(spi.engineGetCertificateAlias(null));
    }

    @Test
    @DisplayName("reads the RSA public key back with the right modulus")
    void rsaPublicKeyIsUsable() throws Exception {
        generateRsa("rsaKey");
        Optional<java.security.PublicKey> pub =
                Optional.ofNullable(load().getPublicKey("rsaKey"));
        java.security.interfaces.RSAPublicKey rsa =
                (java.security.interfaces.RSAPublicKey) pub.orElseThrow();
        assertEquals(2048, rsa.getModulus().bitLength());
        assertEquals(BigInteger.valueOf(65537), rsa.getPublicExponent());
    }

    @Test
    @DisplayName("matches the public key to the private key by label")
    void publicKeyIsMatchedToItsPrivateKey() throws Exception {
        generateEc("ecOne", "P-256");
        generateEc("ecTwo", "P-384");

        Kimbo11ngKeyStoreSpi spi = load();

        // Two EC keys differing only by curve: if the pairing were by anything looser than the
        // label, one alias would get the other's public key and every signature would fail
        // verification for a reason nothing in the logs would explain.
        assertEquals(256, ((java.security.interfaces.ECPublicKey) spi.getPublicKey("ecOne"))
                .getParams().getCurve().getField().getFieldSize());
        assertEquals(384, ((java.security.interfaces.ECPublicKey) spi.getPublicKey("ecTwo"))
                .getParams().getCurve().getField().getFieldSize());
        assertEquals(CKK.EC, CKK.EC, "sanity: both were generated as EC");
    }
}

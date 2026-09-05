/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.CkULong;
import ch.ithings.kimbo11ng.p11.Pkcs11v32;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.KemUsage;
import ch.ithings.kimbo11ng.profile.Pkcs11v32Profile;
import ch.ithings.kimbo11ng.profile.PqcFamily;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKO;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The key-generation templates.
 *
 * <p>These attributes are set once, at generation, and can never be changed on a token object
 * afterwards — an HSM will refuse. A key generated {@code CKA_EXTRACTABLE} or without
 * {@code CKA_SIGN} has to be regenerated, and for a CA root that means a new certificate. So the
 * template content is asserted attribute by attribute rather than inferred from a signing test.
 */
@DisplayName("KeyTemplates")
class KeyTemplatesTest {

    private static final byte[] LABEL = "signKey0001".getBytes(StandardCharsets.UTF_8);

    private final Pkcs11v32Profile profile = new Pkcs11v32Profile();

    private static Optional<CKA> find(List<CKA> template, long type) {
        return template.stream().filter(a -> a.type == type).findFirst();
    }

    private static void assertBoolean(List<CKA> template, long type, boolean expected,
            String what) {
        CKA attr = find(template, type)
                .orElseThrow(() -> new AssertionError("template has no " + what));
        assertEquals(expected, attr.getValueBool(), what);
    }

    private static void assertAbsent(List<CKA> template, long type, String what) {
        assertTrue(find(template, type).isEmpty(), () -> "template must not carry " + what);
    }

    @Nested
    @DisplayName("private-key protection, on every algorithm")
    class PrivateKeyProtection {

        /** RSA, EC and a PQC entry all go through the same base, so all three are checked. */
        private List<List<CKA>> allPrivateTemplates() throws Exception {
            byte[] id = KeyTemplates.newKeyId();
            AlgorithmEntry mlDsa = profile.lookup("ML-DSA-65").orElseThrow();
            return List.of(
                    KeyTemplates.rsa(LABEL, id, 2048).privateTemplate(),
                    KeyTemplates.ec(LABEL, id, "P-256").privateTemplate(),
                    KeyTemplates.pqc(LABEL, id, mlDsa, profile).privateTemplate());
        }

        @Test
        @DisplayName("marks every private key sensitive and non-extractable")
        void sensitiveAndNotExtractable() throws Exception {
            for (List<CKA> priv : allPrivateTemplates()) {
                assertBoolean(priv, CKA.SENSITIVE, true, "CKA_SENSITIVE");
                assertBoolean(priv, CKA.EXTRACTABLE, false, "CKA_EXTRACTABLE");
                assertBoolean(priv, CKA.PRIVATE, true, "CKA_PRIVATE");
                assertBoolean(priv, CKA.TOKEN, true, "CKA_TOKEN");
                assertEquals(CKO.PRIVATE_KEY, find(priv, CKA.CLASS).orElseThrow().getValueLong());
            }
        }

        @Test
        @DisplayName("never marks a private key wrappable out of the token")
        void notWrappable() throws Exception {
            for (List<CKA> priv : allPrivateTemplates()) {
                // CKA_EXTRACTABLE false already blocks C_WrapKey, but an explicit
                // CKA_WRAP_WITH_TRUSTED=false or CKA_WRAP=true here would be a contradiction
                // worth catching: the template must simply not mention wrapping the private key.
                assertAbsent(priv, CKA.WRAP, "CKA_WRAP on a private key");
            }
        }
    }

    @Nested
    @DisplayName("CKA_ID")
    class KeyId {

        @Test
        @DisplayName("puts the same id on both halves of the pair")
        void idIsSharedByThePair() {
            byte[] id = KeyTemplates.newKeyId();
            KeyTemplates.Pair pair = KeyTemplates.rsa(LABEL, id, 2048);
            // Phase 3 resolves a key by CKA_ID; if the two halves carried different ids, a
            // private key found by id would have no matching public object.
            assertArrayEquals(id, find(pair.publicTemplate(), CKA.ID).orElseThrow().getValue());
            assertArrayEquals(id, find(pair.privateTemplate(), CKA.ID).orElseThrow().getValue());
        }

        @Test
        @DisplayName("generates 16 distinct random bytes per call")
        void idsAreUnique() {
            Set<String> seen = new HashSet<>();
            for (int i = 0; i < 256; i++) {
                byte[] id = KeyTemplates.newKeyId();
                assertEquals(16, id.length);
                assertTrue(seen.add(java.util.Arrays.toString(id)), "CKA_ID repeated");
            }
        }
    }

    @Nested
    @DisplayName("RSA")
    class Rsa {

        @Test
        @DisplayName("requests the modulus size and F4 as the public exponent")
        void modulusAndExponent() {
            KeyTemplates.Pair pair = KeyTemplates.rsa(LABEL, KeyTemplates.newKeyId(), 3072);
            List<CKA> pub = pair.publicTemplate();
            assertEquals(3072L, find(pub, CKA.MODULUS_BITS).orElseThrow().getValueLong());
            assertEquals(CKK.RSA, find(pub, CKA.KEY_TYPE).orElseThrow().getValueLong());
            assertArrayEquals(new byte[] {0x01, 0x00, 0x01},
                    find(pub, CKA.PUBLIC_EXPONENT).orElseThrow().getValue());
        }

        @Test
        @DisplayName("permits sign, decrypt and unwrap on the private key")
        void privateOperations() {
            List<CKA> priv = KeyTemplates.rsa(LABEL, KeyTemplates.newKeyId(), 2048)
                    .privateTemplate();
            // BaseCryptoToken.testKeyPair branches on CKA_DECRYPT (0x105) to run an encryption
            // test and CKA_SIGN (0x108) to run a signing test; RSA must support both.
            assertBoolean(priv, CKA.SIGN, true, "CKA_SIGN");
            assertBoolean(priv, CKA.DECRYPT, true, "CKA_DECRYPT");
            assertBoolean(priv, CKA.UNWRAP, true, "CKA_UNWRAP");
        }
    }

    @Nested
    @DisplayName("EC")
    class Ec {

        @Test
        @DisplayName("names the curve on the public template only")
        void curveOnPublicTemplateOnly() throws Exception {
            KeyTemplates.Pair pair = KeyTemplates.ec(LABEL, KeyTemplates.newKeyId(), "P-384");
            byte[] expected = new ASN1ObjectIdentifier("1.3.132.0.34").getEncoded();
            assertArrayEquals(expected,
                    find(pair.publicTemplate(), CKA.EC_PARAMS).orElseThrow().getValue());
            // Not on the private template: for CKM_EC_KEY_PAIR_GEN the token derives that copy
            // itself, so supplying it sets a read-only attribute and SoftHSMv3 fails the whole
            // generation with CKR_ATTRIBUTE_READ_ONLY.
            assertAbsent(pair.privateTemplate(), CKA.EC_PARAMS,
                    "CKA_EC_PARAMS on an EC private-key generation template");
        }

        @ParameterizedTest
        @CsvSource({
            "P-256,           1.2.840.10045.3.1.7",
            "prime256v1,      1.2.840.10045.3.1.7",
            "secp256r1,       1.2.840.10045.3.1.7",
            "p256,            1.2.840.10045.3.1.7",
            "P_256,           1.2.840.10045.3.1.7",
            "P-384,           1.3.132.0.34",
            "secp384r1,       1.3.132.0.34",
            "P-521,           1.3.132.0.35",
            "secp256k1,       1.3.132.0.10",
            "brainpoolP256r1, 1.3.36.3.3.2.8.1.1.7",
            "brainpoolP384r1, 1.3.36.3.3.2.8.1.1.11",
            "brainpoolP512r1, 1.3.36.3.3.2.8.1.1.13",
        })
        @DisplayName("resolves the curve spellings EJBCA emits")
        void curveSpellings(String name, String expectedOid) {
            assertEquals(expectedOid, KeyTemplates.resolveCurveOid(name));
        }

        @Test
        @DisplayName("falls back to BouncyCastle's table for curves not listed explicitly")
        void bouncyCastleTableFallback() {
            // Not in the switch: proves the table lookup is reached rather than the name being
            // passed through as if it were already an OID.
            assertEquals("1.3.132.0.33", KeyTemplates.resolveCurveOid("secp224r1"));
        }

        @Test
        @DisplayName("passes an unrecognised name through as an OID literal")
        void unknownNamePassesThrough() {
            assertEquals("1.2.3.4", KeyTemplates.resolveCurveOid("1.2.3.4"));
            // A genuinely unknown name is returned unchanged and fails at ASN.1 encoding, which
            // names the curve in the error, rather than silently becoming a different curve.
            assertEquals("no-such-curve", KeyTemplates.resolveCurveOid("no-such-curve"));
        }
    }

    @Nested
    @DisplayName("post-quantum")
    class Pqc {

        @ParameterizedTest
        @ValueSource(strings = {"ML-DSA-44", "ML-DSA-87", "SLH-DSA-SHA2-128S",
                "SLH-DSA-SHAKE-256F"})
        @DisplayName("permits sign and verify for a signature algorithm, and nothing else")
        void signatureAlgorithms(String keySpec) {
            AlgorithmEntry entry = profile.lookup(keySpec).orElseThrow();
            KeyTemplates.Pair pair = KeyTemplates.pqc(LABEL, KeyTemplates.newKeyId(), entry,
                    profile);

            assertBoolean(pair.privateTemplate(), CKA.SIGN, true, "CKA_SIGN");
            assertBoolean(pair.publicTemplate(), CKA.VERIFY, true, "CKA_VERIFY");
            // A PQC signing key that also advertised CKA_DECRYPT would make
            // BaseCryptoToken.testKeyPair run an RSA-style encryption test against it.
            assertAbsent(pair.privateTemplate(), CKA.DECRYPT, "CKA_DECRYPT on a signing key");
            assertAbsent(pair.publicTemplate(), CKA.ENCRYPT, "CKA_ENCRYPT on a signing key");
        }

        @ParameterizedTest
        @ValueSource(strings = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
        @DisplayName("asks for both the v3.2 and the encryption usage attributes, and not signing")
        void kemAlgorithms(String keySpec) {
            AlgorithmEntry entry = profile.lookup(keySpec).orElseThrow();
            KeyTemplates.Pair pair = KeyTemplates.pqc(LABEL, KeyTemplates.newKeyId(), entry,
                    profile);

            // What PKCS#11 v3.2 gates C_EncapsulateKey and C_DecapsulateKey on.
            assertBoolean(pair.publicTemplate(), Pkcs11v32.CKA_ENCAPSULATE, true,
                    "CKA_ENCAPSULATE");
            assertBoolean(pair.privateTemplate(), Pkcs11v32.CKA_DECAPSULATE, true,
                    "CKA_DECAPSULATE");
            // And what EJBCA reads. It compares usage sets against {261} by number to decide the
            // admin UI shows ENCRYPT, and branches testKeyPair on the same constant; it has never
            // heard of 0x634. Correct-per-spec and invisible-to-the-CA is not an improvement.
            assertBoolean(pair.publicTemplate(), CKA.ENCRYPT, true, "CKA_ENCRYPT");
            assertBoolean(pair.privateTemplate(), CKA.DECRYPT, true, "CKA_DECRYPT");

            assertAbsent(pair.privateTemplate(), CKA.SIGN, "CKA_SIGN on an ML-KEM key");
            assertAbsent(pair.publicTemplate(), CKA.VERIFY, "CKA_VERIFY on an ML-KEM key");
        }

        @ParameterizedTest
        @ValueSource(strings = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
        @DisplayName("each kill-switch setting sends exactly the pair it names")
        void kemUsageModes(String keySpec) {
            AlgorithmEntry entry = profile.lookup(keySpec).orElseThrow();

            KeyTemplates.Pair legacy = KeyTemplates.pqc(LABEL, KeyTemplates.newKeyId(), entry,
                    profile, KemUsage.LEGACY);
            assertBoolean(legacy.publicTemplate(), CKA.ENCRYPT, true, "CKA_ENCRYPT");
            assertBoolean(legacy.privateTemplate(), CKA.DECRYPT, true, "CKA_DECRYPT");
            assertAbsent(legacy.publicTemplate(), Pkcs11v32.CKA_ENCAPSULATE,
                    "CKA_ENCAPSULATE under legacy");
            assertAbsent(legacy.privateTemplate(), Pkcs11v32.CKA_DECAPSULATE,
                    "CKA_DECAPSULATE under legacy");

            KeyTemplates.Pair v32 = KeyTemplates.pqc(LABEL, KeyTemplates.newKeyId(), entry,
                    profile, KemUsage.V32);
            assertBoolean(v32.publicTemplate(), Pkcs11v32.CKA_ENCAPSULATE, true,
                    "CKA_ENCAPSULATE");
            assertBoolean(v32.privateTemplate(), Pkcs11v32.CKA_DECAPSULATE, true,
                    "CKA_DECAPSULATE");
            // The mode for a token that refuses CKA_ENCRYPT on a KEM key. It costs the EJBCA
            // reporting above, which is why it is not the default.
            assertAbsent(v32.publicTemplate(), CKA.ENCRYPT, "CKA_ENCRYPT under v32");
            assertAbsent(v32.privateTemplate(), CKA.DECRYPT, "CKA_DECRYPT under v32");
        }

        @Test
        @DisplayName("the kill-switch defaults to both and refuses a value it does not understand")
        void kemUsageProperty() {
            // Unset, blank and absent all mean the default: an operator who has never heard of
            // this property gets a key that both a v3.2 token and EJBCA understand.
            assertEquals(KemUsage.BOTH, KemUsage.parse(null, KemUsage.BOTH));
            assertEquals(KemUsage.BOTH, KemUsage.parse("  ", KemUsage.BOTH));
            assertEquals(KemUsage.V32, KemUsage.parse("v32", KemUsage.BOTH));
            assertEquals(KemUsage.LEGACY, KemUsage.parse(" LEGACY ", KemUsage.BOTH));

            // Not silently defaulted. A typo here would otherwise generate every ML-KEM key with
            // a spelling the operator did not choose, and say nothing about it.
            IllegalArgumentException refused = org.junit.jupiter.api.Assertions.assertThrows(
                    IllegalArgumentException.class, () -> KemUsage.parse("v3.2", KemUsage.BOTH));
            assertTrue(refused.getMessage().contains(KemUsage.PROPERTY),
                    refused.getMessage());
        }

        @Test
        @DisplayName("sends CKA_PARAMETER_SET on both halves when the profile defines one")
        void parameterSetIsSent() {
            AlgorithmEntry entry = profile.lookup("ML-DSA-65").orElseThrow();
            KeyTemplates.Pair pair = KeyTemplates.pqc(LABEL, KeyTemplates.newKeyId(), entry,
                    profile);
            long cka = profile.ckaParameterSet();
            assertEquals(entry.ckpParameterSet().orElseThrow(),
                    find(pair.publicTemplate(), cka).orElseThrow().getValueLong());
            assertEquals(entry.ckpParameterSet().orElseThrow(),
                    find(pair.privateTemplate(), cka).orElseThrow().getValueLong());
        }

        @Test
        @DisplayName("omits CKA_PARAMETER_SET for a vendor entry that has none")
        void parameterSetOmittedWhenAbsent() {
            // Thales may distinguish parameter sets by mechanism rather than attribute. Sending
            // the attribute anyway is rejected as an unknown template item, so the absence has to
            // propagate from the entry to the template.
            AlgorithmEntry vendor = new AlgorithmEntry("VENDOR-ML-DSA-65", PqcFamily.ML_DSA,
                    0x8000_0100L, 0x8000_0200L, 0x8000_0201L, java.util.OptionalLong.empty(),
                    new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.18"), 1952,
                    Set.of(AlgorithmEntry.KeyOp.SIGN, AlgorithmEntry.KeyOp.VERIFY));
            KeyTemplates.Pair pair = KeyTemplates.pqc(LABEL, KeyTemplates.newKeyId(), vendor,
                    profile);
            assertAbsent(pair.publicTemplate(), profile.ckaParameterSet(), "CKA_PARAMETER_SET");
            assertAbsent(pair.privateTemplate(), profile.ckaParameterSet(), "CKA_PARAMETER_SET");
            // Read through CkULong, not getValueLong: JackNJI11 sign-extends every value with bit
            // 31 set, and CKK_VENDOR_DEFINED is 0x80000000, so every vendor key type is affected.
            assertEquals(0x8000_0100L, CkULong.typeCode(
                    find(pair.publicTemplate(), CKA.KEY_TYPE).orElseThrow()));
        }

        @Test
        @DisplayName("survives the binding sign-extending a vendor key type")
        void vendorKeyTypeRoundTrips() {
            // The regression this pins: a Luna table entry written as 0x80000100L would never
            // match the value the token reports, and every key of that type would be skipped at
            // enumeration as "profile does not describe CKK".
            AlgorithmEntry vendor = new AlgorithmEntry("VENDOR-ML-DSA-44", PqcFamily.ML_DSA,
                    0x8000_0100L, 0x8000_0200L, 0x8000_0201L, java.util.OptionalLong.empty(),
                    new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.17"), 1312,
                    Set.of(AlgorithmEntry.KeyOp.SIGN, AlgorithmEntry.KeyOp.VERIFY));
            long asTokenReportsIt = find(
                    KeyTemplates.pqc(LABEL, KeyTemplates.newKeyId(), vendor, profile)
                            .publicTemplate(), CKA.KEY_TYPE).orElseThrow().getValueLong();

            assertTrue(asTokenReportsIt < 0, "precondition: the binding sign-extends this value");
            assertEquals(vendor.ckkKeyType(), CkULong.typeCode(asTokenReportsIt));
        }

        @Test
        @DisplayName("does not put CKA_MODULUS_BITS or CKA_EC_PARAMS on a PQC key")
        void noClassicalSizeAttributes() {
            AlgorithmEntry entry = profile.lookup("SLH-DSA-SHA2-192F").orElseThrow();
            List<CKA> pub = KeyTemplates.pqc(LABEL, KeyTemplates.newKeyId(), entry, profile)
                    .publicTemplate();
            assertAbsent(pub, CKA.MODULUS_BITS, "CKA_MODULUS_BITS");
            assertAbsent(pub, CKA.EC_PARAMS, "CKA_EC_PARAMS");
        }
    }

    @Nested
    @DisplayName("Pair")
    class PairShape {

        @Test
        @DisplayName("copies the templates it is given")
        void defensiveCopy() {
            List<CKA> mutable = new java.util.ArrayList<>(
                    List.of(new CKA(CKA.CLASS, CKO.PUBLIC_KEY)));
            KeyTemplates.Pair pair = new KeyTemplates.Pair(mutable, mutable);
            mutable.add(new CKA(CKA.EXTRACTABLE, true));
            assertEquals(1, pair.publicTemplate().size(),
                    "a caller must not be able to add attributes after the pair is built");
        }

        @Test
        @DisplayName("hands the arrays JackNJI11 expects")
        void arrays() {
            KeyTemplates.Pair pair = KeyTemplates.rsa(LABEL, KeyTemplates.newKeyId(), 2048);
            assertEquals(pair.publicTemplate().size(), pair.pub().length);
            assertEquals(pair.privateTemplate().size(), pair.priv().length);
            assertNotNull(pair.pub()[0]);
            assertNotEquals(pair.pub(), pair.pub(), "each call returns a fresh array");
        }
    }

    @Test
    @DisplayName("labels both halves with the alias EJBCA asked for")
    void labelOnBothHalves() {
        KeyTemplates.Pair pair = KeyTemplates.rsa(LABEL, KeyTemplates.newKeyId(), 2048);
        assertArrayEquals(LABEL, find(pair.publicTemplate(), CKA.LABEL).orElseThrow().getValue());
        assertArrayEquals(LABEL, find(pair.privateTemplate(), CKA.LABEL).orElseThrow().getValue());
        assertFalse(pair.publicTemplate().isEmpty());
        assertNull(find(pair.publicTemplate(), CKA.SENSITIVE).orElse(null),
                "CKA_SENSITIVE is meaningless on a public key");
    }
}

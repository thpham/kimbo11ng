/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashSet;
import java.util.OptionalLong;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Invariants of the standard PKCS#11 v3.2 algorithm table.
 *
 * <p>These are the assertions that stop a mislabelled key reaching a certificate: an OID paired
 * with the wrong parameter set, or two entries a token could not tell apart.
 */
@DisplayName("Pkcs11v32Profile")
class Pkcs11v32ProfileTest {

    private final Pkcs11v32Profile profile = new Pkcs11v32Profile();

    @Nested
    @DisplayName("table shape")
    class TableShape {

        @Test
        @DisplayName("describes 3 ML-DSA, 3 ML-KEM and 12 SLH-DSA parameter sets")
        void completeness() {
            assertEquals(3, count(PqcFamily.ML_DSA));
            assertEquals(3, count(PqcFamily.ML_KEM));
            assertEquals(12, count(PqcFamily.SLH_DSA));
            assertEquals(18, profile.entries().size());
        }

        private long count(PqcFamily family) {
            return profile.entries().stream().filter(e -> e.family() == family).count();
        }

        @Test
        @DisplayName("assigns every entry a distinct OID")
        void oidsAreUnique() {
            Set<String> seen = new HashSet<>();
            for (AlgorithmEntry entry : profile.entries()) {
                assertTrue(seen.add(entry.oid().getId()),
                        () -> "OID " + entry.oid().getId() + " is used by more than one entry, "
                                + "so two algorithms would produce identical SubjectPublicKeyInfo "
                                + "algorithm identifiers (" + entry.canonicalName() + ")");
            }
        }

        @Test
        @DisplayName("names every entry as EJBCA spells it")
        void namesMatchEjbca() {
            // AlgorithmConstants.KEYALGORITHM_* values; a mismatch means EJBCA asks for an
            // algorithm the profile cannot resolve.
            for (String name : new String[] {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                    "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-256F"}) {
                assertTrue(profile.lookup(name).isPresent(), name + " must be resolvable");
                assertEquals(name, profile.lookup(name).orElseThrow().canonicalName());
            }
        }
    }

    @Nested
    @DisplayName("lookup by key specification")
    class Lookup {

        @ParameterizedTest
        @ValueSource(strings = {"ML-DSA-65", "MLDSA65", "ml-dsa-65", "ML_DSA_65", "mldsa65"})
        @DisplayName("tolerates separator and case differences")
        void normalisedSpellings(String keySpec) {
            assertEquals("ML-DSA-65", profile.lookup(keySpec).orElseThrow().canonicalName());
        }

        @ParameterizedTest
        @ValueSource(strings = {"RSA2048", "2048", "prime256v1", "unknown", "FALCON-512", ""})
        @DisplayName("does not resolve non-PQC or unknown specifications")
        void unknown(String keySpec) {
            assertTrue(profile.lookup(keySpec).isEmpty());
            assertFalse(profile.supports(keySpec));
        }

        @Test
        @DisplayName("treats null as unsupported rather than throwing")
        void nullSpec() {
            assertTrue(profile.lookup(null).isEmpty());
            assertFalse(profile.supports(null));
        }
    }

    @Nested
    @DisplayName("NIST OIDs")
    class Oids {

        @ParameterizedTest
        @CsvSource({
            "ML-DSA-44, 2.16.840.1.101.3.4.3.17",
            "ML-DSA-65, 2.16.840.1.101.3.4.3.18",
            "ML-DSA-87, 2.16.840.1.101.3.4.3.19",
            "ML-KEM-512,  2.16.840.1.101.3.4.4.1",
            "ML-KEM-768,  2.16.840.1.101.3.4.4.2",
            "ML-KEM-1024, 2.16.840.1.101.3.4.4.3",
        })
        void mlOids(String keySpec, String expectedOid) {
            assertEquals(expectedOid, profile.lookup(keySpec).orElseThrow().oid().getId());
        }

        @ParameterizedTest
        @CsvSource({
            "SLH-DSA-SHA2-128S, 2.16.840.1.101.3.4.3.20",
            "SLH-DSA-SHA2-128F, 2.16.840.1.101.3.4.3.21",
            "SLH-DSA-SHA2-192S, 2.16.840.1.101.3.4.3.22",
            "SLH-DSA-SHA2-192F, 2.16.840.1.101.3.4.3.23",
            "SLH-DSA-SHA2-256S, 2.16.840.1.101.3.4.3.24",
            "SLH-DSA-SHA2-256F, 2.16.840.1.101.3.4.3.25",
        })
        @DisplayName("groups all SHA2 variants in .20-.25")
        void slhDsaSha2Grouping(String keySpec, String expectedOid) {
            assertEquals(expectedOid, profile.lookup(keySpec).orElseThrow().oid().getId());
        }

        @ParameterizedTest
        @CsvSource({
            "SLH-DSA-SHAKE-128S, 2.16.840.1.101.3.4.3.26",
            "SLH-DSA-SHAKE-128F, 2.16.840.1.101.3.4.3.27",
            "SLH-DSA-SHAKE-192S, 2.16.840.1.101.3.4.3.28",
            "SLH-DSA-SHAKE-192F, 2.16.840.1.101.3.4.3.29",
            "SLH-DSA-SHAKE-256S, 2.16.840.1.101.3.4.3.30",
            "SLH-DSA-SHAKE-256F, 2.16.840.1.101.3.4.3.31",
        })
        @DisplayName("groups all SHAKE variants in .26-.31")
        void slhDsaShakeGrouping(String keySpec, String expectedOid) {
            assertEquals(expectedOid, profile.lookup(keySpec).orElseThrow().oid().getId());
        }

        @Test
        @DisplayName("keeps CKP order and OID order independent")
        void ckpAndOidOrdersDiffer() {
            // The regression this guards: CKP counts s-then-f within each level and interleaves
            // SHA2/SHAKE, while the OID arc groups all SHA2 before all SHAKE. Deriving one from
            // the other by arithmetic silently mislabels keys, which is why both live in the row.
            AlgorithmEntry shake128s = profile.lookup("SLH-DSA-SHAKE-128S").orElseThrow();
            AlgorithmEntry sha2128f = profile.lookup("SLH-DSA-SHA2-128F").orElseThrow();
            assertEquals(2L, shake128s.ckpParameterSet().orElseThrow());
            assertEquals(3L, sha2128f.ckpParameterSet().orElseThrow());
            // CKP 2 < 3, but the OIDs run the other way.
            assertEquals("2.16.840.1.101.3.4.3.26", shake128s.oid().getId());
            assertEquals("2.16.840.1.101.3.4.3.21", sha2128f.oid().getId());
        }
    }

    @Nested
    @DisplayName("FIPS public-key sizes")
    class PublicKeySizes {

        @ParameterizedTest
        @CsvSource({
            "ML-DSA-44, 1312", "ML-DSA-65, 1952", "ML-DSA-87, 2592",
            "ML-KEM-512, 800", "ML-KEM-768, 1184", "ML-KEM-1024, 1568",
            "SLH-DSA-SHA2-128S, 32", "SLH-DSA-SHAKE-192F, 48", "SLH-DSA-SHA2-256F, 64",
        })
        void sizes(String keySpec, int expected) {
            assertEquals(expected, profile.lookup(keySpec).orElseThrow().publicKeyLength());
        }

        @Test
        @DisplayName("ML-DSA and ML-KEM sizes identify a parameter set on their own")
        void mlSizesAreUnique() {
            // This is what lets a misresolved parameter set be caught from the key alone.
            for (int length : new int[] {1312, 1952, 2592}) {
                assertEquals(1, profile.byPublicKeyLength(PqcFamily.ML_DSA, length).size());
            }
            for (int length : new int[] {800, 1184, 1568}) {
                assertEquals(1, profile.byPublicKeyLength(PqcFamily.ML_KEM, length).size());
            }
        }

        @Test
        @DisplayName("SLH-DSA sizes identify only the security level, not the variant")
        void slhDsaSizesAreAmbiguous() {
            // Four variants share each size, so length alone cannot resolve an SLH-DSA key and
            // the caller must rely on the requested specification.
            assertEquals(4, profile.byPublicKeyLength(PqcFamily.SLH_DSA, 32).size());
            assertEquals(4, profile.byPublicKeyLength(PqcFamily.SLH_DSA, 48).size());
            assertEquals(4, profile.byPublicKeyLength(PqcFamily.SLH_DSA, 64).size());
        }
    }

    @Nested
    @DisplayName("reverse lookup, for keys already on the token")
    class ReverseLookup {

        @ParameterizedTest
        @ValueSource(strings = {"ML-DSA-44", "ML-DSA-87", "ML-KEM-768", "SLH-DSA-SHAKE-256F"})
        @DisplayName("round-trips key type plus parameter set back to the same entry")
        void roundTrip(String keySpec) {
            AlgorithmEntry entry = profile.lookup(keySpec).orElseThrow();
            AlgorithmEntry found = profile
                    .lookupByKeyType(entry.ckkKeyType(), entry.ckpParameterSet())
                    .orElseThrow();
            assertSame(entry, found);
        }

        @Test
        @DisplayName("returns nothing when the token reports no parameter set")
        void noParameterSetIsAmbiguous() {
            // Three ML-DSA entries share the key type, so there is no safe answer. Returning a
            // default here is exactly how a key ends up labelled with the wrong OID.
            long mlDsaKeyType = profile.lookup("ML-DSA-65").orElseThrow().ckkKeyType();
            assertTrue(profile.lookupByKeyType(mlDsaKeyType, OptionalLong.empty()).isEmpty());
        }

        @Test
        @DisplayName("returns nothing for an unknown key type")
        void unknownKeyType() {
            assertTrue(profile.lookupByKeyType(0xDEADL, OptionalLong.of(1L)).isEmpty());
        }
    }

    @Nested
    @DisplayName("operations")
    class Operations {

        @ParameterizedTest
        @ValueSource(strings = {"ML-DSA-65", "SLH-DSA-SHA2-128F"})
        void signatureAlgorithmsCanSign(String keySpec) {
            assertTrue(profile.lookup(keySpec).orElseThrow().canSign());
        }

        @ParameterizedTest
        @ValueSource(strings = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
        @DisplayName("ML-KEM cannot sign")
        void kemCannotSign(String keySpec) {
            // Guards against registering a Signature service for a key-establishment algorithm.
            assertFalse(profile.lookup(keySpec).orElseThrow().canSign());
        }
    }

    @Test
    @DisplayName("uses the v3.2 parameter-set attribute")
    void parameterSetAttribute() {
        assertEquals(0x0000061DL, profile.ckaParameterSet());
    }
}

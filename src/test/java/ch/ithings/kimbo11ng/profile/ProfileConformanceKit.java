/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import ch.ithings.kimbo11ng.CryptoTokenImpl;
import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestBridge;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import ch.ithings.kimbo11ng.provider.Kimbo11ngKeyStoreSpi;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The contract every {@link PqcMechanismProfile} must satisfy, whoever wrote it.
 *
 * <p>Subclass it and return the profile from {@link #profile()}; the whole suite then runs against
 * that table. Adding an HSM vendor is a table plus four lines of test, and if the table is wrong
 * this says so by name rather than a certificate carrying the wrong algorithm months later.
 *
 * <p>The suite is in two halves. The first checks the table against itself and against FIPS: sizes,
 * OIDs, and — more importantly — that no two rows are indistinguishable to a token, because the
 * only thing available after a restart is the key type plus the parameter set the token reports.
 * The second half installs the profile's own constants into {@link FakeToken}, so the fake answers
 * <em>only</em> that numbering, and drives a real {@code CryptoTokenImpl} through generate,
 * re-enumerate and sign. Without that second half a vendor table could only be checked for internal
 * consistency, and a table that is perfectly self-consistent and wrong about the hardware passes
 * every static assertion there is.
 *
 * <p>What the kit cannot check is whether the constants match the firmware; that is what
 * {@code HsmConformanceIT} is for.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class ProfileConformanceKit {

    /** The profile under test. Must return an equal table on every call. */
    protected abstract PqcMechanismProfile profile();

    /**
     * FIPS-defined public-key lengths by canonical algorithm name. These do not vary by vendor: a
     * profile that disagrees with this map is wrong, not different.
     */
    private static final Map<String, Integer> FIPS_PUBLIC_KEY_LENGTHS = fipsLengths();

    private static Map<String, Integer> fipsLengths() {
        Map<String, Integer> sizes = new HashMap<>();
        // FIPS 204.
        sizes.put("ML-DSA-44", 1312);
        sizes.put("ML-DSA-65", 1952);
        sizes.put("ML-DSA-87", 2592);
        // FIPS 203.
        sizes.put("ML-KEM-512", 800);
        sizes.put("ML-KEM-768", 1184);
        sizes.put("ML-KEM-1024", 1568);
        // FIPS 205: the public key is 2n bytes.
        for (String hash : new String[] {"SHA2", "SHAKE"}) {
            for (String speed : new String[] {"S", "F"}) {
                sizes.put("SLH-DSA-" + hash + "-128" + speed, 32);
                sizes.put("SLH-DSA-" + hash + "-192" + speed, 48);
                sizes.put("SLH-DSA-" + hash + "-256" + speed, 64);
            }
        }
        return Map.copyOf(sizes);
    }

    /** NIST OID arcs. A post-quantum OID outside them is a typo or a private-arc placeholder. */
    private static final String SIG_ARC = "2.16.840.1.101.3.4.3.";
    private static final String KEM_ARC = "2.16.840.1.101.3.4.4.";

    /** The PIN {@link FakeToken} is configured with. */
    private static final char[] PIN = "1234".toCharArray();

    @BeforeAll
    void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** Parameter source: every row in the table under test. */
    Stream<AlgorithmEntry> everyEntry() {
        return profile().entries().stream();
    }

    // ------------------------------------------------------------------ the table by itself

    @Test
    @DisplayName("has a name that can be selected by property, and at least one algorithm")
    void nameAndContents() {
        PqcMechanismProfile p = profile();
        assertNotNull(p.name(), "a profile must be nameable in " + ProfileResolver.PROFILE_PROPERTY);
        assertFalse(p.name().isBlank(), "a blank name cannot be selected");
        assertFalse(p.entries().isEmpty(),
                "an empty profile supports nothing; do not ship one as a placeholder");
    }

    @Test
    @DisplayName("returns the same table every time it is asked")
    void tableIsStable() {
        // Callers hold entries for a token's whole lifetime and compare them by identity on the
        // reverse-lookup path. A profile that rebuilt its rows per call would break that quietly.
        assertEquals(new ArrayList<>(profile().entries()), new ArrayList<>(profile().entries()));
    }

    @Test
    @DisplayName("names every algorithm exactly once")
    void namesAreUnique() {
        Set<String> seen = new HashSet<>();
        for (AlgorithmEntry entry : profile().entries()) {
            assertTrue(seen.add(entry.normalizedName()),
                    () -> entry.canonicalName() + " appears twice; lookup would be a coin toss");
        }
    }

    @Test
    @DisplayName("assigns every entry a distinct OID")
    void oidsAreUnique() {
        Set<String> seen = new HashSet<>();
        for (AlgorithmEntry entry : profile().entries()) {
            assertTrue(seen.add(entry.oid().getId()),
                    () -> "OID " + entry.oid().getId() + " is shared with another entry, so two"
                            + " algorithms would produce the same SubjectPublicKeyInfo algorithm"
                            + " identifier (" + entry.canonicalName() + ")");
        }
    }

    @Test
    @DisplayName("gives a token a way to tell any two rows apart")
    void rowsAreDistinguishable() {
        // Key type plus parameter set is all reverse lookup has. Two rows sharing that pair means a
        // key already on the token cannot be resolved, which is a wrong OID or a hard failure.
        Set<String> pairs = new HashSet<>();
        for (AlgorithmEntry entry : profile().entries()) {
            String pair = Long.toHexString(entry.ckkKeyType()) + "/" + entry.ckpParameterSet();
            assertTrue(pairs.add(pair),
                    () -> entry.canonicalName() + " shares its key type and parameter set with"
                            + " another entry. Give each row its own CKP, or its own CKK, or — for"
                            + " firmware predating CKA_PARAMETER_SET — its own generation mechanism"
                            + " with an empty CKP.");
        }
    }

    @Test
    @DisplayName("does not resolve algorithms it has no row for")
    void unknownSpecifications() {
        for (String keySpec : new String[] {"RSA2048", "2048", "prime256v1", "FALCON-512",
                "unknown", ""}) {
            assertTrue(profile().lookup(keySpec).isEmpty(),
                    () -> "'" + keySpec + "' must not resolve; guessing here mislabels a key");
        }
        assertTrue(profile().lookup(null).isEmpty(), "a null spec is unsupported, not an exception");
        assertTrue(profile().lookupByKeyType(0xDEADL, OptionalLong.of(1L)).isEmpty());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("everyEntry")
    @DisplayName("carries the FIPS public-key length for its parameter set")
    void fipsLength(AlgorithmEntry entry) {
        Integer expected = FIPS_PUBLIC_KEY_LENGTHS.get(entry.canonicalName());
        assertNotNull(expected, () -> entry.canonicalName() + " is not an algorithm this kit knows a"
                + " FIPS length for. Either the name is misspelled — EJBCA matches"
                + " AlgorithmConstants.KEYALGORITHM_* exactly — or the kit needs extending.");
        assertEquals(expected.intValue(), entry.publicKeyLength(),
                () -> entry.canonicalName() + " declares the wrong public-key length. That length is"
                        + " what catches a parameter set resolved wrongly, so a wrong value here"
                        + " disables the check rather than merely being cosmetic.");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("everyEntry")
    @DisplayName("uses the NIST OID arc for its family")
    void nistOid(AlgorithmEntry entry) {
        String arc = entry.family() == PqcFamily.ML_KEM ? KEM_ARC : SIG_ARC;
        assertTrue(entry.oid().getId().startsWith(arc),
                () -> entry.canonicalName() + " has OID " + entry.oid().getId() + ", outside the"
                        + " NIST arc " + arc + ". OIDs are FIPS-defined and do not vary by vendor.");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("everyEntry")
    @DisplayName("declares operations matching its family")
    void operations(AlgorithmEntry entry) {
        if (entry.family() == PqcFamily.ML_KEM) {
            assertFalse(entry.canSign(),
                    "a key-encapsulation algorithm must not be registered as a signing service");
        } else {
            assertTrue(entry.canSign(), entry.canonicalName() + " is a signature algorithm");
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("everyEntry")
    @DisplayName("round-trips its key specification back to itself")
    void keySpecRoundTrip(AlgorithmEntry entry) {
        assertSame(entry, profile().lookup(entry.canonicalName()).orElseThrow(),
                () -> entry.canonicalName() + " is in the table but does not resolve by name");
        // Separator and case differences reach us from EJBCA properties and from the CLI.
        for (String spelling : new String[] {
                entry.canonicalName().replace("-", ""),
                entry.canonicalName().replace("-", "_"),
                entry.canonicalName().toLowerCase(Locale.ROOT)}) {
            assertSame(entry, profile().lookup(spelling).orElseThrow(),
                    () -> "'" + spelling + "' must resolve to " + entry.canonicalName());
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("everyEntry")
    @DisplayName("is recoverable from what a token reports about the key")
    void reverseLookupRoundTrip(AlgorithmEntry entry) {
        Optional<AlgorithmEntry> found =
                profile().lookupByKeyType(entry.ckkKeyType(), entry.ckpParameterSet());
        assertSame(entry, found.orElseThrow(() -> new AssertionError(entry.canonicalName()
                + " cannot be recovered from CKK 0x" + Long.toHexString(entry.ckkKeyType())
                + " plus parameter set " + entry.ckpParameterSet() + ", so a key already on the"
                + " token would be enumerated wrongly or not at all")));
    }

    // ------------------------------------------------------------------ against a token

    /**
     * A fake token built from this profile's own numbering — and nothing else — driven through the
     * real token implementation.
     */
    @Nested
    @DisplayName("on a token that speaks this profile's numbering")
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class OnToken {

        private CryptoTokenImpl impl;

        @BeforeEach
        void openToken() throws Exception {
            FakeToken token = new FakeToken().profile(profile());
            Properties properties = new Properties();
            properties.setProperty(CryptoTokenImpl.SHLIB_LABEL_KEY, "/nonexistent/libkit.so");
            properties.setProperty(CryptoTokenImpl.SLOT_LABEL_TYPE, "SLOT_INDEX");
            properties.setProperty(CryptoTokenImpl.SLOT_LABEL_VALUE, "0");
            properties.setProperty(CryptoTokenImpl.DO_NOT_ADD_P11_PROVIDER, "true");
            // Named rather than auto-detected: auto-detection is the resolver's test, and naming
            // the profile is also how an operator pins a vendor table in production.
            properties.setProperty(ProfileResolver.PROFILE_PROPERTY, profile().name());

            impl = new CryptoTokenImpl(new TestBridge(), new Pkcs11ModuleRegistry(path -> token));
            impl.init(properties, null, 71);
            impl.activate(PIN.clone());
        }

        @AfterEach
        void closeToken() {
            if (impl != null) {
                impl.reset();
            }
        }

        @Test
        @DisplayName("init keeps every algorithm, because the token advertises exactly this table")
        void nothingIsProbedAway() {
            // The fake was built from this very table, so an algorithm missing here is one the
            // profile names in one field and contradicts in another — a signing mechanism that is
            // not the mechanism it says the token generates keys with, most often.
            assertEquals(profile().entries().size(),
                    impl.getProvider().runtime().algorithms().supported().size(),
                    () -> "the capability probe excluded an algorithm from a token built out of"
                            + " the profile's own constants: "
                            + impl.getProvider().runtime().algorithms().excluded());
        }

        /** Parameter source for this nested class; JUnit resolves it here, not on the enclosing. */
        Stream<AlgorithmEntry> everyEntryOnToken() {
            return everyEntry();
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("everyEntryOnToken")
        @DisplayName("generates, re-enumerates under the right OID, and signs")
        void roundTrip(AlgorithmEntry entry) throws Exception {
            String alias = "kit-" + entry.canonicalName();
            impl.generateKeyPair(entry.canonicalName(), alias);

            // Throw away everything cached and read the key back off the token — the restart path,
            // and the only one that must recover the parameter set from the token's own answers.
            Kimbo11ngKeyStoreSpi keyStore = impl.getProvider().getKeyStoreSpi();
            keyStore.clear();
            keyStore.engineLoad(null, PIN.clone());
            assertTrue(keyStore.engineContainsAlias(alias),
                    alias + " did not survive re-enumeration");

            PublicKey pub = keyStore.getPublicKey(alias);
            assertNotNull(pub, "no public key came back for " + alias);
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pub.getEncoded());
            assertEquals(entry.oid(), spki.getAlgorithm().getAlgorithm(),
                    entry.canonicalName() + " came back under the wrong OID");
            assertEquals(entry.publicKeyLength(), spki.getPublicKeyData().getOctets().length,
                    entry.canonicalName() + " came back the wrong size");

            if (!entry.canSign()) {
                return;
            }
            // The fake returns a synthetic post-quantum signature, so nothing here can verify one.
            // What is under test is that the profile's signing mechanism was accepted by a token
            // advertising only this profile's numbering — where a table that shifts the generation
            // mechanism but forgets the signing one fails.
            PrivateKey privateKey = (PrivateKey) keyStore.engineGetKey(alias, PIN.clone());
            assertNotNull(privateKey, "no private key came back for " + alias);
            Signature signer = Signature.getInstance(entry.canonicalName(), impl.getProvider());
            signer.initSign(privateKey);
            signer.update("kimbo11ng profile conformance".getBytes(StandardCharsets.UTF_8));
            assertTrue(signer.sign().length > 0,
                    entry.canonicalName() + " produced an empty signature");
        }
    }
}

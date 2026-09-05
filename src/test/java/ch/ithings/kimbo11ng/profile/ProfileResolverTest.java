/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import ch.ithings.kimbo11ng.fake.VendorTestProfile;
import ch.ithings.kimbo11ng.p11.TokenCapabilities;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.pkcs11.jacknji11.CK_MECHANISM_INFO;

import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ProfileResolver")
class ProfileResolverTest {

    private static Properties withProfile(String name) {
        Properties props = new Properties();
        props.setProperty(ProfileResolver.PROFILE_PROPERTY, name);
        return props;
    }

    @Test
    @DisplayName("discovers profiles through ServiceLoader")
    void discovery() {
        // Proves META-INF/services is present and correct. If it were missing, PQC support would
        // silently disappear from a deployed jar.
        List<String> names = ProfileResolver.available().stream()
                .map(PqcMechanismProfile::name)
                .toList();
        assertTrue(names.contains("pkcs11v32"), () -> "expected pkcs11v32 in " + names);
        assertTrue(names.contains("thales-luna"), () -> "expected thales-luna in " + names);
    }

    @Test
    @DisplayName("defaults to the v3.2 profile with no properties")
    void defaultsWithoutProperties() {
        assertInstanceOf(Pkcs11v32Profile.class, ProfileResolver.resolve(null));
        assertInstanceOf(Pkcs11v32Profile.class, ProfileResolver.resolve(new Properties()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"pkcs11v32", "PKCS11V32", "Pkcs11v32"})
    @DisplayName("matches the profile name case-insensitively")
    void matchesByName(String requested) {
        assertInstanceOf(Pkcs11v32Profile.class, ProfileResolver.resolve(withProfile(requested)));
    }

    @Test
    @DisplayName("selects the Thales profile when asked for by name")
    void selectsThales() {
        assertInstanceOf(ThalesLunaProfile.class,
                ProfileResolver.resolve(withProfile("thales-luna")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"nonexistent", "  ", "java.lang.String"})
    @DisplayName("falls back to the default for an unknown name")
    void unknownFallsBack(String requested) {
        // "java.lang.String" is included deliberately: the previous implementation passed the
        // property to Class.forName, instantiating whatever class configuration named.
        assertInstanceOf(Pkcs11v32Profile.class, ProfileResolver.resolve(withProfile(requested)));
    }

    // ---- auto-detection ----

    private static TokenCapabilities capabilitiesOf(FakeToken token) throws Exception {
        try (TestSlot fixture = new TestSlot(token)) {
            return fixture.slot().capabilities();
        }
    }

    /** Every post-quantum mechanism the v3.2 profile relies on. */
    private static final long[] V32_PQC_MECHANISMS = {
            FakeToken.CKM_ML_DSA_KEY_PAIR_GEN, FakeToken.CKM_ML_DSA,
            FakeToken.CKM_SLH_DSA_KEY_PAIR_GEN, FakeToken.CKM_SLH_DSA,
            FakeToken.CKM_ML_KEM_KEY_PAIR_GEN, FakeToken.CKM_ML_KEM};

    /** A token that answers only the vendor mechanisms, as pre-v3.2 firmware would. */
    private static FakeToken vendorToken() {
        FakeToken token = new FakeToken().hideMechanism(V32_PQC_MECHANISMS);
        for (long ckm : VendorTestProfile.MECHANISMS) {
            token.advertiseMechanism(ckm)
                    .mechanismFlags(ckm, ckm == VendorTestProfile.CKM_VENDOR_MLDSA
                            ? CK_MECHANISM_INFO.CKF_SIGN | CK_MECHANISM_INFO.CKF_VERIFY
                            : CK_MECHANISM_INFO.CKF_GENERATE_KEY_PAIR);
        }
        return token;
    }

    @Test
    @DisplayName("selects the vendor profile for a token that answers only vendor mechanisms")
    void autoDetectsVendorProfile() throws Exception {
        // The point of the whole probe: an operator who has not set kimbo11ng.pqc.profile on a
        // vendor HSM gets the right table anyway, rather than eighteen CKR_MECHANISM_INVALIDs.
        assertInstanceOf(VendorTestProfile.class,
                ProfileResolver.resolve(new Properties(), capabilitiesOf(vendorToken())));
    }

    @Test
    @DisplayName("selects the v3.2 profile for a token that answers the v3.2 mechanisms")
    void autoDetectsStandardProfile() throws Exception {
        assertInstanceOf(Pkcs11v32Profile.class,
                ProfileResolver.resolve(new Properties(), capabilitiesOf(new FakeToken())));
    }

    @Test
    @DisplayName("an explicit profile wins over what the probe found")
    void explicitProfileBeatsAutoDetection() throws Exception {
        // A token may under-report its mechanisms — a vendor mechanism behind a policy will not be
        // listed. Overriding an operator who named a profile on that basis would be worse than
        // honouring a wrong one, which at least fails where it was configured.
        assertInstanceOf(Pkcs11v32Profile.class,
                ProfileResolver.resolve(withProfile("pkcs11v32"), capabilitiesOf(vendorToken())));
    }

    @Test
    @DisplayName("falls back to the default when no profile matches the token")
    void nothingMatches() throws Exception {
        // An RSA/EC-only HSM. There is nothing to detect, and nothing to fail: the profile governs
        // post-quantum algorithms only, and the token is perfectly usable without them.
        FakeToken bare = new FakeToken().hideMechanism(V32_PQC_MECHANISMS);
        assertInstanceOf(Pkcs11v32Profile.class,
                ProfileResolver.resolve(new Properties(), capabilitiesOf(bare)));
    }

    @Test
    @DisplayName("does not guess between two profiles the token fits equally")
    void tiesAreNotBroken() throws Exception {
        // Three vendor ML-DSA sets, three standard ML-KEM sets: both profiles score 3. Picking
        // either is a guess about whose numbering is in force, and the cost of guessing wrong is a
        // certificate naming the wrong algorithm — so the built-in profile is used and both are
        // named in the log.
        FakeToken tied = vendorToken()
                .advertiseMechanism(FakeToken.CKM_ML_KEM_KEY_PAIR_GEN)
                .mechanismFlags(FakeToken.CKM_ML_KEM_KEY_PAIR_GEN,
                        CK_MECHANISM_INFO.CKF_GENERATE_KEY_PAIR);
        TokenCapabilities capabilities = capabilitiesOf(tied);

        assertEquals(3, AlgorithmSupport.score(new VendorTestProfile(), capabilities));
        assertEquals(3, AlgorithmSupport.score(new Pkcs11v32Profile(), capabilities),
                "the three ML-KEM parameter sets share one generation mechanism");
        assertInstanceOf(Pkcs11v32Profile.class,
                ProfileResolver.resolve(new Properties(), capabilities));
    }

    @Test
    @DisplayName("resolving without a probe behaves as it did before")
    void unprobedKeepsTheOldBehaviour() {
        assertInstanceOf(Pkcs11v32Profile.class,
                ProfileResolver.resolve(new Properties(),
                        TokenCapabilities.unknown("no probe was run")));
    }

    @Test
    @DisplayName("leaves the Thales table empty until vendor constants are supplied")
    void thalesIsAnHonestStub() {
        ThalesLunaProfile thales = new ThalesLunaProfile();
        assertEquals(0, thales.entries().size());
        assertTrue(thales.lookup("ML-DSA-65").isEmpty(),
                "an unpopulated profile must report no support rather than guessing");
    }
}

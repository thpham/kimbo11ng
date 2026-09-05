/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

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

    @Test
    @DisplayName("leaves the Thales table empty until vendor constants are supplied")
    void thalesIsAnHonestStub() {
        ThalesLunaProfile thales = new ThalesLunaProfile();
        assertEquals(0, thales.entries().size());
        assertTrue(thales.lookup("ML-DSA-65").isEmpty(),
                "an unpopulated profile must report no support rather than guessing");
    }
}

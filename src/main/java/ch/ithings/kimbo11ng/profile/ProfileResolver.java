/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.ServiceLoader;

/**
 * Selects the {@link PqcMechanismProfile} for a token.
 *
 * <p>Profiles are discovered with {@link ServiceLoader}, so a vendor can ship one in its own jar
 * and select it by name. This replaces an earlier {@code Class.forName} on the property value,
 * which would instantiate any class named in configuration.
 */
public final class ProfileResolver {

    private static final Logger log = Logger.getLogger(ProfileResolver.class);

    public static final String PROFILE_PROPERTY = "kimbo11ng.pqc.profile";

    private ProfileResolver() {
    }

    /** Every profile on the classpath. */
    public static List<PqcMechanismProfile> available() {
        List<PqcMechanismProfile> found = new ArrayList<>();
        for (PqcMechanismProfile profile : ServiceLoader.load(PqcMechanismProfile.class,
                ProfileResolver.class.getClassLoader())) {
            found.add(profile);
        }
        if (found.isEmpty()) {
            // A jar repackaged without META-INF/services would otherwise leave the token with no
            // PQC support at all, which is worth stating loudly rather than discovering later.
            log.warn("No PqcMechanismProfile found via ServiceLoader; falling back to the built-in "
                    + "PKCS#11 v3.2 profile. Check META-INF/services in the deployed jar.");
            found.add(new Pkcs11v32Profile());
        }
        return found;
    }

    /**
     * Resolve from configuration.
     *
     * @param properties token properties, optionally carrying {@value #PROFILE_PROPERTY}
     * @return the resolved profile, never {@code null}
     */
    public static PqcMechanismProfile resolve(Properties properties) {
        String requested = properties == null ? null : properties.getProperty(PROFILE_PROPERTY);
        List<PqcMechanismProfile> profiles = available();

        if (requested != null && !requested.isBlank()) {
            String wanted = requested.trim();
            for (PqcMechanismProfile profile : profiles) {
                if (profile.name().equalsIgnoreCase(wanted)) {
                    log.info("Using PQC mechanism profile '" + profile.name() + "' (from "
                            + PROFILE_PROPERTY + ")");
                    return profile;
                }
            }
            List<String> names = profiles.stream().map(PqcMechanismProfile::name).toList();
            log.warn("Unknown PQC profile '" + wanted + "'; available profiles are " + names
                    + ". Falling back to the PKCS#11 v3.2 profile.");
        }

        for (PqcMechanismProfile profile : profiles) {
            if (profile instanceof Pkcs11v32Profile) {
                return profile;
            }
        }
        return new Pkcs11v32Profile();
    }
}

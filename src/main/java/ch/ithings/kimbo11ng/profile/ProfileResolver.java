/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import ch.ithings.kimbo11ng.p11.TokenCapabilities;
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
     * Resolve from configuration alone, without asking a token. Equivalent to
     * {@link #resolve(Properties, TokenCapabilities)} with an unprobed token.
     */
    public static PqcMechanismProfile resolve(Properties properties) {
        return resolve(properties, TokenCapabilities.unknown("no capability probe was run"));
    }

    /**
     * Resolve from configuration, falling back to whichever profile the token actually fits.
     *
     * <p>Order: the {@value #PROFILE_PROPERTY} property wins outright, because an operator naming a
     * profile has said something the probe cannot contradict — a token may under-report its
     * mechanisms, and overriding an explicit choice on that basis would be worse than honouring a
     * wrong one, which at least fails where it was configured. Otherwise the profile whose table
     * the token can satisfy most of is chosen. A tie, or nothing usable, means the probe told us
     * nothing useful, and the built-in v3.2 profile is used with a warning naming the alternatives.
     *
     * @param properties   token properties, optionally carrying {@value #PROFILE_PROPERTY}
     * @param capabilities what the token advertises; see {@link TokenCapabilities#unknown}
     * @return the resolved profile, never {@code null}
     */
    public static PqcMechanismProfile resolve(Properties properties,
            TokenCapabilities capabilities) {
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
                    + ". Falling back to auto-detection.");
        }

        PqcMechanismProfile best = autoDetect(profiles, capabilities);
        if (best != null) {
            return best;
        }
        return builtIn(profiles);
    }

    /**
     * The single profile the token fits best, or {@code null} when the probe cannot decide.
     *
     * <p>A tie is deliberately not broken. Two profiles scoring equally means their mechanism
     * constants overlap on this token, and picking either would be a guess about which vendor's
     * numbering is in force — the same class of guess that used to put the wrong OID in a
     * certificate. The default profile is used instead, and both candidates are named.
     */
    private static PqcMechanismProfile autoDetect(List<PqcMechanismProfile> profiles,
            TokenCapabilities capabilities) {
        if (!capabilities.probed()) {
            return null;
        }
        PqcMechanismProfile best = null;
        int bestScore = 0;
        boolean tied = false;
        List<String> tiedNames = new ArrayList<>();
        for (PqcMechanismProfile profile : profiles) {
            int score = AlgorithmSupport.score(profile, capabilities);
            if (score == 0) {
                continue;
            }
            if (score > bestScore) {
                best = profile;
                bestScore = score;
                tied = false;
                tiedNames = new ArrayList<>(List.of(profile.name()));
            } else if (score == bestScore) {
                tied = true;
                tiedNames.add(profile.name());
            }
        }
        if (best == null) {
            log.warn("No PQC profile matches this token: none of the mechanisms any profile"
                    + " declares are advertised. Using the built-in PKCS#11 v3.2 profile; if the"
                    + " token does support post-quantum algorithms under vendor mechanisms, name"
                    + " its profile with " + PROFILE_PROPERTY + ".");
            return null;
        }
        if (tied) {
            log.warn("Profiles " + tiedNames + " all match " + bestScore + " algorithm(s) on this"
                    + " token and cannot be told apart by their mechanisms. Using the built-in"
                    + " PKCS#11 v3.2 profile; set " + PROFILE_PROPERTY + " to choose deliberately.");
            return null;
        }
        log.info("Auto-detected PQC mechanism profile '" + best.name() + "': " + bestScore
                + " of its " + best.entries().size() + " algorithms are advertised by the token.");
        return best;
    }

    private static PqcMechanismProfile builtIn(List<PqcMechanismProfile> profiles) {
        for (PqcMechanismProfile profile : profiles) {
            if (profile instanceof Pkcs11v32Profile) {
                return profile;
            }
        }
        return new Pkcs11v32Profile();
    }
}

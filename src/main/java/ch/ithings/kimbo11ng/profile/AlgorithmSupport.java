/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import ch.ithings.kimbo11ng.p11.TokenCapabilities;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * The algorithms a profile describes, intersected with what this token and this BouncyCastle can
 * actually do.
 *
 * <p>A profile table is a claim about a vendor. Two things can falsify it at runtime, and both used
 * to surface far from their cause:
 *
 * <ul>
 *   <li>The token does not offer the mechanism. Key generation then failed inside EJBCA with
 *       {@code CKR_MECHANISM_INVALID} and no indication of which mechanism was asked for.
 *   <li>The deployed BouncyCastle cannot materialise the key type. EJBCA 9.3.7 ships BC 1.79+ with
 *       ML-DSA and SLH-DSA, but a container built against an older one would generate the key on
 *       the token, fail to read it back, and leave an orphan key behind. This is also what replaces
 *       the deleted {@code RawPqcPublicKey} fallback: an algorithm BC cannot recognise is excluded
 *       up front rather than wrapped in something EJBCA cannot sign with.
 * </ul>
 *
 * <p>Exclusions are recorded with their reason, not merely dropped, because the reason is the whole
 * value: "the token does not advertise 0x0000001d" points at firmware, "BouncyCastle has no ML-DSA
 * KeyFactory" points at the classpath, and the two have nothing in common but the symptom.
 */
public final class AlgorithmSupport {

    private static final Logger log = Logger.getLogger(AlgorithmSupport.class);

    private final PqcMechanismProfile profile;
    private final TokenCapabilities capabilities;
    private final boolean failFast;
    private final List<AlgorithmEntry> supported;
    private final Map<String, String> excluded;

    private AlgorithmSupport(PqcMechanismProfile profile, TokenCapabilities capabilities,
            boolean failFast, List<AlgorithmEntry> supported, Map<String, String> excluded) {
        this.profile = profile;
        this.capabilities = capabilities;
        this.failFast = failFast;
        this.supported = supported;
        this.excluded = excluded;
    }

    /**
     * Everything the profile claims, without checking any of it. For the paths that have no token
     * to ask — tests, and a runtime constructed before a probe has run.
     */
    public static AlgorithmSupport unchecked(PqcMechanismProfile profile) {
        return new AlgorithmSupport(profile, TokenCapabilities.unknown("not probed"), false,
                List.copyOf(profile.entries()), Map.of());
    }

    /** Intersects {@code profile} with the token, and with the BouncyCastle on this classpath. */
    public static AlgorithmSupport compute(PqcMechanismProfile profile,
            TokenCapabilities capabilities, boolean failFast) {
        return compute(profile, capabilities, failFast, AlgorithmSupport::bouncyCastleCanBuild);
    }

    /** As {@link #compute}, with the BouncyCastle check supplied — for tests without a real gap. */
    public static AlgorithmSupport compute(PqcMechanismProfile profile,
            TokenCapabilities capabilities, boolean failFast, Predicate<PqcFamily> jcaAvailable) {
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(capabilities, "capabilities");

        List<AlgorithmEntry> supported = new ArrayList<>();
        Map<String, String> excluded = new LinkedHashMap<>();
        for (AlgorithmEntry entry : profile.entries()) {
            String reason = reasonToExclude(entry, capabilities, jcaAvailable);
            if (reason == null) {
                supported.add(entry);
            } else {
                excluded.put(entry.canonicalName(), reason);
            }
        }
        return new AlgorithmSupport(profile, capabilities, failFast, List.copyOf(supported),
                // Not Map.copyOf: the iteration order of the exclusions is the table order, which
                // is what makes the logged block readable.
                Collections.unmodifiableMap(excluded));
    }

    /** Why this entry is unusable here, or {@code null} if it is usable. */
    private static String reasonToExclude(AlgorithmEntry entry, TokenCapabilities capabilities,
            Predicate<PqcFamily> jcaAvailable) {
        if (!capabilities.canGenerateKeyPair(entry.ckmKeyPairGen())) {
            return "the token does not offer key-pair generation with "
                    + TokenCapabilities.name(entry.ckmKeyPairGen());
        }
        // ML-KEM's operation mechanism is encapsulation, not signing, and the flag differs. Only
        // the signing families are checked here; a KEM key is generated and enumerated and never
        // asked to sign, so a token that lists CKM_ML_KEM without any usable flag is still fine
        // for what this token does with it.
        if (entry.canSign() && !capabilities.canSign(entry.ckmOperation())) {
            return "the token does not offer signing with "
                    + TokenCapabilities.name(entry.ckmOperation());
        }
        if (!jcaAvailable.test(entry.family())) {
            return "the deployed BouncyCastle has no " + entry.family().jcaName()
                    + " KeyFactory, so a key of this type could be generated but never read back";
        }
        return null;
    }

    /**
     * Cached, because a {@code KeyFactory} lookup per algorithm per token init is wasteful.
     *
     * <p>Only successes are remembered. A negative answer depends on which providers happen to be
     * registered at the moment it is asked, and caching it would make the order in which EJBCA
     * registers BouncyCastle and initialises tokens decide whether PQC works at all.
     */
    private static final Map<PqcFamily, Boolean> JCA_AVAILABLE =
            Collections.synchronizedMap(new EnumMap<>(PqcFamily.class));

    private static boolean bouncyCastleCanBuild(PqcFamily family) {
        if (Boolean.TRUE.equals(JCA_AVAILABLE.get(family))) {
            return true;
        }
        try {
            KeyFactory.getInstance(family.jcaName(), BouncyCastleProvider.PROVIDER_NAME);
            JCA_AVAILABLE.put(family, Boolean.TRUE);
            return true;
        } catch (Exception e) {
            log.warn("BouncyCastle on this classpath has no KeyFactory for " + family.jcaName()
                    + "; keys of that family will not be offered. EJBCA 9.3.7 ships"
                    + " BouncyCastle 1.79 or later, which has one.");
            return false;
        }
    }

    public PqcMechanismProfile profile() {
        return profile;
    }

    public TokenCapabilities capabilities() {
        return capabilities;
    }

    /** @see TokenCapabilities#PROBE_FAIL_FAST */
    public boolean failFast() {
        return failFast;
    }

    /** Entries this token can actually generate and use. */
    public List<AlgorithmEntry> supported() {
        return List.copyOf(supported);
    }

    /** Canonical name to the reason it was excluded, in table order. */
    public Map<String, String> excluded() {
        return new LinkedHashMap<>(excluded);
    }

    /**
     * Resolve a key specification, but only to an entry this token can honour.
     *
     * <p>Empty means one of two different things — unknown to the profile, or known and
     * unsupported — which is why {@link #rejectionReason(String)} exists to say which.
     */
    public Optional<AlgorithmEntry> lookupSupported(String keySpec) {
        Optional<AlgorithmEntry> entry = profile.lookup(keySpec);
        if (entry.isEmpty() || !failFast) {
            return entry;
        }
        return excluded.containsKey(entry.get().canonicalName()) ? Optional.empty() : entry;
    }

    /**
     * Why a key specification the profile knows cannot be used here, or {@code null} if it can be
     * (or if the profile does not know it at all, which is a different caller's error).
     */
    public String rejectionReason(String keySpec) {
        return profile.lookup(keySpec)
                .map(e -> excluded.get(e.canonicalName()))
                .orElse(null);
    }

    /**
     * The effective algorithm table, as one multi-line block.
     *
     * <p>One log event rather than eighteen: an operator reading a startup log wants the table
     * together, and EJBCA's log has plenty of other tenants.
     */
    public String describe() {
        StringBuilder sb = new StringBuilder(512);
        sb.append("Effective algorithms for profile '").append(profile.name()).append("' (")
                .append(supported.size()).append('/')
                .append(supported.size() + excluded.size()).append(" usable");
        if (!capabilities.probed()) {
            sb.append("; NOT PROBED: ").append(capabilities.unprobedReason());
        }
        sb.append(')');
        for (AlgorithmEntry entry : supported) {
            sb.append(String.format("%n  %-20s ok       keygen=%s op=%s",
                    entry.canonicalName(),
                    TokenCapabilities.name(entry.ckmKeyPairGen()),
                    TokenCapabilities.name(entry.ckmOperation())));
        }
        for (Map.Entry<String, String> e : excluded.entrySet()) {
            sb.append(String.format("%n  %-20s excluded %s", e.getKey(), e.getValue()));
        }
        if (!excluded.isEmpty()) {
            sb.append(String.format("%n  Requesting an excluded algorithm %s. Set %s=false to"
                    + " attempt it anyway.",
                    failFast ? "is refused" : "is attempted anyway and logged",
                    TokenCapabilities.PROBE_FAIL_FAST));
        }
        return sb.toString();
    }

    /**
     * Score for profile auto-detection: how many of this profile's algorithms the token can
     * actually do.
     */
    static int score(PqcMechanismProfile profile, TokenCapabilities capabilities) {
        if (!capabilities.probed()) {
            return 0;
        }
        int matches = 0;
        for (AlgorithmEntry entry : profile.entries()) {
            if (capabilities.canGenerateKeyPair(entry.ckmKeyPairGen())
                    && (!entry.canSign() || capabilities.canSign(entry.ckmOperation()))) {
                matches++;
            }
        }
        return matches;
    }

    @Override
    public String toString() {
        return "AlgorithmSupport{" + profile.name().toLowerCase(Locale.ROOT) + ": "
                + supported.size() + " supported, " + excluded.size() + " excluded}";
    }
}

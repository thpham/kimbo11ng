/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CK_MECHANISM_INFO;
import org.pkcs11.jacknji11.CryptokiE;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * What one slot's token says it can actually do, read from {@code C_GetMechanismList} and
 * {@code C_GetMechanismInfo}.
 *
 * <p>Every mechanism constant in {@link ch.ithings.kimbo11ng.profile.Pkcs11v32Profile} is
 * hand-entered from a specification that no shipped token predates by less than a year. Until the
 * token confirms them they are assumptions, and the failure mode of a wrong one is poor: key
 * generation fails somewhere inside EJBCA with {@code CKR_MECHANISM_INVALID} and nothing says which
 * mechanism was asked for or what the token offers instead.
 *
 * <h2>Flags, not mere presence</h2>
 *
 * <p>A mechanism appearing in the list is not permission to use it for a given operation. Measured
 * against SoftHSMv3, {@code CKM_ML_KEM} (0x17) is advertised with flags {@code 0x30000000} —
 * encapsulate and decapsulate — and no {@code CKF_SIGN}, which is correct and is exactly the
 * distinction that would be lost by testing presence alone. So each mechanism is asked for its
 * flags and the operation is checked against them.
 *
 * <h2>What this cannot tell you</h2>
 *
 * <p>Mechanisms are coarser than parameter sets. SoftHSMv3 offers one {@code CKM_SLH_DSA} covering
 * all twelve FIPS 205 variants, so a probe can say the token does SLH-DSA and cannot say it does
 * SLH-DSA-SHAKE-256F. Key size bounds are no help either: the same token reports
 * {@code ulMinKeySize=128, ulMaxKeySize=256} for {@code CKM_ML_DSA}, which are security strengths,
 * not key lengths. Only the mechanism and its flags are read, and nothing infers more.
 */
public final class TokenCapabilities {

    private static final Logger log = Logger.getLogger(TokenCapabilities.class);

    /**
     * Whether to refuse an operation whose mechanism the token did not advertise.
     *
     * <p>On by default. It turns "{@code CKR_MECHANISM_INVALID} during key generation" into a
     * refusal at the point of the request naming the mechanism. Turn it off for a token that
     * under-reports its mechanism list — which happens, particularly for vendor-defined mechanisms
     * behind a policy — and the probe becomes advisory: what it finds is logged and every request
     * is attempted anyway.
     */
    public static final String PROBE_FAIL_FAST = "kimbo11ng.probe.failFast";

    /** Flags value recorded for a mechanism the token listed but would not describe. */
    private static final long FLAGS_UNKNOWN = -1L;

    private final Map<Long, Long> flagsByMechanism;
    private final boolean probed;
    private final String unprobedReason;

    private TokenCapabilities(Map<Long, Long> flagsByMechanism, boolean probed,
            String unprobedReason) {
        this.flagsByMechanism = flagsByMechanism;
        this.probed = probed;
        this.unprobedReason = unprobedReason;
    }

    /**
     * Reads the mechanism list and each mechanism's flags.
     *
     * <p>No session is needed and no login: this is a slot-level call, which is why it can run at
     * token init before any PIN is available.
     *
     * <p>A token that will not answer {@code C_GetMechanismList} at all yields
     * {@link #unknown(String)} rather than an empty set. The difference matters: an empty set means
     * "this token does nothing" and would refuse every operation, whereas the truth is that we do
     * not know, and refusing on an unanswered question would take a working token out of service.
     */
    public static TokenCapabilities probe(CryptokiE ce, long slotId) {
        long[] mechanisms;
        try {
            mechanisms = ce.GetMechanismList(slotId);
        } catch (Exception e) {
            String reason = "the token would not list its mechanisms"
                    + Pkcs11Errors.describe(e);
            log.warn("Capability probe on slot " + slotId + " failed: " + reason
                    + ". Continuing without it; every mechanism will be attempted as configured.");
            return unknown(reason);
        }
        if (mechanisms == null) {
            return unknown("the token returned no mechanism list");
        }

        Map<Long, Long> flags = new LinkedHashMap<>();
        for (long raw : mechanisms) {
            long mechanism = CkULong.typeCode(raw);
            try {
                CK_MECHANISM_INFO info = ce.GetMechanismInfo(slotId, raw);
                flags.put(mechanism, info == null ? FLAGS_UNKNOWN : info.flags);
            } catch (Exception e) {
                // Listed but not describable. Some modules answer CKR_MECHANISM_INVALID for their
                // own vendor mechanisms. Record it as present with unknown flags rather than
                // dropping it, so it is never the reason an operation is refused.
                if (log.isDebugEnabled()) {
                    log.debug("Slot " + slotId + " lists mechanism " + name(mechanism)
                            + " but will not describe it" + Pkcs11Errors.describe(e));
                }
                flags.put(mechanism, FLAGS_UNKNOWN);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Slot " + slotId + " advertises " + flags.size() + " mechanism(s)");
        }
        return new TokenCapabilities(Collections.unmodifiableMap(flags), true, null);
    }

    /**
     * Capabilities that could not be determined. Answers yes to everything, on the principle that
     * an unanswered question is not evidence of absence.
     */
    public static TokenCapabilities unknown(String reason) {
        return new TokenCapabilities(Map.of(), false, reason);
    }

    /** False when the probe failed; every {@code can*} answer is then an assumption, not a fact. */
    public boolean probed() {
        return probed;
    }

    /** Why the probe produced nothing, or {@code null} when it succeeded. */
    public String unprobedReason() {
        return unprobedReason;
    }

    /** The mechanisms the token advertised, normalised to unsigned 32 bits. */
    public Set<Long> mechanisms() {
        return flagsByMechanism.keySet();
    }

    /** True if the token listed this mechanism at all. */
    public boolean has(long ckm) {
        return !probed || flagsByMechanism.containsKey(CkULong.typeCode(ckm));
    }

    /**
     * True if the token listed this mechanism with this {@code CKF_*} flag set.
     *
     * <p>Also true when the probe failed, and when the token listed the mechanism but would not
     * describe it — in both cases the honest answer is "unknown", and refusing on that would be
     * worse than attempting the operation and reporting what the token says.
     */
    public boolean can(long ckm, long ckfFlag) {
        if (!probed) {
            return true;
        }
        Long flags = flagsByMechanism.get(CkULong.typeCode(ckm));
        if (flags == null) {
            return false;
        }
        return flags == FLAGS_UNKNOWN || (flags & ckfFlag) != 0;
    }

    /** True if the token will generate key pairs with this mechanism. */
    public boolean canGenerateKeyPair(long ckm) {
        return can(ckm, CK_MECHANISM_INFO.CKF_GENERATE_KEY_PAIR);
    }

    /** True if the token will sign with this mechanism. */
    public boolean canSign(long ckm) {
        return can(ckm, CK_MECHANISM_INFO.CKF_SIGN);
    }

    /**
     * {@code "CKM_ECDSA (0x00001041)"}, for messages that have to name a mechanism.
     *
     * <p>Bare hex whenever the bindings cannot name the mechanism, because their placeholder
     * ("unknown CKM constant …") reads as an error rather than a value. Which mechanisms that
     * covers depends on the build: Keyfactor's jacknji11 1.3.1 predates PKCS#11 v3.2 and names
     * none of {@code 0x1C}, {@code 0x1D}, {@code 0x2D}, {@code 0x2E}, {@code 0x0F} or
     * {@code 0x17}, while upstream HEAD names all six. Vendor-defined mechanisms are never named
     * by either. The hex is always present, so a log line identifies the mechanism regardless.
     */
    public static String name(long ckm) {
        long code = CkULong.typeCode(ckm);
        String hex = String.format("0x%08x", code);
        String symbolic = CKM.L2S(code);
        if (symbolic == null || symbolic.startsWith("unknown ")) {
            return hex;
        }
        return "CKM_" + symbolic + " (" + hex + ")";
    }

    @Override
    public String toString() {
        return probed
                ? "TokenCapabilities{" + flagsByMechanism.size() + " mechanisms}"
                : "TokenCapabilities{unprobed: " + unprobedReason + "}";
    }
}

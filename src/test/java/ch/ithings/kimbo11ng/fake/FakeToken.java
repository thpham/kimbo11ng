/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.fake;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKS;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_C_INITIALIZE_ARGS;
import org.pkcs11.jacknji11.CK_MECHANISM_INFO;
import org.pkcs11.jacknji11.CK_NOTIFY;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.pkcs11.jacknji11.LongRef;
import org.pkcs11.jacknji11.NativePointer;
import org.pkcs11.jacknji11.ULong;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * An in-memory PKCS#11 v3.2 token, implemented at the {@link org.pkcs11.jacknji11.NativeProvider}
 * seam so the whole kimbo11ng stack can be exercised with no HSM and no Docker.
 *
 * <p>Two properties make it worth more than a mock:
 *
 * <ul>
 *   <li><b>It enforces the protocol.</b> Sessions carry real per-session operation state, so a
 *       second {@code C_FindObjectsInit} on a busy session answers {@code CKR_OPERATION_ACTIVE}
 *       exactly as a real token would. That is what turns the "one shared session" defect from an
 *       argument into a failing test.
 *   <li><b>It can misbehave on demand.</b> The knobs below reproduce the ways a Thales Luna is
 *       known to diverge from SoftHSM — divergences that are invisible in the current suite
 *       because SoftHSM happens to take the friendly branch every time.
 * </ul>
 *
 * <p>RSA and EC keys are real BouncyCastle keys, so signatures verify and {@code CKA_EC_POINT}
 * carries a genuine curve point. PQC keys are random material of the exact FIPS public-key length
 * (ML-DSA 1312/1952/2592, ML-KEM 800/1184/1568, SLH-DSA 32/48/64): enough to exercise parameter-set
 * resolution, OID selection and length cross-validation, which is all the plumbing under test.
 *
 * <p>Not thread-safe by accident: it is synchronized on the instance precisely so that concurrency
 * tests observe the token's own serialization, not a data race inside the double.
 */
public final class FakeToken extends UnsupportedNativeProvider {

    /** How the token reports {@code CKA_EC_POINT}. Real modules disagree; both are seen in the wild. */
    public enum EcPointEncoding {
        /** Wrapped in a DER OCTET STRING, as PKCS#11 literally specifies. SoftHSM does this. */
        DER,
        /** The bare uncompressed point {@code 04||X||Y}. Several HSMs do this instead. */
        RAW
    }

    // ---- PKCS#11 v3.2 constants jacknji11 1.3.1 does not define ----
    public static final long CKK_ML_DSA = 0x0000004AL;
    public static final long CKK_ML_KEM = 0x00000049L;
    public static final long CKK_SLH_DSA = 0x0000004BL;
    public static final long CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001CL;
    public static final long CKM_ML_DSA = 0x0000001DL;
    public static final long CKM_ML_KEM_KEY_PAIR_GEN = 0x0000000FL;
    public static final long CKM_ML_KEM = 0x00000017L;
    public static final long CKM_SLH_DSA_KEY_PAIR_GEN = 0x0000002DL;
    public static final long CKM_SLH_DSA = 0x0000002EL;
    public static final long CKA_PARAMETER_SET = 0x0000061DL;

    /** {@code CKF_ENCAPSULATE | CKF_DECAPSULATE}, added in v3.2 and absent from jacknji11 1.3.1. */
    public static final long CKF_KEM = 0x30000000L;

    private static final BouncyCastleProvider BC = new BouncyCastleProvider();
    private static final SecureRandom RANDOM = new SecureRandom();

    /** FIPS 204 public-key sizes by CKP parameter set (1=44, 2=65, 3=87). */
    private static final Map<Long, Integer> ML_DSA_PUBLIC_KEY_LEN = Map.of(1L, 1312, 2L, 1952, 3L, 2592);
    /** FIPS 203 public-key sizes by CKP parameter set (1=512, 2=768, 3=1024). */
    private static final Map<Long, Integer> ML_KEM_PUBLIC_KEY_LEN = Map.of(1L, 800, 2L, 1184, 3L, 1568);

    // ---- token state ----
    private final long slotId;
    private final String tokenLabel;
    private final char[] pin;
    private final Map<Long, Map<Long, byte[]>> objects = new LinkedHashMap<>();
    private final Map<Long, Session> sessions = new HashMap<>();
    private final AtomicLong nextHandle = new AtomicLong(1);
    private final AtomicLong nextSession = new AtomicLong(100);
    private boolean initialized;
    private boolean loggedIn;

    // ---- observability, for assertions ----
    private int initializeCalls;
    private int finalizeCalls;
    private int sessionInfoCalls;
    private int loginCalls;
    private int findObjectsCalls;

    // ---- fault-injection knobs (0.3) ----
    private EcPointEncoding ecPointEncoding = EcPointEncoding.DER;
    private final Set<Long> omittedAttributes = new HashSet<>();
    private final Set<Long> emptyAttributes = new HashSet<>();
    private String pqcSpkiOid;
    private final Set<Long> readOnlyAttributes = new HashSet<>();
    private final Map<Long, Long> vendorMechanisms = new HashMap<>();
    private final Set<Long> extraMechanisms = new HashSet<>();
    private final Set<Long> hiddenMechanisms = new HashSet<>();
    private final Set<Long> underReportedMechanisms = new HashSet<>();
    private final Map<Long, Long> mechanismFlags = new HashMap<>();
    private final Set<Long> undescribableMechanisms = new HashSet<>();
    private long mechanismListCkr = -1;
    private long failNextCkr = -1;
    private int killSessionsAfter = -1;
    private int operationCount;

    public FakeToken() {
        this(0L, "FakeToken", "1234".toCharArray());
    }

    public FakeToken(long slotId, String tokenLabel, char[] pin) {
        this.slotId = slotId;
        this.tokenLabel = tokenLabel;
        this.pin = pin.clone();
    }

    // ---------------------------------------------------------------- knobs

    /** Report {@code CKA_EC_POINT} raw instead of DER-wrapped, as several HSMs do. */
    public FakeToken ecPointEncoding(EcPointEncoding encoding) {
        this.ecPointEncoding = encoding;
        return this;
    }

    /** Hide an attribute entirely, as a vendor that does not implement it would. */
    public FakeToken omitAttribute(long cka) {
        omittedAttributes.add(cka);
        return this;
    }

    /**
     * Report an attribute as present but zero-length. Distinct from {@link #omitAttribute}: the
     * call succeeds and the caller gets an empty array rather than an error, which is how some
     * modules answer for an attribute they store but have not populated.
     */
    public FakeToken emptyAttribute(long cka) {
        emptyAttributes.add(cka);
        return this;
    }

    /**
     * Wrap the {@code CKA_VALUE} of subsequently generated post-quantum public keys in a
     * {@code SubjectPublicKeyInfo} carrying {@code oid}, instead of reporting raw key material.
     *
     * <p>PKCS#11 v3.2 does not settle which of the two a token reports, and implementations
     * differ, so the reader has to handle both without configuration. The OID is a parameter
     * rather than derived here on purpose: the fake holds no algorithm table of its own, so it
     * cannot mask a mistake in the profile's.
     *
     * @param oid dotted OID, or {@code null} to go back to raw material
     */
    public FakeToken pqcSpkiOid(String oid) {
        this.pqcSpkiOid = oid;
        return this;
    }

    /** Reject {@code C_SetAttributeValue} on these attributes with {@code CKR_ATTRIBUTE_READ_ONLY}. */
    public FakeToken readOnlyAttributes(long... ckas) {
        for (long cka : ckas) {
            readOnlyAttributes.add(cka);
        }
        return this;
    }

    /**
     * Answer {@code standardCkm} only under {@code vendorCkm}, the way a vendor that predates the
     * v3.2 assignments does. The standard value then reports {@code CKR_MECHANISM_INVALID}.
     */
    public FakeToken vendorMechanism(long standardCkm, long vendorCkm) {
        vendorMechanisms.put(standardCkm, vendorCkm);
        return this;
    }

    /** Advertise an extra mechanism in {@code C_GetMechanismList}. */
    public FakeToken advertiseMechanism(long ckm) {
        extraMechanisms.add(ckm);
        return this;
    }

    /**
     * Stop advertising a mechanism, as firmware that predates an algorithm does. The mechanism then
     * appears in neither {@code C_GetMechanismList} nor {@code C_GetMechanismInfo}, and any
     * operation asking for it answers {@code CKR_MECHANISM_INVALID}.
     */
    public FakeToken hideMechanism(long... ckms) {
        for (long ckm : ckms) {
            hiddenMechanisms.add(ckm);
        }
        return this;
    }

    /**
     * Omit a mechanism from {@code C_GetMechanismList} while still honouring it.
     *
     * <p>Different from {@link #hideMechanism} in the way that matters: here the probe is wrong, not
     * the token. Modules do under-report — a mechanism gated by a partition policy may be usable
     * and unlisted — and that is the case the {@code kimbo11ng.probe.failFast} kill switch exists
     * for.
     */
    public FakeToken underReportMechanism(long ckm) {
        underReportedMechanisms.add(ckm);
        return this;
    }

    /**
     * Report specific {@code CKF_*} flags for a mechanism. For the case a probe exists to catch: a
     * mechanism that is listed but not usable for the operation being asked of it.
     */
    public FakeToken mechanismFlags(long ckm, long flags) {
        mechanismFlags.put(ckm, flags);
        return this;
    }

    /**
     * List a mechanism but answer {@code CKR_MECHANISM_INVALID} when asked to describe it. Real
     * modules do this for some of their own vendor mechanisms.
     */
    public FakeToken undescribableMechanism(long ckm) {
        undescribableMechanisms.add(ckm);
        return this;
    }

    /**
     * Refuse {@code C_GetMechanismList} for good, as a module behind a policy that will not
     * enumerate its mechanisms does. Distinct from {@link #failNextWith}: this fails only the probe
     * and fails it every time, so the rest of the token stays usable and the question of what
     * kimbo11ng does with an unanswerable probe can actually be asked.
     */
    public FakeToken failMechanismList(long ckr) {
        this.mechanismListCkr = ckr;
        return this;
    }

    /**
     * Forget every open session, as a network HSM does when it drops an idle connection: the
     * handles the client holds keep looking valid until it tries to use one.
     */
    public synchronized FakeToken dropAllSessions() {
        sessions.clear();
        return this;
    }

    /** Fail the next PKCS#11 call with this CKR, once. */
    public FakeToken failNextWith(long ckr) {
        this.failNextCkr = ckr;
        return this;
    }

    /**
     * Invalidate every open session after {@code n} more operations, as a network HSM does when the
     * link drops. Subsequent calls answer {@code CKR_SESSION_HANDLE_INVALID} until a session is
     * reopened.
     */
    public FakeToken killSessionsAfter(int n) {
        this.killSessionsAfter = n;
        this.operationCount = 0;
        return this;
    }

    public int initializeCalls() {
        return initializeCalls;
    }

    /** {@code C_GetSessionInfo} calls, to assert that validation happens only when it should. */
    public synchronized int sessionInfoCalls() {
        return sessionInfoCalls;
    }

    /** {@code C_Login} calls, to assert that login happens per token rather than per session. */
    public synchronized int loginCalls() {
        return loginCalls;
    }

    /** Object searches, to assert that a code path does not touch the token at all. */
    public synchronized int findObjectsCalls() {
        return findObjectsCalls;
    }

    public int finalizeCalls() {
        return finalizeCalls;
    }

    public synchronized int openSessionCount() {
        return sessions.size();
    }

    public synchronized boolean isLoggedIn() {
        return loggedIn;
    }

    /** Object handles currently on the token, for assertions. */
    public synchronized List<Long> handles() {
        return new ArrayList<>(objects.keySet());
    }

    /** Raw attribute value as the token holds it, for assertions. */
    public synchronized byte[] attribute(long handle, long cka) {
        Map<Long, byte[]> o = objects.get(handle);
        byte[] v = (o == null) ? null : o.get(cka);
        return (v == null) ? null : v.clone();
    }

    // ---------------------------------------------------------------- session plumbing

    private static final class Session {
        final long slot;
        boolean findActive;
        List<Long> findResults = Collections.emptyList();
        int findIndex;
        long signKey = -1;
        long signMechanism = -1;
        long verifyKey = -1;
        long verifyMechanism = -1;

        Session(long slot) {
            this.slot = slot;
        }
    }

    /** Applies the one-shot failure and session-death knobs. Returns non-OK to short-circuit. */
    private long gate() {
        if (failNextCkr >= 0) {
            long ckr = failNextCkr;
            failNextCkr = -1;
            return ckr;
        }
        if (killSessionsAfter >= 0) {
            if (operationCount >= killSessionsAfter) {
                sessions.clear();
                killSessionsAfter = -1;
                return CKR.SESSION_HANDLE_INVALID;
            }
            operationCount++;
        }
        return CKR.OK;
    }

    private Session session(long handle) {
        return sessions.get(handle);
    }

    // ---------------------------------------------------------------- library lifecycle

    @Override
    public synchronized long C_Initialize(CK_C_INITIALIZE_ARGS args) {
        initializeCalls++;
        if (initialized) {
            return CKR.CRYPTOKI_ALREADY_INITIALIZED;
        }
        initialized = true;
        return CKR.OK;
    }

    @Override
    public synchronized long C_Finalize(NativePointer reserved) {
        finalizeCalls++;
        if (!initialized) {
            return CKR.CRYPTOKI_NOT_INITIALIZED;
        }
        initialized = false;
        sessions.clear();
        loggedIn = false;
        return CKR.OK;
    }

    @Override
    public synchronized long C_GetSlotList(boolean tokenPresent, long[] list, LongRef count) {
        // Gated: reading the slot list is where a library whose client has lost its connection
        // reports itself, and caching that failure was a real defect.
        long gated = gate();
        if (gated != CKR.OK) {
            return gated;
        }
        if (!initialized) {
            return CKR.CRYPTOKI_NOT_INITIALIZED;
        }
        if (list == null) {
            count.value = 1;
            return CKR.OK;
        }
        if (list.length < 1) {
            count.value = 1;
            return CKR.BUFFER_TOO_SMALL;
        }
        list[0] = slotId;
        count.value = 1;
        return CKR.OK;
    }

    @Override
    public synchronized long C_GetTokenInfo(long slot, CK_TOKEN_INFO info) {
        long gated = gate();
        if (gated != CKR.OK) {
            return gated;
        }
        if (slot != slotId) {
            return CKR.SLOT_ID_INVALID;
        }
        // CK_TOKEN_INFO.label is a space-padded 32-byte field.
        byte[] label = new byte[32];
        Arrays.fill(label, (byte) ' ');
        byte[] src = tokenLabel.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(src, 0, label, 0, Math.min(src.length, 32));
        info.label = label;
        return CKR.OK;
    }

    @Override
    public synchronized long C_GetMechanismList(long slot, long[] list, LongRef count) {
        // Gated: a token whose client has lost its connection reports itself here too, and the
        // capability probe must not turn that into "this token supports nothing".
        long gated = gate();
        if (gated != CKR.OK) {
            return gated;
        }
        if (mechanismListCkr >= 0) {
            return mechanismListCkr;
        }
        if (slot != slotId) {
            return CKR.SLOT_ID_INVALID;
        }
        List<Long> mechanisms = advertisedMechanisms();
        if (list == null) {
            count.value = mechanisms.size();
            return CKR.OK;
        }
        if (list.length < mechanisms.size()) {
            count.value = mechanisms.size();
            return CKR.BUFFER_TOO_SMALL;
        }
        for (int i = 0; i < mechanisms.size(); i++) {
            list[i] = mechanisms.get(i);
        }
        count.value = mechanisms.size();
        return CKR.OK;
    }

    /** What {@code C_GetMechanismList} answers: everything supported, less the under-reported. */
    private List<Long> advertisedMechanisms() {
        List<Long> advertised = mechanismList();
        advertised.removeAll(underReportedMechanisms);
        return advertised;
    }

    /** What the token will actually do, which is not always what it admits to. */
    private List<Long> mechanismList() {
        List<Long> base = new ArrayList<>(List.of(
                CKM.RSA_PKCS_KEY_PAIR_GEN, CKM.SHA1_RSA_PKCS,
                CKM.SHA256_RSA_PKCS, CKM.SHA384_RSA_PKCS, CKM.SHA512_RSA_PKCS,
                // SoftHSMv3 advertises all three PSS mechanisms with CKF_SIGN|CKF_VERIFY.
                CKM.SHA256_RSA_PKCS_PSS, CKM.SHA384_RSA_PKCS_PSS, CKM.SHA512_RSA_PKCS_PSS,
                CKM.EC_KEY_PAIR_GEN, CKM.ECDSA, CKM.ECDSA_SHA256, CKM.ECDSA_SHA384, CKM.ECDSA_SHA512,
                CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA,
                CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA,
                CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM));
        base.removeAll(hiddenMechanisms);
        // A vendor-remapped mechanism is advertised under its vendor value only.
        base.replaceAll(m -> vendorMechanisms.getOrDefault(m, m));
        base.addAll(extraMechanisms);
        return base;
    }

    @Override
    public synchronized long C_GetMechanismInfo(long slot, long type, CK_MECHANISM_INFO info) {
        if (slot != slotId) {
            return CKR.SLOT_ID_INVALID;
        }
        if (!advertisedMechanisms().contains(type) || undescribableMechanisms.contains(type)) {
            return CKR.MECHANISM_INVALID;
        }
        info.flags = flagsFor(type);
        info.ulMinKeySize = 0;
        info.ulMaxKeySize = 4096;
        return CKR.OK;
    }

    /** Flags matching what SoftHSMv3 reports, unless a test has overridden them. */
    private long flagsFor(long type) {
        Long override = mechanismFlags.get(type);
        if (override != null) {
            return override;
        }
        if (type == CKM.RSA_PKCS_KEY_PAIR_GEN || type == CKM.EC_KEY_PAIR_GEN
                || type == CKM_ML_DSA_KEY_PAIR_GEN || type == CKM_SLH_DSA_KEY_PAIR_GEN
                || type == CKM_ML_KEM_KEY_PAIR_GEN) {
            return CK_MECHANISM_INFO.CKF_GENERATE_KEY_PAIR;
        }
        // Encapsulate/decapsulate, not sign — the distinction a presence-only probe would lose.
        if (type == CKM_ML_KEM) {
            return CKF_KEM;
        }
        return CK_MECHANISM_INFO.CKF_SIGN | CK_MECHANISM_INFO.CKF_VERIFY;
    }

    // ---------------------------------------------------------------- sessions and login

    @Override
    public synchronized long C_OpenSession(long slot, long flags, NativePointer app,
            CK_NOTIFY notify, LongRef handle) {
        // Gated like any other call: opening a session is exactly where a token that has been
        // removed, or an HSM whose client has lost its connection, first reports itself.
        long gated = gate();
        if (gated != CKR.OK) {
            return gated;
        }
        if (!initialized) {
            return CKR.CRYPTOKI_NOT_INITIALIZED;
        }
        if (slot != slotId) {
            return CKR.SLOT_ID_INVALID;
        }
        long h = nextSession.getAndIncrement();
        sessions.put(h, new Session(slot));
        handle.value = h;
        return CKR.OK;
    }

    @Override
    public synchronized long C_CloseSession(long handle) {
        return sessions.remove(handle) == null ? CKR.SESSION_HANDLE_INVALID : CKR.OK;
    }

    @Override
    public synchronized long C_CloseAllSessions(long slot) {
        if (slot != slotId) {
            return CKR.SLOT_ID_INVALID;
        }
        sessions.clear();
        return CKR.OK;
    }

    @Override
    public synchronized long C_GetSessionInfo(long handle, CK_SESSION_INFO info) {
        sessionInfoCalls++;
        Session s = session(handle);
        if (s == null) {
            return CKR.SESSION_HANDLE_INVALID;
        }
        info.slotID = s.slot;
        info.state = loggedIn ? CKS.RW_USER_FUNCTIONS : CKS.RW_PUBLIC_SESSION;
        return CKR.OK;
    }

    @Override
    public synchronized long C_Login(long handle, long userType, byte[] suppliedPin, long pinLen) {
        loginCalls++;
        long gated = gate();
        if (gated != CKR.OK) {
            return gated;
        }
        if (session(handle) == null) {
            return CKR.SESSION_HANDLE_INVALID;
        }
        if (userType != CKU.USER && userType != CKU.SO) {
            return CKR.ARGUMENTS_BAD;
        }
        // A real token short-circuits here WITHOUT checking the PIN. kimbo11ng must therefore
        // never treat a second successful login as evidence the credential was correct.
        if (loggedIn) {
            return CKR.USER_ALREADY_LOGGED_IN;
        }
        byte[] expected = new String(pin).getBytes(StandardCharsets.UTF_8);
        byte[] actual = (suppliedPin == null) ? new byte[0]
                : Arrays.copyOf(suppliedPin, (int) Math.min(pinLen, suppliedPin.length));
        if (!Arrays.equals(expected, actual)) {
            return CKR.PIN_INCORRECT;
        }
        loggedIn = true;
        return CKR.OK;
    }

    @Override
    public synchronized long C_Logout(long handle) {
        if (session(handle) == null) {
            return CKR.SESSION_HANDLE_INVALID;
        }
        if (!loggedIn) {
            return CKR.USER_NOT_LOGGED_IN;
        }
        loggedIn = false;
        return CKR.OK;
    }

    // ---------------------------------------------------------------- objects and attributes

    @Override
    public synchronized long C_CreateObject(long handle, CKA[] template, long count, LongRef out) {
        if (session(handle) == null) {
            return CKR.SESSION_HANDLE_INVALID;
        }
        out.value = store(toMap(template));
        return CKR.OK;
    }

    @Override
    public synchronized long C_DestroyObject(long handle, long object) {
        if (session(handle) == null) {
            return CKR.SESSION_HANDLE_INVALID;
        }
        return objects.remove(object) == null ? CKR.OBJECT_HANDLE_INVALID : CKR.OK;
    }

    /**
     * Implements the two-pass fetch jacknji11 drives: a {@code null pValue} is a length query, an
     * undersized buffer yields {@code CKR_BUFFER_TOO_SMALL}, and an absent attribute is reported by
     * setting {@code ulValueLen = -1} plus {@code CKR_ATTRIBUTE_TYPE_INVALID}.
     */
    @Override
    public synchronized long C_GetAttributeValue(long handle, long object, CKA[] template, long count) {
        long gated = gate();
        if (gated != CKR.OK) {
            return gated;
        }
        if (session(handle) == null) {
            return CKR.SESSION_HANDLE_INVALID;
        }
        Map<Long, byte[]> attrs = objects.get(object);
        if (attrs == null) {
            return CKR.OBJECT_HANDLE_INVALID;
        }
        long rv = CKR.OK;
        for (CKA cka : template) {
            byte[] value = omittedAttributes.contains(cka.type) ? null : attrs.get(cka.type);
            if (value != null && emptyAttributes.contains(cka.type)) {
                value = new byte[0];
            }
            if (value == null) {
                cka.ulValueLen = -1;
                rv = CKR.ATTRIBUTE_TYPE_INVALID;
            } else if (cka.pValue == null) {
                cka.ulValueLen = value.length;
            } else if (cka.pValue.length < value.length) {
                cka.ulValueLen = -1;
                rv = CKR.BUFFER_TOO_SMALL;
            } else {
                System.arraycopy(value, 0, cka.pValue, 0, value.length);
                cka.ulValueLen = value.length;
            }
            // The JNA transport marks every entry as populated after reading it back from native
            // memory (jna/Template.update), and CKA.hasValue() gates on that flag. Without this
            // the caller sees a null value even when the length and buffer are correct.
            cka.set();
        }
        return rv;
    }

    @Override
    public synchronized long C_SetAttributeValue(long handle, long object, CKA[] template, long count) {
        if (session(handle) == null) {
            return CKR.SESSION_HANDLE_INVALID;
        }
        Map<Long, byte[]> attrs = objects.get(object);
        if (attrs == null) {
            return CKR.OBJECT_HANDLE_INVALID;
        }
        for (CKA cka : template) {
            if (readOnlyAttributes.contains(cka.type)) {
                return CKR.ATTRIBUTE_READ_ONLY;
            }
        }
        attrs.putAll(toMap(template));
        return CKR.OK;
    }

    // ---------------------------------------------------------------- find

    @Override
    public synchronized long C_FindObjectsInit(long handle, CKA[] template, long count) {
        findObjectsCalls++;
        long gated = gate();
        if (gated != CKR.OK) {
            return gated;
        }
        Session s = session(handle);
        if (s == null) {
            return CKR.SESSION_HANDLE_INVALID;
        }
        // The whole point of the double: a find already running on this session is a protocol
        // violation, and a shared-session design trips it under concurrency.
        if (s.findActive) {
            return CKR.OPERATION_ACTIVE;
        }
        Map<Long, byte[]> criteria = toMap(template);
        List<Long> hits = new ArrayList<>();
        for (Map.Entry<Long, Map<Long, byte[]>> e : objects.entrySet()) {
            boolean match = true;
            for (Map.Entry<Long, byte[]> c : criteria.entrySet()) {
                if (!Arrays.equals(c.getValue(), e.getValue().get(c.getKey()))) {
                    match = false;
                    break;
                }
            }
            if (match) {
                hits.add(e.getKey());
            }
        }
        s.findActive = true;
        s.findResults = hits;
        s.findIndex = 0;
        return CKR.OK;
    }

    @Override
    public synchronized long C_FindObjects(long handle, long[] out, long max, LongRef count) {
        Session s = session(handle);
        if (s == null) {
            return CKR.SESSION_HANDLE_INVALID;
        }
        if (!s.findActive) {
            return CKR.OPERATION_NOT_INITIALIZED;
        }
        int n = 0;
        while (n < max && n < out.length && s.findIndex < s.findResults.size()) {
            out[n++] = s.findResults.get(s.findIndex++);
        }
        count.value = n;
        return CKR.OK;
    }

    @Override
    public synchronized long C_FindObjectsFinal(long handle) {
        Session s = session(handle);
        if (s == null) {
            return CKR.SESSION_HANDLE_INVALID;
        }
        if (!s.findActive) {
            return CKR.OPERATION_NOT_INITIALIZED;
        }
        s.findActive = false;
        s.findResults = Collections.emptyList();
        s.findIndex = 0;
        return CKR.OK;
    }

    // ---------------------------------------------------------------- key generation

    @Override
    public synchronized long C_GenerateKeyPair(long handle, CKM mechanism, CKA[] pubTemplate,
            long pubCount, CKA[] privTemplate, long privCount, LongRef pubOut, LongRef privOut) {
        long gated = gate();
        if (gated != CKR.OK) {
            return gated;
        }
        if (session(handle) == null) {
            return CKR.SESSION_HANDLE_INVALID;
        }
        if (!loggedIn) {
            return CKR.USER_NOT_LOGGED_IN;
        }
        long ckm = mechanism.mechanism;
        if (!mechanismList().contains(ckm)) {
            return CKR.MECHANISM_INVALID;
        }
        // Undo any vendor remapping so the switch below reasons in standard terms.
        for (Map.Entry<Long, Long> e : vendorMechanisms.entrySet()) {
            if (e.getValue() == ckm) {
                ckm = e.getKey();
                break;
            }
        }

        Map<Long, byte[]> pub = toMap(pubTemplate);
        Map<Long, byte[]> priv = toMap(privTemplate);
        // For CKM_EC_KEY_PAIR_GEN the curve is an input to the public template only; the token
        // derives the private key's copy. Supplying it on the private template sets a read-only
        // attribute, and SoftHSMv3 fails the whole generation with CKR_ATTRIBUTE_READ_ONLY. The
        // fake used to accept it, so a template that no real token would take passed the unit
        // suite and only failed against an HSM.
        if (ckm == CKM.EC_KEY_PAIR_GEN && priv.containsKey(CKA.EC_PARAMS)) {
            return CKR.ATTRIBUTE_READ_ONLY;
        }
        try {
            if (ckm == CKM.RSA_PKCS_KEY_PAIR_GEN) {
                generateRsa(pub, priv);
            } else if (ckm == CKM.EC_KEY_PAIR_GEN) {
                generateEc(pub, priv);
            } else if (ckm == CKM_ML_DSA_KEY_PAIR_GEN) {
                generatePqc(pub, priv, CKK_ML_DSA, ML_DSA_PUBLIC_KEY_LEN, 1952);
            } else if (ckm == CKM_ML_KEM_KEY_PAIR_GEN) {
                generatePqc(pub, priv, CKK_ML_KEM, ML_KEM_PUBLIC_KEY_LEN, 1184);
            } else if (ckm == CKM_SLH_DSA_KEY_PAIR_GEN) {
                generateSlhDsa(pub, priv);
            } else {
                return CKR.MECHANISM_INVALID;
            }
        } catch (Exception e) {
            return CKR.GENERAL_ERROR;
        }
        pubOut.value = store(pub);
        privOut.value = store(priv);
        return CKR.OK;
    }

    private void generateRsa(Map<Long, byte[]> pub, Map<Long, byte[]> priv) throws Exception {
        int bits = 2048;
        byte[] modulusBits = pub.get(CKA.MODULUS_BITS);
        if (modulusBits != null) {
            bits = (int) decodeLong(modulusBits);
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);
        kpg.initialize(bits);
        KeyPair kp = kpg.generateKeyPair();
        RSAPublicKey rsaPub = (RSAPublicKey) kp.getPublic();
        pub.put(CKA.MODULUS, unsigned(rsaPub.getModulus()));
        pub.put(CKA.PUBLIC_EXPONENT, unsigned(rsaPub.getPublicExponent()));
        pub.put(CKA.KEY_TYPE, encodeLong(CKK.RSA));
        priv.put(CKA.KEY_TYPE, encodeLong(CKK.RSA));
        priv.put(PRIVATE_MATERIAL, kp.getPrivate().getEncoded());
        priv.put(SIGN_ALGORITHM, "RSA".getBytes(StandardCharsets.UTF_8));
    }

    private void generateEc(Map<Long, byte[]> pub, Map<Long, byte[]> priv) throws Exception {
        byte[] ecParams = pub.get(CKA.EC_PARAMS);
        if (ecParams == null) {
            throw new IllegalArgumentException("CKA_EC_PARAMS missing");
        }
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(ecParams);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
        kpg.initialize(new ECGenParameterSpec(oid.getId()));
        KeyPair kp = kpg.generateKeyPair();

        org.bouncycastle.jce.interfaces.ECPublicKey bcPub =
                (org.bouncycastle.jce.interfaces.ECPublicKey) kp.getPublic();
        byte[] point = bcPub.getQ().getEncoded(false);
        pub.put(CKA.EC_POINT, encodeEcPoint(point));
        pub.put(CKA.KEY_TYPE, encodeLong(CKK.EC));
        priv.put(CKA.KEY_TYPE, encodeLong(CKK.EC));
        priv.put(CKA.EC_PARAMS, ecParams);
        priv.put(PRIVATE_MATERIAL, kp.getPrivate().getEncoded());
        priv.put(SIGN_ALGORITHM, "EC".getBytes(StandardCharsets.UTF_8));
    }

    private byte[] encodeEcPoint(byte[] rawPoint) throws IOException {
        return ecPointEncoding == EcPointEncoding.DER
                ? new DEROctetString(rawPoint).getEncoded()
                : rawPoint;
    }

    private void generatePqc(Map<Long, byte[]> pub, Map<Long, byte[]> priv, long ckk,
            Map<Long, Integer> sizesByParamSet, int defaultSize) {
        byte[] psBytes = pub.containsKey(CKA_PARAMETER_SET) ? pub.get(CKA_PARAMETER_SET)
                : priv.get(CKA_PARAMETER_SET);
        int size = defaultSize;
        if (psBytes != null) {
            Integer mapped = sizesByParamSet.get(decodeLong(psBytes));
            if (mapped == null) {
                throw new IllegalArgumentException("Unknown CKA_PARAMETER_SET " + decodeLong(psBytes));
            }
            size = mapped;
        }
        byte[] material = new byte[size];
        RANDOM.nextBytes(material);
        pub.put(CKA.VALUE, publicValue(material));
        // putIfAbsent, not put: PKCS#11 validates CKA_KEY_TYPE from the template rather than
        // overwriting it, so a vendor profile's own key type must survive generation.
        pub.putIfAbsent(CKA.KEY_TYPE, encodeLong(ckk));
        priv.putIfAbsent(CKA.KEY_TYPE, encodeLong(ckk));
        priv.put(SIGN_ALGORITHM, "PQC".getBytes(StandardCharsets.UTF_8));
    }

    /** Applies the {@link #pqcSpkiOid} knob to freshly generated public-key material. */
    private byte[] publicValue(byte[] material) {
        if (pqcSpkiOid == null) {
            return material;
        }
        try {
            return new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(new ASN1ObjectIdentifier(pqcSpkiOid)), material)
                    .getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("cannot encode a SubjectPublicKeyInfo for OID "
                    + pqcSpkiOid, e);
        }
    }

    private void generateSlhDsa(Map<Long, byte[]> pub, Map<Long, byte[]> priv) {
        byte[] psBytes = pub.containsKey(CKA_PARAMETER_SET) ? pub.get(CKA_PARAMETER_SET)
                : priv.get(CKA_PARAMETER_SET);
        long paramSet = (psBytes == null) ? 1L : decodeLong(psBytes);
        if (paramSet < 1 || paramSet > 12) {
            throw new IllegalArgumentException("Unknown SLH-DSA CKA_PARAMETER_SET " + paramSet);
        }
        // FIPS 205 public key is 2n bytes: n=16 for the 128 family, 24 for 192, 32 for 256.
        int size = paramSet <= 4 ? 32 : (paramSet <= 8 ? 48 : 64);
        byte[] material = new byte[size];
        RANDOM.nextBytes(material);
        pub.put(CKA.VALUE, publicValue(material));
        pub.putIfAbsent(CKA.KEY_TYPE, encodeLong(CKK_SLH_DSA));
        priv.putIfAbsent(CKA.KEY_TYPE, encodeLong(CKK_SLH_DSA));
        priv.put(SIGN_ALGORITHM, "PQC".getBytes(StandardCharsets.UTF_8));
    }

    // ---------------------------------------------------------------- sign and verify

    @Override
    public synchronized long C_SignInit(long handle, CKM mechanism, long key) {
        long gated = gate();
        if (gated != CKR.OK) {
            return gated;
        }
        Session s = session(handle);
        if (s == null) {
            return CKR.SESSION_HANDLE_INVALID;
        }
        if (s.signKey >= 0) {
            return CKR.OPERATION_ACTIVE;
        }
        if (!objects.containsKey(key)) {
            return CKR.KEY_HANDLE_INVALID;
        }
        if (!pssParamIsValid(mechanism)) {
            return CKR.MECHANISM_PARAM_INVALID;
        }
        s.signKey = key;
        s.signMechanism = mechanism.mechanism;
        return CKR.OK;
    }

    @Override
    public synchronized long C_Sign(long handle, byte[] data, long dataLen, byte[] out, LongRef outLen) {
        long gated = gate();
        if (gated != CKR.OK) {
            return gated;
        }
        Session s = session(handle);
        if (s == null) {
            return CKR.SESSION_HANDLE_INVALID;
        }
        if (s.signKey < 0) {
            return CKR.OPERATION_NOT_INITIALIZED;
        }
        byte[] signature;
        try {
            signature = sign(s, Arrays.copyOf(data, (int) dataLen));
        } catch (Exception e) {
            return CKR.GENERAL_ERROR;
        }
        if (out == null) {
            outLen.value = signature.length;
            return CKR.OK;
        }
        if (out.length < signature.length) {
            outLen.value = signature.length;
            return CKR.BUFFER_TOO_SMALL;
        }
        System.arraycopy(signature, 0, out, 0, signature.length);
        outLen.value = signature.length;
        s.signKey = -1;
        s.signMechanism = -1;
        return CKR.OK;
    }

    private byte[] sign(Session s, byte[] data) throws Exception {
        Map<Long, byte[]> key = objects.get(s.signKey);
        byte[] alg = key.get(SIGN_ALGORITHM);
        String algorithm = (alg == null) ? "PQC" : new String(alg, StandardCharsets.UTF_8);
        if ("PQC".equals(algorithm)) {
            // No real PQC signing: nothing under test verifies these, and a wrong-length blob
            // would be a worse lie than an obviously synthetic one of plausible size.
            byte[] fake = new byte[64];
            RANDOM.nextBytes(fake);
            return fake;
        }
        PrivateKey privateKey = java.security.KeyFactory
                .getInstance(algorithm, BC)
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(key.get(PRIVATE_MATERIAL)));
        Signature sig = Signature.getInstance(signatureAlgorithm(s.signMechanism, algorithm), BC);
        sig.initSign(privateKey);
        sig.update(data);
        byte[] der = sig.sign();
        // PKCS#11 returns ECDSA as the raw r||s pair, not DER — mirroring that is essential,
        // because converting it back is exactly what Kimbo11ngSignatureSpi has to get right.
        return "EC".equals(algorithm) ? derToRawEcdsa(der, fieldSize(key)) : der;
    }

    private static String signatureAlgorithm(long ckm, String keyAlgorithm) {
        if ("EC".equals(keyAlgorithm)) {
            if (ckm == CKM.ECDSA_SHA384) {
                return "SHA384withECDSA";
            }
            if (ckm == CKM.ECDSA_SHA512) {
                return "SHA512withECDSA";
            }
            return "SHA256withECDSA";
        }
        if (ckm == CKM.SHA1_RSA_PKCS) {
            return "SHA1withRSA";
        }
        if (ckm == CKM.SHA384_RSA_PKCS) {
            return "SHA384withRSA";
        }
        if (ckm == CKM.SHA512_RSA_PKCS) {
            return "SHA512withRSA";
        }
        // PSS through BouncyCastle's own SHAxxxwithRSAandMGF1, which uses a salt equal to the
        // digest length — the same choice RsaPssParams encodes. If the two ever disagree, a
        // signature produced here stops verifying and the round-trip test says so.
        if (ckm == CKM.SHA256_RSA_PKCS_PSS) {
            return "SHA256withRSAandMGF1";
        }
        if (ckm == CKM.SHA384_RSA_PKCS_PSS) {
            return "SHA384withRSAandMGF1";
        }
        if (ckm == CKM.SHA512_RSA_PKCS_PSS) {
            return "SHA512withRSAandMGF1";
        }
        return "SHA256withRSA";
    }

    /**
     * Rejects a PSS {@code C_SignInit} whose mechanism parameter is missing or the wrong size.
     *
     * <p>Real tokens answer {@code CKR_MECHANISM_PARAM_INVALID} here, and jacknji11 supplies no
     * default for these mechanisms — so without this the fake would happily sign a PSS operation
     * that every real HSM refuses, and the gap would only appear against hardware.
     */
    private static boolean pssParamIsValid(CKM mechanism) {
        long ckm = mechanism.mechanism;
        if (ckm != CKM.SHA256_RSA_PKCS_PSS && ckm != CKM.SHA384_RSA_PKCS_PSS
                && ckm != CKM.SHA512_RSA_PKCS_PSS && ckm != CKM.RSA_PKCS_PSS
                && ckm != CKM.SHA1_RSA_PKCS_PSS) {
            return true;
        }
        // CK_RSA_PKCS_PSS_PARAMS is three CK_ULONGs: hashAlg, mgf, sLen.
        return mechanism.ulParameterLen == 3L * ULong.ULONG_SIZE.size();
    }

    private int fieldSize(Map<Long, byte[]> key) {
        byte[] ecParams = key.get(CKA.EC_PARAMS);
        ECNamedCurveParameterSpec spec = org.bouncycastle.jce.ECNamedCurveTable
                .getParameterSpec(ASN1ObjectIdentifier.getInstance(ecParams).getId());
        return (spec.getCurve().getFieldSize() + 7) / 8;
    }

    private static byte[] derToRawEcdsa(byte[] der, int fieldSize) throws IOException {
        org.bouncycastle.asn1.ASN1Sequence seq =
                org.bouncycastle.asn1.ASN1Sequence.getInstance(der);
        BigInteger r = org.bouncycastle.asn1.ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        BigInteger s = org.bouncycastle.asn1.ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
        byte[] out = new byte[fieldSize * 2];
        byte[] rb = unsigned(r);
        byte[] sb = unsigned(s);
        System.arraycopy(rb, 0, out, fieldSize - rb.length, rb.length);
        System.arraycopy(sb, 0, out, fieldSize * 2 - sb.length, sb.length);
        return out;
    }

    // ---------------------------------------------------------------- helpers

    /** Internal-only attribute slots, well outside the PKCS#11 vendor-defined range. */
    private static final long PRIVATE_MATERIAL = 0x7F000001L;
    private static final long SIGN_ALGORITHM = 0x7F000002L;

    private long store(Map<Long, byte[]> attributes) {
        long handle = nextHandle.getAndIncrement();
        objects.put(handle, new LinkedHashMap<>(attributes));
        return handle;
    }

    private static Map<Long, byte[]> toMap(CKA[] template) {
        Map<Long, byte[]> map = new LinkedHashMap<>();
        if (template != null) {
            for (CKA cka : template) {
                map.put(cka.type, cka.pValue == null ? new byte[0] : cka.pValue.clone());
            }
        }
        return map;
    }

    /** CK_ULONG is little-endian on every platform kimbo11ng targets. */
    /**
     * A {@code CK_ULONG} in the token's native width and byte order.
     *
     * <p>Delegated to the binding's own codec rather than fixed at 8 bytes: {@code CK_ULONG} is 4
     * bytes on some builds and 8 on others, and {@code CKA.getValueLong()} rejects any value whose
     * length is not exactly {@code ULong.ULONG_SIZE}. A fake that hard-codes the width produces
     * attributes the caller cannot read at all — which is precisely what a token with a mismatched
     * library does, and not what these tests are for.
     */
    private static byte[] encodeLong(long value) {
        return ULong.ulong2b(value);
    }

    private static long decodeLong(byte[] bytes) {
        return ULong.b2ulong(bytes) & 0xFFFF_FFFFL;
    }

    /** Big-endian magnitude with no sign byte, which is how PKCS#11 carries big integers. */
    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }
}

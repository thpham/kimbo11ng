/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.pkcs11.jacknji11.Cryptoki;
import org.pkcs11.jacknji11.CryptokiE;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * One loaded PKCS#11 library.
 *
 * <p>Previously each {@code CryptokiDevice} and each {@code SlotListWrapper} constructed its own
 * {@code Cryptoki} and called {@code C_Initialize}, so resolving a slot and then opening it
 * initialised the same library two or three times. PKCS#11 permits exactly one
 * {@code C_Initialize} per library per application; the extra calls answer
 * {@code CKR_CRYPTOKI_ALREADY_INITIALIZED}, which the old code swallowed along with every other
 * failure — including a library that could not load at all.
 *
 * <h2>C_Finalize is never called</h2>
 *
 * <p>Not an oversight, and not laziness about cleanup. EJBCA selects a
 * {@code PKCS11SlotListWrapperFactory} through {@code ServiceLoader} by priority, and ours (2)
 * outranks the SunPKCS11-backed one (1). EJBCA's <em>classic</em> {@code PKCS11CryptoToken}
 * therefore resolves its slots through this module, for every library — including libraries whose
 * keys are being used through SunPKCS11, whose own state we would be tearing down. Finalising a
 * library another component is still using invalidates its sessions and object handles, and the
 * damage appears somewhere else entirely. SunPKCS11 makes the same choice for the same reason: the
 * library stays initialised for the life of the JVM.
 */
public final class Pkcs11Module {

    private static final Logger log = Logger.getLogger(Pkcs11Module.class);

    private final String canonicalPath;
    private final CryptokiE ce;

    private final ConcurrentMap<Long, SessionPool> pools = new ConcurrentHashMap<>();
    private java.util.function.LongSupplier clock = System::currentTimeMillis;
    private final Map<Long, char[]> tokenLabels = new ConcurrentHashMap<>();
    private volatile long[] slots;

    Pkcs11Module(String canonicalPath, NativeProviderFactory factory)
            throws CryptoTokenOfflineException {
        this.canonicalPath = canonicalPath;
        this.ce = new CryptokiE(new Cryptoki(factory.create(canonicalPath)));
        initialize();
    }

    private void initialize() throws CryptoTokenOfflineException {
        try {
            ce.Initialize();
            log.info("Initialized PKCS#11 library " + canonicalPath);
        } catch (Exception e) {
            if (Pkcs11Errors.isAlreadyInitialized(e)) {
                // Another component in this JVM got there first. Expected, and fine: the library
                // is initialised, which is all we need.
                if (log.isDebugEnabled()) {
                    log.debug("PKCS#11 library " + canonicalPath
                            + " was already initialized by another component");
                }
                return;
            }
            // Everything else is fatal and must say so. The previous code logged this at debug and
            // carried on, so a library that failed to load produced "no slots found" much later,
            // with nothing pointing at the real cause.
            throw Pkcs11Errors.offline(
                    "Could not initialize the PKCS#11 library " + canonicalPath, e);
        }
    }

    public String path() {
        return canonicalPath;
    }

    /**
     * The library's own handle. Exposed because every PKCS#11 call needs it; the session it acts
     * on comes from a {@link SessionLease}, never from here.
     */
    public CryptokiE ce() {
        return ce;
    }

    /**
     * Slots with a token present.
     *
     * <p>Cached, because EJBCA asks per token and per CA operation and the answer changes only when
     * hardware does. <b>Failures are never cached.</b> The previous implementation stored an empty
     * array when the call failed, so one transient error at startup — a Luna client not yet
     * connected, say — made the library permanently slotless for the life of the JVM, and only a
     * restart fixed it.
     */
    public long[] slotList() throws CryptoTokenOfflineException {
        long[] cached = slots;
        if (cached != null) {
            return cached.clone();
        }
        try {
            long[] fresh = ce.GetSlotList(true);
            if (fresh == null) {
                fresh = new long[0];
            }
            slots = fresh;
            if (log.isDebugEnabled()) {
                log.debug("Library " + canonicalPath + " reports " + fresh.length
                        + " slot(s) with a token present");
            }
            return fresh.clone();
        } catch (Exception e) {
            throw Pkcs11Errors.offline("Could not read the slot list from " + canonicalPath, e);
        }
    }

    /** The token label for a slot, trimmed. Cached; failures are not. */
    public char[] tokenLabel(long slotId) throws CryptoTokenOfflineException {
        char[] cached = tokenLabels.get(slotId);
        if (cached != null) {
            return cached.clone();
        }
        try {
            CK_TOKEN_INFO info = ce.GetTokenInfo(slotId);
            String label = info.label == null ? ""
                    : new String(info.label, StandardCharsets.UTF_8).trim();
            char[] chars = label.toCharArray();
            tokenLabels.put(slotId, chars);
            return chars.clone();
        } catch (Exception e) {
            throw Pkcs11Errors.offline("Could not read the token label for slot " + slotId
                    + " of " + canonicalPath, e);
        }
    }

    /**
     * Forgets the slot and label caches so the next call asks the token again. For a slot that has
     * been re-provisioned, or a client that has reconnected.
     */
    public void invalidate() {
        slots = null;
        tokenLabels.clear();
        if (log.isDebugEnabled()) {
            log.debug("Invalidated slot caches for " + canonicalPath);
        }
    }

    /**
     * The session pool for a slot, created on first use.
     *
     * <p>One pool per slot, shared by every token instance pointing at it — two EJBCA crypto tokens
     * on the same slot are the same PKCS#11 application and share its session budget and login
     * state, so giving them separate pools would let them exceed the token's session limit between
     * them.
     */
    public SessionPool pool(long slotId, SessionPoolConfig config) {
        return pools.computeIfAbsent(slotId, id -> new SessionPool(ce, id, config, clock));
    }

    /** Replaces the pools' clock. For tests that need to reach the idle-validation threshold. */
    void clock(java.util.function.LongSupplier clock) {
        this.clock = clock;
    }

    /** The pool for a slot if one has been created, else {@code null}. */
    public SessionPool existingPool(long slotId) {
        return pools.get(slotId);
    }

    /**
     * Drains and forgets the pool for a slot. The library itself stays initialised — see the class
     * comment on why {@code C_Finalize} is not called.
     */
    public void releaseSlot(long slotId) {
        SessionPool pool = pools.remove(slotId);
        if (pool != null) {
            pool.drain();
        }
    }

    /** A module bound to a slot, which is what a crypto token actually works against. */
    public P11Slot slot(long slotId, Properties properties) {
        return new P11Slot(this, slotId, SessionPoolConfig.from(properties));
    }

    @Override
    public String toString() {
        return "Pkcs11Module{" + canonicalPath + ", " + pools.size() + " slot pool(s)}";
    }
}

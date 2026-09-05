/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CryptokiE;

import java.io.File;

/**
 * One slot of one PKCS#11 library: what a crypto token actually operates on.
 *
 * <p>Replaces {@code CryptokiDevice}, which owned a library initialisation, a single session and
 * the login state all at once. Those are three different lifetimes — the library outlives the JVM's
 * use of any slot, sessions come and go, and login belongs to the token — and conflating them is
 * what made a shared session look like a reasonable design.
 *
 * <p>Callers never hold a session; they borrow one:
 *
 * <pre>{@code
 * try (SessionLease lease = slot.borrow()) {
 *     slot.ce().Sign(lease.session(), data);
 * }
 * }</pre>
 */
public final class P11Slot {

    private static final Logger log = Logger.getLogger(P11Slot.class);

    private final Pkcs11Module module;
    private final long slotId;
    private final SessionPoolConfig config;
    private volatile boolean loggedIn;

    P11Slot(Pkcs11Module module, long slotId, SessionPoolConfig config) {
        this.module = module;
        this.slotId = slotId;
        this.config = config;
        module.pool(slotId, config);
    }

    /**
     * The live pool for this slot.
     *
     * <p>Looked up on each use rather than cached in a field. {@link #close()} drains the pool and
     * drops it from the module, and a cached reference would leave this slot pointing at a closed
     * pool forever: EJBCA calls {@code reset()} and then {@code activate()} on the same crypto
     * token object, so a slot that could not be reopened would be dead until the application
     * server restarted. The lookup is a {@code computeIfAbsent} on a concurrent map.
     */
    public SessionPool pool() {
        return module.pool(slotId, config);
    }

    /** Takes a session for the duration of one operation. */
    public SessionLease borrow() throws CryptoTokenOfflineException {
        return pool().borrow();
    }

    /** The library handle. The session to act on comes from {@link #borrow()}. */
    public CryptokiE ce() {
        return module.ce();
    }

    public Pkcs11Module module() {
        return module;
    }

    public long slotId() {
        return slotId;
    }

    public String libPath() {
        return module.path();
    }

    /**
     * The library file name with everything but {@code [A-Za-z0-9_-]} replaced, used to build the
     * JCA provider name. Stable for a given library, which is what EJBCA relies on: it resolves
     * providers by name and registers a name only once.
     */
    public String libraryName() {
        return new File(module.path()).getName().replaceAll("[^a-zA-Z0-9_-]", "_");
    }

    /**
     * Authenticates to the token, once.
     *
     * <p>The flag is an optimisation, not the authority — PKCS#11 login state lives on the token,
     * and {@link SessionPool#login} tolerates {@code CKR_USER_ALREADY_LOGGED_IN} for the case where
     * something else in this JVM logged in first.
     */
    public synchronized void login(char[] pin)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        if (loggedIn) {
            return;
        }
        pool().login(pin);
        loggedIn = true;
    }

    /** Drops the token's login state. Sessions stay open. */
    public synchronized void logout() {
        if (!loggedIn) {
            return;
        }
        pool().logout();
        loggedIn = false;
    }

    /**
     * Closes every session on this slot and forgets its pool.
     *
     * <p>The library stays initialised: see {@link Pkcs11Module} for why finalising it would break
     * other users of the same library in this JVM.
     */
    public synchronized void close() {
        logout();
        module.releaseSlot(slotId);
        if (log.isDebugEnabled()) {
            log.debug("Released slot " + slotId + " of " + module.path());
        }
    }

    public boolean isLoggedIn() {
        return loggedIn;
    }

    @Override
    public String toString() {
        return "P11Slot{" + module.path() + " slot=" + slotId + "}";
    }
}

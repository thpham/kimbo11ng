/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.CryptokiE;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.concurrent.Semaphore;
import java.util.function.LongSupplier;
import java.util.concurrent.TimeUnit;

/**
 * A bounded pool of PKCS#11 sessions for one slot.
 *
 * <p>Replaces a single session shared by every thread. That design worked against SoftHSM under a
 * test load and would not survive a real CA: two concurrent signings, or a signing concurrent with
 * an enumeration, collide on the session's operation state and one of them fails with
 * {@code CKR_OPERATION_ACTIVE}. Serialising every operation behind one lock — the previous
 * mitigation — trades the corruption for a throughput ceiling of one operation at a time across
 * the whole HSM.
 *
 * <h2>What the pool guarantees</h2>
 *
 * <ul>
 *   <li>A borrowed session is used by exactly one thread until its lease closes.
 *   <li>The pool never grows past {@code kimbo11ng.sessions.max}. HSMs have a hard session limit
 *       (a Luna partition's is configurable but finite), and exceeding it fails operations for
 *       every application on the token, not only this one.
 *   <li>It never shrinks to zero while alive. PKCS#11 ties login state to the application's last
 *       session on a token: close them all and the token logs out, so the next operation fails
 *       with {@code CKR_USER_NOT_LOGGED_IN} and EJBCA takes the CA offline. Sessions are therefore
 *       only closed when broken, or by {@link #drain()}.
 *   <li>A session idle longer than {@link #VALIDATE_AFTER_IDLE_MILLIS} is validated before it is
 *       handed out, so a connection the HSM dropped while nothing was happening surfaces as a
 *       fresh session rather than as a failed signature.
 * </ul>
 *
 * <p>Login is not per session. {@code C_Login} authenticates the application to the <em>token</em>,
 * so it happens once per pool and every session opened afterwards inherits the state.
 */
public final class SessionPool {

    private static final Logger log = Logger.getLogger(SessionPool.class);

    /**
     * How long a pooled session may sit unused before it is checked with {@code C_GetSessionInfo}.
     * Not configurable: the check costs one cheap round trip and only runs on a session that has
     * been idle, so there is no tuning to do. Chosen well below the idle timeout of any HSM or
     * firewall likely to sit in front of one.
     */
    static final long VALIDATE_AFTER_IDLE_MILLIS = 60_000L;

    /** Open R/W: EJBCA generates and deletes keys, which a read-only session cannot do. */
    private static final long SESSION_FLAGS =
            CK_SESSION_INFO.CKF_SERIAL_SESSION | CK_SESSION_INFO.CKF_RW_SESSION;

    private final CryptokiE ce;
    private final long slotId;
    private final SessionPoolConfig config;
    /** Wall clock, injectable so the idle threshold can be tested without waiting a minute. */
    private final LongSupplier clock;

    /** Permits bound the number of live sessions; acquiring one is the right to hold a session. */
    private final Semaphore permits;
    private final Deque<Idle> idle = new ArrayDeque<>();
    private final Object lock = new Object();

    private int live;
    private volatile boolean closed;

    private record Idle(long session, long lastUsedMillis) {
    }

    SessionPool(CryptokiE ce, long slotId, SessionPoolConfig config) {
        this(ce, slotId, config, System::currentTimeMillis);
    }

    SessionPool(CryptokiE ce, long slotId, SessionPoolConfig config, LongSupplier clock) {
        this.ce = ce;
        this.slotId = slotId;
        this.config = config;
        this.clock = clock;
        // Fair, so a thread that has been waiting for a session is served before one that just
        // arrived. Under saturation an unfair semaphore can starve a request until its borrow
        // timeout expires and the CA is declared offline while work is in fact completing.
        this.permits = new Semaphore(config.maxSessions(), true);
    }

    /**
     * Takes a session, opening one if the pool is below its ceiling and blocking up to the
     * configured timeout otherwise.
     *
     * @throws CryptoTokenOfflineException if no session becomes available in time, or the token
     *         cannot provide one. Offline rather than a generic failure because that is what makes
     *         EJBCA stop routing work to this CA instead of piling more onto a stuck HSM.
     */
    public SessionLease borrow() throws CryptoTokenOfflineException {
        if (closed) {
            throw new CryptoTokenOfflineException(
                    "The session pool for slot " + slotId + " has been closed; the token is offline");
        }
        boolean acquired;
        try {
            acquired = permits.tryAcquire(config.borrowTimeoutSeconds(), TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CryptoTokenOfflineException(
                    "Interrupted while waiting for a PKCS#11 session on slot " + slotId, e);
        }
        if (!acquired) {
            throw new CryptoTokenOfflineException("No PKCS#11 session became available for slot "
                    + slotId + " within " + config.borrowTimeoutSeconds() + "s. All "
                    + config.maxSessions() + " sessions are in use; raise "
                    + SessionPoolConfig.MAX_SESSIONS + " or look for an operation that is not"
                    + " returning.");
        }
        try {
            return new SessionLease(this, takeOrOpen());
        } catch (RuntimeException | CryptoTokenOfflineException e) {
            permits.release();
            throw e;
        }
    }

    private long takeOrOpen() throws CryptoTokenOfflineException {
        while (true) {
            Idle candidate;
            synchronized (lock) {
                candidate = idle.pollLast();
            }
            if (candidate == null) {
                return openSession();
            }
            if (clock.getAsLong() - candidate.lastUsedMillis()
                    < VALIDATE_AFTER_IDLE_MILLIS || isAlive(candidate.session())) {
                return candidate.session();
            }
            // Stale. Drop it and look at the next one; the permit is already ours, so this cannot
            // spin indefinitely — the pool has at most maxSessions entries to discard.
            discard(candidate.session());
        }
    }

    private boolean isAlive(long session) {
        try {
            ce.GetSessionInfo(session, new CK_SESSION_INFO());
            return true;
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Discarding session " + session + " on slot " + slotId
                        + " after idle: " + Pkcs11Errors.describe(e));
            }
            return false;
        }
    }

    private long openSession() throws CryptoTokenOfflineException {
        try {
            long session = ce.OpenSession(slotId, SESSION_FLAGS, null, null);
            synchronized (lock) {
                live++;
            }
            if (log.isDebugEnabled()) {
                log.debug("Opened session " + session + " on slot " + slotId + " (live=" + live
                        + "/" + config.maxSessions() + ")");
            }
            return session;
        } catch (Exception e) {
            throw Pkcs11Errors.offline(
                    "Could not open a PKCS#11 session on slot " + slotId, e);
        }
    }

    /** Called by {@link SessionLease#close()}. */
    void release(long session, boolean broken) {
        try {
            if (closed || broken) {
                discard(session);
                return;
            }
            synchronized (lock) {
                idle.addLast(new Idle(session, clock.getAsLong()));
            }
        } finally {
            permits.release();
        }
    }

    private void discard(long session) {
        try {
            ce.CloseSession(session);
        } catch (Exception e) {
            // Already gone as far as the token is concerned, which is the state we wanted.
            if (log.isDebugEnabled()) {
                log.debug("C_CloseSession on " + session + " failed: " + Pkcs11Errors.describe(e));
            }
        }
        synchronized (lock) {
            live--;
        }
    }

    /**
     * Authenticates the application to the token.
     *
     * <p>Once, per token, not per session: PKCS#11 login state belongs to the application and the
     * token together. {@code CKR_USER_ALREADY_LOGGED_IN} is therefore an expected answer — another
     * component in this JVM (SunPKCS11 through EJBCA's classic token, most likely) may have logged
     * in to the same slot already — and is not an error.
     *
     * @param pin zeroed by the caller; this method copies nothing that outlives it
     * @throws CryptoTokenAuthenticationFailedException if {@code pin} is absent or empty, without
     *         contacting the token — see below
     */
    public void login(char[] pin)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        // An absent credential is refused here rather than sent on. Pins.encodeUtf8 turns null into
        // an empty array, and C_Login with an empty PIN is not a no-op: most tokens count it as a
        // failed authentication attempt, and a handful of those in a row lock the user PIN. Both
        // callers can produce one — the CLI when an operator aborts the prompt, and
        // CryptoTokenImpl.activate when EJBCA holds no auth code — so the guard belongs at the one
        // place they share. A token with CKF_PROTECTED_AUTHENTICATION_PATH would legitimately log
        // in with no PIN, but nothing in this project supports one, and adding that support is
        // where this check would need revisiting.
        if (pin == null || pin.length == 0) {
            throw new CryptoTokenAuthenticationFailedException("No PIN was supplied for slot "
                    + slotId + ". Refusing to send an empty credential to the token, because it"
                    + " would count as a failed attempt against the user PIN.");
        }
        byte[] pinBytes = Pins.encodeUtf8(pin);
        try {
            try {
                loginOnce(pinBytes);
            } catch (CryptoTokenOfflineException | RuntimeException first) {
                if (Pkcs11Errors.classify(first) != Pkcs11Errors.Kind.RETRYABLE) {
                    throw first;
                }
                // The pooled session was dead, not the token. loginOnce has already dropped it, so
                // this attempt opens a fresh one. Without the retry an HSM that reconnected while
                // EJBCA kept the token loaded could never be re-activated: every attempt drew the
                // same stale handle and only an application server restart cleared it.
                log.info("Retrying login to slot " + slotId + " on a fresh session"
                        + Pkcs11Errors.describe(first));
                loginOnce(pinBytes);
            }
        } catch (Exception e) {
            if (Pkcs11Errors.isAlreadyLoggedIn(e)) {
                if (log.isDebugEnabled()) {
                    log.debug("Slot " + slotId + " was already logged in; continuing");
                }
                return;
            }
            if (Pkcs11Errors.classify(e) == Pkcs11Errors.Kind.AUTH_FAILED) {
                // CryptoTokenAuthenticationFailedException has no cause-carrying constructor, so
                // the CKR is named in the message instead of being lost.
                throw new CryptoTokenAuthenticationFailedException("PKCS#11 login to slot "
                        + slotId + " was rejected" + Pkcs11Errors.describe(e));
            }
            throw Pkcs11Errors.offline("PKCS#11 login to slot " + slotId + " failed", e);
        } finally {
            Arrays.fill(pinBytes, (byte) 0);
        }
    }

    /** One {@code C_Login} on one borrowed session. The lease is dropped if the session is dead. */
    private void loginOnce(byte[] pinBytes) throws CryptoTokenOfflineException {
        SessionLease lease = borrow();
        try {
            ce.Login(lease.session(), CKU.USER, pinBytes);
            if (log.isDebugEnabled()) {
                log.debug("Logged in to slot " + slotId);
            }
        } catch (RuntimeException e) {
            invalidateIfDead(lease, e);
            throw e;
        } finally {
            lease.close();
        }
    }

    /** Ends the token's login state. Sessions stay open; only the authentication is dropped. */
    public void logout() {
        try {
            SessionLease lease = borrow();
            try {
                ce.Logout(lease.session());
            } catch (RuntimeException e) {
                invalidateIfDead(lease, e);
                throw e;
            } finally {
                lease.close();
            }
        } catch (Exception e) {
            // Logging out a token that is not logged in is the state we wanted anyway.
            if (log.isDebugEnabled()) {
                log.debug("C_Logout on slot " + slotId + ": " + Pkcs11Errors.describe(e));
            }
        }
    }

    /**
     * Drops the session behind a lease when the failure says the session, not the token, is gone.
     *
     * <p>The signing paths have always done this; the login and logout paths did not, and a session
     * a reconnected HSM had forgotten went back into the pool looking healthy. Every later borrow
     * drew it out again and failed identically, so the token stayed unusable until the application
     * server was restarted.
     */
    private void invalidateIfDead(SessionLease lease, Throwable failure) {
        if (Pkcs11Errors.classify(failure) == Pkcs11Errors.Kind.RETRYABLE) {
            lease.invalidate();
        }
    }

    /**
     * Closes every session and refuses further borrows.
     *
     * <p>Waits for in-flight leases rather than closing sessions underneath them: closing a session
     * mid-operation leaves the caller with a handle the token has already forgotten, and the
     * failure surfaces as a corrupt signature rather than as a shutdown.
     */
    public void drain() {
        closed = true;
        boolean allReturned;
        try {
            allReturned = permits.tryAcquire(config.maxSessions(),
                    config.borrowTimeoutSeconds(), TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            allReturned = false;
        }
        if (!allReturned) {
            log.warn("Draining slot " + slotId + " with operations still in flight; their sessions"
                    + " will be closed as they are returned.");
        }
        synchronized (lock) {
            for (Idle entry : idle) {
                try {
                    ce.CloseSession(entry.session());
                } catch (Exception e) {
                    if (log.isDebugEnabled()) {
                        log.debug("C_CloseSession during drain: " + Pkcs11Errors.describe(e));
                    }
                }
            }
            idle.clear();
            live = 0;
        }
        if (allReturned) {
            permits.release(config.maxSessions());
        }
    }

    /** Live sessions, open or lent out. For tests and diagnostics. */
    public int liveSessions() {
        synchronized (lock) {
            return live;
        }
    }

    /** Sessions sitting idle in the pool. For tests and diagnostics. */
    public int idleSessions() {
        synchronized (lock) {
            return idle.size();
        }
    }
}

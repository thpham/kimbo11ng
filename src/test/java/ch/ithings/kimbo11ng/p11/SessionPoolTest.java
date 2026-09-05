/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import ch.ithings.kimbo11ng.fake.FakeToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.Cryptoki;
import org.pkcs11.jacknji11.CryptokiE;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The session pool's contract.
 *
 * <p>Each of these is a property a real HSM will punish us for getting wrong: exceeding the session
 * limit, handing out a session with a live operation on it, or blocking forever on a token that has
 * stopped answering.
 */
@DisplayName("SessionPool")
class SessionPoolTest {

    private FakeToken token;

    private SessionPool pool(SessionPoolConfig config) {
        return pool(config, System::currentTimeMillis);
    }

    private SessionPool pool(SessionPoolConfig config, java.util.function.LongSupplier clock) {
        token = new FakeToken();
        CryptokiE ce = new CryptokiE(new Cryptoki(token));
        ce.Initialize();
        return new SessionPool(ce, 0L, config, clock);
    }

    @Test
    @DisplayName("refuses an absent PIN without spending an attempt on the token")
    void refusesAnAbsentPin() throws Exception {
        SessionPool pool = pool(SessionPoolConfig.defaults());

        // Both shapes an absent credential arrives in: EJBCA holding no auth code, and an operator
        // aborting the CLI's prompt. Pins.encodeUtf8 turns either into an empty byte array, and an
        // empty C_Login is not free — most tokens count it as a failed attempt, and a few in a row
        // lock the user PIN. The assertion that matters is the call count, not the exception.
        assertThrows(CryptoTokenAuthenticationFailedException.class, () -> pool.login(null));
        assertThrows(CryptoTokenAuthenticationFailedException.class,
                () -> pool.login(new char[0]));
        assertEquals(0, token.loginCalls(),
                "an absent PIN must never reach C_Login, or it costs a real attempt");

        // And the guard does not stand in the way of a real credential.
        pool.login("1234".toCharArray());
        assertEquals(1, token.loginCalls());
    }

    @Test
    @DisplayName("gives concurrent borrowers different sessions")
    void borrowersGetDistinctSessions() throws Exception {
        SessionPool pool = pool(SessionPoolConfig.defaults());
        try (SessionLease a = pool.borrow();
             SessionLease b = pool.borrow();
             SessionLease c = pool.borrow()) {
            // The whole point: two callers must never be on the same session, or a C_SignInit from
            // one lands on top of a C_FindObjectsInit from the other.
            assertEquals(3, Set.of(a.session(), b.session(), c.session()).size());
            assertEquals(3, pool.liveSessions());
        }
        assertEquals(3, pool.idleSessions(), "returned sessions stay open for reuse");
    }

    @Test
    @DisplayName("reuses a returned session instead of opening another")
    void reusesReturnedSessions() throws Exception {
        SessionPool pool = pool(SessionPoolConfig.defaults());
        long first;
        try (SessionLease lease = pool.borrow()) {
            first = lease.session();
        }
        try (SessionLease lease = pool.borrow()) {
            assertEquals(first, lease.session());
        }
        assertEquals(1, pool.liveSessions(), "no second session should have been opened");
    }

    @Test
    @DisplayName("never opens more sessions than the configured maximum")
    void respectsTheCeiling() throws Exception {
        SessionPool pool = pool(new SessionPoolConfig(2, 1));
        try (SessionLease a = pool.borrow(); SessionLease b = pool.borrow()) {
            assertEquals(2, pool.liveSessions());
            assertNotEquals(a.session(), b.session());

            // An HSM partition has a hard session limit; blowing past it fails operations for
            // every application on the token, so the pool must wait rather than open one more.
            CryptoTokenOfflineException e = assertThrows(CryptoTokenOfflineException.class,
                    pool::borrow);
            assertTrue(e.getMessage().contains(SessionPoolConfig.MAX_SESSIONS),
                    "the message must name the property to raise: " + e.getMessage());
            assertEquals(2, token.openSessionCount());
        }
    }

    @Test
    @DisplayName("hands a waiting borrower the session as soon as one is returned")
    void waiterIsServedOnRelease() throws Exception {
        SessionPool pool = pool(new SessionPoolConfig(1, 10));
        CountDownLatch borrowed = new CountDownLatch(1);
        CountDownLatch waiterDone = new CountDownLatch(1);
        AtomicLong waiterSession = new AtomicLong(-1);

        Thread waiter = new Thread(() -> {
            try {
                borrowed.await();
                try (SessionLease lease = pool.borrow()) {
                    waiterSession.set(lease.session());
                }
            } catch (Exception e) {
                waiterSession.set(-2);
            } finally {
                waiterDone.countDown();
            }
        });
        waiter.start();

        long held;
        try (SessionLease lease = pool.borrow()) {
            held = lease.session();
            borrowed.countDown();
            // Give the waiter time to block on the semaphore rather than race past it.
            Thread.sleep(150);
            assertEquals(-1, waiterSession.get(), "the waiter must not proceed while we hold it");
        }
        assertTrue(waiterDone.await(10, TimeUnit.SECONDS), "waiter never completed");
        assertEquals(held, waiterSession.get(), "the freed session should go to the waiter");
    }

    @Test
    @DisplayName("closes an invalidated session instead of returning it to the pool")
    void invalidatedSessionIsDiscarded() throws Exception {
        SessionPool pool = pool(SessionPoolConfig.defaults());
        long discarded;
        try (SessionLease lease = pool.borrow()) {
            discarded = lease.session();
            lease.invalidate();
        }
        assertEquals(0, pool.idleSessions());
        assertEquals(0, pool.liveSessions());

        try (SessionLease lease = pool.borrow()) {
            assertNotEquals(discarded, lease.session(), "a fresh session, not the broken one");
        }
    }

    @Test
    @DisplayName("replaces a session the token dropped while it sat idle")
    void staleIdleSessionIsReplaced() throws Exception {
        AtomicLong now = new AtomicLong(1_000_000L);
        SessionPool pool = pool(SessionPoolConfig.defaults(), now::get);

        long original;
        try (SessionLease lease = pool.borrow()) {
            original = lease.session();
        }

        // A network HSM drops idle connections. Nothing tells us; the session simply stops
        // working, and without validation the next signature fails instead of the next borrow.
        token.dropAllSessions();
        now.addAndGet(SessionPool.VALIDATE_AFTER_IDLE_MILLIS + 1);

        try (SessionLease lease = pool.borrow()) {
            assertNotEquals(original, lease.session(),
                    "an idle session that no longer validates must be replaced, not handed out");
        }
    }

    @Test
    @DisplayName("hands back a fresh idle session without a validation round trip")
    void freshIdleSessionIsNotValidated() throws Exception {
        SessionPool pool = pool(SessionPoolConfig.defaults());
        long first;
        try (SessionLease lease = pool.borrow()) {
            first = lease.session();
        }
        // Just returned, so no C_GetSessionInfo should be needed: validating on every borrow would
        // double the round trips for every operation the CA performs.
        int before = token.sessionInfoCalls();
        try (SessionLease lease = pool.borrow()) {
            assertEquals(first, lease.session());
        }
        assertEquals(before, token.sessionInfoCalls());
    }

    @Test
    @DisplayName("closes every session on drain and refuses further borrows")
    void drainClosesEverything() throws Exception {
        SessionPool pool = pool(SessionPoolConfig.defaults());
        List<SessionLease> leases = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            leases.add(pool.borrow());
        }
        for (SessionLease lease : leases) {
            lease.close();
        }
        assertEquals(3, token.openSessionCount());

        pool.drain();

        assertEquals(0, token.openSessionCount());
        assertEquals(0, pool.idleSessions());
        assertThrows(CryptoTokenOfflineException.class, pool::borrow);
        assertEquals(0, token.finalizeCalls(), "draining a pool must not finalize the library");
    }

    @Test
    @DisplayName("a lease cannot be used after it is returned")
    void leaseIsSingleUse() throws Exception {
        SessionPool pool = pool(SessionPoolConfig.defaults());
        SessionLease lease = pool.borrow();
        lease.close();
        // Using a returned lease means operating on a session another thread now owns.
        assertThrows(IllegalStateException.class, lease::session);
        lease.close(); // idempotent: try-with-resources plus an explicit close must not double-free
        assertEquals(1, pool.idleSessions());
    }

    @Test
    @DisplayName("reports a token that cannot open a session as offline")
    void openFailureIsOffline() {
        SessionPool pool = pool(SessionPoolConfig.defaults());
        token.failNextWith(CKR.TOKEN_NOT_PRESENT);

        CryptoTokenOfflineException e = assertThrows(CryptoTokenOfflineException.class,
                pool::borrow);
        assertTrue(e.getMessage().contains("TOKEN_NOT_PRESENT"), e.getMessage());
        // The permit must have been returned, or the pool leaks capacity on every failed borrow
        // and eventually refuses to hand out any session at all.
        assertEquals(0, pool.liveSessions());
        try (SessionLease lease = pool.borrow()) {
            assertTrue(lease.session() > 0, "the pool must still work after a failed borrow");
        } catch (CryptoTokenOfflineException retry) {
            throw new AssertionError("the pool leaked a permit on the failed borrow", retry);
        }
    }

    @Test
    @DisplayName("logs in once for the token, not once per session")
    void loginIsPerToken() throws Exception {
        SessionPool pool = pool(SessionPoolConfig.defaults());
        pool.login("1234".toCharArray());

        Set<Long> sessions = new HashSet<>();
        try (SessionLease a = pool.borrow(); SessionLease b = pool.borrow()) {
            sessions.add(a.session());
            sessions.add(b.session());
        }
        assertEquals(2, sessions.size());
        // PKCS#11 login state belongs to the application and token together, so a session opened
        // after the login is already authenticated. One C_Login is both necessary and sufficient.
        assertEquals(1, token.loginCalls());
        assertTrue(token.isLoggedIn());
    }

    @Test
    @DisplayName("tolerates a token something else already logged in")
    void alreadyLoggedInIsNotAnError() throws Exception {
        SessionPool pool = pool(SessionPoolConfig.defaults());
        pool.login("1234".toCharArray());
        // A second login answers CKR_USER_ALREADY_LOGGED_IN. In production the other logger-in is
        // typically SunPKCS11, reaching the same slot through EJBCA's classic token.
        pool.login("1234".toCharArray());
        assertTrue(token.isLoggedIn());
    }

    @Test
    @DisplayName("reports a rejected PIN as an authentication failure, not as offline")
    void wrongPinIsAuthFailure() {
        SessionPool pool = pool(SessionPoolConfig.defaults());
        assertThrows(com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException.class,
                () -> pool.login("wrong-pin".toCharArray()));
    }
}

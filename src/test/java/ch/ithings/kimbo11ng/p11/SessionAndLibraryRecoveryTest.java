/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import ch.ithings.kimbo11ng.fake.FakeToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.Cryptoki;
import org.pkcs11.jacknji11.CryptokiE;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Recovery from the two failures that used to need an application server restart.
 *
 * <p>One is a pooled session the HSM dropped while the token sat activated: every later activation
 * drew the same dead handle back out of the pool. The other is a PKCS#11 library whose own shared
 * objects do not resolve, which reaches the caller as an {@code Error} that no
 * {@code catch (Exception)} on the way out is looking for.
 */
@DisplayName("Session and library recovery")
class SessionAndLibraryRecoveryTest {

    private static final String LIB = "/nonexistent/libfake.so";

    private FakeToken token;

    private SessionPool pool() {
        token = new FakeToken();
        CryptokiE ce = new CryptokiE(new Cryptoki(token));
        ce.Initialize();
        return new SessionPool(ce, 0L, SessionPoolConfig.defaults());
    }

    @Test
    @DisplayName("re-activates on a fresh session after the HSM dropped the pooled one")
    void loginRecoversFromADeadPooledSession() throws Exception {
        SessionPool pool = pool();
        // Warm the pool so a login draws a pooled session rather than opening one.
        try (SessionLease lease = pool.borrow()) {
            assertTrue(lease.session() > 0);
        }

        // A network HSM that reconnects leaves the client holding handles the token has forgotten.
        // The session is fresh enough that the pool hands it out without validating it, which is
        // exactly the window in which an activation attempt hits a dead handle.
        token.dropAllSessions();

        pool.login("1234".toCharArray());

        assertTrue(token.isLoggedIn(), "the token must be usable again without a restart");
        assertEquals(1, token.openSessionCount(), "the login must have opened a fresh session");
    }

    @Test
    @DisplayName("does not put a session the token has forgotten back into the pool")
    void logoutDiscardsADeadSession() throws Exception {
        SessionPool pool = pool();
        pool.login("1234".toCharArray());
        try (SessionLease lease = pool.borrow()) {
            assertTrue(lease.session() > 0);
        }

        token.dropAllSessions();
        pool.logout();

        // Returning the dead handle to the pool is what made the failure permanent: the next
        // borrower draws it, fails the same way, and nothing ever opens a replacement.
        assertEquals(0, pool.idleSessions(), "the dead session must not go back into the pool");
        assertEquals(0, pool.liveSessions());
    }

    @Test
    @DisplayName("reports a library whose dependencies do not resolve as offline")
    void unresolvedLibraryDependencyIsOffline() {
        // What LD_LIBRARY_PATH exists for, and the single most common HSM misconfiguration. JNA
        // answers it with an Error, so it used to escape every catch between here and EJBCA.
        Pkcs11ModuleRegistry registry = new Pkcs11ModuleRegistry(path -> {
            throw new UnsatisfiedLinkError(
                    "libCryptoki2_64.so: cannot open shared object file: no such file");
        });

        CryptoTokenOfflineException e = assertThrows(CryptoTokenOfflineException.class,
                () -> registry.get(LIB));
        assertTrue(e.getMessage().contains(LIB),
                "the message must name the library: " + e.getMessage());
        assertTrue(e.getMessage().contains("libCryptoki2_64.so"),
                "the message must carry what the linker said: " + e.getMessage());
        assertFalse(registry.isLoaded(LIB), "a library that would not load must not be cached");
    }
}

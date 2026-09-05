/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.fake;

import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.p11.Pkcs11Module;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import ch.ithings.kimbo11ng.p11.SessionLease;
import org.pkcs11.jacknji11.CryptokiE;

import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A {@link FakeToken} wired up behind a private module registry, for tests.
 *
 * <p>Private on purpose: the production registry is process-wide, and a test that reached into it
 * would see modules left behind by earlier tests and initialise a library only on whichever test
 * happened to run first. Each fixture gets its own registry and its own library path, so
 * "C_Initialize was called exactly once" is a claim about this test alone.
 */
public final class TestSlot implements AutoCloseable {

    /** Distinct per fixture so two fixtures never canonicalize to the same registry key. */
    private static final AtomicInteger PATHS = new AtomicInteger();

    private final FakeToken token;
    private final Pkcs11ModuleRegistry registry;
    private final Pkcs11Module module;
    private final P11Slot slot;

    public TestSlot() throws Exception {
        this(new FakeToken(), new Properties());
    }

    public TestSlot(FakeToken token) throws Exception {
        this(token, new Properties());
    }

    public TestSlot(FakeToken token, Properties properties) throws Exception {
        this.token = token;
        this.registry = new Pkcs11ModuleRegistry(path -> token);
        this.module = registry.get("/nonexistent/libfake-" + PATHS.incrementAndGet() + ".so");
        this.slot = module.slot(0L, properties);
    }

    /** Logs in with the fake's default PIN. */
    public TestSlot loggedIn() throws Exception {
        slot.login("1234".toCharArray());
        return this;
    }

    public FakeToken token() {
        return token;
    }

    public P11Slot slot() {
        return slot;
    }

    public Pkcs11Module module() {
        return module;
    }

    public Pkcs11ModuleRegistry registry() {
        return registry;
    }

    public CryptokiE ce() {
        return slot.ce();
    }

    /** A PKCS#11 call that needs a session. */
    @FunctionalInterface
    public interface SessionCall<T> {
        T apply(CryptokiE ce, long session) throws Exception;
    }

    /** Runs {@code call} under a borrowed lease — the shape production code uses. */
    public <T> T onSession(SessionCall<T> call) throws Exception {
        try (SessionLease lease = slot.borrow()) {
            return call.apply(slot.ce(), lease.session());
        }
    }

    @Override
    public void close() {
        slot.close();
    }
}

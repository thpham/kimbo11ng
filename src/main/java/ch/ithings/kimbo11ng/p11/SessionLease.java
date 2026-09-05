/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

/**
 * Exclusive use of one PKCS#11 session for the duration of a try-with-resources block.
 *
 * <p>A PKCS#11 session carries operation state: between {@code C_SignInit} and {@code C_Sign} it
 * belongs to one caller, and a second {@code C_FindObjectsInit} on the same session answers
 * {@code CKR_OPERATION_ACTIVE}. Sharing a session across threads is therefore not slow, it is
 * wrong. A lease is what makes that impossible to get wrong by accident:
 *
 * <pre>{@code
 * try (SessionLease lease = slot.borrow()) {
 *     ce.SignInit(lease.session(), mechanism, handle);
 *     return ce.Sign(lease.session(), data);
 * }
 * }</pre>
 *
 * <p>Not thread-safe and not meant to be: a lease belongs to the thread that borrowed it, and
 * escaping one from its block defeats the point.
 */
public final class SessionLease implements AutoCloseable {

    private final SessionPool pool;
    private final long session;
    private boolean broken;
    private boolean closed;

    SessionLease(SessionPool pool, long session) {
        this.pool = pool;
        this.session = session;
    }

    /** The session handle. Valid until {@link #close()}. */
    public long session() {
        if (closed) {
            throw new IllegalStateException("Session lease already returned to the pool");
        }
        return session;
    }

    /**
     * Marks the session unusable so it is closed rather than returned to the pool.
     *
     * <p>Call this when a PKCS#11 operation failed in a way that leaves the session in an unknown
     * state — a dropped connection, or an aborted operation whose {@code C_SignFinal} never ran.
     * Returning such a session to the pool hands the next borrower a session with a live operation
     * on it, and the failure then surfaces on an unrelated thread.
     */
    public void invalidate() {
        this.broken = true;
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        pool.release(session, broken);
    }
}

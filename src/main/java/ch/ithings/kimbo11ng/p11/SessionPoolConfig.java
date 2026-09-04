/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import org.apache.log4j.Logger;

import java.util.Properties;

/**
 * Session-pool settings, read from the crypto token's own properties.
 *
 * <p>There is deliberately no {@code kimbo11ng.sessions.min}. The pool has no eviction policy — a
 * session it opened is kept until it breaks or the pool drains — so there is nothing for a floor to
 * guard against, and a property that changes no behaviour is worse than no property: someone will
 * eventually set it and believe it did something.
 *
 * @param maxSessions          hard ceiling on live sessions for one slot
 * @param borrowTimeoutSeconds how long a caller waits for a session before the token is declared
 *                             offline
 */
public record SessionPoolConfig(int maxSessions, int borrowTimeoutSeconds) {

    public static final String MAX_SESSIONS = "kimbo11ng.sessions.max";
    public static final String BORROW_TIMEOUT_SECONDS = "kimbo11ng.sessions.borrowTimeoutSeconds";

    /**
     * Eight is comfortably above EJBCA's concurrency for one CA and comfortably below the session
     * limit of any HSM partition worth deploying. It is a ceiling, not an allocation: the pool
     * opens sessions only as concurrent callers ask for them.
     */
    public static final int DEFAULT_MAX_SESSIONS = 8;

    /**
     * Long enough to ride out a slow HSM operation queued ahead of us, short enough that a wedged
     * token surfaces as an offline CA rather than as threads accumulating in the application
     * server until it stops answering anything at all.
     */
    public static final int DEFAULT_BORROW_TIMEOUT_SECONDS = 30;

    private static final Logger log = Logger.getLogger(SessionPoolConfig.class);

    public SessionPoolConfig {
        if (maxSessions < 1) {
            throw new IllegalArgumentException(MAX_SESSIONS + " must be at least 1, got "
                    + maxSessions);
        }
        if (borrowTimeoutSeconds < 1) {
            throw new IllegalArgumentException(BORROW_TIMEOUT_SECONDS
                    + " must be at least 1, got " + borrowTimeoutSeconds);
        }
    }

    public static SessionPoolConfig defaults() {
        return new SessionPoolConfig(DEFAULT_MAX_SESSIONS, DEFAULT_BORROW_TIMEOUT_SECONDS);
    }

    /** Reads the pool settings from token properties, falling back to the defaults. */
    public static SessionPoolConfig from(Properties properties) {
        if (properties == null) {
            return defaults();
        }
        return new SessionPoolConfig(
                positiveInt(properties, MAX_SESSIONS, DEFAULT_MAX_SESSIONS),
                positiveInt(properties, BORROW_TIMEOUT_SECONDS, DEFAULT_BORROW_TIMEOUT_SECONDS));
    }

    private static int positiveInt(Properties properties, String key, int fallback) {
        String raw = properties.getProperty(key);
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            int value = Integer.parseInt(raw.trim());
            if (value < 1) {
                log.warn(key + "=" + raw + " is not a positive integer; using " + fallback);
                return fallback;
            }
            return value;
        } catch (NumberFormatException e) {
            // A misconfigured pool size must not stop a CA from starting.
            log.warn(key + "=" + raw + " is not a number; using " + fallback);
            return fallback;
        }
    }
}

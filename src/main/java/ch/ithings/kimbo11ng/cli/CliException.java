/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

/**
 * A failure the operator caused and can fix, as opposed to one the token reported.
 *
 * <p>The distinction drives the exit code and the amount of noise: a {@code CliException} prints one
 * line and, when {@link #usage()} is set, the offending command's help. Anything else prints the
 * exception chain, because a {@code CKR_} code is only useful with its context.
 */
final class CliException extends Exception {

    private static final long serialVersionUID = 1L;

    private final boolean usage;

    CliException(String message) {
        this(message, false, null);
    }

    CliException(String message, Throwable cause) {
        this(message, false, cause);
    }

    private CliException(String message, boolean usage, Throwable cause) {
        super(message, cause);
        this.usage = usage;
    }

    /** A malformed command line: the help for the command is worth printing after the message. */
    static CliException usage(String message) {
        return new CliException(message, true, null);
    }

    boolean usage() {
        return usage;
    }
}

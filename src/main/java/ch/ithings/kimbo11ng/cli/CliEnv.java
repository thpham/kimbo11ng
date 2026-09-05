/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.p11.NativeProviderFactory;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;

import java.io.Console;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Everything the CLI touches outside itself: the two streams, the PIN reader, and the PKCS#11
 * module registry.
 *
 * <p>Injected rather than reached for statically so the whole tool can be driven end to end in a
 * unit test against the in-memory {@code FakeToken} — the commands are the part most likely to
 * break silently, being the part with no other caller.
 */
final class CliEnv {

    /** Reads a PIN, without echoing it. Separated so a test can supply one. */
    @FunctionalInterface
    interface PinReader {
        char[] read(String prompt);
    }

    private final PrintStream out;
    private final PrintStream err;
    private final PinReader pinReader;
    private final Pkcs11ModuleRegistry modules;

    CliEnv(PrintStream out, PrintStream err, PinReader pinReader, Pkcs11ModuleRegistry modules) {
        this.out = Objects.requireNonNull(out, "out");
        this.err = Objects.requireNonNull(err, "err");
        this.pinReader = Objects.requireNonNull(pinReader, "pinReader");
        this.modules = Objects.requireNonNull(modules, "modules");
    }

    /**
     * The environment a real invocation runs in.
     *
     * <p>A private registry rather than {@link Pkcs11ModuleRegistry#shared()}: the shared one exists
     * so that a crypto token and EJBCA's slot-list wrapper share a single {@code C_Initialize} in
     * the same JVM. This process opens one library and exits, so nothing is gained by reaching into
     * process-wide state — and keeping out of it means a test can run a second invocation against a
     * different fake token in the same JVM.
     */
    static CliEnv systemEnv() {
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        PrintStream err = new PrintStream(System.err, true, StandardCharsets.UTF_8);
        return new CliEnv(out, err, CliEnv::readPinFromConsole,
                new Pkcs11ModuleRegistry(NativeProviderFactory.jna()));
    }

    private static char[] readPinFromConsole(String prompt) {
        Console console = System.console();
        if (console == null) {
            // No terminal — a CI job, a pipeline, an init script. Refusing is the honest answer:
            // reading the PIN off stdin here would work but would also silently accept a PIN piped
            // in from a file that the operator did not mean as a credential.
            throw new IllegalStateException("No console available to prompt for a PIN. Pass"
                    + " --password, or run the command from a terminal.");
        }
        return console.readPassword("%s", prompt);
    }

    PrintStream out() {
        return out;
    }

    PrintStream err() {
        return err;
    }

    Pkcs11ModuleRegistry modules() {
        return modules;
    }

    /**
     * The PIN for this invocation: {@code --password} when given, otherwise prompted for.
     *
     * <p>The prompt string is Keyfactor's, verbatim, so an operator's existing expect scripts and
     * their muscle memory both survive the move.
     *
     * <p>The caller owns the returned array and must zero it.
     */
    char[] pin(Args args) {
        String supplied = args.get("password", null);
        if (supplied != null) {
            return supplied.toCharArray();
        }
        return pinReader.read("Enter slot login password: ");
    }
}

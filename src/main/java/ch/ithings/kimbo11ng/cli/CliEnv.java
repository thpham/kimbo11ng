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
     * <p>An absent credential never leaves this method. {@code Console.readPassword} returns
     * {@code null} at EOF, which is what Ctrl-D at the prompt produces, and {@code Pins.encodeUtf8}
     * turns both that and an empty array into a zero-length PIN — so passing one on would reach
     * {@code C_Login} as a real authentication attempt with an empty credential. Most tokens count
     * that as a failure, and three or five failures lock the user PIN. An operator who cancelled a
     * prompt should not have spent one of those.
     *
     * <p>The caller owns the returned array and must zero it.
     *
     * @throws CliException if no credential was supplied, or the one supplied was empty
     */
    char[] pin(Args args) throws CliException {
        String supplied = args.get("password", null);
        if (supplied != null) {
            if (supplied.isEmpty()) {
                throw CliException.usage("--password was given with an empty value. An empty PIN is"
                        + " not a credential: the token would score it as a failed login attempt,"
                        + " and a few of those lock the user PIN. Pass the PIN, or omit --password"
                        + " to be prompted for it.");
            }
            return supplied.toCharArray();
        }
        char[] entered = pinReader.read("Enter slot login password: ");
        if (entered == null || entered.length == 0) {
            throw new CliException("No PIN was entered, so nothing was sent to the token and no"
                    + " login attempt was used. Run the command again and type the PIN at the"
                    + " prompt, or pass --password.");
        }
        return entered;
    }
}

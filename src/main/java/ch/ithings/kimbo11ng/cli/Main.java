/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Entry point for the kimbo11ng command-line tool.
 *
 * <h2>Why this exists</h2>
 *
 * <p>EJBCA Community ships one PKCS#11 key tool, {@code clientToolBox PKCS11HSMKeyTool}, and it
 * goes through SunPKCS11. Its key specifications are RSA, an EC curve, or {@code DSAnnnn} — there is
 * no path through it to ML-DSA, ML-KEM or SLH-DSA. An operator who installs kimbo11ng to get
 * post-quantum keys therefore has a key-management CLI that cannot see the keys they installed it
 * for. Keyfactor closed the same gap in Enterprise with {@code p11ng-cli}; this is the open
 * equivalent, reconstructed from published documentation — see {@code docs/P11NG_CLI_SURFACE.md}
 * for the evidence behind every command name and option spelling.
 *
 * <h2>What makes it trustworthy</h2>
 *
 * <p>Every command that touches a key drives {@code CryptoTokenImpl} through
 * {@link StandaloneBridge}, so it runs the code EJBCA runs. The tool does not model what the CA
 * would do; it does it.
 *
 * <h2>Exit codes</h2>
 *
 * <p>{@code 0} success, {@code 1} the operation failed, {@code 2} the command line was wrong.
 * Distinct because an init script needs to tell "this key already exists" from "you typed the slot
 * reference wrong", and both from success.
 */
public final class Main {

    static final int OK = 0;
    static final int FAILED = 1;
    static final int USAGE = 2;

    private Main() {
    }

    public static void main(String[] argv) {
        CliEnv env = CliEnv.systemEnv();
        System.exit(run(argv, env));
    }

    /**
     * Runs one invocation and returns its exit code.
     *
     * <p>Separated from {@link #main} so the whole tool can be exercised in a unit test against an
     * in-memory token: the commands are the part of this project with no other caller, so a bug in
     * them would otherwise only surface in front of an operator.
     */
    static int run(String[] argv, CliEnv env) {
        installCryptoProvider();
        Map<String, Command> commands = commands();
        if (argv.length == 0 || isHelp(argv[0])) {
            printOverview(env.out(), commands.values());
            return argv.length == 0 ? USAGE : OK;
        }
        Command command = commands.get(argv[0].toLowerCase(java.util.Locale.ROOT));
        if (command == null) {
            env.err().println("Unknown command '" + argv[0] + "'.");
            printOverview(env.err(), commands.values());
            return USAGE;
        }
        try {
            Args args = Args.parse(argv, 1, command);
            if (args.wantsHelp()) {
                command.printHelp(env);
                return OK;
            }
            command.run(env, args);
            return OK;
        } catch (CliException e) {
            env.err().println(e.getMessage());
            if (e.usage()) {
                env.err().println();
                command.printHelp(env);
                return USAGE;
            }
            return FAILED;
        } catch (Exception e) {
            // The whole chain, because a PKCS#11 failure is a CKR_ code wrapped in three layers and
            // only the innermost one names what the token objected to.
            env.err().println(describe(e));
            return FAILED;
        }
    }

    /**
     * Installs BouncyCastle, the way EJBCA's own startup does.
     *
     * <p>Not optional, and not merely tidy. {@code AlgorithmSupport.compute} decides an algorithm is
     * usable only if a {@code KeyFactory} exists to read the resulting public key back, and every
     * post-quantum {@code KeyFactory} in this stack comes from BouncyCastle. In the application
     * server EJBCA has already registered it before any crypto token initialises; in a bare JVM
     * nothing has, so without this call the tool reports every ML-DSA, ML-KEM and SLH-DSA algorithm
     * as excluded — telling an operator their HSM cannot do post-quantum when it can, which is the
     * worst answer this tool could give.
     *
     * <p>Found by running the tool against real SoftHSMv3 rather than by reading it.
     *
     * <p>Through EJBCA's own helper first, so the provider set is assembled the same way and in the
     * same order the CA assembles it — but not <em>only</em> through it. That helper touches
     * {@code CryptoProviderRegistry}, whose static initialiser runs a {@link java.util.ServiceLoader}
     * over every {@code com.keyfactor.util.crypto.provider.CryptoProvider} on the classpath.
     * cesecore-common declares one that needs {@code org.ejbca.cvc.CVCProvider}, and cert-cvc is
     * not on a classpath assembled outside the application server. The loader then throws
     * {@link java.util.ServiceConfigurationError} — an {@code Error}, so it sails past every
     * {@code catch (Exception)} between here and {@code main}, and the tool dies on a stack trace
     * before parsing its first argument.
     *
     * <p>That is the same shape of defect the review found in {@code Pkcs11Module}: a
     * {@code LinkageError} crossing a boundary built for exceptions. The answer is the same. What
     * this method actually has to guarantee is that BouncyCastle is registered, because that is
     * where every post-quantum {@code KeyFactory} comes from; assembling the rest of EJBCA's
     * provider set is a nicety that a standalone tool can do without.
     */
    private static void installCryptoProvider() {
        try {
            com.keyfactor.util.CryptoProviderTools.installBCProviderIfNotAvailable();
            return;
        } catch (Exception | LinkageError | java.util.ServiceConfigurationError e) {
            // Nothing is logged here: log4j is normally unconfigured under the CLI, and the
            // fallback below restores the only property that matters. If it too fails, the
            // exception carries both causes to the operator.
            installBouncyCastleDirectly(e);
        }
    }

    /**
     * The fallback: BouncyCastle alone, registered by hand.
     *
     * @param cause why EJBCA's own installer could not be used, kept so a failure here reports both
     */
    private static void installBouncyCastleDirectly(Throwable cause) {
        if (java.security.Security.getProvider(
                org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME) != null) {
            return;
        }
        try {
            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider());
        } catch (Exception | LinkageError e) {
            IllegalStateException failure = new IllegalStateException(
                    "Could not register BouncyCastle, so no post-quantum algorithm can be read back"
                            + " and every one of them would be reported as unsupported. Check that"
                            + " bcprov is on the classpath.", e);
            failure.addSuppressed(cause);
            throw failure;
        }
    }

    private static boolean isHelp(String token) {
        return "--help".equals(token) || "-h".equals(token) || "help".equals(token);
    }

    /** The chain of causes, one per line, deepest last. */
    static String describe(Throwable failure) {
        StringBuilder message = new StringBuilder();
        Throwable current = failure;
        String indent = "";
        while (current != null) {
            message.append(indent).append(current.getClass().getSimpleName()).append(": ")
                    .append(shorten(current.getMessage()));
            Throwable next = current.getCause();
            if (next == current) {
                break;
            }
            current = next;
            indent = System.lineSeparator() + "  caused by ";
        }
        return message.toString();
    }

    /**
     * How much of one cause's message is worth printing.
     *
     * <p>The commonest failure this tool reports is a PKCS#11 module that will not load, and JNA's
     * message for that embeds the entire classpath — three kilobytes of jar paths, repeated once
     * per nesting level, around the twenty characters that say which library and why. Printing it
     * whole buries the answer in the noise, which on a diagnostic tool is its own defect.
     *
     * <p>Truncating rather than filtering, and generously: the useful part of every message in this
     * chain is at the front, and a rule that tried to recognise JNA's phrasing would go stale the
     * first time JNA reworded it.
     */
    private static String shorten(String message) {
        if (message == null) {
            return "(no message)";
        }
        String collapsed = message.strip();
        if (collapsed.length() <= MAX_CAUSE_CHARS) {
            return collapsed;
        }
        return collapsed.substring(0, MAX_CAUSE_CHARS) + "… (" + collapsed.length()
                + " characters in all)";
    }

    /** Long enough for any CKR line and for JNA's "cannot load X" prefix; short of its classpath. */
    private static final int MAX_CAUSE_CHARS = 320;

    static Map<String, Command> commands() {
        List<Command> all = new ArrayList<>();
        all.addAll(InfoCommands.all());
        all.addAll(ObjectCommands.all());
        all.addAll(KeyCommands.all());
        all.addAll(PerformanceCommands.all());
        Map<String, Command> byName = new LinkedHashMap<>();
        for (Command command : all) {
            byName.put(command.name(), command);
        }
        return byName;
    }

    private static void printOverview(PrintStream out, Iterable<Command> commands) {
        out.println("kimbo11ng-cli — PKCS#11 administration for the kimbo11ng crypto token");
        out.println();
        out.println("Usage: kimbo11ng-cli <command> [options]");
        out.println("       kimbo11ng-cli <command> --help");
        out.println();
        out.println("Commands:");
        int width = 0;
        for (Command command : commands) {
            width = Math.max(width, command.name().length());
        }
        for (Command command : commands) {
            out.println("  " + InfoCommands.pad(command.name(), width) + "  " + command.summary());
        }
        out.println();
        out.println("Keys are created and read through the same crypto token EJBCA loads, so what");
        out.println("this tool reports is what the CA will see.");
    }
}

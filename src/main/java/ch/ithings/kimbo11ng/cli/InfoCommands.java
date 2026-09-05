/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.p11.Pkcs11Module;
import ch.ithings.kimbo11ng.p11.TokenCapabilities;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.AlgorithmSupport;
import org.pkcs11.jacknji11.CK_INFO;
import org.pkcs11.jacknji11.CK_SLOT_INFO;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.pkcs11.jacknji11.CK_VERSION;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The commands that describe the HSM without changing anything on it.
 *
 * <p>Ordered by how little they need: {@code listslots} needs a library path, {@code showslotinfo}
 * and {@code showtokeninfo} need a slot, and none of them needs a PIN. That is deliberate — the
 * first question about an HSM is whether the library loads and the slot exists, and answering it
 * should not require a credential the operator may not yet have.
 */
final class InfoCommands {

    private InfoCommands() {
    }

    static List<Command> all() {
        return List.of(listSlots(), showInfo(), showSlotInfo(), showTokenInfo(), capabilities());
    }

    private static Command listSlots() {
        return Command.of("listslots",
                "Lists the slots the library reports, with the label of each token present.",
                List.of(Opt.libFile()),
                (env, args) -> {
                    Pkcs11Module module = TokenHandle.library(env, args);
                    long[] withToken = module.slotList();
                    long[] allSlots = allSlots(module, withToken);
                    env.out().println("All slots:        " + list(allSlots));
                    env.out().println("Slots with token: " + list(withToken));
                    for (long slotId : withToken) {
                        // tokenLabel answers "" for a token that carries no label, never null.
                        String label = new String(module.tokenLabel(slotId)).trim();
                        env.out().println("ID: " + slotId + ", Label: "
                                + (label.isEmpty() ? "<none>" : label));
                    }
                });
    }

    /**
     * Every slot, including empty ones.
     *
     * <p>{@code Pkcs11Module.slotList()} asks for token-present slots only, because that is what
     * every other caller wants. Here the empty ones are the point: a slot list that is shorter than
     * expected is the first sign that a partition is not assigned, and {@code SLOT_INDEX} is
     * counted over the list the library returns, so knowing which list is which matters.
     */
    private static long[] allSlots(Pkcs11Module module, long[] fallback) {
        try {
            return module.ce().GetSlotList(false);
        } catch (RuntimeException e) {
            // Some libraries refuse tokenPresent=false outright. Reporting the slots we do know
            // beats failing the whole command over the less important of the two lists.
            return fallback;
        }
    }

    private static Command showInfo() {
        return Command.of("showinfo",
                "Prints the library's own description of itself: Cryptoki version, vendor, build.",
                List.of(Opt.libFile()),
                (env, args) -> {
                    CK_INFO info = TokenHandle.library(env, args).ce().GetInfo();
                    PrintStream out = env.out();
                    field(out, "Cryptoki version", version(info.cryptokiVersion));
                    field(out, "Manufacturer", text(info.manufacturerID));
                    field(out, "Library", text(info.libraryDescription));
                    field(out, "Library version", version(info.libraryVersion));
                    field(out, "Flags", "0x" + Long.toHexString(info.flags));
                });
    }

    private static Command showSlotInfo() {
        return Command.slotLevel("showslotinfo",
                "Prints the slot's description, hardware and firmware versions, and flags.",
                List.of(),
                (env, args) -> {
                    long slotId = TokenHandle.slotId(env, args);
                    CK_SLOT_INFO info = TokenHandle.library(env, args).ce().GetSlotInfo(slotId);
                    PrintStream out = env.out();
                    field(out, "Slot id", Long.toString(slotId));
                    field(out, "Description", text(info.slotDescription));
                    field(out, "Manufacturer", text(info.manufacturerID));
                    field(out, "Hardware version", version(info.hardwareVersion));
                    field(out, "Firmware version", version(info.firmwareVersion));
                    field(out, "Token present", yesNo(info.isFlagSet(CK_SLOT_INFO.CKF_TOKEN_PRESENT)));
                    field(out, "Removable", yesNo(info.isFlagSet(CK_SLOT_INFO.CKF_REMOVABLE_DEVICE)));
                    field(out, "Hardware slot", yesNo(info.isFlagSet(CK_SLOT_INFO.CKF_HW_SLOT)));
                    field(out, "Flags", CK_SLOT_INFO.f2s(info.flags));
                });
    }

    private static Command showTokenInfo() {
        return Command.slotLevel("showtokeninfo",
                "Prints the token's label, model, serial, session counts and PIN state.",
                List.of(),
                (env, args) -> {
                    long slotId = TokenHandle.slotId(env, args);
                    CK_TOKEN_INFO info = TokenHandle.library(env, args).ce().GetTokenInfo(slotId);
                    PrintStream out = env.out();
                    field(out, "Slot id", Long.toString(slotId));
                    field(out, "Label", text(info.label));
                    field(out, "Manufacturer", text(info.manufacturerID));
                    field(out, "Model", text(info.model));
                    field(out, "Serial number", text(info.serialNumber));
                    field(out, "Hardware version", version(info.hardwareVersion));
                    field(out, "Firmware version", version(info.firmwareVersion));
                    field(out, "Sessions", count(info.ulSessionCount, info.ulMaxSessionCount));
                    field(out, "R/W sessions", count(info.ulRwSessionCount, info.ulMaxRwSessionCount));
                    field(out, "PIN length", info.ulMinPinLen + " to " + info.ulMaxPinLen);
                    field(out, "Login required",
                            yesNo(info.isFlagSet(CK_TOKEN_INFO.CKF_LOGIN_REQUIRED)));
                    field(out, "Write protected",
                            yesNo(info.isFlagSet(CK_TOKEN_INFO.CKF_WRITE_PROTECTED)));
                    // Called out on its own line rather than left in the flag dump: a locked or
                    // nearly-locked PIN is the one piece of token state that turns a retry into an
                    // outage, and an operator debugging a failed activation needs to see it before
                    // they try the PIN again.
                    field(out, "User PIN state", pinState(info));
                    field(out, "Flags", CK_TOKEN_INFO.f2s(info.flags));
                });
    }

    private static String pinState(CK_TOKEN_INFO info) {
        List<String> warnings = new ArrayList<>();
        if (info.isFlagSet(CK_TOKEN_INFO.CKF_USER_PIN_LOCKED)) {
            warnings.add("LOCKED");
        }
        if (info.isFlagSet(CK_TOKEN_INFO.CKF_USER_PIN_FINAL_TRY)) {
            warnings.add("FINAL TRY");
        }
        if (info.isFlagSet(CK_TOKEN_INFO.CKF_USER_PIN_COUNT_LOW)) {
            warnings.add("failed attempts recorded");
        }
        if (info.isFlagSet(CK_TOKEN_INFO.CKF_USER_PIN_TO_BE_CHANGED)) {
            warnings.add("must be changed");
        }
        if (!info.isFlagSet(CK_TOKEN_INFO.CKF_USER_PIN_INITIALIZED)) {
            warnings.add("not initialized");
        }
        return warnings.isEmpty() ? "ok" : String.join(", ", warnings);
    }

    /**
     * The command with no counterpart in Keyfactor's tool: what this token can do, and what
     * kimbo11ng will therefore offer EJBCA.
     *
     * <p>Today that verdict is only readable in the application server log, after the crypto token
     * has been created and EJBCA has already tried to use it. Here it is a pre-flight check that
     * needs no PIN, so an operator can answer "can this HSM host a post-quantum CA" before
     * provisioning anything.
     */
    private static Command capabilities() {
        return Command.slotLevel("capabilities",
                "Reports the token's mechanisms and the algorithm profile kimbo11ng resolves for it.",
                List.of(Opt.flag("mechanisms", "Also list every mechanism the token advertises.")),
                (env, args) -> {
                    try (TokenHandle handle = TokenHandle.slot(env, args)) {
                        AlgorithmSupport algorithms =
                                handle.token().getProvider().runtime().algorithms();
                        TokenCapabilities capabilities = algorithms.capabilities();
                        PrintStream out = env.out();
                        field(out, "Library", handle.slot().libPath());
                        field(out, "Slot id", Long.toString(handle.slot().slotId()));
                        field(out, "Profile", algorithms.profile().name());
                        out.println();
                        out.println(algorithms.describe());
                        out.println();
                        out.println("Post-quantum algorithms usable on this token:");
                        if (algorithms.supported().isEmpty()) {
                            out.println("  (none)");
                        }
                        for (AlgorithmEntry entry : algorithms.supported()) {
                            out.println("  " + pad(entry.canonicalName(), 16)
                                    + "  " + entry.family()
                                    + "  keygen=" + TokenCapabilities.name(entry.ckmKeyPairGen())
                                    + "  ops=" + entry.ops());
                        }
                        if (!algorithms.excluded().isEmpty()) {
                            out.println();
                            out.println("Excluded:");
                            for (Map.Entry<String, String> excluded
                                    : algorithms.excluded().entrySet()) {
                                out.println("  " + pad(excluded.getKey(), 16) + "  "
                                        + excluded.getValue());
                            }
                        }
                        if (args.has("mechanisms")) {
                            printMechanisms(out, capabilities);
                        }
                    }
                });
    }

    private static void printMechanisms(PrintStream out, TokenCapabilities capabilities) {
        out.println();
        if (!capabilities.probed()) {
            out.println("Mechanisms: not available (" + capabilities.unprobedReason() + ")");
            return;
        }
        out.println("Mechanisms advertised by the token (" + capabilities.mechanisms().size() + "):");
        List<Long> sorted = capabilities.mechanisms().stream().sorted().collect(Collectors.toList());
        for (long ckm : sorted) {
            List<String> uses = new ArrayList<>();
            if (capabilities.canSign(ckm)) {
                uses.add("sign");
            }
            if (capabilities.canGenerate(ckm)) {
                uses.add("generate");
            }
            if (capabilities.canGenerateKeyPair(ckm)) {
                uses.add("generate-key-pair");
            }
            out.println("  " + pad(TokenCapabilities.name(ckm), 34)
                    + "  " + (uses.isEmpty() ? "-" : String.join(", ", uses)));
        }
    }

    // ---- formatting ----

    private static void field(PrintStream out, String name, String value) {
        out.println(pad(name + ":", 20) + " " + value);
    }

    static String pad(String text, int width) {
        return text.length() >= width ? text : text + " ".repeat(width - text.length());
    }

    private static String list(long[] values) {
        return Arrays.stream(values).mapToObj(Long::toString).collect(Collectors.joining(", ",
                "[", "]"));
    }

    /** A fixed-width PKCS#11 string field: space-padded, not NUL-terminated. */
    private static String text(byte[] raw) {
        if (raw == null) {
            return "";
        }
        return new String(raw, StandardCharsets.UTF_8).trim();
    }

    private static String version(CK_VERSION version) {
        if (version == null) {
            return "?";
        }
        // Unsigned: a firmware minor of 0x80 is 128, not -128.
        return (version.major & 0xFF) + "." + (version.minor & 0xFF);
    }

    /**
     * A PKCS#11 count, where the sentinel means "the token does not say" rather than a real number.
     */
    private static String count(long current, long max) {
        String limit = max == CK_EFFECTIVELY_INFINITE || max == CK_UNAVAILABLE_INFORMATION
                ? "unlimited" : Long.toString(max);
        String seen = current == CK_UNAVAILABLE_INFORMATION ? "?" : Long.toString(current);
        return seen + " of " + limit;
    }

    /** {@code CK_UNAVAILABLE_INFORMATION}, which is {@code ~0UL} in the specification. */
    private static final long CK_UNAVAILABLE_INFORMATION = -1L;

    /** {@code CK_EFFECTIVELY_INFINITE}, which the specification defines as 0. */
    private static final long CK_EFFECTIVELY_INFINITE = 0L;

    private static String yesNo(boolean value) {
        return value ? "yes" : "no";
    }
}

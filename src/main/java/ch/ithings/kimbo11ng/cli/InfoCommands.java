/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.p11.Pkcs11Module;
import ch.ithings.kimbo11ng.p11.TokenCapabilities;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.AlgorithmSupport;
import ch.ithings.kimbo11ng.provider.KeyTemplates;
import ch.ithings.kimbo11ng.provider.SecretKeyType;
import org.pkcs11.jacknji11.CK_INFO;
import org.pkcs11.jacknji11.CK_SLOT_INFO;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.pkcs11.jacknji11.CK_VERSION;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
                    PrintStream out = env.out();
                    field(out, "All slots", list(allSlots));
                    field(out, "Slots with token", list(withToken));
                    for (long slotId : withToken) {
                        // tokenLabel answers "" for a token that carries no label, never null.
                        String label = new String(module.tokenLabel(slotId)).trim();
                        field(out, "  slot " + slotId, label.isEmpty() ? "<none>" : label);
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
                        int total = algorithms.supported().size() + algorithms.excluded().size();
                        field(out, "Library", handle.slot().libPath());
                        field(out, "Slot id", Long.toString(handle.slot().slotId()));
                        // The verdict that used to head algorithms.describe(). Folded into the
                        // profile line because describe() then repeated all eighteen algorithms
                        // immediately above the table that lists them again, in a second layout.
                        field(out, "Profile", algorithms.profile().name() + "  ("
                                + algorithms.supported().size() + " of " + total
                                + " post-quantum algorithms usable)");
                        printKeyAlgorithms(out, algorithms, capabilities);
                        printServices(out, handle.token().getProvider());
                        if (!algorithms.excluded().isEmpty()) {
                            section(out, "Post-quantum algorithms this token cannot do");
                            for (Map.Entry<String, String> excluded
                                    : algorithms.excluded().entrySet()) {
                                out.println("  " + pad(excluded.getKey(), NAME_WIDTH)
                                        + excluded.getValue());
                            }
                        }
                        if (args.has("mechanisms")) {
                            printMechanisms(out, capabilities);
                        }
                    }
                });
    }

    /**
     * Every key algorithm this crypto token can create on this HSM, post-quantum or not, in one
     * table.
     *
     * <p>Classical algorithms are absent from {@link AlgorithmSupport} by construction, and
     * reasonably so — a {@code PqcMechanismProfile} exists to resolve variation, and there is none
     * to resolve here. {@code CKM_RSA_PKCS_KEY_PAIR_GEN} has meant the same thing since PKCS#11
     * v2.0, whereas a post-quantum mechanism number and its parameter-set attribute differ between
     * vendors and between draft revisions, which is the whole reason profiles exist.
     *
     * <p>But that is an implementation boundary, not one an operator should have to know about. A
     * command called {@code capabilities} is asked what the token can do; splitting the answer in
     * two along the line of what happened to need a profile makes the reader reassemble it, and on
     * a token with no ML-DSA at all the post-quantum table alone would report nothing usable while
     * RSA worked perfectly.
     *
     * <p>The classical rows are gated on exactly the mechanisms {@code CryptoTokenImpl} requires
     * before it generates — {@code generateKeyPair} checks {@code CKM_RSA_PKCS_KEY_PAIR_GEN} and
     * {@code CKM_EC_KEY_PAIR_GEN}, {@code generateKey} goes through {@link SecretKeyType} — so this
     * reports what generation will actually accept rather than a second opinion about it.
     */
    private static void printKeyAlgorithms(PrintStream out, AlgorithmSupport algorithms,
            TokenCapabilities capabilities) throws java.io.IOException {
        section(out, "Key algorithms this crypto token can use on this HSM");
        if (!capabilities.probed()) {
            out.println("  (unknown: " + capabilities.unprobedReason() + ")");
            return;
        }
        // Notes are collected and printed under the table rather than trailing each row. Two rows
        // out of twenty-five carry one, and inline they set the table's width for all of them —
        // the reader then scans past 90 columns of nothing to reach the next value.
        List<String> notes = new ArrayList<>();
        byte[] sample = "sample".getBytes(StandardCharsets.UTF_8);
        header(out);

        KeyTemplates.Pair rsa = KeyTemplates.rsa(sample, sample, 2048);
        algorithmRow(out, notes, "RSA", "RSA", CKM.RSA_PKCS_KEY_PAIR_GEN,
                capabilities.canGenerateKeyPair(CKM.RSA_PKCS_KEY_PAIR_GEN) ? "ok"
                        : "not advertised",
                usages(rsa), "");

        KeyTemplates.Pair ec = KeyTemplates.ec(sample, sample, "secp256r1");
        algorithmRow(out, notes, "EC", "EC", CKM.EC_KEY_PAIR_GEN,
                capabilities.canGenerateKeyPair(CKM.EC_KEY_PAIR_GEN) ? "ok" : "not advertised",
                usages(ec),
                // All CKF_GENERATE_KEY_PAIR promises. Which curves the token holds parameters for
                // is not in the mechanism list at all, and implying otherwise would be the kind of
                // confident wrong answer this command exists to prevent.
                "Curves are not advertised per mechanism; the token decides which ones it holds"
                        + " parameters for at generation.");

        for (AlgorithmEntry entry : algorithms.supported()) {
            KeyTemplates.Pair pqc = KeyTemplates.pqc(sample, sample, entry, algorithms.profile());
            algorithmRow(out, notes, entry.canonicalName(), entry.family().jcaName(),
                    entry.ckmKeyPairGen(), "ok",
                    usages(pqc), "");
        }

        for (SecretKeyType type : SecretKeyType.all()) {
            // Two different reasons an algorithm may be unavailable, and collapsing them into one
            // "not advertised" would blame the token for our own gap. SoftHSMv3 does advertise
            // CKM_AES_KEY_GEN; what is missing is a Cipher service in this provider, and since the
            // key is generated CKA_SENSITIVE and not extractable, nothing in the JVM could use one.
            // generateKey refuses it for exactly that reason, so the status has to say which is
            // which — that is the difference between this list and a raw mechanism dump.
            boolean advertised = capabilities.canGenerate(type.ckmKeyGen());
            String status = !advertised ? "not advertised"
                    : type.usableHere() ? "ok" : "unusable here";
            algorithmRow(out, notes, type.jcaName(), type.usableHere() ? "HMAC" : "AES",
                    type.ckmKeyGen(), status,
                    usages(KeyTemplates.secret(sample, sample, type, type.defaultBits())),
                    type.usableHere() ? ""
                            : "generatekey refuses " + type.jcaName() + " outright: the key would"
                                    + " be CKA_SENSITIVE and not extractable, and this provider"
                                    + " registers no Cipher to use it with, so it would be an"
                                    + " unusable object left on the token.");
        }
        for (int i = 0; i < notes.size(); i++) {
            prose(out, "  [" + (i + 1) + "] ", notes.get(i));
        }
    }

    /**
     * A sentence wrapped to {@link #WRAP_WIDTH}, continuation lines aligned under the first word.
     *
     * <p>So a footnote folds where this command decides rather than wherever the terminal happens
     * to be cut off, which is what makes the second line of one note distinguishable from the
     * first line of the next.
     */
    private static void prose(PrintStream out, String prefix, String text) {
        String indent = " ".repeat(prefix.length());
        StringBuilder line = new StringBuilder(prefix);
        int atLineStart = prefix.length();
        for (String word : text.split(" ")) {
            if (line.length() > atLineStart && line.length() + 1 + word.length() > WRAP_WIDTH) {
                out.println(line.toString());
                line = new StringBuilder(indent).append(word);
            } else {
                line.append(line.length() > atLineStart ? " " : "").append(word);
            }
        }
        out.println(line.toString());
    }

    /**
     * The operations a key of this algorithm is generated able to perform.
     *
     * <p>Read out of {@link KeyTemplates} rather than restated here, by building the template this
     * command would generate with and collecting the usage attributes it sets. Restating them was
     * the first version and it was already wrong: it listed RSA as {@code SIGN, VERIFY} when the
     * template also sets {@code CKA_ENCRYPT} and {@code CKA_WRAP} on the public half and
     * {@code CKA_DECRYPT} and {@code CKA_UNWRAP} on the private one. Deriving them means the column
     * cannot say one thing while generation does another.
     *
     * <p>What a key <em>may</em> do is not what this crypto token can <em>drive</em>: there is no
     * Cipher service here, so the encrypt and wrap halves are reachable only by another provider
     * holding the same token. {@link #undrivable} is what says so, per row.
     */
    private static String usages(KeyTemplates.Pair pair) {
        return usagesOf(List.of(pair.publicTemplate(), pair.privateTemplate()));
    }

    /** The same, for a secret key, which is one template rather than a pair. */
    private static String usages(List<CKA> template) {
        return usagesOf(List.of(template));
    }

    private static String usagesOf(List<List<CKA>> templates) {
        Set<Long> set = new java.util.LinkedHashSet<>();
        for (List<CKA> template : templates) {
            for (CKA attribute : template) {
                if (USAGE_ATTRIBUTES.containsKey(attribute.type)
                        && Boolean.TRUE.equals(attribute.getValueBool())) {
                    set.add(attribute.type);
                }
            }
        }
        // Ordered by the attribute table, not by the templates, so two algorithms that grant the
        // same operations read identically instead of differing by the order they were added in.
        return USAGE_ATTRIBUTES.entrySet().stream()
                .filter(e -> set.contains(e.getKey()))
                .map(Map.Entry::getValue)
                .collect(Collectors.joining(", "));
    }

    /** The {@code CKA_*} usage attributes this project ever sets, in the order they are printed. */
    private static final Map<Long, String> USAGE_ATTRIBUTES = new java.util.LinkedHashMap<>(
            Map.of());

    static {
        USAGE_ATTRIBUTES.put(CKA.SIGN, "SIGN");
        USAGE_ATTRIBUTES.put(CKA.VERIFY, "VERIFY");
        USAGE_ATTRIBUTES.put(CKA.ENCRYPT, "ENCRYPT");
        USAGE_ATTRIBUTES.put(CKA.DECRYPT, "DECRYPT");
        USAGE_ATTRIBUTES.put(CKA.WRAP, "WRAP");
        USAGE_ATTRIBUTES.put(CKA.UNWRAP, "UNWRAP");
        USAGE_ATTRIBUTES.put(CKA.DERIVE, "DERIVE");
    }

    /**
     * The operations in {@code granted} that no service in this provider can reach.
     *
     * <p>Empty when everything granted is drivable. Signing and verification are covered by the
     * Signature and Mac services; nothing else is, because there is no Cipher and no KEM service
     * here — so an RSA key really can decrypt, just not through this crypto token.
     */
    private static String undrivable(String granted) {
        List<String> stranded = Arrays.stream(granted.split(", "))
                .filter(op -> !"SIGN".equals(op) && !"VERIFY".equals(op) && !op.isEmpty())
                .collect(Collectors.toList());
        return stranded.isEmpty() ? "" : String.join(", ", stranded);
    }

    /**
     * One table row, plus whichever footnotes it earns.
     *
     * <p>Two of them are automatic. A row whose key can do more than this provider can drive gets
     * the stranded operations named, because a reader who sees {@code DECRYPT} in the column and
     * no Cipher in the services below is owed the explanation rather than left to infer it. The
     * other is whatever the caller passes.
     */
    private static void algorithmRow(PrintStream out, List<String> notes, String name,
            String family, long ckm, String status, String ops, String extra) {
        List<String> markers = new ArrayList<>();
        if (!extra.isEmpty()) {
            markers.add(note(notes, extra));
        }
        String stranded = undrivable(ops);
        if (!stranded.isEmpty()) {
            // Phrased without the algorithm name so that ML-KEM-512, -768 and -1024 share one
            // footnote instead of earning three identical ones.
            markers.add(note(notes, "Generated able to " + stranded + ", but this provider"
                    + " registers no service for those — they are reachable only by another"
                    + " provider holding the same token. What kimbo11ng itself offers is in the"
                    + " services list below."));
        }
        row(out, name, family, ckm, status, ops.isEmpty() ? "—" : ops, String.join("", markers));
    }

    /**
     * Records a footnote and returns the marker that points at it, reusing one that already says
     * the same thing.
     *
     * <p>Three ML-KEM sizes carry the identical caveat; printing it three times pushes the reader
     * to skim past all of them, which defeats the point of writing it once.
     */
    private static String note(List<String> notes, String text) {
        int existing = notes.indexOf(text);
        if (existing >= 0) {
            return "[" + (existing + 1) + "]";
        }
        notes.add(text);
        return "[" + notes.size() + "]";
    }

    private static void header(PrintStream out) {
        out.println("  " + pad("ALGORITHM", NAME_WIDTH) + pad("FAMILY", FAMILY_WIDTH)
                + pad("STATUS", STATUS_WIDTH) + pad("KEY GENERATION", KEYGEN_WIDTH)
                + "OPERATIONS");
    }

    private static void row(PrintStream out, String name, String family, long ckm, String status,
            String ops, String marker) {
        // No trailing padding when there is no footnote: a line that ends in spaces is invisible
        // here and noise in a diff or a copied-out log.
        String tail = marker.isEmpty() ? ops : pad(ops, OPS_WIDTH) + marker;
        out.println("  " + pad(name, NAME_WIDTH) + pad(family, FAMILY_WIDTH)
                + pad(status, STATUS_WIDTH) + pad(TokenCapabilities.name(ckm), KEYGEN_WIDTH)
                + tail);
    }

    // One set of column widths for the whole command, so the tables under each heading line up
    // with one another instead of each being padded to whatever its own longest value happens
    // to be.
    private static final int NAME_WIDTH = 22;
    private static final int FAMILY_WIDTH = 10;
    private static final int STATUS_WIDTH = 16;
    private static final int KEYGEN_WIDTH = 42;
    private static final int OPS_WIDTH = 32;

    /** A blank line and a heading, so every block in this command opens the same way. */
    private static void section(PrintStream out, String title) {
        out.println();
        out.println(title);
    }

    /**
     * What EJBCA will actually be able to ask for, taken from the provider rather than restated.
     *
     * <p>The table above says which keys can exist; this says what can be done with them, which is
     * the question behind it. The two are not the same list: a token can generate an EC key and
     * still not sign with SHA-512, and {@link ch.ithings.kimbo11ng.provider.Kimbo11ngProvider}
     * registers a signature service only for the mechanisms the probe confirmed.
     *
     * <p>Read through {@link java.security.Provider#getServices()} on purpose. That is the same
     * call the JCA makes on EJBCA's behalf, so this cannot drift from what the CA sees — a private
     * accessor listing the same thing could, and a hand-maintained list here certainly would.
     */
    private static void printServices(PrintStream out, java.security.Provider provider) {
        Map<String, List<String>> byType = new java.util.TreeMap<>();
        for (java.security.Provider.Service service : provider.getServices()) {
            byType.computeIfAbsent(service.getType(), key -> new ArrayList<>())
                    .add(service.getAlgorithm());
        }
        section(out, "Services EJBCA can request from this token");
        if (byType.isEmpty()) {
            out.println("  (none — the provider registered no service for this token)");
            return;
        }
        for (Map.Entry<String, List<String>> entry : byType.entrySet()) {
            List<String> names = entry.getValue().stream().sorted().collect(Collectors.toList());
            // The marker rides after the values, not on the label: appended to the label it
            // overflows the column and pushes that one row out of line with the rest.
            wrapped(out, entry.getKey() + " (" + names.size() + ")", names,
                    "KeyPairGenerator".equals(entry.getKey()) ? " [*]" : "");
        }
        if (byType.containsKey("KeyPairGenerator")) {
            // Without this the reader concludes that only RSA and EC key pairs can be created,
            // which the table above contradicts and which is simply untrue — and the two sections
            // disagreeing is worse than either being incomplete.
            prose(out, "  [*] ", "Post-quantum key pairs are not created through a JCA"
                    + " KeyPairGenerator. CryptoTokenImpl.generateKeyPair drives PKCS#11 directly"
                    + " for them, which is the method EJBCA calls and the one generatekeypair uses,"
                    + " so every algorithm marked ok above can be generated. This row lists the"
                    + " JCA service, not the limit.");
        }
    }

    /**
     * A labelled list that wraps under its own label instead of running off the terminal.
     *
     * <p>The Signature row alone is twenty-six algorithm names — over a thousand characters, which
     * the terminal folds back to column zero and so ends up indistinguishable from the next label.
     */
    private static void wrapped(PrintStream out, String label, List<String> values,
            String suffix) {
        String indent = " ".repeat(2 + NAME_WIDTH);
        StringBuilder line = new StringBuilder("  " + pad(label, NAME_WIDTH));
        boolean first = true;
        for (String value : values) {
            String piece = first ? value : ", " + value;
            if (!first && line.length() + piece.length() > WRAP_WIDTH) {
                out.println(line.append(',').toString());
                line = new StringBuilder(indent).append(value);
            } else {
                line.append(piece);
            }
            first = false;
        }
        out.println(line.append(suffix).toString());
    }

    /**
     * Where a wrapped list folds.
     *
     * <p>Wider than the classic eighty because the table above is wider than eighty and wrapping
     * the two at different points would look like an accident. Narrow enough that a terminal at
     * 120 — and the side-by-side panes people actually read logs in — does not fold it again.
     */
    private static final int WRAP_WIDTH = 110;

    private static void printMechanisms(PrintStream out, TokenCapabilities capabilities) {
        if (!capabilities.probed()) {
            section(out, "Mechanisms: not available (" + capabilities.unprobedReason() + ")");
            return;
        }
        section(out, "Mechanisms advertised by the token (" + capabilities.mechanisms().size()
                + ")");
        out.println("  " + pad("MECHANISM", KEYGEN_WIDTH) + "USES");
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
            out.println("  " + pad(TokenCapabilities.name(ckm), KEYGEN_WIDTH)
                    + (uses.isEmpty() ? "—" : String.join(", ", uses)));
        }
    }

    // ---- formatting ----

    private static void field(PrintStream out, String name, String value) {
        out.println(pad(name + ":", NAME_WIDTH) + value);
    }

    /**
     * Left-aligns {@code text} in a column of {@code width}, always leaving a separator.
     *
     * <p>The minimum matters: an alias longer than its column used to be returned untouched, so
     * {@code listkeypairs} printed {@code demo…MLDSA87key pair} with no gap and the two values read
     * as one. Overflowing a column costs alignment on that row, which is unavoidable; losing the
     * separator costs the reader the ability to tell where the value ended, which is not.
     */
    static String pad(String text, int width) {
        return text.length() >= width ? text + " " : text + " ".repeat(width - text.length());
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

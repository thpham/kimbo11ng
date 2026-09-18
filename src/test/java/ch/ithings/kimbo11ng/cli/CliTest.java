/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The CLI, driven end to end against the in-memory token.
 *
 * <p>Written at the {@link Main#run} boundary rather than against the individual commands, because
 * the parts most likely to be wrong are the ones between them: an option declared but never read, a
 * command that forgets to log in, an exit code that says success after printing an error. Those are
 * invisible to a test that calls a command's body directly.
 *
 * <p>This is also the only caller the commands have. Nothing in EJBCA invokes them, so a defect
 * here would otherwise surface for the first time in front of an operator holding a broken HSM.
 */
@DisplayName("command-line tool")
class CliTest {

    private static final String LIB = "/nonexistent/libfake.so";
    private static final String PIN = "1234";

    private FakeToken token;
    private ByteArrayOutputStream out;
    private ByteArrayOutputStream err;
    private CliEnv env;
    private final List<String> prompts = new ArrayList<>();

    // Deliberately no @BeforeAll registering BouncyCastle. Every other test class in this project
    // does, because they are testing the crypto token as EJBCA has already set it up. The CLI has
    // no EJBCA to do that for it, so installing the provider is its own job — and the post-quantum
    // tests below are what hold it to that.

    @BeforeEach
    void setUp() {
        token = new FakeToken();
        out = new ByteArrayOutputStream();
        err = new ByteArrayOutputStream();
        prompts.clear();
        env = new CliEnv(stream(out), stream(err), prompt -> {
            prompts.add(prompt);
            return PIN.toCharArray();
        }, new Pkcs11ModuleRegistry(path -> token));
    }

    private static PrintStream stream(ByteArrayOutputStream sink) {
        return new PrintStream(sink, true, StandardCharsets.UTF_8);
    }

    private String stdout() {
        return out.toString(StandardCharsets.UTF_8);
    }

    private String stderr() {
        return err.toString(StandardCharsets.UTF_8);
    }

    /** Runs a command with the library, slot and PIN every session-level command needs. */
    private int session(String... command) {
        List<String> argv = new ArrayList<>(List.of(command));
        argv.addAll(List.of("--lib-file", LIB, "--slot", "0", "--password", PIN));
        return Main.run(argv.toArray(new String[0]), env);
    }

    // ---- dispatch ----

    @Test
    @DisplayName("no arguments prints the command list and reports a usage error")
    void noArguments() {
        assertEquals(Main.USAGE, Main.run(new String[0], env));
        assertTrue(stdout().contains("listslots"), stdout());
        assertTrue(stdout().contains("generatekeypair"), stdout());
    }

    @Test
    @DisplayName("--help succeeds and lists every command")
    void overviewHelp() {
        assertEquals(Main.OK, Main.run(new String[] {"--help"}, env));
        for (String name : Main.commands().keySet()) {
            assertTrue(stdout().contains(name), "help omitted " + name);
        }
    }

    @Test
    @DisplayName("an unknown command is a usage error, not a crash")
    void unknownCommand() {
        assertEquals(Main.USAGE, Main.run(new String[] {"listslot"}, env));
        assertTrue(stderr().contains("Unknown command 'listslot'"), stderr());
    }

    @Test
    @DisplayName("per-command help names the command's own options")
    void commandHelp() {
        assertEquals(Main.OK, Main.run(new String[] {"generatekeypair", "--help"}, env));
        assertTrue(stdout().contains("--key-spec"), stdout());
        assertTrue(stdout().contains("--alias"), stdout());
    }

    @Test
    @DisplayName("every option carries help, and the token-wide ones read the same everywhere")
    void everyOptionIsDocumented() {
        // --alias and --key-spec are deliberately excluded: they name a different thing in each
        // command ("alias to test", "alias for the new key"), and one shared wording would be
        // vaguer than five specific ones. The options below are the same option every time, so a
        // difference between two of them can only be drift — which is exactly what happened
        // between the library-level commands and Opt.slot() before this test existed.
        List<String> tokenWide = List.of("lib-file", "slot-ref", "slot", "property", "password");
        Map<String, String> helpByOption = new HashMap<>();
        for (Command command : Main.commands().values()) {
            for (Opt option : command.options()) {
                assertFalse(option.help().isBlank(),
                        command.name() + " --" + option.name() + " has no help text");
                if (!tokenWide.contains(option.name())) {
                    continue;
                }
                String seen = helpByOption.putIfAbsent(option.name(), option.help());
                assertTrue(seen == null || seen.equals(option.help()),
                        "--" + option.name() + " is described two ways, one of them in "
                                + command.name());
            }
        }
        assertEquals(tokenWide.size(), helpByOption.size(),
                "a token-wide option vanished from every command: " + helpByOption.keySet());
    }

    @Test
    @DisplayName("an unknown option is refused by name rather than ignored")
    void unknownOption() {
        int code = Main.run(new String[] {"listslots", "--lib-file", LIB, "--slott", "0"}, env);
        assertEquals(Main.USAGE, code);
        assertTrue(stderr().contains("--slott"), stderr());
    }

    @Test
    @DisplayName("a missing required option says which one")
    void missingRequiredOption() {
        assertEquals(Main.USAGE, Main.run(new String[] {"listslots"}, env));
        assertTrue(stderr().contains("--lib-file is required"), stderr());
    }

    @Test
    @DisplayName("an option that needs a value and has none is a usage error")
    void danglingOption() {
        assertEquals(Main.USAGE, Main.run(new String[] {"listslots", "--lib-file"}, env));
        assertTrue(stderr().contains("requires a value"), stderr());
    }

    @Test
    @DisplayName("a bad --slot-ref is refused before the library is touched")
    void badSlotRef() {
        int code = Main.run(new String[] {"showtokeninfo", "--lib-file", LIB,
                "--slot-ref", "SLOT_NAME", "--slot", "0"}, env);
        assertEquals(Main.USAGE, code);
        assertTrue(stderr().contains("SLOT_NUMBER"), stderr());
    }

    @Test
    @DisplayName("repeating a non-repeatable option is refused")
    void repeatedOption() {
        int code = Main.run(new String[] {"listslots", "--lib-file", LIB, "--lib-file", LIB}, env);
        assertEquals(Main.USAGE, code);
        assertTrue(stderr().contains("more than once"), stderr());
    }

    // ---- information, without a PIN ----

    @Test
    @DisplayName("listslots reports the slots and the token label without logging in")
    void listSlots() {
        assertEquals(Main.OK, Main.run(new String[] {"listslots", "--lib-file", LIB}, env));
        assertTrue(stdout().contains("All slots:"), stdout());
        assertTrue(stdout().contains("Slots with token:"), stdout());
        assertTrue(stdout().contains("slot 0:"), stdout());
        assertTrue(prompts.isEmpty(), "listslots must not ask for a PIN");
    }

    @Test
    @DisplayName("showinfo describes the library")
    void showInfo() {
        assertEquals(Main.OK, Main.run(new String[] {"showinfo", "--lib-file", LIB}, env));
        assertTrue(stdout().contains("Cryptoki version:"), stdout());
        assertTrue(stdout().contains("FakeToken"), stdout());
    }

    @Test
    @DisplayName("showslotinfo and showtokeninfo describe the slot and the token")
    void showSlotAndTokenInfo() {
        assertEquals(Main.OK, Main.run(new String[] {"showslotinfo", "--lib-file", LIB,
                "--slot", "0"}, env));
        assertTrue(stdout().contains("Token present"), stdout());
        assertTrue(stdout().contains("yes"), stdout());

        out.reset();
        assertEquals(Main.OK, Main.run(new String[] {"showtokeninfo", "--lib-file", LIB,
                "--slot", "0"}, env));
        assertTrue(stdout().contains("Label:"), stdout());
        assertTrue(stdout().contains("User PIN state:"), stdout());
    }

    // ---- the three info views, field by field ----

    /**
     * Asserts every label is present and carries the expected value.
     *
     * <p>Per field, not "the output is non-empty": a dropped line leaves a report that still looks
     * like a report, and the operator reading it has no way to know a field was ever meant to be
     * there. These commands exist to answer "what is this HSM", so a silently missing answer is the
     * failure mode worth pinning.
     */
    private void assertFields(String... labelsAndValues) {
        String output = stdout();
        for (int i = 0; i < labelsAndValues.length; i += 2) {
            String label = labelsAndValues[i];
            String value = labelsAndValues[i + 1];
            String line = output.lines().filter(l -> l.contains(label)).findFirst().orElse(null);
            assertNotNull(line, "no '" + label + "' line in:\n" + output);
            assertTrue(line.contains(value),
                    "'" + label + "' should report '" + value + "' but was: " + line);
        }
    }

    @Test
    @DisplayName("showinfo reports every field of the library's own identity")
    void showInfoFields() {
        assertEquals(Main.OK, Main.run(new String[] {"showinfo", "--lib-file", LIB}, env));
        assertFields(
                "Cryptoki version", "3.0",
                "Manufacturer", "kimbo11ng",
                "Library", "FakeToken",
                "Library version", "1.0",
                "Flags", "0x");
    }

    @Test
    @DisplayName("showslotinfo reports every field of the slot")
    void showSlotInfoFields() {
        assertEquals(Main.OK, Main.run(new String[] {"showslotinfo", "--lib-file", LIB,
                "--slot", "0"}, env));
        assertFields(
                "Slot id", "0",
                "Description", "FakeToken slot",
                "Manufacturer", "kimbo11ng",
                "Hardware version", "1.0",
                "Firmware version", "1.0",
                "Token present", "yes",
                "Removable", "no",
                "Hardware slot", "no",
                "Flags", "CKF_TOKEN_PRESENT");
    }

    @Test
    @DisplayName("showtokeninfo reports every field of the token")
    void showTokenInfoFields() {
        assertEquals(Main.OK, Main.run(new String[] {"showtokeninfo", "--lib-file", LIB,
                "--slot", "0"}, env));
        assertFields(
                "Slot id", "0",
                "Label", "FakeToken",
                "Manufacturer", "kimbo11ng",
                "Model", "FakeToken v3.2",
                "Serial number", "FAKE-0001",
                "Hardware version", "1.0",
                "Firmware version", "3.128",
                "Sessions", "of 64",
                "R/W sessions", "of 64",
                "PIN length", "4 to 32",
                "Login required", "yes",
                "Write protected", "no",
                "User PIN state", "ok",
                "Flags", "CKF_");
    }

    // ---- what showtokeninfo reports about the token's own state ----

    @Test
    @DisplayName("a healthy token reports its PIN state as ok")
    void tokenInfoPinStateOk() {
        assertEquals(Main.OK, Main.run(new String[] {"showtokeninfo", "--lib-file", LIB,
                "--slot", "0"}, env));
        assertTrue(stdout().contains("User PIN state"), stdout());
        assertTrue(stdout().lines().anyMatch(l -> l.contains("User PIN state") && l.contains("ok")),
                stdout());
    }

    @Test
    @DisplayName("a locked PIN is named, because it turns a retry into an outage")
    void tokenInfoPinLocked() {
        token.tokenFlags(CK_TOKEN_INFO.CKF_USER_PIN_LOCKED);

        assertEquals(Main.OK, Main.run(new String[] {"showtokeninfo", "--lib-file", LIB,
                "--slot", "0"}, env));
        // The operator about to type the PIN again has to see this first: on most tokens the retry
        // is what consumes the last attempt.
        assertTrue(pinState().contains("LOCKED"), stdout());
    }

    @Test
    @DisplayName("every PIN warning flag is reported, and several at once are all listed")
    void tokenInfoPinWarnings() {
        token.tokenFlags(CK_TOKEN_INFO.CKF_USER_PIN_FINAL_TRY
                | CK_TOKEN_INFO.CKF_USER_PIN_COUNT_LOW
                | CK_TOKEN_INFO.CKF_USER_PIN_TO_BE_CHANGED);

        assertEquals(Main.OK, Main.run(new String[] {"showtokeninfo", "--lib-file", LIB,
                "--slot", "0"}, env));
        String state = pinState();
        // Each flag independently, not "the first one wins": a token on its final try whose PIN
        // must also be changed is exactly the state where a missing half misleads.
        assertTrue(state.contains("FINAL TRY"), state);
        assertTrue(state.contains("failed attempts recorded"), state);
        assertTrue(state.contains("must be changed"), state);
        assertFalse(state.contains("ok"), state);
    }

    @Test
    @DisplayName("an uninitialised user PIN is reported as such")
    void tokenInfoPinNotInitialized() {
        // The one state expressed by a flag's absence rather than its presence: a token straight
        // out of the box, whose user PIN has never been set.
        token.clearTokenFlag(CK_TOKEN_INFO.CKF_USER_PIN_INITIALIZED);

        assertEquals(Main.OK, Main.run(new String[] {"showtokeninfo", "--lib-file", LIB,
                "--slot", "0"}, env));
        assertTrue(pinState().contains("not initialized"), stdout());
    }

    @Test
    @DisplayName("a firmware minor of 0x80 prints as 128, not -128")
    void tokenInfoVersionsAreUnsigned() {
        assertEquals(Main.OK, Main.run(new String[] {"showtokeninfo", "--lib-file", LIB,
                "--slot", "0"}, env));
        // CK_VERSION fields are bytes and the values are unsigned. A signed read turns a perfectly
        // ordinary firmware version into a negative number in front of the operator.
        String line = stdout().lines().filter(l -> l.contains("Firmware version")).findFirst()
                .orElse("");
        assertTrue(line.contains("3.128"), line);
        assertFalse(line.contains("-"), line);
    }

    @Test
    @DisplayName("session counts are reported against the token's ceiling")
    void tokenInfoSessionCounts() {
        assertEquals(Main.OK, Main.run(new String[] {"showtokeninfo", "--lib-file", LIB,
                "--slot", "0"}, env));
        String line = stdout().lines().filter(l -> l.contains("Sessions")).findFirst().orElse("");
        assertTrue(line.matches(".*\\d+ of 64.*"), line);
    }

    /** The value printed on the "User PIN state" line. */
    private String pinState() {
        return stdout().lines().filter(l -> l.contains("User PIN state")).findFirst().orElse("");
    }

    @Test
    @DisplayName("capabilities reports the resolved profile with no PIN")
    void capabilities() {
        int code = Main.run(new String[] {"capabilities", "--lib-file", LIB, "--slot", "0"}, env);
        assertEquals(Main.OK, code);
        assertTrue(stdout().contains("Profile:"), stdout());
        assertTrue(stdout().contains("Key algorithms this crypto token can use on this HSM"),
                stdout());
        assertTrue(prompts.isEmpty(), "capabilities must not ask for a PIN");
    }

    @Test
    @DisplayName("capabilities reports RSA, EC and the secret-key algorithms, not only the profile")
    void capabilitiesReportsClassical() {
        int code = Main.run(new String[] {"capabilities", "--lib-file", LIB, "--slot", "0"}, env);
        assertEquals(Main.OK, code);
        // One table, not two: the profile boundary between classical and post-quantum is an
        // implementation detail, and on a token with no ML-DSA the post-quantum list alone would
        // report nothing usable while RSA worked perfectly.
        assertTrue(stdout().contains("Key algorithms this crypto token can use on this HSM"),
                stdout());
        assertTrue(stdout().contains("CKM_RSA_PKCS_KEY_PAIR_GEN"), stdout());
        assertTrue(stdout().contains("CKM_EC_KEY_PAIR_GEN"), stdout());
        assertTrue(stdout().contains("HmacSHA256"), stdout());
        assertTrue(stdout().contains("ML-DSA-65"), stdout());
        // The OPERATIONS column, no longer bracketed now that it has a header of its own.
        assertTrue(stdout().contains("SIGN, VERIFY"), stdout());
        // Read from Provider.getServices(), which is the same call the JCA makes on EJBCA's
        // behalf, so this section cannot drift from what the CA is actually offered.
        assertTrue(stdout().contains("Services EJBCA can request from this token"), stdout());
        // Named through the v3.2 fallback: jacknji11 1.3.1 knows none of the six post-quantum
        // mechanisms, and a table where RSA is a name and ML-DSA is a hex number reads as though
        // the second were less well understood than the first.
        assertTrue(stdout().contains("CKM_ML_DSA_KEY_PAIR_GEN"), stdout());
    }

    @Test
    @DisplayName("capabilities separates a mechanism the token lacks from one this provider lacks")
    void capabilitiesDistinguishesTheTwoReasons() {
        int code = Main.run(new String[] {"capabilities", "--lib-file", LIB, "--slot", "0"}, env);
        assertEquals(Main.OK, code);
        // FakeToken advertises CKM_AES_KEY_GEN, so "not advertised" here would blame the token for
        // a gap that is ours: no Cipher service, and the key is sensitive and not extractable.
        String aes = stdout().lines().filter(line -> line.startsWith("  AES ")).findFirst()
                .orElse("");
        assertTrue(aes.contains("unusable here"), aes);
        assertFalse(aes.contains("not advertised"), aes);

        // The OPERATIONS column is read out of KeyTemplates, not restated: the first version of
        // this table said RSA was SIGN, VERIFY when the template also sets CKA_ENCRYPT, CKA_WRAP
        // on the public half and CKA_DECRYPT, CKA_UNWRAP on the private one.
        String rsa = stdout().lines().filter(line -> line.startsWith("  RSA ")).findFirst()
                .orElse("");
        assertTrue(rsa.contains("ENCRYPT"), rsa);
        assertTrue(rsa.contains("UNWRAP"), rsa);
        // And what the key may do is marked apart from what this provider can drive: there is no
        // Cipher service here, so those four are reachable only through another provider.
        assertTrue(rsa.matches(".*\\[\\d+\\].*"), "RSA row carries no footnote marker: " + rsa);
    }

    @Test
    @DisplayName("no view leaves trailing whitespace or runs two columns together")
    void tablesAreReadable() {
        assertEquals(Main.OK, Main.run(new String[] {"capabilities", "--lib-file", LIB,
                "--slot", "0", "--mechanisms"}, env));
        for (String line : stdout().split("\n", -1)) {
            assertEquals(line.stripTrailing(), line, "trailing whitespace: [" + line + "]");
        }
        // pad() used to return an over-long value untouched, so a column that overflowed ran
        // straight into the next one. Every data row here has at least one value at or past its
        // column width, which is what makes this a real check rather than a tautology.
        String mldsa = stdout().lines().filter(line -> line.startsWith("  ML-DSA-44"))
                .findFirst().orElse("");
        assertTrue(mldsa.contains("ML-DSA-44  "), mldsa);
    }

    @Test
    @DisplayName("the KEM footnote describes the template this token will actually be sent")
    void capabilitiesKemNoteFollowsTheProperty() {
        // The footnote is read by an operator deciding whether their token will accept the key, so
        // it has to describe this run's template and not the general case. Each setting names its
        // own attributes and nobody else's.
        assertEquals(Main.OK, Main.run(new String[] {"capabilities", "--lib-file", LIB,
                "--slot", "0", "--property", "kimbo11ng.pqc.kemUsage=v32"}, env));
        String v32 = stdout();
        assertTrue(v32.contains("CKA_ENCAPSULATE"), v32);
        assertFalse(v32.contains("CKA_ENCRYPT and CKA_DECRYPT"), v32);
        // v32 alone means EJBCA shows no usage at all, which is the cost the operator is choosing.
        assertTrue(v32.contains("show no usage"), v32);

        out.reset();
        assertEquals(Main.OK, Main.run(new String[] {"capabilities", "--lib-file", LIB,
                "--slot", "0", "--property", "kimbo11ng.pqc.kemUsage=legacy"}, env));
        String legacy = stdout();
        assertTrue(legacy.contains("CKA_ENCRYPT and CKA_DECRYPT"), legacy);
        assertFalse(legacy.contains("CKA_ENCAPSULATE"), legacy);
        assertFalse(legacy.contains("show no usage"), legacy);

        out.reset();
        assertEquals(Main.OK, Main.run(new String[] {"capabilities", "--lib-file", LIB,
                "--slot", "0", "--property", "kimbo11ng.pqc.kemUsage=both"}, env));
        String both = stdout();
        assertTrue(both.contains("CKA_ENCAPSULATE"), both);
        assertTrue(both.contains("and also with "), both);
        assertTrue(both.contains("CKA_ENCRYPT and CKA_DECRYPT"), both);
        assertFalse(both.contains("show no usage"), both);

        // Whatever the setting, the same thing stays true and has to be said.
        for (String output : new String[] {v32, legacy, both}) {
            assertTrue(output.contains("No signing service is registered"), output);
        }
    }

    @Test
    @DisplayName("the KEM footnote names the property that produced it")
    void capabilitiesKemNoteNamesTheProperty() {
        assertEquals(Main.OK, Main.run(new String[] {"capabilities", "--lib-file", LIB,
                "--slot", "0", "--property", "kimbo11ng.pqc.kemUsage=v32"}, env));
        // Naming the setting is what lets a reader change it without going to the documentation.
        assertTrue(stdout().contains("kimbo11ng.pqc.kemUsage=v32"), stdout());
    }

    @Test
    @DisplayName("capabilities --mechanisms lists the mechanism table")
    void capabilitiesMechanisms() {
        int code = Main.run(new String[] {"capabilities", "--lib-file", LIB, "--slot", "0",
                "--mechanisms"}, env);
        assertEquals(Main.OK, code);
        assertTrue(stdout().contains("Mechanisms advertised by the token"), stdout());
        assertTrue(stdout().contains("generate-key-pair"), stdout());
    }

    @Test
    @DisplayName("--property reaches the crypto token")
    void propertyPassthrough() {
        int code = Main.run(new String[] {"capabilities", "--lib-file", LIB, "--slot", "0",
                "--property", "kimbo11ng.pqc.profile=pkcs11v32"}, env);
        assertEquals(Main.OK, code);
        assertTrue(stdout().contains("pkcs11v32"), stdout());
    }

    @Test
    @DisplayName("a malformed --property is a usage error")
    void malformedProperty() {
        int code = Main.run(new String[] {"capabilities", "--lib-file", LIB, "--slot", "0",
                "--property", "novalue"}, env);
        assertEquals(Main.USAGE, code);
        assertTrue(stderr().contains("key=value"), stderr());
    }

    // ---- keys ----

    @Test
    @DisplayName("generatekeypair then listkeypairs shows the alias EJBCA would see")
    void generateAndList() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "signKey",
                "--key-spec", "2048"), stderr());
        assertTrue(stdout().contains("Generated key pair with alias signKey"), stdout());

        out.reset();
        assertEquals(Main.OK, session("listkeypairs"), stderr());
        assertTrue(stdout().contains("signKey"), stdout());
        assertTrue(stdout().contains("RSA"), stdout());
    }

    @Test
    @DisplayName("testkeypair signs and verifies, which is what EJBCA does before trusting a key")
    void testKeyPair() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "signKey",
                "--key-spec", "2048"), stderr());
        out.reset();
        assertEquals(Main.OK, session("testkeypair", "--alias", "signKey"), stderr());
        assertTrue(stdout().contains("signed and verified with SHA256withRSA"), stdout());
    }

    @Test
    @DisplayName("a post-quantum key pair generates and appears under its alias")
    void postQuantumKeyPair() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "pqcKey",
                "--key-spec", "ML-DSA-65"), stderr());
        assertTrue(stdout().contains("Generated key pair with alias pqcKey"), stdout());
        out.reset();
        assertEquals(Main.OK, session("listkeypairs"), stderr());
        assertTrue(stdout().contains("pqcKey"), stdout());
        assertTrue(stdout().contains("ML-DSA-65"), stdout());
    }

    @Test
    @DisplayName("testkeypair picks the algorithm from the key, for a post-quantum alias too")
    void testKeyPairPostQuantum() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "pqcKey",
                "--key-spec", "ML-DSA-65"), stderr());
        out.reset();

        // The alias carries its algorithm, so nothing has to be passed on the command line; for a
        // post-quantum key the JCA name and the algorithm name are the same string.
        assertEquals(Main.OK, session("testkeypair", "--alias", "pqcKey"), stderr());
        assertTrue(stdout().contains("ML-DSA-65"), stdout());
    }

    @Test
    @DisplayName("testkeypair picks SHA256withECDSA for an EC alias")
    void testKeyPairEc() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "ecKey",
                "--key-spec", "secp256r1"), stderr());
        out.reset();

        assertEquals(Main.OK, session("testkeypair", "--alias", "ecKey"), stderr());
        assertTrue(stdout().contains("SHA256withECDSA"), stdout());
    }

    @Test
    @DisplayName("testkeypair refuses an ML-KEM alias as a question that does not apply")
    void testKeyPairRefusesKem() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "kemKey",
                "--key-spec", "ML-KEM-768"), stderr());
        out.reset();

        // Not "no such algorithm for this provider", which reads as a gap here. The key generated
        // perfectly well and simply has no signature to make.
        assertEquals(Main.FAILED, session("testkeypair", "--alias", "kemKey"));
        assertTrue(stderr().contains("key encapsulation, not signing"), stderr());
        assertTrue(stderr().contains("ML-KEM-768"), stderr());
    }

    @Test
    @DisplayName("--signature-algorithm overrides what the alias would have chosen")
    void testKeyPairExplicitAlgorithm() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "signKey",
                "--key-spec", "2048"), stderr());
        out.reset();

        // An operator whose token needs a different digest than the default has to be able to say
        // so, and the explicit value must win over the alias's own answer.
        assertEquals(Main.OK, session("testkeypair", "--alias", "signKey",
                "--signature-algorithm", "SHA512withRSA"), stderr());
        assertTrue(stdout().contains("SHA512withRSA"), stdout());
        assertFalse(stdout().contains("SHA256withRSA"), stdout());
    }

    @Test
    @DisplayName("listobjects shows the raw objects behind one alias")
    void listObjects() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "signKey",
                "--key-spec", "2048"), stderr());
        out.reset();
        assertEquals(Main.OK, session("listobjects"), stderr());
        assertTrue(stdout().contains("HANDLE"), stdout());
        assertTrue(stdout().contains("private_key"), stdout());
        assertTrue(stdout().contains("public_key"), stdout());
    }

    @Test
    @DisplayName("showobjectattributes reports the hygiene attributes by alias")
    void showObjectAttributes() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "signKey",
                "--key-spec", "2048"), stderr());
        out.reset();
        assertEquals(Main.OK, session("showobjectattributes", "--alias", "signKey"), stderr());
        assertTrue(stdout().contains("CKA_SENSITIVE"), stdout());
        assertTrue(stdout().contains("CKA_EXTRACTABLE"), stdout());
    }

    @Test
    @DisplayName("showobjectattributes needs a target")
    void showObjectAttributesWithoutTarget() {
        assertEquals(Main.USAGE, session("showobjectattributes"));
        assertTrue(stderr().contains("--object or --alias"), stderr());
    }

    @Test
    @DisplayName("showobjectattributes on an unknown alias says so")
    void showObjectAttributesUnknownAlias() {
        assertEquals(Main.FAILED, session("showobjectattributes", "--alias", "absent"));
        assertTrue(stderr().contains("No object on the token carries the label 'absent'"),
                stderr());
    }

    @Test
    @DisplayName("deleteobject by alias removes it from the alias list")
    void deleteByAlias() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "doomed",
                "--key-spec", "2048"), stderr());
        out.reset();
        assertEquals(Main.OK, session("deleteobject", "--alias", "doomed"), stderr());
        assertTrue(stdout().contains("Deleted alias doomed"), stdout());

        out.reset();
        assertEquals(Main.OK, session("listkeypairs"), stderr());
        assertFalse(stdout().contains("doomed"), stdout());
    }

    @Test
    @DisplayName("deleteobject refuses both --alias and --object at once")
    void deleteNeedsExactlyOneTarget() {
        assertEquals(Main.USAGE, session("deleteobject", "--alias", "a", "--object", "1"));
        assertTrue(stderr().contains("not both and not neither"), stderr());
        err.reset();
        assertEquals(Main.USAGE, session("deleteobject"));
    }

    @Test
    @DisplayName("generatekey makes a symmetric key the token can MAC with")
    void generateSecretKey() {
        assertEquals(Main.OK, session("generatekey", "--alias", "hmac",
                "--key-spec", "HmacSHA256"), stderr());
        assertTrue(stdout().contains("Generated HmacSHA256 key with alias hmac"), stdout());

        out.reset();
        assertEquals(Main.OK, session("listkeypairs"), stderr());
        assertTrue(stdout().contains("secret"), stdout());
    }

    @Test
    @DisplayName("testkeypair refuses a secret key and says what to use instead")
    void testKeyPairOnSecretKey() {
        assertEquals(Main.OK, session("generatekey", "--alias", "hmac",
                "--key-spec", "HmacSHA256"), stderr());
        assertEquals(Main.FAILED, session("testkeypair", "--alias", "hmac"));
        assertTrue(stderr().contains("signs through a Mac"), stderr());
    }

    @Test
    @DisplayName("an alias that does not exist fails without a stack trace")
    void testKeyPairOnMissingAlias() {
        assertEquals(Main.FAILED, session("testkeypair", "--alias", "absent"));
        assertTrue(stderr().contains("No key on the token under alias 'absent'"), stderr());
    }

    @Test
    @DisplayName("an unsupported key specification fails with the token's own reason")
    void unsupportedKeySpec() {
        int code = session("generatekeypair", "--alias", "nope", "--key-spec", "ML-DSA-1024");
        assertEquals(Main.FAILED, code);
        assertNotEquals("", stderr());
    }

    // ---- measurement ----

    @Test
    @DisplayName("signperformancetest reports a rate and verifies when asked")
    void signPerformanceTest() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "perfKey",
                "--key-spec", "2048"), stderr());
        out.reset();
        int code = session("signperformancetest", "--alias", "perfKey",
                "--time-limit", "150", "--verify");
        assertEquals(Main.OK, code, stderr());
        assertTrue(stdout().contains("Total number of signings:"), stdout());
        assertTrue(stdout().contains("Signings per second:"), stdout());
        assertTrue(stdout().contains("Every signature was verified."), stdout());
    }

    @Test
    @DisplayName("signperformancetest refuses a thread count below one")
    void signPerformanceTestBadThreads() {
        int code = session("signperformancetest", "--alias", "perfKey", "--threads", "0");
        assertEquals(Main.USAGE, code);
        assertTrue(stderr().contains("--threads must be at least 1"), stderr());
    }

    @Test
    @DisplayName("a non-numeric --threads is a usage error, not a crash")
    void signPerformanceTestNonNumericThreads() {
        int code = session("signperformancetest", "--alias", "perfKey", "--threads", "many");
        assertEquals(Main.USAGE, code);
        assertTrue(stderr().contains("whole number"), stderr());
    }

    // ---- credentials ----

    @Test
    @DisplayName("without --password the PIN is prompted for, once")
    void promptsForPin() {
        int code = Main.run(new String[] {"listkeypairs", "--lib-file", LIB, "--slot", "0"}, env);
        assertEquals(Main.OK, code, stderr());
        assertEquals(List.of("Enter slot login password: "), prompts);
    }

    @Test
    @DisplayName("a wrong PIN fails the command rather than the process")
    void wrongPin() {
        int code = Main.run(new String[] {"listkeypairs", "--lib-file", LIB, "--slot", "0",
                "--password", "wrong"}, env);
        assertEquals(Main.FAILED, code);
        assertNotEquals("", stderr());
    }

    @Test
    @DisplayName("a runaway cause message is truncated, not printed whole")
    void describeTruncatesLongCauses() {
        // JNA's "native library not found" message embeds the whole classpath, once per nesting
        // level. That is the message an operator sees for the commonest failure this tool reports —
        // a PKCS#11 module that will not load — and printing it whole buries the one line that
        // says which library and why.
        String huge = "Native library (x.so) not found in resource path (" + "j".repeat(4000) + ")";
        String described = Main.describe(new IllegalStateException(huge));
        assertTrue(described.startsWith("IllegalStateException: Native library (x.so) not found"),
                described);
        assertTrue(described.contains("characters in all"), described);
        assertTrue(described.length() < 500, "still " + described.length() + " characters");
    }

    @Test
    @DisplayName("the failure report carries the whole cause chain")
    void describeChainsCauses() {
        String described = Main.describe(
                new IllegalStateException("outer", new IllegalArgumentException("inner")));
        assertTrue(described.contains("outer"), described);
        assertTrue(described.contains("inner"), described);
        assertTrue(described.contains("caused by"), described);
    }
}

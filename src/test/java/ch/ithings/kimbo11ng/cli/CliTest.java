/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
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

    /**
     * The generation half only.
     *
     * <p>{@code testkeypair} is not run against a post-quantum alias here because
     * {@link FakeToken} returns a stub of the right length instead of a real ML-DSA signature, so a
     * verification would fail for reasons that have nothing to do with the CLI. That path is
     * covered against real firmware by {@code HsmConformanceIT}.
     */
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

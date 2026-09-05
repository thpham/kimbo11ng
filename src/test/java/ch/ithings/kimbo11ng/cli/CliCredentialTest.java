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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What the CLI does when the credential it was asked to use is absent.
 *
 * <p>The case that matters is an operator who hits Ctrl-D at the prompt: {@code
 * Console.readPassword} returns {@code null} at EOF, and an absent credential passed on to
 * {@code C_Login} arrives as an empty PIN. Most tokens score that as a failed authentication
 * attempt, and three or five of those lock the user PIN — so an aborted prompt must cost nothing.
 * The assertion carrying that is {@link FakeToken#loginCalls()}: it has to stay at zero.
 *
 * <p>Driven through {@link Main#run} for the same reason {@code CliTest} is: the defect lives in the
 * hand-off between the argument parser, the environment and the token, which a test of any one of
 * them in isolation cannot see.
 */
@DisplayName("command-line tool, absent credentials")
class CliCredentialTest {

    private static final String LIB = "/nonexistent/libfake.so";

    private FakeToken token;
    private ByteArrayOutputStream err;

    @BeforeEach
    void setUp() {
        token = new FakeToken();
        err = new ByteArrayOutputStream();
    }

    /** An environment whose prompt returns {@code pin}; {@code null} models an aborted prompt. */
    private CliEnv envWithPin(char[] pin) {
        PrintStream out = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        return new CliEnv(out, new PrintStream(err, true, StandardCharsets.UTF_8),
                prompt -> pin, new Pkcs11ModuleRegistry(path -> token));
    }

    private String stderr() {
        return err.toString(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("a cancelled PIN prompt spends no login attempt on the token")
    void abortedPromptNeverReachesTheToken() {
        int code = Main.run(new String[] {"listkeypairs", "--lib-file", LIB, "--slot", "0"},
                envWithPin(null));
        assertEquals(Main.FAILED, code, stderr());
        assertEquals(0, token.loginCalls(),
                "an aborted prompt must not be sent to the token as an empty PIN");
        assertTrue(stderr().contains("No PIN"), stderr());
    }

    @Test
    @DisplayName("an empty --password is refused rather than sent as a credential")
    void emptyPasswordNeverReachesTheToken() {
        int code = Main.run(new String[] {"listkeypairs", "--lib-file", LIB, "--slot", "0",
                "--password", ""}, envWithPin("1234".toCharArray()));
        assertEquals(Main.USAGE, code, stderr());
        assertEquals(0, token.loginCalls(),
                "an empty --password must not be sent to the token as a credential");
        assertTrue(stderr().contains("--password"), stderr());
    }

    @Test
    @DisplayName("a prompt that returns nothing at all is refused the same way")
    void emptyPromptNeverReachesTheToken() {
        int code = Main.run(new String[] {"listkeypairs", "--lib-file", LIB, "--slot", "0"},
                envWithPin(new char[0]));
        assertEquals(Main.FAILED, code, stderr());
        assertEquals(0, token.loginCalls(),
                "an empty prompt response must not be sent to the token as a credential");
        assertTrue(stderr().contains("No PIN"), stderr());
    }
}

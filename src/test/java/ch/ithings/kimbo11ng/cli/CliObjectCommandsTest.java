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
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.NativeProvider;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The object commands, held to reporting what actually happened on the token.
 *
 * <p>Every case here is one where the tool used to exit {@code 0} on a slot where nothing had been
 * done, or where the token had stopped answering. That is worse than a crash: an operator reading
 * "Deleted alias signKey1" stops looking for the key, and a nightly script that keys off the exit
 * code records a deletion the HSM never performed.
 *
 * <p>Driven through {@link Main#run} for the same reason {@code CliTest} is: the exit code is half
 * of what is being asserted, and a test that calls a command's body directly cannot see it.
 */
@DisplayName("object commands report what the token actually did")
class CliObjectCommandsTest {

    private static final String LIB = "/nonexistent/libfake.so";
    private static final String PIN = "1234";

    private FakeToken token;
    private ByteArrayOutputStream out;
    private ByteArrayOutputStream err;
    private CliEnv env;

    @BeforeEach
    void setUp() {
        token = new FakeToken();
        out = new ByteArrayOutputStream();
        err = new ByteArrayOutputStream();
        env = env(new Pkcs11ModuleRegistry(path -> token));
    }

    private CliEnv env(Pkcs11ModuleRegistry registry) {
        return new CliEnv(stream(out), stream(err), prompt -> PIN.toCharArray(), registry);
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

    private int session(String... command) {
        return session(env, command);
    }

    /** Runs a command with the library, slot and PIN every session-level command needs. */
    private static int session(CliEnv target, String... command) {
        List<String> argv = new ArrayList<>(List.of(command));
        argv.addAll(List.of("--lib-file", LIB, "--slot", "0", "--password", PIN));
        return Main.run(argv.toArray(new String[0]), target);
    }

    // ---- deleteobject --alias ----

    @Test
    @DisplayName("deleting an alias the keystore does not hold fails instead of claiming success")
    void deleteUnknownAliasFails() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "signKey",
                "--key-spec", "2048"), stderr());
        int before = token.handles().size();
        out.reset();

        // The typo an operator actually makes: the alias is signKey, not signKey1.
        assertEquals(Main.FAILED, session("deleteobject", "--alias", "signKey1"), stdout());
        assertFalse(stdout().contains("Deleted"), stdout());
        assertTrue(stderr().contains("signKey1"), stderr());
        assertTrue(stderr().contains("listkeypairs"), stderr());
        assertEquals(before, token.handles().size(), "nothing may be removed from the token");
    }

    @Test
    @DisplayName("deleting a key pair still succeeds and names what went with it")
    void deleteKeyPairReportsWhatWasRemoved() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "doomed",
                "--key-spec", "2048"), stderr());
        out.reset();

        assertEquals(Main.OK, session("deleteobject", "--alias", "doomed"), stderr());
        assertTrue(stdout().contains("Deleted alias doomed"), stdout());
        assertTrue(stdout().contains("public"), stdout());
        assertTrue(token.handles().isEmpty(), "the token still holds " + token.handles());
    }

    @Test
    @DisplayName("deleting a secret key says it was a secret key, not a key pair")
    void deleteSecretKeyReportsWhatWasRemoved() {
        assertEquals(Main.OK, session("generatekey", "--alias", "hmac",
                "--key-spec", "HmacSHA256"), stderr());
        out.reset();

        assertEquals(Main.OK, session("deleteobject", "--alias", "hmac"), stderr());
        assertTrue(stdout().contains("Deleted alias hmac"), stdout());
        assertTrue(stdout().contains("secret key"), stdout());
    }

    // ---- showobjectattributes ----

    @Test
    @DisplayName("a handle no object carries fails rather than printing an empty object")
    void unknownObjectHandleFails() {
        assertEquals(Main.OK, session("generatekeypair", "--alias", "signKey",
                "--key-spec", "2048"), stderr());
        out.reset();

        assertEquals(Main.FAILED, session("showobjectattributes", "--object", "999999"), stdout());
        assertFalse(stdout().contains("Object 999999"),
                "a mistyped handle must not print as a real object: " + stdout());
        assertTrue(stderr().contains("999999"), stderr());
        assertTrue(stderr().contains("listobjects"), stderr());
    }

    @Test
    @DisplayName("an attribute the object legitimately lacks stays quiet")
    void absentAttributeIsNotAFailure() {
        // A public key has no CKA_SENSITIVE and a token is entitled to omit CKA_ALWAYS_SENSITIVE
        // entirely; neither is a failure, and the rest of the object must still print.
        token.omitAttribute(CKA.ALWAYS_SENSITIVE);
        assertEquals(Main.OK, session("generatekeypair", "--alias", "signKey",
                "--key-spec", "2048"), stderr());
        out.reset();

        assertEquals(Main.OK, session("showobjectattributes", "--alias", "signKey"), stderr());
        assertTrue(stdout().contains("CKA_LABEL"), stdout());
        assertFalse(stdout().contains("CKA_ALWAYS_SENSITIVE"), stdout());
        assertEquals("", stderr());
    }

    // ---- a token that stops answering ----

    @Test
    @DisplayName("a session that dies mid-listing fails instead of reporting unlabelled objects")
    void deadSessionDuringListingFails() {
        FakeToken backing = new FakeToken();
        CliEnv proxied = env(new Pkcs11ModuleRegistry(path -> dropSessionOnEnumeration(backing)));

        assertEquals(Main.OK, session(proxied, "generatekeypair", "--alias", "signKey",
                "--key-spec", "2048"), stderr());
        out.reset();

        assertEquals(Main.FAILED, session(proxied, "listobjects"), stdout());
        // The old behaviour: a full table of "? - <blank> <blank>" rows and exit 0, which reads as
        // "the objects are there and carry no labels" — the opposite of what happened.
        assertFalse(stdout().contains("?"), stdout());
        assertTrue(stderr().contains("SESSION_HANDLE_INVALID"), stderr());
    }

    /**
     * {@code backing}, but every attribute read after an unfiltered search answers
     * {@code CKR_SESSION_HANDLE_INVALID}.
     *
     * <p>A network HSM drops the connection when it feels like it, which is untestable; the
     * unfiltered {@code C_FindObjectsInit} that only {@code listobjects} issues is the same event
     * made deterministic. Through a {@link Proxy} rather than a knob on {@link FakeToken} because
     * the trigger is specific to this one command.
     */
    private static NativeProvider dropSessionOnEnumeration(FakeToken backing) {
        boolean[] armed = {false};
        InvocationHandler handler = (unusedProxy, method, args) -> {
            if ("C_FindObjectsInit".equals(method.getName()) && (long) args[2] == 0L) {
                armed[0] = true;
            }
            if (armed[0] && "C_GetAttributeValue".equals(method.getName())) {
                return CKR.SESSION_HANDLE_INVALID;
            }
            try {
                return method.invoke(backing, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        };
        return (NativeProvider) Proxy.newProxyInstance(NativeProvider.class.getClassLoader(),
                new Class<?>[] {NativeProvider.class}, handler);
    }
}

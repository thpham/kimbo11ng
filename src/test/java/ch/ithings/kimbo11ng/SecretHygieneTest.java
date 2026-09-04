/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A source scan for the two ways an HSM credential leaks out of this code.
 *
 * <p>Neither is caught by any other gate. SpotBugs has no detector for "you turned a {@code char[]}
 * PIN into a String", and a test cannot observe a heap that no longer holds a reference. So this
 * asserts on the source, which is unusual but is the only place the property is visible.
 *
 * <p>Both patterns were present before phase 2: {@code new String(pin).getBytes(UTF_8)} in the
 * login path, and the token {@code Properties} — which carry {@code pin=} — reachable from log
 * statements. The first is now {@link ch.ithings.kimbo11ng.p11.Pins}; the second never happened,
 * and this keeps it that way.
 */
@DisplayName("secret hygiene")
class SecretHygieneTest {

    private static final Path SOURCE_ROOT = Path.of("src", "main", "java");

    /**
     * Constructing a String from a credential. An immutable String cannot be cleared and lives
     * until the collector happens to reclaim it, so every heap dump, core file and swap page taken
     * in between contains the PIN in plain text.
     */
    private static final Pattern STRINGIFIED_SECRET = Pattern.compile(
            "new\\s+String\\s*\\(\\s*(pin|authCode|password|authenticationCode)\\b"
                    + "|String\\.valueOf\\s*\\(\\s*(pin|authCode|password)\\b");

    /**
     * A log statement mentioning a credential or the whole property set. Token properties carry
     * {@code pin=} — that is how EJBCA stores it — so logging them wholesale publishes it.
     */
    private static final Pattern LOGGED_SECRET = Pattern.compile(
            "log\\.(trace|debug|info|warn|error|fatal)\\s*\\([^)]*\\b"
                    + "(pin|authCode|password|properties|getProperties)\\b");

    private record Finding(Path file, int line, String text) {
        @Override
        public String toString() {
            return file + ":" + line + "  " + text.trim();
        }
    }

    private List<Finding> scan(Pattern pattern) throws IOException {
        List<Finding> found = new ArrayList<>();
        try (Stream<Path> files = Files.walk(SOURCE_ROOT)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                List<String> lines = Files.readAllLines(file);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i);
                    if (isComment(line)) {
                        // Javadoc that names the bad pattern in order to explain what replaced it
                        // is the documentation working, not a leak.
                        continue;
                    }
                    if (pattern.matcher(line).find()) {
                        found.add(new Finding(file, i + 1, line));
                    }
                }
            }
        }
        return found;
    }

    private static boolean isComment(String line) {
        String trimmed = line.trim();
        return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*");
    }

    @Test
    @DisplayName("no credential is ever turned into a String")
    void noStringifiedCredential() throws IOException {
        List<Finding> found = scan(STRINGIFIED_SECRET);
        assertTrue(found.isEmpty(), () -> "A PIN must reach the token as bytes encoded from the "
                + "char[] and zeroed afterwards — see ch.ithings.kimbo11ng.p11.Pins. Found:\n"
                + String.join("\n", found.stream().map(Object::toString).toList()));
    }

    @Test
    @DisplayName("no log statement names a credential or the property set")
    void noLoggedCredential() throws IOException {
        List<Finding> found = scan(LOGGED_SECRET);
        assertTrue(found.isEmpty(), () -> "Token properties carry pin=; log the one value you "
                + "mean, never the set. Found:\n"
                + String.join("\n", found.stream().map(Object::toString).toList()));
    }

    @Test
    @DisplayName("the scan actually reads the sources it claims to")
    void scanIsNotVacuous() throws IOException {
        // Without this, a wrong SOURCE_ROOT or a changed working directory would turn both gates
        // above into assertions about an empty list, and they would pass forever.
        try (Stream<Path> files = Files.walk(SOURCE_ROOT)) {
            long count = files.filter(p -> p.toString().endsWith(".java")).count();
            assertTrue(count > 15, () -> "expected the main source tree, found " + count + " files");
        }
        assertTrue(scan(Pattern.compile("class\\s+CryptoTokenImpl")).stream()
                        .anyMatch(f -> f.text().toLowerCase(Locale.ROOT).contains("class")),
                "the scanner must be able to match something that is really there");
    }
}

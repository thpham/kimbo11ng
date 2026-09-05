/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Deployment gate on the shipped artifact.
 *
 * <p>The JAR is copied into {@code ejbca.ear/lib/}, the same classloader that already holds
 * EJBCA's own BouncyCastle. A second copy there yields two {@code BouncyCastleProvider} classes
 * with distinct identities, and EJBCA's {@code AlgorithmTools} decides what a key can sign with
 * {@code instanceof MLDSAKey} / {@code SLHDSAKey} — checks that silently fail across a
 * classloader split, reporting "no valid signing algorithm" for a perfectly good PQC key.
 *
 * <p>Runs in the default build rather than only under {@code -Pit}, because it needs no Docker
 * and guards every packaging change.
 */
@DisplayName("shipped artifact")
class ArtifactContentsIT {

    private static Path artifact;
    private static Path basedir;
    private static List<String> entries;

    @BeforeAll
    static void locateAndReadArtifact() throws IOException {
        Path target = Paths.get(System.getProperty("kimbo11ng.targetDir", "target"));
        basedir = target.toAbsolutePath().getParent();
        try (DirectoryStream<Path> jars =
                Files.newDirectoryStream(target, "*-jar-with-dependencies.jar")) {
            for (Path jar : jars) {
                artifact = jar;
                break;
            }
        }
        if (artifact == null) {
            fail("No *-jar-with-dependencies.jar in " + target.toAbsolutePath()
                    + " - this test must run after the package phase.");
        }
        List<String> names = new ArrayList<>();
        try (JarFile jarFile = new JarFile(artifact.toFile())) {
            for (Enumeration<JarEntry> e = jarFile.entries(); e.hasMoreElements(); ) {
                names.add(e.nextElement().getName());
            }
        }
        entries = Collections.unmodifiableList(names);
    }

    /** The only package roots this project owns. Everything else belongs to the container. */
    private static final List<String> OWN_PACKAGES = List.of(
            "ch/ithings/kimbo11ng/",
            "org/cesecore/keys/token/p11ng/cryptotoken/",
            "com/keyfactor/util/keys/token/pkcs11/");

    @Test
    @DisplayName("bundles no second copy of BouncyCastle")
    void noBouncyCastle() {
        List<String> bc = entries.stream()
                .filter(n -> n.startsWith("org/bouncycastle/")
                        || (n.startsWith("META-INF/versions/") && n.contains("/org/bouncycastle/")))
                .toList();
        assertTrue(bc.isEmpty(),
                () -> "Artifact " + artifact.getFileName() + " bundles " + bc.size()
                        + " BouncyCastle entries; bcprov must stay 'provided'. First few: "
                        + bc.subList(0, Math.min(5, bc.size())));
    }

    @Test
    @DisplayName("ships our own classes and nothing else")
    void shipsOnlyOwnClasses() {
        // Broader than the BouncyCastle check on purpose: every dependency that also lives in
        // ejbca.ear/lib (jacknji11, JNA, commons-logging, cesecore, cryptotokens) must stay
        // 'provided'. JNA is the sharpest case - a duplicate copy fails at runtime with
        // "native library already loaded in another classloader".
        List<String> foreign = entries.stream()
                .filter(n -> n.endsWith(".class"))
                .filter(n -> OWN_PACKAGES.stream().noneMatch(n::startsWith))
                .toList();
        assertTrue(foreign.isEmpty(),
                () -> "Artifact " + artifact.getFileName() + " bundles " + foreign.size()
                        + " classes outside " + OWN_PACKAGES + ". First few: "
                        + foreign.subList(0, Math.min(5, foreign.size())));
    }

    @Test
    @DisplayName("registers no foreign JCA provider")
    void noForeignProviderService() {
        assertFalse(entries.contains("META-INF/services/java.security.Provider"),
                "Artifact ships META-INF/services/java.security.Provider - a dependency's JCA "
                        + "provider registration leaked into the uber-JAR and would be picked up "
                        + "alongside EJBCA's own.");
    }

    @Test
    @DisplayName("still registers the slot-list factory EJBCA discovers by ServiceLoader")
    void keepsOwnServiceRegistration() {
        // Positive control: proves the assertions above are not passing because the JAR is empty.
        assertTrue(entries.contains(
                        "META-INF/services/com.keyfactor.util.keys.token.pkcs11.PKCS11SlotListWrapperFactory"),
                "The PKCS11SlotListWrapperFactory service file is missing; EJBCA's Pkcs11SlotLabel "
                        + "would fall back to SunP11SlotListWrapperFactory.");
        assertNotNull(artifact);
    }

    /** The line in the launcher that names the jar it expects the build to have left in target/. */
    private static final Pattern LAUNCHER_GLOB =
            Pattern.compile("^\\s*for candidate in \"\\$repo\"/target/(\\S+); do\\s*$",
                    Pattern.MULTILINE);

    @Test
    @DisplayName("carries the name cli/kimbo11ng-cli.sh expects in a build tree")
    void launcherFindsTheBuiltArtifact() throws IOException {
        // With no EJBCA install to borrow a classpath from, the launcher builds one out of target/.
        // It used to look there for a "kimbo11ng.jar" the build has never written - the name was
        // spelled once in the pom's finalName, once in the justfile's `artifact`, and a third time,
        // wrongly, in the script - so that branch was dead and `just cli` never ran outside a
        // container. The script now matches the suffix the jar-with-dependencies descriptor
        // appends; this asserts that what it matches on is still what the build produces, since
        // nothing else in the build would notice if the two drifted apart again.
        Path launcher = basedir.resolve("cli").resolve("kimbo11ng-cli.sh");
        assertTrue(Files.isRegularFile(launcher), () -> "Missing launcher " + launcher);
        String script = new String(Files.readAllBytes(launcher), StandardCharsets.UTF_8);
        Matcher m = LAUNCHER_GLOB.matcher(script);
        assertTrue(m.find(),
                () -> launcher + " no longer selects the build-tree jar with a `for candidate in "
                        + "\"$repo\"/target/<glob>; do` loop, so this guard cannot see which name "
                        + "it expects. Restore the loop or re-point this test at whatever replaced "
                        + "it - do not delete the guard.");
        String glob = m.group(1);
        assertTrue(FileSystems.getDefault().getPathMatcher("glob:" + glob)
                        .matches(artifact.getFileName()),
                () -> "The launcher looks for target/" + glob + " but the build produced "
                        + artifact.getFileName() + ". Outside a container that mismatch leaves the "
                        + "CLI with no classpath at all. Fix the glob in " + launcher + ".");
    }
}

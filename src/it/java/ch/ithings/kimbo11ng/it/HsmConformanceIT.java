/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.it;

import ch.ithings.kimbo11ng.p11.HsmContract;
import ch.ithings.kimbo11ng.p11.NativeProviderFactory;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The HSM contract against a real PKCS#11 library — the day-one script for hardware.
 *
 * <pre>
 * mvn verify -Pit \
 *   -Dkimbo11ng.it.lib=/usr/safenet/lunaclient/lib/libCryptoki2_64.so \
 *   -Dkimbo11ng.it.slot=0 \
 *   -Dkimbo11ng.it.pin=userpin
 * </pre>
 *
 * <p>Without {@code kimbo11ng.it.lib} the whole class is skipped, so it costs a normal run nothing.
 * The same assertions run on every build against the in-memory fake as
 * {@code HsmContractFakeTest}; what this adds is the token, and therefore the answer to every
 * question the fake can only assume: whether the mechanism list is what the profile expects,
 * whether {@code CKA_ID} survives, whether a post-quantum signature made on the HSM verifies with
 * BouncyCastle, and whether the pool's idea of session lifetime matches the firmware's.
 *
 * <p>The PIN is read from a system property, so it lands in the shell history and the process list
 * of whoever runs it. Use a test partition.
 */
@Tag("hsm")
@DisplayName("HSM conformance: real library")
@EnabledIfSystemProperty(named = "kimbo11ng.it.lib", matches = ".+",
        disabledReason = "set -Dkimbo11ng.it.lib to point this at a PKCS#11 library")
class HsmConformanceIT extends HsmContract {

    private static final String LIB = System.getProperty("kimbo11ng.it.lib", "");
    private static final String SLOT = System.getProperty("kimbo11ng.it.slot", "0");
    private static final String PIN = System.getProperty("kimbo11ng.it.pin", "");

    /**
     * Private to this run: the shared registry is process-wide, and a library initialized by an
     * earlier test would make "C_Initialize ran once" untestable.
     */
    private final Pkcs11ModuleRegistry registry =
            new Pkcs11ModuleRegistry(NativeProviderFactory.jna());

    @Override
    protected Pkcs11ModuleRegistry registry() {
        assertTrue(Files.isReadable(Path.of(LIB)),
                () -> "kimbo11ng.it.lib is '" + LIB + "', which is not a readable file");
        return registry;
    }

    @Override
    protected String libPath() {
        return LIB;
    }

    @Override
    protected long slotIndex() {
        return Long.parseLong(SLOT);
    }

    @Override
    protected char[] pin() {
        return PIN.toCharArray();
    }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import ch.ithings.kimbo11ng.fake.FakeToken;
import org.junit.jupiter.api.DisplayName;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * The HSM contract run against the in-memory fake.
 *
 * <p>This proves nothing about any hardware — that is what {@code HsmConformanceIT} is for. What it
 * does is keep the suite honest between hardware sessions: a contract that only ever ran when
 * someone had a Luna in front of them would stop compiling, then stop passing, and nobody would
 * find out until the day it mattered.
 */
@DisplayName("HSM contract: in-memory fake")
class HsmContractFakeTest extends HsmContract {

    /** Distinct per instance so the registry key is never shared with another test. */
    private static final AtomicInteger PATHS = new AtomicInteger();

    private final String libPath = "/nonexistent/libcontract-" + PATHS.incrementAndGet() + ".so";
    private final FakeToken token = new FakeToken();
    private final Pkcs11ModuleRegistry registry = new Pkcs11ModuleRegistry(path -> token);

    @Override
    protected Pkcs11ModuleRegistry registry() {
        return registry;
    }

    @Override
    protected String libPath() {
        return libPath;
    }

    @Override
    protected long slotIndex() {
        return 0L;
    }

    @Override
    protected char[] pin() {
        return "1234".toCharArray();
    }

    @Override
    protected boolean verifiesSignaturesFor(String jcaName) {
        // The fake signs RSA and EC for real, through BouncyCastle, so those are verified here.
        // Post-quantum signatures are synthetic — the fake has no ML-DSA implementation, and a
        // wrong-length blob would be a worse lie than an obviously fake one — so only the hardware
        // run can check those.
        return !jcaName.startsWith("ML-") && !jcaName.startsWith("SLH-");
    }
}

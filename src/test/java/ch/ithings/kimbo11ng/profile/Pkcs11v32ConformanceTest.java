/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import org.junit.jupiter.api.DisplayName;

/** The standard profile against the conformance kit — the reference every vendor is held to. */
@DisplayName("conformance: pkcs11v32")
class Pkcs11v32ConformanceTest extends ProfileConformanceKit {

    private final Pkcs11v32Profile profile = new Pkcs11v32Profile();

    @Override
    protected PqcMechanismProfile profile() {
        return profile;
    }
}

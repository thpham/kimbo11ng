/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import org.junit.jupiter.api.DisplayName;

/**
 * The Luna profile against the conformance kit.
 *
 * <p>It is a table of six rows and no logic, so what this really proves is that a profile
 * describing a subset of the algorithms — Luna 7.9.x has no SLH-DSA — is a first-class thing rather
 * than a degraded one: it generates, enumerates and signs on a token that answers only those six.
 */
@DisplayName("conformance: thales-luna")
class ThalesLunaConformanceTest extends ProfileConformanceKit {

    private final ThalesLunaProfile profile = new ThalesLunaProfile();

    @Override
    protected PqcMechanismProfile profile() {
        return profile;
    }
}

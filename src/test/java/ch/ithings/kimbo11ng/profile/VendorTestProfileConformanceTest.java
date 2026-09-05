/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import ch.ithings.kimbo11ng.fake.VendorTestProfile;
import org.junit.jupiter.api.DisplayName;

/**
 * A profile that agrees with the standard on nothing but the FIPS constants, against the same kit.
 *
 * <p>This is the acceptance criterion for the whole vendor-profile design: {@code VendorTestProfile}
 * uses vendor-defined key types and mechanisms above {@code 0x80000000}, shifts its generation and
 * signing mechanisms independently, and distinguishes parameter sets by mechanism rather than by a
 * shared attribute. If it passes the kit unmodified, then adding a real vendor is a table.
 */
@DisplayName("conformance: vendor-test")
class VendorTestProfileConformanceTest extends ProfileConformanceKit {

    private final VendorTestProfile profile = new VendorTestProfile();

    @Override
    protected PqcMechanismProfile profile() {
        return profile;
    }
}

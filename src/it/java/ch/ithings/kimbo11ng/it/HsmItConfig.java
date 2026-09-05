/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.it;

/**
 * The system properties that point the hardware tests at a real HSM.
 *
 * <p>One place, because two integration tests read them and a name that drifted between the two
 * would show up as "skipped" rather than as an error — the most expensive kind of silence when
 * hardware time is the scarce resource.
 *
 * <p>None of these have a useful default. Absent {@link #LIB}, every test that reads them is
 * disabled, which is what keeps an ordinary {@code mvn verify -Pit} free of hardware assumptions.
 */
final class HsmItConfig {

    /** Absolute path to the vendor's PKCS#11 library. Its absence disables the hardware tests. */
    static final String LIB = "kimbo11ng.it.lib";

    /** Slot to use, read according to {@link #SLOT_TYPE}. */
    static final String SLOT = "kimbo11ng.it.slot";

    /** {@code SLOT_INDEX} (default), {@code SLOT_LABEL}, {@code SLOT_NUMBER} or {@code SUN_FILE}. */
    static final String SLOT_TYPE = "kimbo11ng.it.slotType";

    /**
     * The partition PIN.
     *
     * <p>A system property lands in the shell history and in the process list of whoever runs the
     * build. Use a test partition, and rotate the PIN if the machine is shared.
     */
    static final String PIN = "kimbo11ng.it.pin";

    /**
     * Path to Thales's {@code LunaProvider.jar}, which enables the JSP cross-check.
     *
     * <p>Optional and separate from {@link #LIB} on purpose: the contract suite is vendor-neutral
     * and must run against any HSM, while the cross-check only means something on a Luna.
     */
    static final String LUNA_JSP = "kimbo11ng.it.luna.jsp";

    /** The Luna partition name, when it differs from {@link #SLOT}. */
    static final String LUNA_PARTITION = "kimbo11ng.it.luna.partition";

    private HsmItConfig() {
    }

    static String get(String property, String fallback) {
        String value = System.getProperty(property);
        return (value == null || value.isBlank()) ? fallback : value;
    }
}

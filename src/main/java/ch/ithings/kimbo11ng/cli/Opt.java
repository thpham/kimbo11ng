/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import java.util.List;

/**
 * One declared command-line option.
 *
 * <p>Declaring options rather than reading them ad hoc buys two things: {@code --help} is generated
 * from the same list the parser validates against, so they cannot drift; and an unknown option is
 * refused by name instead of being silently ignored, which on a tool that takes a PIN and a slot
 * matters — a mistyped {@code --slot-ref} that is quietly dropped would operate on the wrong slot.
 *
 * @param name    long-option name without the leading dashes
 * @param argName placeholder shown in help, or {@code null} for a flag that takes no value
 * @param help    one-line description
 * @param repeatable whether the option may be given more than once
 */
record Opt(String name, String argName, String help, boolean repeatable) {

    static Opt arg(String name, String argName, String help) {
        return new Opt(name, argName, help, false);
    }

    static Opt repeatable(String name, String argName, String help) {
        return new Opt(name, argName, help, true);
    }

    static Opt flag(String name, String help) {
        return new Opt(name, null, help, false);
    }

    boolean takesValue() {
        return argName != null;
    }

    /** The options every command that opens a slot accepts. */
    static List<Opt> slot() {
        return List.of(
                arg("lib-file", "<path>", "PKCS#11 shared library. Required."),
                arg("slot-ref", "<type>", "How --slot is interpreted: SLOT_NUMBER, SLOT_INDEX or "
                        + "SLOT_LABEL. Default SLOT_INDEX, which is what the crypto token defaults "
                        + "to."),
                arg("slot", "<value>", "The slot, read according to --slot-ref. Default 0."),
                repeatable("property", "<key=value>", "A crypto token property, repeatable. This is "
                        + "how kimbo11ng.pqc.profile and kimbo11ng.probe.failFast are set."));
    }

    /** The options a command that logs in accepts, on top of {@link #slot()}. */
    static List<Opt> login() {
        return List.of(
                arg("password", "<pin>", "Slot PIN. Prompted for when omitted, which is the only "
                        + "form that keeps it out of the process list and the shell history."));
    }
}

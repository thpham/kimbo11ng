/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */

import java.util.Arrays;

/**
 * Loads and initialises classes with the JVM's bytecode verifier forced on, and fails unless each
 * one came from the jar it was meant to.
 *
 * <p>StartupCheckPatcher proves the rewritten method is a bare {@code return}. That says nothing
 * about whether the class around it still verifies and links against the classes EJBCA ships, which
 * only the JVM can answer. Run with {@code -Xverify:all}, and with the artefact under test first on
 * the class path, so that a copy of the same class further along cannot answer instead.
 *
 * <p>Usage: {@code java -Xverify:all -cp <jar under test first>:... LinkCheck.java <expected-jar>
 * <class>...}
 */
public final class LinkCheck {

    private LinkCheck() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: LinkCheck <expected-jar> <class>...");
            System.exit(2);
        }
        String expected = args[0];
        for (String name : Arrays.copyOfRange(args, 1, args.length)) {
            Class<?> type = Class.forName(name, true, LinkCheck.class.getClassLoader());
            String origin = type.getProtectionDomain().getCodeSource().getLocation().getPath();
            if (!origin.endsWith(expected)) {
                System.err.println("LinkCheck: " + name + " was loaded from " + origin
                        + ", not from " + expected + ", so the check did not test what it should");
                System.exit(1);
            }
            System.out.println("   links and verifies: " + name);
        }
    }
}

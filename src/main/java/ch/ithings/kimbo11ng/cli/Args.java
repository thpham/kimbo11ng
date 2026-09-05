/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * A parsed command line, validated against the command's declared {@link Opt}s.
 *
 * <p>Only GNU long options are accepted — {@code --name value} and {@code --flag} — which is the
 * grammar EJBCA's own {@code p11ng-cli} uses. Matching it is not imitation for its own sake: an
 * operator moving between the two tools has the option names in their fingers, and every published
 * Keyfactor integration guide is written in that grammar.
 *
 * <p>Hand-rolled rather than delegating to a parser library, because this jar is dropped into
 * {@code ejbca.ear/lib} where every extra class is a candidate for a classloader conflict. The
 * grammar is small enough that the trade is not close.
 */
final class Args {

    private final Map<String, List<String>> values;

    private Args(Map<String, List<String>> values) {
        this.values = values;
    }

    /**
     * Parses {@code argv} from {@code from}, accepting only the options {@code command} declares.
     *
     * @throws CliException on an unknown option, a missing value, or a repeat of an option that is
     *                      not marked repeatable
     */
    static Args parse(String[] argv, int from, Command command) throws CliException {
        Map<String, Opt> declared = new LinkedHashMap<>();
        for (Opt opt : command.options()) {
            declared.put(opt.name(), opt);
        }
        Map<String, List<String>> parsed = new LinkedHashMap<>();
        for (int i = from; i < argv.length; i++) {
            String token = argv[i];
            if (!token.startsWith("--")) {
                throw CliException.usage("Unexpected argument '" + token
                        + "'. Every argument is a --long-option.");
            }
            String name = token.substring(2);
            String inlineValue = null;
            int equals = name.indexOf('=');
            if (equals >= 0) {
                inlineValue = name.substring(equals + 1);
                name = name.substring(0, equals);
            }
            if ("help".equals(name)) {
                parsed.computeIfAbsent("help", n -> new ArrayList<>()).add("true");
                continue;
            }
            Opt opt = declared.get(name);
            if (opt == null) {
                throw CliException.usage("Unknown option '--" + name + "' for command '"
                        + command.name() + "'. Run '" + command.name() + " --help'.");
            }
            String value;
            if (!opt.takesValue()) {
                if (inlineValue != null) {
                    throw CliException.usage("--" + name + " is a flag and takes no value.");
                }
                value = "true";
            } else if (inlineValue != null) {
                value = inlineValue;
            } else if (i + 1 < argv.length) {
                value = argv[++i];
            } else {
                throw CliException.usage("--" + name + " requires a value ("
                        + opt.argName() + ").");
            }
            List<String> existing = parsed.computeIfAbsent(name, n -> new ArrayList<>());
            if (!existing.isEmpty() && !opt.repeatable()) {
                throw CliException.usage("--" + name + " was given more than once.");
            }
            existing.add(value);
        }
        return new Args(parsed);
    }

    boolean has(String name) {
        return values.containsKey(name);
    }

    /** True when {@code --help} appeared anywhere on the line. */
    boolean wantsHelp() {
        return has("help");
    }

    String get(String name, String fallback) {
        List<String> found = values.get(name);
        return found == null || found.isEmpty() ? fallback : found.get(found.size() - 1);
    }

    String require(String name) throws CliException {
        String value = get(name, null);
        if (value == null || value.isEmpty()) {
            throw CliException.usage("--" + name + " is required.");
        }
        return value;
    }

    List<String> all(String name) {
        return List.copyOf(values.getOrDefault(name, List.of()));
    }

    int getInt(String name, int fallback) throws CliException {
        String value = get(name, null);
        if (value == null) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw CliException.usage("--" + name + " must be a whole number, got '" + value + "'.");
        }
    }

    long requireLong(String name) throws CliException {
        String value = require(name);
        try {
            // Decode, not parseLong: an object handle is as likely to be pasted back as 0x… from
            // another tool's output as it is to be typed in decimal.
            return Long.decode(value.trim());
        } catch (NumberFormatException e) {
            throw CliException.usage("--" + name + " must be a number, got '" + value + "'.");
        }
    }

    /**
     * The crypto token properties this command line describes.
     *
     * <p>Everything the token reads comes from here, so a CLI invocation and an EJBCA crypto token
     * configuration are the same object seen twice. That is the property that makes the tool worth
     * having: what it reports is what EJBCA will do, not an approximation of it.
     */
    Properties tokenProperties(String libFile) throws CliException {
        Properties properties = new Properties();
        properties.setProperty("sharedLibrary", libFile);
        properties.setProperty("slotLabelType", slotRef());
        properties.setProperty("slotLabelValue", get("slot", "0"));
        // Registering the provider in java.security is EJBCA's job inside the container; here there
        // is no container and nothing looks providers up by name, so it is left out.
        properties.setProperty("doNotAddP11Provider", "true");
        for (String property : all("property")) {
            int equals = property.indexOf('=');
            if (equals <= 0) {
                throw CliException.usage("--property expects key=value, got '" + property + "'.");
            }
            properties.setProperty(property.substring(0, equals).trim(),
                    property.substring(equals + 1).trim());
        }
        return properties;
    }

    /**
     * The slot reference type, defaulting to {@code SLOT_INDEX}.
     *
     * <p>Keyfactor's tool leaves its default undocumented — its {@code signperformancetest}
     * examples pass {@code --slot} with no {@code --slot-ref} at all. Rather than guess at theirs,
     * this defaults to what {@code CryptoTokenImpl} defaults to, so an invocation with the options
     * omitted addresses the same slot the crypto token would.
     */
    private String slotRef() throws CliException {
        String ref = get("slot-ref", "SLOT_INDEX").trim().toUpperCase(Locale.ROOT);
        switch (ref) {
            case "SLOT_NUMBER":
            case "SLOT_INDEX":
            case "SLOT_LABEL":
                return ref;
            default:
                throw CliException.usage("--slot-ref must be SLOT_NUMBER, SLOT_INDEX or SLOT_LABEL,"
                        + " got '" + ref + "'.");
        }
    }
}

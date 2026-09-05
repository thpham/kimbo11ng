/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import java.util.ArrayList;
import java.util.List;

/**
 * One CLI verb: its name, its one-line summary, the options it accepts, and what it does.
 *
 * <p>Commands are values rather than classes so a group of related verbs can live in one file
 * without a class-per-verb ceremony, and so {@link Main} can build its dispatch table and its help
 * from the same list.
 */
final class Command {

    /** What a command does, once its arguments have been parsed and validated. */
    @FunctionalInterface
    interface Action {
        void run(CliEnv env, Args args) throws Exception;
    }

    private final String name;
    private final String summary;
    private final List<Opt> options;
    private final Action action;

    private Command(String name, String summary, List<Opt> options, Action action) {
        this.name = name;
        this.summary = summary;
        this.options = List.copyOf(options);
        this.action = action;
    }

    static Command of(String name, String summary, List<Opt> options, Action action) {
        return new Command(name, summary, options, action);
    }

    /** A command that opens a slot but does not log in. */
    static Command slotLevel(String name, String summary, List<Opt> extra, Action action) {
        return new Command(name, summary, concat(Opt.slot(), extra), action);
    }

    /** A command that opens a slot and logs in. */
    static Command sessionLevel(String name, String summary, List<Opt> extra, Action action) {
        return new Command(name, summary, concat(concat(Opt.slot(), Opt.login()), extra), action);
    }

    private static List<Opt> concat(List<Opt> first, List<Opt> second) {
        List<Opt> all = new ArrayList<>(first);
        all.addAll(second);
        return all;
    }

    String name() {
        return name;
    }

    String summary() {
        return summary;
    }

    List<Opt> options() {
        return options;
    }

    void run(CliEnv env, Args args) throws Exception {
        action.run(env, args);
    }

    /** Prints this command's own usage block. */
    void printHelp(CliEnv env) {
        env.out().println("Usage: kimbo11ng-cli " + name() + " [options]");
        env.out().println();
        env.out().println("  " + summary());
        env.out().println();
        int width = 0;
        for (Opt opt : options) {
            width = Math.max(width, label(opt).length());
        }
        for (Opt opt : options) {
            env.out().println("  " + pad(label(opt), width) + "  " + opt.help());
        }
        env.out().println("  " + pad("--help", width) + "  Prints this text.");
    }

    private static String label(Opt opt) {
        return "--" + opt.name() + (opt.takesValue() ? " " + opt.argName() : "");
    }

    private static String pad(String text, int width) {
        return text.length() >= width ? text : text + " ".repeat(width - text.length());
    }
}

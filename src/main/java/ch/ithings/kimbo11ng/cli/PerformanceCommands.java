/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Signing throughput, measured against the real token through the real provider.
 *
 * <p>Keyfactor's tool has this command and so does this one, but the reason to want it here is
 * different. For RSA and ECDSA the figure is well known and every vendor publishes it. For SLH-DSA
 * it is not published by anyone, it is orders of magnitude smaller, and it is the number that
 * decides whether a given HSM can serve a CA at a given issuance rate. Measuring it is the point;
 * matching upstream's option names is only so the command reads the same.
 *
 * <p>The measurement goes through {@code Signature.getInstance(alg, provider)} rather than straight
 * to {@code C_Sign}, because the session pool, the handle cache and the DER wrapping are all part of
 * what a CA pays per signature. A number that excluded them would be a number about the HSM rather
 * than about this deployment.
 */
final class PerformanceCommands {

    private PerformanceCommands() {
    }

    static List<Command> all() {
        return List.of(signPerformanceTest());
    }

    private static Command signPerformanceTest() {
        return Command.sessionLevel("signperformancetest",
                "Signs in a loop with one key and reports throughput.",
                List.of(Opt.arg("alias", "<name>", "Alias to sign with. Required."),
                        Opt.arg("signature-algorithm", "<alg>",
                                "Signature algorithm. Defaults to one derived from the key."),
                        Opt.arg("time-limit", "<ms>",
                                "How long to measure, in milliseconds. Default 10000."),
                        Opt.arg("warmup-time", "<ms>",
                                "Signings before this point are not counted. Default 0."),
                        Opt.arg("threads", "<n>", "Concurrent signing threads. Default 1."),
                        Opt.flag("verify",
                                "Verify every signature. Costs throughput; catches a key pair whose "
                                        + "halves do not match.")),
                (env, args) -> {
                    String alias = args.require("alias");
                    long timeLimit = args.getInt("time-limit", 10_000);
                    long warmup = args.getInt("warmup-time", 0);
                    int threads = args.getInt("threads", 1);
                    if (threads < 1) {
                        throw CliException.usage("--threads must be at least 1.");
                    }
                    if (timeLimit < 1) {
                        throw CliException.usage("--time-limit must be a positive number of"
                                + " milliseconds.");
                    }
                    boolean verify = args.has("verify");
                    try (TokenHandle handle = TokenHandle.session(env, args)) {
                        PrivateKey privateKey = KeyCommands.privateKey(handle, alias);
                        String algorithm = KeyCommands.signatureAlgorithm(handle.token(), alias,
                                args.get("signature-algorithm", null));
                        PublicKey publicKey = verify
                                ? handle.token().readPublicKey(alias, true) : null;
                        if (verify && publicKey == null) {
                            throw new CliException("--verify needs the public key, and alias '"
                                    + alias + "' has none readable on the token.");
                        }
                        run(env, handle, algorithm, privateKey, publicKey, threads, warmup,
                                timeLimit);
                    }
                });
    }

    private static void run(CliEnv env, TokenHandle handle, String algorithm, PrivateKey privateKey,
            PublicKey publicKey, int threads, long warmupMillis, long timeLimitMillis)
            throws Exception {
        PrintStream out = env.out();
        out.println("Running signing test with " + threads + " thread"
                + (threads == 1 ? "" : "s") + " using signature algorithm " + algorithm + ".");
        if (warmupMillis > 0) {
            out.println("Warming up for " + warmupMillis + " ms; those signings are not counted.");
        }
        out.println("Signing through provider " + handle.token().getProvider().getName() + ".");

        byte[] message = "kimbo11ng performance test".getBytes(StandardCharsets.UTF_8);
        Provider provider = handle.token().getProvider();
        AtomicBoolean stop = new AtomicBoolean();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Result> results = new ArrayList<>();
        try {
            long warmupUntil = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(warmupMillis);
            long stopAt = warmupUntil + TimeUnit.MILLISECONDS.toNanos(timeLimitMillis);
            List<Future<Result>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                int threadNumber = i;
                futures.add(pool.submit(() -> signUntil(threadNumber, provider, algorithm,
                        privateKey, publicKey, message, warmupUntil, stopAt, stop)));
            }
            for (Future<Result> future : futures) {
                results.add(future.get());
            }
        } finally {
            stop.set(true);
            pool.shutdownNow();
        }

        long total = 0;
        long totalNanos = 0;
        for (Result result : results) {
            out.println("Number of operations for thread " + result.thread() + ": "
                    + result.operations());
            total += result.operations();
            totalNanos += result.nanos();
        }
        out.println("Total number of signings: " + total);
        double seconds = timeLimitMillis / 1000.0;
        out.println("Signings per second: " + (total / seconds));
        if (total > 0) {
            // Per-signature latency, which for SLH-DSA is the figure that actually constrains a CA:
            // throughput can be bought with threads, a single issuance cannot.
            out.println("Average time per signing: "
                    + String.format("%.3f", totalNanos / (double) total / 1_000_000.0) + " ms");
        }
        if (publicKey != null) {
            out.println("Every signature was verified.");
        }
    }

    private record Result(int thread, long operations, long nanos) {
    }

    private static Result signUntil(int thread, Provider provider, String algorithm,
            PrivateKey privateKey, PublicKey publicKey, byte[] message, long warmupUntil,
            long stopAt, AtomicBoolean stop) throws Exception {
        // One Signature object per thread, reused across iterations: calling getInstance every time
        // would put provider lookup into a measurement that is supposed to be about the HSM.
        Signature signer = Signature.getInstance(algorithm, provider);
        // Verification never goes to the token — see KeyCommands.verifier.
        Signature verifier = publicKey == null ? null : KeyCommands.verifier(algorithm);
        long operations = 0;
        long nanos = 0;
        while (!stop.get() && System.nanoTime() < stopAt) {
            long started = System.nanoTime();
            signer.initSign(privateKey);
            signer.update(message);
            byte[] signature = signer.sign();
            long elapsed = System.nanoTime() - started;
            if (verifier != null) {
                verifier.initVerify(publicKey);
                verifier.update(message);
                if (!verifier.verify(signature)) {
                    throw new IllegalStateException("A signature made on the token did not verify."
                            + " The key pair's halves do not match.");
                }
            }
            if (System.nanoTime() >= warmupUntil) {
                operations++;
                nanos += elapsed;
            }
        }
        return new Result(thread, operations, nanos);
    }
}

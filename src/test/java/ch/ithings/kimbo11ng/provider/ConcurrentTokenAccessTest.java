/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import ch.ithings.kimbo11ng.p11.Pkcs11Errors;
import ch.ithings.kimbo11ng.p11.SessionPoolConfig;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.Pkcs11v32Profile;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.LongRef;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.Signature;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The reason the session pool exists.
 *
 * <p>A PKCS#11 session holds operation state, so two threads sharing one cannot both be mid-
 * operation: the second {@code C_SignInit} or {@code C_FindObjectsInit} answers
 * {@code CKR_OPERATION_ACTIVE}. The old design shared a single session across the whole JVM and
 * papered over it with {@code synchronized (device)}, which made every signature in the process
 * queue behind every other one — a CA under load spending its time waiting on a lock rather than
 * on the HSM.
 *
 * <p>{@link FakeToken} enforces per-session operation state exactly as a real token does, which is
 * what turns "sharing a session is wrong" from an argument into a failing test.
 */
@DisplayName("concurrent token access")
class ConcurrentTokenAccessTest {

    private static final int THREADS = 32;
    private static final int ITERATIONS = 8;

    /**
     * How many times the fault-injection run repeats.
     *
     * <p>One in an ordinary build; the roadmap's acceptance criterion is 100 consecutive green
     * runs, which is a soak rather than something to pay for on every {@code mvn test}. Run it with
     * {@code mvn test -Dtest=ConcurrentTokenAccessTest -Dkimbo11ng.soak.runs=100}. A concurrency
     * bug that reproduces once in fifty is not caught by a suite that runs the case once, and the
     * point of a knob rather than a fixed number is that the soak uses the same code path as the
     * build, not a separate harness that could drift from it.
     */
    private static final int SOAK_RUNS =
            Integer.getInteger("kimbo11ng.soak.runs", 1);

    private TestSlot fixture;
    private final Pkcs11v32Profile profile = new Pkcs11v32Profile();

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void openSlot() throws Exception {
        Properties properties = new Properties();
        // Fewer sessions than threads on purpose: threads must queue for a session and be served,
        // not fail. A pool sized to the thread count would never exercise the waiting path.
        properties.setProperty(SessionPoolConfig.MAX_SESSIONS, "6");
        fixture = new TestSlot(new FakeToken(), properties);
        fixture.slot().login("1234".toCharArray());
    }

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    @DisplayName("32 threads signing, enumerating and generating never collide on a session")
    void mixedWorkloadIsClean() throws Exception {
        long[] rsa = generateRsa("shared-rsa");
        AlgorithmEntry mlDsa = profile.lookup("ML-DSA-65").orElseThrow();

        Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                new TokenRuntime(fixture.slot(), profile));
        Kimbo11ngKeyStoreSpi keyStore = new Kimbo11ngKeyStoreSpi(
                new TokenRuntime(fixture.slot(), profile));

        ConcurrentLinkedQueue<Throwable> failures = new ConcurrentLinkedQueue<>();
        AtomicInteger operations = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService threads = Executors.newFixedThreadPool(THREADS);

        try {
            for (int t = 0; t < THREADS; t++) {
                int kind = t % 4;
                int id = t;
                threads.submit(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < ITERATIONS; i++) {
                            switch (kind) {
                                case 0 -> sign(provider, rsa[1]);
                                case 1 -> keyStore.engineLoad(null, null);
                                case 2 -> generateRsa("gen-" + id + "-" + i);
                                default -> generatePqc("pqc-" + id + "-" + i, mlDsa);
                            }
                            operations.incrementAndGet();
                        }
                    } catch (Throwable e) {
                        failures.add(e);
                    }
                });
            }
            start.countDown();
            threads.shutdown();
            assertTrue(threads.awaitTermination(90, TimeUnit.SECONDS),
                    "the workload did not finish: a lease was most likely never returned");
        } finally {
            threads.shutdownNow();
        }

        List<Throwable> collided = failures.stream()
                .filter(e -> Pkcs11Errors.is(e, CKR.OPERATION_ACTIVE))
                .toList();
        assertTrue(collided.isEmpty(),
                () -> "two threads used the same session: " + describe(collided));
        assertTrue(failures.isEmpty(), () -> "unexpected failures: " + describe(failures));
        assertEquals(THREADS * ITERATIONS, operations.get());
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    @DisplayName("returns every session to the pool when the work is done")
    void noSessionsAreLeaked() throws Exception {
        long[] rsa = generateRsa("leak-check");
        Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                new TokenRuntime(fixture.slot(), profile));

        ExecutorService threads = Executors.newFixedThreadPool(THREADS);
        try {
            CountDownLatch start = new CountDownLatch(1);
            for (int t = 0; t < THREADS; t++) {
                threads.submit(() -> {
                    start.await();
                    for (int i = 0; i < ITERATIONS; i++) {
                        sign(provider, rsa[1]);
                    }
                    return null;
                });
            }
            start.countDown();
            threads.shutdown();
            assertTrue(threads.awaitTermination(45, TimeUnit.SECONDS));
        } finally {
            threads.shutdownNow();
        }

        // Every session accounted for: a lease that is not returned is a permit never released,
        // and after enough of them the pool refuses every borrow and the CA goes offline for good.
        assertEquals(fixture.slot().pool().liveSessions(), fixture.slot().pool().idleSessions(),
                "some session was borrowed and never returned");
        assertTrue(fixture.slot().pool().liveSessions() <= 6, "the ceiling must hold under load");
    }

    /** One entry per soak run; read at runtime, because an annotation needs a constant. */
    static java.util.stream.IntStream soakRuns() {
        return java.util.stream.IntStream.range(0, SOAK_RUNS);
    }

    @ParameterizedTest(name = "run {0}")
    @MethodSource("soakRuns")
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    @DisplayName("survives sessions dying underneath the workload")
    void survivesInjectedFaults(int run) throws Exception {
        // The mix above with the connection dropping mid-flight, which is the failure a network
        // HSM actually produces. What must hold is not that nothing fails — a delete racing a sign
        // legitimately fails — but that nothing fails with CKR_OPERATION_ACTIVE, that the pool
        // never wedges, and that every lease comes back.
        FakeToken token = fixture.token();
        long[] rsa = generateRsa("fault-rsa");
        Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                new TokenRuntime(fixture.slot(), profile));
        Kimbo11ngKeyStoreSpi keyStore = new Kimbo11ngKeyStoreSpi(
                new TokenRuntime(fixture.slot(), profile));

        ConcurrentLinkedQueue<Throwable> failures = new ConcurrentLinkedQueue<>();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService threads = Executors.newFixedThreadPool(THREADS);
        try {
            for (int t = 0; t < THREADS; t++) {
                int kind = t % 5;
                int id = t;
                threads.submit(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < ITERATIONS; i++) {
                            try {
                                switch (kind) {
                                    case 0 -> sign(provider, rsa[1]);
                                    case 1 -> keyStore.engineLoad(null, null);
                                    case 2 -> generateRsa("f-" + id + "-" + i);
                                    case 3 -> deleteIfPresent(keyStore, "f-" + id + "-" + i);
                                    default -> token.dropAllSessions();
                                }
                            } catch (Throwable expected) {
                                // Recorded, then filtered: only the invariants below are asserted.
                                failures.add(expected);
                            }
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                });
            }
            start.countDown();
            threads.shutdown();
            assertTrue(threads.awaitTermination(90, TimeUnit.SECONDS),
                    "the workload did not finish: a lease was most likely never returned");
        } finally {
            threads.shutdownNow();
        }

        List<Throwable> collided = failures.stream()
                .filter(e -> Pkcs11Errors.is(e, CKR.OPERATION_ACTIVE))
                .toList();
        assertTrue(collided.isEmpty(),
                () -> "two threads used the same session: " + describe(collided));

        // The pool has to be usable afterwards. A broken session that went back into the pool, or
        // a permit that was never released, shows up here and nowhere else.
        try (var lease = fixture.slot().borrow()) {
            assertTrue(lease.session() > 0);
        }
        assertEquals(fixture.slot().pool().liveSessions(), fixture.slot().pool().idleSessions(),
                "some session was borrowed and never returned");
    }

    private void deleteIfPresent(Kimbo11ngKeyStoreSpi keyStore, String alias)
            throws java.security.KeyStoreException {
        if (keyStore.engineContainsAlias(alias)) {
            keyStore.engineDeleteEntry(alias);
        }
    }

    private static String describe(Iterable<Throwable> failures) {
        StringBuilder sb = new StringBuilder();
        for (Throwable t : failures) {
            sb.append("\n  ").append(t);
        }
        return sb.toString();
    }

    private void sign(Kimbo11ngProvider provider, long privateHandle) throws Exception {
        Kimbo11ngPrivateKey key = new Kimbo11ngPrivateKey("RSA", fixture.slot(),
                new P11KeyRef(null, "shared-rsa", null), privateHandle);
        Signature signer = Signature.getInstance("SHA256withRSA", provider);
        signer.initSign(key);
        signer.update("kimbo11ng".getBytes(StandardCharsets.UTF_8));
        signer.sign();
    }

    private long[] generateRsa(String alias) throws Exception {
        KeyTemplates.Pair t = KeyTemplates.rsa(alias.getBytes(StandardCharsets.UTF_8),
                KeyTemplates.newKeyId(), 2048);
        return fixture.onSession((ce, session) -> {
            LongRef pub = new LongRef();
            LongRef priv = new LongRef();
            ce.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN),
                    t.pub(), t.priv(), pub, priv);
            return new long[] {pub.value(), priv.value()};
        });
    }

    private void generatePqc(String alias, AlgorithmEntry entry) throws Exception {
        KeyTemplates.Pair t = KeyTemplates.pqc(alias.getBytes(StandardCharsets.UTF_8),
                KeyTemplates.newKeyId(), entry, profile);
        fixture.onSession((ce, session) -> {
            ce.GenerateKeyPair(session, new CKM(entry.ckmKeyPairGen()),
                    t.pub(), t.priv(), new LongRef(), new LongRef());
            return null;
        });
    }
}

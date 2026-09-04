/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import ch.ithings.kimbo11ng.CryptoTokenImpl;
import ch.ithings.kimbo11ng.fake.TestBridge;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.provider.Kimbo11ngKeyStoreSpi;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.pkcs11.jacknji11.CKM;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Everything kimbo11ng assumes about a PKCS#11 library, in one runnable suite.
 *
 * <p>Subclass it, say which library, slot and PIN to use, and it exercises the whole stack against
 * that token: the module registry, the capability probe, the session pool under concurrent load,
 * key identity by {@code CKA_ID}, and a generate/re-enumerate/sign round trip for every algorithm
 * the token turns out to support. Nothing here is specific to a vendor, and nothing here asserts
 * that a particular algorithm is present — a token that does only RSA passes, having proved the
 * parts that apply to it.
 *
 * <p>It exists to be the first thing run against real hardware. Every assumption below was learned
 * from SoftHSMv3 and could be a SoftHSM peculiarity; running this against a Luna is what turns each
 * of them from an assumption into a fact, and a failure names which one.
 *
 * <p>{@code HsmContractFakeTest} runs it against the in-memory fake so the harness itself cannot
 * rot between hardware sessions; {@code HsmConformanceIT} runs it against whatever library the
 * operator points it at.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class HsmContract {

    /** A registry private to this run, so "initialized once" is a claim about this test alone. */
    protected abstract Pkcs11ModuleRegistry registry();

    /** Absolute path to the PKCS#11 library. */
    protected abstract String libPath();

    /**
     * How {@link #slotLabelValue()} should be read: a {@code Pkcs11SlotLabelType} key, one of
     * {@code SLOT_INDEX}, {@code SLOT_LABEL}, {@code SLOT_NUMBER} or {@code SUN_FILE}.
     *
     * <p>Index is the default because it needs no prior knowledge of the token. On real hardware
     * prefer {@code SLOT_LABEL}: a Luna partition keeps its name across an appliance reboot, and
     * slot numbering does not.
     */
    protected String slotLabelType() {
        return "SLOT_INDEX";
    }

    /** The slot to use, interpreted according to {@link #slotLabelType()}. */
    protected abstract String slotLabelValue();

    /** The user PIN. Returned fresh each call: the token implementation may zero what it is given. */
    protected abstract char[] pin();

    /** Extra token properties, merged last. */
    protected Properties extraProperties() {
        return new Properties();
    }

    private CryptoTokenImpl impl;
    private final List<String> aliases = new ArrayList<>();

    @BeforeAll
    void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void openToken() throws Exception {
        Properties properties = new Properties();
        properties.setProperty(CryptoTokenImpl.SHLIB_LABEL_KEY, libPath());
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_TYPE, slotLabelType());
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_VALUE, slotLabelValue());
        properties.setProperty(CryptoTokenImpl.DO_NOT_ADD_P11_PROVIDER, "true");
        properties.putAll(extraProperties());

        impl = new CryptoTokenImpl(new TestBridge(), registry());
        impl.init(properties, null, 72);
        impl.activate(pin());
    }

    @AfterEach
    void closeToken() {
        if (impl == null) {
            return;
        }
        for (String alias : aliases) {
            try {
                impl.deleteEntry(alias);
            } catch (Exception e) {
                // A leftover key is worth reporting but must not mask the real failure.
                System.err.println("could not delete '" + alias + "': " + e);
            }
        }
        aliases.clear();
        impl.reset();
        impl = null;
    }

    /** Registers an alias for cleanup and returns it. */
    private String alias(String suffix) {
        String alias = "hsmcontract-" + suffix;
        aliases.add(alias);
        return alias;
    }

    private P11Slot slot() {
        return impl.getSlot();
    }

    // ------------------------------------------------------------------ registry and module

    @Test
    @DisplayName("initializes the library once, however many times it is asked for")
    void moduleIsShared() throws Exception {
        Pkcs11Module module = registry().get(libPath());
        assertSame(module, registry().get(libPath()),
                "a second look-up returned a different module, so C_Initialize ran twice — which"
                        + " some libraries treat as an error and others as a reset");
        assertSame(module, slot().module(), "the token is using a module from outside the registry");
        assertTrue(registry().isLoaded(libPath()));
    }

    @Test
    @DisplayName("reports a slot list containing the configured slot")
    void slotList() throws Exception {
        long[] slots = registry().get(libPath()).slotList();
        assertTrue(slots.length > 0, "the library reported no slots at all");

        if ("SLOT_INDEX".equals(slotLabelType())) {
            int index = Integer.parseInt(slotLabelValue());
            assertTrue(slots.length > index,
                    () -> "slot index " + index + " is out of range; the library reported "
                            + slots.length + " slot(s)");
            assertEquals(slots[index], slot().slotId());
            return;
        }
        // Addressed by label or number: the index mapping says nothing, but whatever the slot
        // resolved to must still be a slot this library admits to having.
        assertTrue(Arrays.stream(slots).anyMatch(s -> s == slot().slotId()),
                () -> "'" + slotLabelValue() + "' (" + slotLabelType() + ") resolved to slot "
                        + slot().slotId() + ", which is not in the library's slot list "
                        + Arrays.toString(slots));
    }

    @Test
    @DisplayName("names the token and the library")
    void identification() throws Exception {
        assertNotNull(registry().get(libPath()).tokenLabel(slot().slotId()));
        assertFalse(slot().libraryName().isBlank(),
                "the library name is what tells two HSMs apart in the provider name");
    }

    // ------------------------------------------------------------------ the probe

    @Test
    @DisplayName("answers a mechanism list, with flags and not merely presence")
    void probe() {
        TokenCapabilities capabilities = slot().capabilities();
        assertTrue(capabilities.probed(),
                () -> "C_GetMechanismList failed: " + capabilities.unprobedReason()
                        + ". kimbo11ng still works, but every algorithm decision then rests on the"
                        + " profile alone rather than on what the token says.");
        assertFalse(capabilities.mechanisms().isEmpty());

        // RSA is the one thing every HSM in scope does; if this is missing the probe is misreading
        // the list rather than the token being unusual.
        assertTrue(capabilities.canGenerateKeyPair(CKM.RSA_PKCS_KEY_PAIR_GEN),
                "the token does not advertise CKM_RSA_PKCS_KEY_PAIR_GEN with CKF_GENERATE_KEY_PAIR");
        assertTrue(capabilities.canSign(CKM.SHA256_RSA_PKCS),
                "the token does not advertise CKM_SHA256_RSA_PKCS with CKF_SIGN");
    }

    @Test
    @DisplayName("settles the algorithm table at init and can explain it")
    void algorithmTable() {
        String table = impl.getProvider().runtime().algorithms().describe();
        assertTrue(table.contains(impl.getPqcProfile().name()),
                () -> "the logged table does not name the profile it came from:\n" + table);
        // Printed so a hardware run leaves a record of what the token actually offered.
        System.out.println(table);
    }

    // ------------------------------------------------------------------ the session pool

    @Test
    @DisplayName("serves more concurrent callers than it has sessions, without deadlocking")
    void poolUnderLoad() throws Exception {
        int callers = 32;
        ExecutorService pool = Executors.newFixedThreadPool(callers);
        try {
            List<Callable<Long>> work = new ArrayList<>();
            for (int i = 0; i < callers; i++) {
                work.add(() -> {
                    try (SessionLease lease = slot().borrow()) {
                        // A real call, not just a borrow: a session that was handed out without
                        // being validated fails here rather than silently.
                        slot().ce().GetSessionInfo(lease.session());
                        return lease.session();
                    }
                });
            }
            List<Future<Long>> results = pool.invokeAll(work, 60, TimeUnit.SECONDS);
            for (Future<Long> result : results) {
                assertFalse(result.isCancelled(),
                        "a borrow did not complete within 60s — the pool is deadlocked or the"
                                + " borrow timeout is longer than this test's patience");
                assertNotNull(result.get());
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("stays logged in across leases")
    void loginIsPerToken() throws Exception {
        assertTrue(slot().isLoggedIn());
        try (SessionLease first = slot().borrow()) {
            assertNotNull(slot().ce().GetSessionInfo(first.session()));
        }
        try (SessionLease second = slot().borrow()) {
            // If login were per session, this would need a second C_Login — and a token that
            // counts failed logins would eventually lock out.
            assertNotNull(slot().ce().GetSessionInfo(second.session()));
        }
        assertTrue(slot().isLoggedIn());
    }

    // ------------------------------------------------------------------ key identity

    @Test
    @DisplayName("finds a key by CKA_ID after everything cached has been discarded")
    void keyIdentitySurvivesRestart() throws Exception {
        String alias = alias("rsa-identity");
        impl.generateKeyPair("2048", alias);

        Kimbo11ngKeyStoreSpi keyStore = impl.getProvider().getKeyStoreSpi();
        byte[] keyId = keyStore.referenceFor(alias).ckaId();
        assertNotNull(keyId, "generation did not write a CKA_ID, so the key has no durable identity");

        // The restart path: forget every handle and every cached key, then look it up again.
        keyStore.clear();
        slot().invalidateHandles();
        keyStore.engineLoad(null, pin());

        assertTrue(keyStore.engineContainsAlias(alias), alias + " did not survive re-enumeration");
        assertArrayEquals(keyId, keyStore.referenceFor(alias).ckaId(),
                "the key came back under a different CKA_ID, so the two are different objects");
    }

    @Test
    @DisplayName("signs with RSA and the signature verifies outside this provider")
    void rsaSignatureIsVerifiable() throws Exception {
        String alias = alias("rsa-sign");
        impl.generateKeyPair("2048", alias);
        signAndVerify(alias, "SHA256withRSA");
    }

    @Test
    @DisplayName("deletes a key so completely that it is gone from a fresh enumeration")
    void deleteRemovesBothHalves() throws Exception {
        String alias = "hsmcontract-doomed";
        impl.generateKeyPair("2048", alias);
        impl.deleteEntry(alias);

        Kimbo11ngKeyStoreSpi keyStore = impl.getProvider().getKeyStoreSpi();
        keyStore.clear();
        keyStore.engineLoad(null, pin());
        assertFalse(keyStore.engineContainsAlias(alias),
                "the alias is still on the token; a leftover public key blocks reusing the name");
    }

    // ------------------------------------------------------------------ the algorithms

    @Test
    @DisplayName("round-trips every algorithm the token turned out to support")
    void everySupportedAlgorithm() throws Exception {
        List<AlgorithmEntry> supported = impl.getProvider().runtime().algorithms().supported();
        for (AlgorithmEntry entry : supported) {
            String alias = alias("pqc-" + entry.canonicalName());
            impl.generateKeyPair(entry.canonicalName(), alias);

            Kimbo11ngKeyStoreSpi keyStore = impl.getProvider().getKeyStoreSpi();
            keyStore.clear();
            keyStore.engineLoad(null, pin());
            assertTrue(keyStore.engineContainsAlias(alias),
                    entry.canonicalName() + " did not survive re-enumeration");

            PublicKey pub = keyStore.getPublicKey(alias);
            assertNotNull(pub, "no public key came back for " + entry.canonicalName());
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pub.getEncoded());
            assertEquals(entry.oid(), spki.getAlgorithm().getAlgorithm(),
                    entry.canonicalName() + " came back under the wrong OID, which is the OID that"
                            + " would land in a certificate");
            assertEquals(entry.publicKeyLength(), spki.getPublicKeyData().getOctets().length,
                    entry.canonicalName() + " came back the wrong size, so the parameter set the"
                            + " token used is not the one that was asked for");

            if (entry.canSign()) {
                signAndVerify(alias, entry.canonicalName());
            }
        }
    }

    /**
     * Symmetric keys, if the token makes them.
     *
     * <p>Skipped rather than failed on a token that does not advertise
     * {@code CKM_GENERIC_SECRET_KEY_GEN} with {@code CKF_GENERATE}: this suite asserts that what a
     * token claims it can do, it does, never that it claims anything in particular.
     *
     * <p>There is no cross-check against another provider here, and there cannot be: the key is
     * {@code CKA_SENSITIVE} and never leaves the token, so nothing outside can recompute the MAC.
     * What is checkable is that the same key over the same input is stable across a full
     * re-enumeration — which is exactly what would break if the key were re-resolved to a different
     * object, or if the token silently made a session key rather than a token one.
     */
    @Test
    @DisplayName("generates a secret key, and MACs with it across a re-enumeration")
    void secretKeyRoundTrip() throws Exception {
        TokenCapabilities capabilities = slot().capabilities();
        org.junit.jupiter.api.Assumptions.assumeTrue(
                capabilities.canGenerate(CKM.GENERIC_SECRET_KEY_GEN)
                        && capabilities.canSign(CKM.SHA256_HMAC),
                "the token does not offer CKM_GENERIC_SECRET_KEY_GEN with CKF_GENERATE and"
                        + " CKM_SHA256_HMAC with CKF_SIGN");

        String alias = alias("hmac");
        impl.generateKey("HmacSHA256", 256, alias);

        Kimbo11ngKeyStoreSpi keyStore = impl.getProvider().getKeyStoreSpi();
        assertTrue(keyStore.engineContainsAlias(alias));
        assertTrue(keyStore.isSecretKey(alias), alias + " is not registered as a secret key");

        byte[] message = ("kimbo11ng hsm contract " + alias).getBytes(StandardCharsets.UTF_8);
        byte[] before = mac(alias, message);
        assertEquals(32, before.length, "HmacSHA256 must be 32 bytes");

        // The restart path, as for the key pairs above.
        keyStore.clear();
        slot().invalidateHandles();
        keyStore.engineLoad(null, pin());

        assertTrue(keyStore.engineContainsAlias(alias),
                alias + " did not survive re-enumeration, so the token made a session key");
        assertArrayEquals(before, mac(alias, message),
                "the same key over the same input produced a different MAC after re-enumeration");
        assertFalse(Arrays.equals(before, mac(alias, "something else".getBytes(StandardCharsets.UTF_8))));
    }

    /** MACs {@code message} with the token-held key registered under {@code alias}. */
    private byte[] mac(String alias, byte[] message) throws Exception {
        javax.crypto.SecretKey key = (javax.crypto.SecretKey)
                impl.getProvider().getKeyStoreSpi().engineGetKey(alias, pin());
        assertNotNull(key, "no secret key for " + alias);
        assertNull(key.getEncoded(), "a sensitive key must not hand out its material");
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256", impl.getProvider());
        mac.init(key);
        return mac.doFinal(message);
    }

    @Test
    @DisplayName("signs with EC and the signature verifies outside this provider")
    void ecSignatureIsVerifiable() throws Exception {
        String alias = alias("ec-sign");
        impl.generateKeyPair("secp256r1", alias);
        signAndVerify(alias, "SHA256withECDSA");
    }

    /**
     * Signs through this provider and verifies with BouncyCastle.
     *
     * <p>Verification elsewhere is the whole point: a wrong mechanism, a missing DER wrap or a PSS
     * salt of the wrong length all produce a signature this codebase accepts and a relying party
     * rejects. Post-quantum signatures are verified the same way, which is what a fake token cannot
     * do and this suite can.
     */
    private void signAndVerify(String alias, String jcaName) throws Exception {
        byte[] message = ("kimbo11ng hsm contract " + alias).getBytes(StandardCharsets.UTF_8);
        Kimbo11ngKeyStoreSpi keyStore = impl.getProvider().getKeyStoreSpi();

        PrivateKey privateKey = (PrivateKey) keyStore.engineGetKey(alias, pin());
        assertNotNull(privateKey, "no private key for " + alias);
        Signature signer = Signature.getInstance(jcaName, impl.getProvider());
        signer.initSign(privateKey);
        signer.update(message);
        byte[] signature = signer.sign();
        assertTrue(signature.length > 0, jcaName + " produced an empty signature");

        if (!verifiesSignaturesFor(jcaName)) {
            return;
        }
        PublicKey publicKey = keyStore.getPublicKey(alias);
        Signature verifier = Signature.getInstance(jcaName, BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(message);
        assertTrue(verifier.verify(signature),
                jcaName + " produced a signature BouncyCastle will not verify — the token and this"
                        + " provider disagree about the mechanism or its encoding");
    }

    /**
     * Whether a signature made with {@code jcaName} should be checked against BouncyCastle.
     *
     * <p>Always true for real hardware, and the reason this suite is worth running there. The
     * in-memory fake overrides it for the algorithms it only pretends to sign with.
     */
    protected boolean verifiesSignaturesFor(String jcaName) {
        return true;
    }
}

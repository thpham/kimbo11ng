/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import ch.ithings.kimbo11ng.p11.TokenCapabilities;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CK_MECHANISM_INFO;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The profile table intersected with what the token and BouncyCastle actually offer.
 *
 * <p>What is being prevented is a class of report, not a crash: "key generation failed,
 * {@code CKR_MECHANISM_INVALID}" with nothing naming the mechanism, the algorithm, or the fifteen
 * others in the same profile that would have worked.
 */
@DisplayName("effective algorithm set")
class AlgorithmSupportTest {

    private final Pkcs11v32Profile profile = new Pkcs11v32Profile();

    private static TokenCapabilities capabilitiesOf(FakeToken token) throws Exception {
        try (TestSlot fixture = new TestSlot(token)) {
            return fixture.slot().capabilities();
        }
    }

    @Test
    @DisplayName("a v3.2 token supports the whole table")
    void fullSupport() throws Exception {
        AlgorithmSupport support = AlgorithmSupport.compute(
                profile, capabilitiesOf(new FakeToken()), true);

        assertEquals(profile.entries().size(), support.supported().size());
        assertTrue(support.excluded().isEmpty(), () -> support.excluded().toString());
    }

    @Test
    @DisplayName("excludes a family whose generation mechanism is missing, and only that family")
    void missingKeygenMechanism() throws Exception {
        FakeToken token = new FakeToken().hideMechanism(FakeToken.CKM_ML_DSA_KEY_PAIR_GEN);
        AlgorithmSupport support = AlgorithmSupport.compute(profile, capabilitiesOf(token), true);

        assertEquals(3, support.excluded().size(), "the three ML-DSA parameter sets");
        assertTrue(support.excluded().containsKey("ML-DSA-65"));
        assertTrue(support.excluded().get("ML-DSA-65").contains("0x0000001c"),
                () -> "the message must name the mechanism: " + support.excluded().get("ML-DSA-65"));
        assertTrue(support.lookupSupported("SLH-DSA-SHA2-128S").isPresent(),
                "one missing mechanism must not disable the rest of the table");
    }

    @Test
    @DisplayName("excludes a signing algorithm whose mechanism is listed without CKF_SIGN")
    void mechanismListedButNotForSigning() throws Exception {
        // Presence is not permission. Generating a key that can never sign is worse than refusing:
        // EJBCA would create the CA and fail on the first issued certificate.
        FakeToken token = new FakeToken().mechanismFlags(FakeToken.CKM_SLH_DSA,
                CK_MECHANISM_INFO.CKF_VERIFY);
        AlgorithmSupport support = AlgorithmSupport.compute(profile, capabilitiesOf(token), true);

        assertEquals(12, support.excluded().size(), "all twelve SLH-DSA variants");
        assertTrue(support.excluded().get("SLH-DSA-SHA2-128S").contains("signing"));
        assertTrue(support.lookupSupported("ML-DSA-44").isPresent());
    }

    @Test
    @DisplayName("ML-KEM survives a mechanism that cannot sign, because it never signs")
    void kemIsNotCheckedForSigning() throws Exception {
        // CKM_ML_KEM is advertised as encapsulate/decapsulate. Checking it for CKF_SIGN would
        // exclude every ML-KEM parameter set on a perfectly correct token.
        AlgorithmSupport support = AlgorithmSupport.compute(
                profile, capabilitiesOf(new FakeToken()), true);
        assertTrue(support.lookupSupported("ML-KEM-768").isPresent());
    }

    @Test
    @DisplayName("excludes a family the deployed BouncyCastle cannot materialise")
    void bouncyCastleGap() throws Exception {
        // This is what replaced the deleted RawPqcPublicKey: rather than wrapping a key EJBCA
        // cannot recognise, the algorithm is not offered at all.
        AlgorithmSupport support = AlgorithmSupport.compute(profile,
                capabilitiesOf(new FakeToken()), true, family -> family != PqcFamily.SLH_DSA);

        assertEquals(12, support.excluded().size());
        assertTrue(support.excluded().get("SLH-DSA-SHAKE-256F").contains("BouncyCastle"),
                () -> support.excluded().get("SLH-DSA-SHAKE-256F"));
    }

    @Test
    @DisplayName("an unprobed token supports everything the profile claims")
    void unprobedSupportsEverything() {
        AlgorithmSupport support = AlgorithmSupport.compute(profile,
                TokenCapabilities.unknown("the library would not answer"), true);

        assertEquals(profile.entries().size(), support.supported().size());
        assertTrue(support.describe().contains("NOT PROBED"),
                "the log must say the table is an assumption, not a measurement");
    }

    @Test
    @DisplayName("without fail-fast an excluded algorithm still resolves, with its reason kept")
    void killSwitch() throws Exception {
        FakeToken token = new FakeToken().hideMechanism(FakeToken.CKM_ML_DSA_KEY_PAIR_GEN);
        AlgorithmSupport lenient = AlgorithmSupport.compute(profile, capabilitiesOf(token), false);

        assertTrue(lenient.lookupSupported("ML-DSA-65").isPresent(),
                "the operator has said to attempt it anyway");
        assertNotNull(lenient.rejectionReason("ML-DSA-65"),
                "but the reason is still known, so the attempt can be logged");
    }

    @Test
    @DisplayName("has nothing to say about a key specification the profile does not know")
    void unknownKeySpec() throws Exception {
        AlgorithmSupport support = AlgorithmSupport.compute(
                profile, capabilitiesOf(new FakeToken()), true);
        assertTrue(support.lookupSupported("RSA2048").isEmpty());
        assertNull(support.rejectionReason("RSA2048"),
                "not the probe's business: RSA does not come from the profile table");
    }

    @Test
    @DisplayName("the logged table names every algorithm and every exclusion")
    void describeIsUsable() throws Exception {
        FakeToken token = new FakeToken().hideMechanism(FakeToken.CKM_ML_DSA_KEY_PAIR_GEN);
        String table = AlgorithmSupport.compute(profile, capabilitiesOf(token), true).describe();

        assertTrue(table.contains("pkcs11v32"));
        assertTrue(table.contains("15/18 usable"), () -> table);
        assertTrue(table.contains("ML-DSA-87"), "an excluded algorithm is listed, not dropped");
        assertTrue(table.contains(TokenCapabilities.PROBE_FAIL_FAST),
                "and the way out is named where the problem is reported");
    }

    @Test
    @DisplayName("scores a profile by how much of its table the token can do")
    void scoring() throws Exception {
        TokenCapabilities full = capabilitiesOf(new FakeToken());
        assertEquals(18, AlgorithmSupport.score(profile, full));
        assertEquals(0, AlgorithmSupport.score(new ThalesLunaProfile(), full),
                "an unpopulated profile scores nothing and can never be auto-selected");

        FakeToken partial = new FakeToken().hideMechanism(FakeToken.CKM_SLH_DSA_KEY_PAIR_GEN);
        assertEquals(6, AlgorithmSupport.score(profile, capabilitiesOf(partial)));

        assertEquals(0, AlgorithmSupport.score(profile, TokenCapabilities.unknown("no probe")),
                "an unprobed token is no evidence for any profile");
    }

    @Test
    @DisplayName("unchecked() claims the whole table without asking anything")
    void uncheckedIsForPathsWithNoToken() {
        AlgorithmSupport support = AlgorithmSupport.unchecked(profile);
        assertEquals(profile.entries().size(), support.supported().size());
        assertFalse(support.failFast());
        assertFalse(support.capabilities().probed());
    }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CK_MECHANISM_INFO;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("capability probe")
class TokenCapabilitiesTest {

    @Test
    @DisplayName("reads the mechanism list and each mechanism's flags")
    void readsFlags() throws Exception {
        try (TestSlot fixture = new TestSlot()) {
            TokenCapabilities caps = fixture.slot().capabilities();

            assertTrue(caps.probed());
            assertTrue(caps.canGenerateKeyPair(FakeToken.CKM_ML_DSA_KEY_PAIR_GEN));
            assertTrue(caps.canSign(FakeToken.CKM_ML_DSA));
            assertTrue(caps.canGenerateKeyPair(CKM.EC_KEY_PAIR_GEN));
            assertTrue(caps.canSign(CKM.ECDSA));
        }
    }

    @Test
    @DisplayName("a listed mechanism is not permission to use it for any operation")
    void presenceIsNotPermission() throws Exception {
        try (TestSlot fixture = new TestSlot()) {
            TokenCapabilities caps = fixture.slot().capabilities();

            // Measured against SoftHSMv3: CKM_ML_KEM is advertised with encapsulate/decapsulate
            // and no CKF_SIGN. A probe that tested presence alone would report this as signable.
            assertTrue(caps.has(FakeToken.CKM_ML_KEM), "the mechanism is advertised");
            assertFalse(caps.canSign(FakeToken.CKM_ML_KEM), "but not for signing");
            assertFalse(caps.canGenerateKeyPair(CKM.ECDSA),
                    "CKM_ECDSA signs; it does not generate key pairs");
        }
    }

    @Test
    @DisplayName("a mechanism the token does not list is refused")
    void missingMechanism() throws Exception {
        FakeToken token = new FakeToken().hideMechanism(FakeToken.CKM_ML_DSA_KEY_PAIR_GEN);
        try (TestSlot fixture = new TestSlot(token)) {
            TokenCapabilities caps = fixture.slot().capabilities();
            assertFalse(caps.has(FakeToken.CKM_ML_DSA_KEY_PAIR_GEN));
            assertFalse(caps.canGenerateKeyPair(FakeToken.CKM_ML_DSA_KEY_PAIR_GEN));
            assertTrue(caps.canSign(FakeToken.CKM_ML_DSA), "the signing mechanism is still there");
        }
    }

    @Test
    @DisplayName("a listed mechanism the token will not describe is treated as usable")
    void undescribableMechanismIsNotHeldAgainstTheToken() throws Exception {
        // Some modules answer CKR_MECHANISM_INVALID for their own vendor mechanisms. Dropping them
        // would make the probe the reason an operation is refused, which is the opposite of what
        // it is for.
        FakeToken token = new FakeToken().undescribableMechanism(FakeToken.CKM_ML_DSA);
        try (TestSlot fixture = new TestSlot(token)) {
            TokenCapabilities caps = fixture.slot().capabilities();
            assertTrue(caps.has(FakeToken.CKM_ML_DSA));
            assertTrue(caps.canSign(FakeToken.CKM_ML_DSA));
            assertTrue(caps.can(FakeToken.CKM_ML_DSA, CK_MECHANISM_INFO.CKF_DERIVE),
                    "unknown flags means unknown, and unknown must not refuse");
        }
    }

    @Test
    @DisplayName("a probe that fails answers yes to everything rather than no")
    void unprobedIsNotEmpty() throws Exception {
        FakeToken token = new FakeToken();
        try (TestSlot fixture = new TestSlot(token)) {
            token.failNextWith(CKR.DEVICE_ERROR);
            TokenCapabilities caps = fixture.slot().capabilities();

            assertFalse(caps.probed());
            assertNotNull(caps.unprobedReason());
            // An empty capability set would mean "this token does nothing" and would take a working
            // token out of service over one unanswered question.
            assertTrue(caps.canGenerateKeyPair(FakeToken.CKM_ML_DSA_KEY_PAIR_GEN));
            assertTrue(caps.canSign(0x12345678L));
        }
    }

    @Test
    @DisplayName("a failed probe is not cached, so the next call asks again")
    void failedProbeIsRetried() throws Exception {
        FakeToken token = new FakeToken();
        try (TestSlot fixture = new TestSlot(token)) {
            token.failNextWith(CKR.DEVICE_ERROR);
            assertFalse(fixture.slot().capabilities().probed());

            TokenCapabilities second = fixture.slot().capabilities();
            assertTrue(second.probed(), "a transient failure must not disable probing for good");
            assertSame(second, fixture.slot().capabilities(), "a success is cached");
        }
    }

    @Test
    @DisplayName("invalidating the module forgets the probe")
    void invalidateForgetsTheProbe() throws Exception {
        try (TestSlot fixture = new TestSlot()) {
            TokenCapabilities first = fixture.slot().capabilities();
            fixture.module().invalidate();
            assertNotSame(first, fixture.slot().capabilities(),
                    "a re-provisioned slot must be probed again");
        }
    }

    @Test
    @DisplayName("a vendor mechanism read back sign-extended still matches its constant")
    void vendorMechanismsAreNormalised() throws Exception {
        // CKM_VENDOR_DEFINED is 0x80000000, so every vendor mechanism has bit 31 set and comes back
        // from jacknji11 sign-extended. See CkULong: an unnormalised comparison matches nothing,
        // which is the Thales Luna case exactly.
        long vendorCkm = 0x80000100L;
        FakeToken token = new FakeToken().advertiseMechanism(vendorCkm);
        try (TestSlot fixture = new TestSlot(token)) {
            TokenCapabilities caps = fixture.slot().capabilities();
            assertTrue(caps.has(vendorCkm));
            assertTrue(caps.has(-2147483392L), "the same mechanism, sign-extended");
        }
    }

    @Test
    @DisplayName("names a standard mechanism and falls back to hex for a v3.2 one")
    void mechanismNames() {
        assertEquals("CKM_ECDSA (0x00001041)", TokenCapabilities.name(CKM.ECDSA));
        // jacknji11 1.3.1 predates v3.2 and its placeholder for an unknown constant reads as an
        // error; bare hex is the honest rendering.
        assertEquals("0x0000001d", TokenCapabilities.name(FakeToken.CKM_ML_DSA));
    }
}

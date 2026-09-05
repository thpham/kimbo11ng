/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import ch.ithings.kimbo11ng.profile.AlgorithmSupport;
import ch.ithings.kimbo11ng.profile.Pkcs11v32Profile;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.LongRef;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code SHA1withECDSA} has to sit on the digesting {@code CKM_ECDSA_SHA1}, like its three
 * siblings, and not on the raw {@code CKM_ECDSA}.
 *
 * <p>Nothing in this provider ever digests: {@code engineUpdate} buffers and {@code engineSign}
 * hands the buffer to {@code C_Sign}. Under the raw mechanism the token treats that buffer as an
 * already-computed hash, so an EJBCA CA on {@code SIGALG_SHA1_WITH_ECDSA} would sign a truncation
 * of the TBSCertificate rather than its SHA-1 — a signature of exactly the right shape that no
 * relying party accepts. Only a verifier outside this codebase can tell the two apart, which is
 * why the round trip below goes through BouncyCastle.
 */
@DisplayName("SHA1withECDSA mechanism")
class Sha1EcdsaSignatureTest {

    private TestSlot fixture;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void openSlot() throws Exception {
        fixture = new TestSlot(new FakeToken()).loggedIn();
    }

    @AfterEach
    void closeSlot() {
        if (fixture != null) {
            fixture.close();
        }
    }

    @Test
    @DisplayName("signs a message the token itself hashes, and BouncyCastle verifies it")
    void roundTrip() throws Exception {
        Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                new TokenRuntime(fixture.slot(), new Pkcs11v32Profile()));
        KeyTemplates.Pair templates = KeyTemplates.ec(
                "sha1-ecdsa".getBytes(StandardCharsets.UTF_8), KeyTemplates.newKeyId(),
                "secp256r1");
        long[] handles = fixture.onSession((ce, session) -> {
            LongRef pub = new LongRef();
            LongRef priv = new LongRef();
            ce.GenerateKeyPair(session, new CKM(CKM.EC_KEY_PAIR_GEN), templates.pub(),
                    templates.priv(), pub, priv);
            return new long[] {pub.value(), priv.value()};
        });
        PublicKey publicKey = fixture.onSession(
                (ce, s) -> PublicKeyReader.readEcPublicKey(ce, s, handles[0]));

        // Longer than a SHA-1 digest and longer than the P-256 group order, as a TBSCertificate is:
        // under the raw mechanism the token has to drop most of it.
        byte[] message = new byte[512];
        for (int i = 0; i < message.length; i++) {
            message[i] = (byte) i;
        }

        Signature signer = Signature.getInstance("SHA1withECDSA", provider);
        signer.initSign(new Kimbo11ngPrivateKey("EC", fixture.slot(),
                new P11KeyRef(null, "sha1-ecdsa", null), handles[1]));
        signer.update(message);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA1withECDSA",
                BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(message);
        assertTrue(verifier.verify(signature),
                "SHA1withECDSA produced a signature BouncyCastle will not verify");
    }

    @Test
    @DisplayName("is offered by a token that has CKM_ECDSA_SHA1 but not the raw CKM_ECDSA")
    void followsTheDigestingMechanism() throws Exception {
        try (TestSlot noRaw = new TestSlot(new FakeToken().hideMechanism(CKM.ECDSA))) {
            assertNotNull(providerFor(noRaw).getService("Signature", "SHA1withECDSA"),
                    "SHA1withECDSA must ride on CKM_ECDSA_SHA1, which this token advertises");
        }
    }

    @Test
    @DisplayName("is withheld by a token that lacks CKM_ECDSA_SHA1")
    void withheldWithoutTheDigestingMechanism() throws Exception {
        // The raw mechanism stays advertised here, so a row still pinned to CKM_ECDSA would happily
        // register a service the token cannot honour for this algorithm.
        try (TestSlot noSha1 = new TestSlot(new FakeToken().hideMechanism(CKM.ECDSA_SHA1))) {
            assertNull(providerFor(noSha1).getService("Signature", "SHA1withECDSA"),
                    "a token without CKM_ECDSA_SHA1 cannot produce a SHA1withECDSA signature");
        }
    }

    /** A provider over {@code slot}, with the capability probe honoured rather than assumed. */
    private static Kimbo11ngProvider providerFor(TestSlot slot) {
        return Kimbo11ngProvider.forToken(new TokenRuntime(slot.slot(),
                AlgorithmSupport.compute(new Pkcs11v32Profile(), slot.slot().capabilities(), true),
                true, PublicKeyReader.Policy.LENIENT));
    }
}

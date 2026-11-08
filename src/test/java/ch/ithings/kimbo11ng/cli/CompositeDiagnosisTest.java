/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.CryptoTokenImpl;
import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestBridge;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import ch.ithings.kimbo11ng.provider.Kimbo11ngKeyStoreSpi;
import ch.ithings.kimbo11ng.provider.Kimbo11ngProvider.CompositeAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The two diagnosis verdicts the fake token cannot provoke through the CLI: a classical half that
 * fails on its own, and two halves that are fine on their own. Called directly, with keys from the
 * crypto token the CLI drives.
 */
@DisplayName("composite failure diagnosis")
class CompositeDiagnosisTest {

    private static final String PIN = "1234";

    private CryptoTokenImpl token;
    private Kimbo11ngKeyStoreSpi keyStore;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void openToken() throws Exception {
        FakeToken fake = new FakeToken();
        Properties properties = new Properties();
        properties.setProperty(CryptoTokenImpl.SHLIB_LABEL_KEY,
                "/nonexistent/libfake-diagnosis.so");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_TYPE, "SLOT_INDEX");
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_VALUE, "0");
        properties.setProperty(CryptoTokenImpl.DO_NOT_ADD_P11_PROVIDER, "true");
        token = new CryptoTokenImpl(new TestBridge(), new Pkcs11ModuleRegistry(path -> fake));
        token.init(properties, null, 91);
        token.activate(PIN.toCharArray());
        token.generateKeyPair("ML-DSA-44", "d-COMPQ");
        token.generateKeyPair("2048", "d-COMPC");
        token.generateKeyPair("2048", "other");
        keyStore = token.getProvider().getKeyStoreSpi();
    }

    @AfterEach
    void closeToken() {
        token.reset();
    }

    private PrivateKey privateKey(String alias) throws Exception {
        return (PrivateKey) keyStore.engineGetKey(alias, PIN.toCharArray());
    }

    private PublicKey publicKey(String alias) throws Exception {
        return keyStore.getPublicKey(alias);
    }

    private CompositeAlgorithm composite() {
        return CompositeKeys.byName(token.getProvider().compositeAlgorithms(),
                "MLDSA44-RSA2048-PSS-SHA256").orElseThrow();
    }

    @Test
    @DisplayName("names the classical half when it fails on its own")
    void classicalHalfFailed() throws Exception {
        // The other RSA key's public half: the classical signature is fine and verifies under
        // nothing it is checked against, which is what a broken classical mechanism looks like.
        String verdict = CompositeDiagnosis.diagnose(token.getProvider(), composite(),
                privateKey("d-COMPQ"), publicKey("d-COMPQ"),
                privateKey("d-COMPC"), publicKey("other"));
        assertTrue(verdict.startsWith("Diagnosis: "), verdict);
        assertTrue(verdict.contains("the classical half failed"), verdict);
        assertTrue(verdict.contains("SHA256withRSAandMGF1"), verdict);
    }

    @Test
    @DisplayName("says so when the ML-DSA half cannot sign at all, context or not")
    void mlDsaHalfFailedOnItsOwn() throws Exception {
        // An RSA key where the ML-DSA half should be: the ML-DSA service refuses it at initSign.
        String verdict = CompositeDiagnosis.diagnose(token.getProvider(), composite(),
                privateKey("d-COMPC"), publicKey("d-COMPQ"),
                privateKey("d-COMPC"), publicKey("d-COMPC"));
        assertTrue(verdict.contains("the ML-DSA half failed on its own"), verdict);
    }

    @Test
    @DisplayName("says so when the ML-DSA half signs but does not verify, context or not")
    void mlDsaHalfDoesNotVerify() throws Exception {
        // The wrong public key for the ML-DSA half: BouncyCastle cannot even initialise the
        // verifier, which has to read as "does not verify", not as an error of its own.
        String verdict = CompositeDiagnosis.diagnose(token.getProvider(), composite(),
                privateKey("d-COMPQ"), publicKey("other"),
                privateKey("d-COMPC"), publicKey("d-COMPC"));
        assertTrue(verdict.contains("signs but does not verify, even without a context"),
                verdict);
    }

    @Test
    @DisplayName("names the classical mechanism when the token will not sign with it")
    void classicalHalfWouldNotSign() throws Exception {
        // An ML-DSA key behind the RSA-PSS service: the token refuses the operation.
        String verdict = CompositeDiagnosis.diagnose(token.getProvider(), composite(),
                privateKey("d-COMPQ"), publicKey("d-COMPQ"),
                privateKey("d-COMPQ"), publicKey("d-COMPC"));
        assertTrue(verdict.contains("the token would not sign SHA256withRSAandMGF1"), verdict);
    }

    @Test
    @DisplayName("an exception's reason is its own message, or the cause's, never a stack trace")
    void reasonReadsTheMessage() {
        assertEquals("plain", CompositeDiagnosis.reason(new IllegalStateException("plain")));
        assertEquals("ends with a stop",
                CompositeDiagnosis.reason(new IllegalStateException("ends with a stop...")));
        assertEquals("inner", CompositeDiagnosis.reason(
                new RuntimeException((String) null, new IllegalStateException("inner"))));
        assertEquals("IllegalStateException",
                CompositeDiagnosis.reason(new IllegalStateException()));
    }

    @Test
    @DisplayName("says so when both halves sign and verify on their own")
    void halvesFine() throws Exception {
        String verdict = CompositeDiagnosis.diagnose(token.getProvider(), composite(),
                privateKey("d-COMPQ"), publicKey("d-COMPQ"),
                privateKey("d-COMPC"), publicKey("d-COMPC"));
        assertTrue(verdict.contains("both halves sign and verify on their own"), verdict);
    }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.provider.Kimbo11ngProvider.CompositeAlgorithm;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Why a composite signature failed, found out on the token rather than guessed.
 *
 * <p>A composite fails as a whole — it throws, or BouncyCastle rejects the signature — and says
 * nothing about which half or why. The one question about kimbo11ng's composites that only
 * hardware can answer is whether the token honours the ML-DSA context string
 * ({@code CK_SIGN_ADDITIONAL_CONTEXT}); a token that ignores it makes signatures of the right
 * length that verify under no context but the empty one. So this signs each half on its own, the
 * ML-DSA half with and without a context, and says which of four things happened.
 *
 * <p>The context is a fixed test string, not the composite's label: BouncyCastle's labels do not
 * always follow the composite name ({@code COMPSIG-MLDSA65-ECDSA-BP256-SHA512}), and any non-empty
 * context answers the question.
 */
final class CompositeDiagnosis {

    /** The context sent to the ML-DSA half. Any non-empty string would do; this one is findable. */
    static final byte[] CONTEXT =
            "kimbo11ng-cli diagnostic context".getBytes(StandardCharsets.US_ASCII);

    private static final byte[] MESSAGE =
            "kimbo11ng-cli composite diagnosis".getBytes(StandardCharsets.US_ASCII);

    private CompositeDiagnosis() {
    }

    /**
     * One line, starting {@code Diagnosis: }, saying which half failed and how, with the likely
     * fix. Signs on the token through {@code tokenProvider}; verifies with BouncyCastle.
     */
    static String diagnose(Provider tokenProvider, CompositeAlgorithm composite,
            PrivateKey pqPrivate, PublicKey pqPublic, PrivateKey classicalPrivate,
            PublicKey classicalPublic) {
        String mlDsa = composite.mlDsaKeySpec();
        byte[] plain;
        try {
            plain = sign(tokenProvider, mlDsa, pqPrivate, null);
        } catch (Exception e) {
            return "Diagnosis: the ML-DSA half failed on its own, even without a context string ("
                    + reason(e) + "). The token cannot sign " + mlDsa + " with this key; test it"
                    + " with testkeypair --alias on the -COMPQ half.";
        }
        if (!verifies("ML-DSA", pqPublic, plain, null)) {
            return "Diagnosis: the ML-DSA half signs but does not verify, even without a context"
                    + " string. The token and BouncyCastle disagree about " + mlDsa + " itself, not"
                    + " about the composite.";
        }

        byte[] withContext;
        try {
            withContext = sign(tokenProvider, mlDsa, pqPrivate, new ContextParameterSpec(CONTEXT));
        } catch (Exception e) {
            return "Diagnosis: the token rejects CK_SIGN_ADDITIONAL_CONTEXT on CKM_ML_DSA ("
                    + reason(e) + "): plain " + mlDsa + " signs, " + mlDsa
                    + " with a context string does not. Composite signatures bind their label into"
                    + " the ML-DSA half through that context, so this token cannot make one. Check"
                    + " whether the HSM firmware supports ML-DSA context strings (PKCS#11 v3.2).";
        }
        if (!verifies("ML-DSA", pqPublic, withContext, new ContextParameterSpec(CONTEXT))) {
            if (verifies("ML-DSA", pqPublic, withContext, null)) {
                return "Diagnosis: the token ignores the ML-DSA context string: it accepts"
                        + " CK_SIGN_ADDITIONAL_CONTEXT, then signs as if the context were empty."
                        + " Every composite signature it makes will fail to verify. Report it to"
                        + " the HSM vendor; the firmware has to honour the context (PKCS#11 v3.2).";
            }
            return "Diagnosis: the ML-DSA half signed with a context string verifies neither under"
                    + " that context nor under the empty one. The token mangles"
                    + " CK_SIGN_ADDITIONAL_CONTEXT.";
        }

        String classical = composite.classicalSignature();
        try {
            byte[] signature = sign(tokenProvider, classical, classicalPrivate, null);
            if (!verifies(classical, classicalPublic, signature, null)) {
                return "Diagnosis: the ML-DSA half signs correctly with a context string, and the"
                        + " classical half failed: " + classical + " signs but does not verify"
                        + " against the -COMPC public key. Test it with testkeypair --alias on the"
                        + " -COMPC half.";
            }
        } catch (Exception e) {
            return "Diagnosis: the ML-DSA half signs correctly with a context string, and the"
                    + " classical half failed: the token would not sign " + classical + " ("
                    + reason(e) + ").";
        }
        return "Diagnosis: both halves sign and verify on their own, the ML-DSA half with a context"
                + " string, so this is not a token behaviour. The composite error above is the one"
                + " to report.";
    }

    private static byte[] sign(Provider provider, String algorithm, PrivateKey key,
            AlgorithmParameterSpec spec) throws Exception {
        Signature signer = Signature.getInstance(algorithm, provider);
        signer.initSign(key);
        if (spec != null) {
            signer.setParameter(spec);
        }
        signer.update(MESSAGE);
        return signer.sign();
    }

    private static boolean verifies(String algorithm, PublicKey key, byte[] signature,
            AlgorithmParameterSpec spec) {
        try {
            Signature verifier = Signature.getInstance(algorithm,
                    BouncyCastleProvider.PROVIDER_NAME);
            verifier.initVerify(key);
            if (spec != null) {
                verifier.setParameter(spec);
            }
            verifier.update(MESSAGE);
            return verifier.verify(signature);
        } catch (java.security.GeneralSecurityException | RuntimeException e) {
            // Not verifying is the answer being asked for, however BouncyCastle says it.
            return false;
        }
    }

    /**
     * An exception's own message, or its type when it has none — never a stack trace. Without a
     * closing full stop, so a caller can end the sentence it is built into.
     */
    static String reason(Throwable e) {
        Throwable cause = e;
        while (cause.getCause() != null && cause.getMessage() == null) {
            cause = cause.getCause();
        }
        String text = cause.getMessage() != null
                ? cause.getMessage()
                : cause.getClass().getSimpleName();
        return text.replaceAll("\\.+$", "");
    }
}

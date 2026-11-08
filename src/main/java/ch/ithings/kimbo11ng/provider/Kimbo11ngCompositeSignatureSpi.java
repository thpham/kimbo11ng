/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;

/**
 * A composite ML-DSA signature (draft-ietf-lamps-pq-composite-sigs) whose component keys live on
 * the token.
 *
 * <p>EJBCA's {@code CryptoTokenCompositeWrapper} builds a BouncyCastle {@code CompositePrivateKey}
 * from the two token keys and asks the crypto token's provider — this one — for the composite
 * algorithm by name. The composite construction itself (the domain label, the pre-hash, the
 * message representative both halves sign, the concatenation) is BouncyCastle's, and it stays
 * BouncyCastle's here: this class delegates to it. That is a choice and not a shortcut. EJBCA and
 * every relying party verify with BouncyCastle, the draft has changed its message format between
 * revisions, and two implementations of it in one JVM would be two chances to disagree.
 *
 * <h2>What this class adds</h2>
 *
 * <p>The provider of each half. BouncyCastle looks up a component signature on the provider the
 * {@code CompositePrivateKey} names for it, and EJBCA's key names none — so BC falls back to
 * {@code Signature.getInstance(name)} across every installed provider, and which one signs then
 * depends on provider order and on whether this one was installed globally at all. The key is
 * rebuilt here with this provider attached to every token-held half, so the half that must be
 * signed by the token is signed by the token, by construction.
 *
 * <p>Verification is refused, as everywhere in this provider: EJBCA verifies through BouncyCastle
 * from the public key.
 */
final class Kimbo11ngCompositeSignatureSpi extends SignatureSpi {

    private final ASN1ObjectIdentifier oid;
    private final Provider tokenProvider;
    private final Signature delegate;

    Kimbo11ngCompositeSignatureSpi(String algorithm, ASN1ObjectIdentifier oid,
            Provider tokenProvider) {
        this.oid = oid;
        this.tokenProvider = tokenProvider;
        try {
            this.delegate = Signature.getInstance(algorithm, BouncyCastleHolder.provider());
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException("BouncyCastle has no composite signature " + algorithm
                    + "; the composite table does not match the BouncyCastle on the classpath", e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof CompositePrivateKey composite)) {
            throw new InvalidKeyException("A composite signature needs a CompositePrivateKey, got "
                    + (privateKey == null ? "null" : privateKey.getClass().getName()));
        }
        if (!oid.equals(composite.getAlgorithmIdentifier().getAlgorithm())) {
            throw new InvalidKeyException("The key is a " + composite.getAlgorithm()
                    + " composite, and this signature is " + oid);
        }
        delegate.initSign(withTokenProvider(composite));
    }

    /** The same key, with this provider named for each half the token holds. */
    private CompositePrivateKey withTokenProvider(CompositePrivateKey composite) {
        List<PrivateKey> components = composite.getPrivateKeys();
        CompositePrivateKey.Builder builder = CompositePrivateKey.builder(oid);
        for (PrivateKey component : components) {
            if (component instanceof Kimbo11ngPrivateKey) {
                builder.addPrivateKey(component, tokenProvider);
            } else {
                // A software half — not something EJBCA builds today, but nothing here needs to
                // forbid it. BouncyCastle chooses its provider exactly as it would without us.
                builder.addPrivateKey(component);
            }
        }
        return builder.build();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        throw new InvalidKeyException("Verification is not supported by this provider; verify with "
                + "the public key through BouncyCastle instead.");
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        delegate.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        delegate.update(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        return delegate.sign();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        throw new SignatureException("Verification is not supported by this provider");
    }

    /** The composite's own context string, which BouncyCastle carries into the message. */
    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (params == null) {
            // As for the single-key services. BouncyCastle's composite refuses null as an
            // unknown spec, which would turn a caller's "no parameters" into a failure.
            return;
        }
        delegate.setParameter(params);
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return delegate.getParameters();
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(String param, Object value) {
        throw new InvalidParameterException("setParameter is not supported");
    }

    @Override
    @SuppressWarnings("deprecation")
    protected Object engineGetParameter(String param) {
        throw new InvalidParameterException("getParameter is not supported");
    }

    /**
     * The BouncyCastle provider to delegate to: the installed one when there is one — EJBCA always
     * installs it — and a private instance otherwise, so the CLI and the tests need not.
     */
    private static final class BouncyCastleHolder {

        static Provider provider() {
            Provider installed = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
            return installed != null ? installed : Fallback.INSTANCE;
        }

        /** Its own class so the instance is built only if it is ever needed. */
        private static final class Fallback {
            static final Provider INSTANCE = new BouncyCastleProvider();
        }
    }
}

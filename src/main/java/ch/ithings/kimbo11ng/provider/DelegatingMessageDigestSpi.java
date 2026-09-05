/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;

/**
 * A digest, computed in software, offered under this provider's name.
 *
 * <h2>Why a PKCS#11 provider registers a software digest</h2>
 *
 * <p>Because BouncyCastle's operator layer asks for one, from <em>this</em> provider, when it
 * builds an RSA-PSS signer. {@code JcaContentSignerBuilder("SHA256withRSAandMGF1").setProvider(p)}
 * resolves every helper it needs through {@code p}, and for PSS that includes
 * {@code MessageDigest.getInstance("SHA256")}. Without it, EJBCA's CA creation fails with
 * <em>"cannot create signer: no such algorithm: SHA256 for provider Kimbo11ng-…"</em> — a message
 * that names neither PSS nor the real gap. Measured, and covered by
 * {@code SignatureAlgorithmTest}.
 *
 * <p>The digest is not sent to the token, and that is deliberate rather than a shortcut. Hashing
 * public data inside an HSM protects nothing, costs a round trip and a session, and the signing
 * mechanisms this provider uses ({@code CKM_SHA256_RSA_PKCS}, {@code CKM_SHA256_RSA_PKCS_PSS})
 * digest on the token anyway — BouncyCastle wants this object to construct algorithm parameters,
 * not to produce the signature's hash.
 */
final class DelegatingMessageDigestSpi extends MessageDigestSpi implements Cloneable {

    private final MessageDigest delegate;

    /**
     * @param algorithm a standard JCA digest name, resolved through the default provider search
     */
    DelegatingMessageDigestSpi(String algorithm) {
        try {
            this.delegate = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            // Every name registered is one the JDK has shipped since 1.4; reaching this means the
            // security configuration removed it, which is not something to paper over.
            throw new ProviderException("The platform has no " + algorithm + " digest", e);
        }
    }

    private DelegatingMessageDigestSpi(MessageDigest delegate) {
        this.delegate = delegate;
    }

    @Override
    protected void engineUpdate(byte input) {
        delegate.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        delegate.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        return delegate.digest();
    }

    @Override
    protected void engineReset() {
        delegate.reset();
    }

    @Override
    protected int engineGetDigestLength() {
        return delegate.getDigestLength();
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        // MessageDigestSpi declares Cloneable support as optional, and BouncyCastle's operator
        // layer clones a digest when it needs two independent running hashes.
        return new DelegatingMessageDigestSpi((MessageDigest) delegate.clone());
    }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CryptokiE;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * Signing through PKCS#11.
 *
 * <p>The mechanism is supplied by a {@link MechanismResolver} rather than hardcoded per algorithm.
 * For RSA and ECDSA it follows from the requested digest, which is a property of the JCA service
 * name and is standard across tokens. For ML-DSA and SLH-DSA it comes from the key's
 * {@link AlgorithmEntry}, so a vendor profile that shifts the signing mechanism is honoured — the
 * previous fixed constants meant such a profile would generate keys correctly and then sign with
 * the wrong mechanism.
 *
 * <p>One instance serves one signing operation; the JCA contract allows reuse after
 * {@code engineSign}, and the buffer is reset accordingly.
 */
public class Kimbo11ngSignatureSpi extends SignatureSpi {

    /** Chooses the PKCS#11 mechanism for a given key. */
    public interface MechanismResolver {
        long resolve(Kimbo11ngPrivateKey key) throws InvalidKeyException;
    }

    private final MechanismResolver resolver;
    private final boolean ecdsaDerEncoding;

    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private CryptokiDevice device;
    private Kimbo11ngPrivateKey signingKey;
    private long mechanism = -1;

    private Kimbo11ngSignatureSpi(MechanismResolver resolver, boolean ecdsaDerEncoding) {
        this.resolver = resolver;
        this.ecdsaDerEncoding = ecdsaDerEncoding;
    }

    /** RSA and ECDSA: the digest fixes the mechanism. */
    public static Kimbo11ngSignatureSpi fixed(long ckMechanism, boolean ecdsaDerEncoding) {
        return new Kimbo11ngSignatureSpi(key -> ckMechanism, ecdsaDerEncoding);
    }

    /** ML-DSA and SLH-DSA: the key's algorithm row fixes the mechanism. */
    public static Kimbo11ngSignatureSpi fromKeyEntry() {
        return new Kimbo11ngSignatureSpi(key -> {
            AlgorithmEntry entry = key.entry().orElseThrow(() -> new InvalidKeyException(
                    "Key " + key.getAlias() + " carries no algorithm entry, so its PKCS#11 signing"
                    + " mechanism is unknown. Post-quantum keys must be created through the "
                    + "algorithm registry."));
            if (!entry.canSign()) {
                throw new InvalidKeyException(entry.canonicalName()
                        + " is a key-encapsulation algorithm and cannot sign.");
            }
            return entry.ckmOperation();
        }, false);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof Kimbo11ngPrivateKey p11Key)) {
            throw new InvalidKeyException("Key must be a Kimbo11ngPrivateKey, got: "
                    + privateKey.getClass().getName());
        }
        if (p11Key.getDevice() == null) {
            throw new InvalidKeyException("Key " + p11Key.getAlias()
                    + " has no device; it was probably deserialized.");
        }
        mechanism = resolver.resolve(p11Key);
        signingKey = p11Key;
        device = p11Key.getDevice();
        buffer.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        // EJBCA verifies with BouncyCastle (KeyTools.testKey resolves the provider from the public
        // key's algorithm), so this provider is never asked to verify.
        throw new InvalidKeyException("Verification is not supported by this provider; verify with "
                + "the public key through BouncyCastle instead.");
    }

    @Override
    protected void engineUpdate(byte b) {
        buffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        buffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (signingKey == null) {
            throw new SignatureException("Not initialized for signing");
        }
        byte[] data = buffer.toByteArray();
        buffer.reset();
        try {
            long session = device.getOrOpenSession();
            CryptokiE ce = device.getCe();
            // TODO(phase-2): the device still exposes one shared session, so the mutual exclusion
            // has to live here. A borrowed session lease replaces this and allows real parallelism.
            synchronized (device) {
                ce.SignInit(session, new CKM(mechanism), signingKey.getObjectHandle());
                byte[] rawSig = ce.Sign(session, data);
                return ecdsaDerEncoding ? convertRawEcdsaToDer(rawSig) : rawSig;
            }
        } catch (Exception e) {
            throw new SignatureException("PKCS#11 signing failed with mechanism 0x"
                    + Long.toHexString(mechanism) + " for key " + signingKey.getAlias()
                    + ": " + e.getMessage(), e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        throw new SignatureException("Verification is not supported by this provider");
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
     * PKCS#11 returns ECDSA as the bare {@code r || s} pair; X.509 needs
     * {@code SEQUENCE { INTEGER r, INTEGER s }}.
     */
    static byte[] convertRawEcdsaToDer(byte[] rawSig) throws SignatureException {
        if (rawSig == null || rawSig.length == 0 || rawSig.length % 2 != 0) {
            throw new SignatureException("Invalid raw ECDSA signature length: "
                    + (rawSig == null ? "null" : rawSig.length)
                    + " (expected an even number of bytes, r||s)");
        }
        int half = rawSig.length / 2;
        BigInteger r = new BigInteger(1, rawSig, 0, half);
        BigInteger s = new BigInteger(1, rawSig, half, half);
        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(r));
            v.add(new ASN1Integer(s));
            return new DERSequence(v).getEncoded();
        } catch (Exception e) {
            throw new SignatureException("Failed to DER-encode ECDSA signature: "
                    + e.getMessage(), e);
        }
    }
}

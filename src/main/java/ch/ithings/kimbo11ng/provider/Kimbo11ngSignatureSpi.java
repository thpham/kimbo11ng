/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.P11Slot;
import org.apache.log4j.Logger;
import ch.ithings.kimbo11ng.p11.Pkcs11Errors;
import ch.ithings.kimbo11ng.p11.SessionLease;
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

    private static final Logger log = Logger.getLogger(Kimbo11ngSignatureSpi.class);

    /** Chooses the PKCS#11 mechanism for a given key. */
    public interface MechanismResolver {
        long resolve(Kimbo11ngPrivateKey key) throws InvalidKeyException;
    }

    private final MechanismResolver resolver;
    private final boolean ecdsaDerEncoding;
    private final byte[] mechanismParam;

    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private P11Slot slot;
    private Kimbo11ngPrivateKey signingKey;
    private long mechanism = -1;

    private Kimbo11ngSignatureSpi(MechanismResolver resolver, boolean ecdsaDerEncoding,
            byte[] mechanismParam) {
        this.resolver = resolver;
        this.ecdsaDerEncoding = ecdsaDerEncoding;
        this.mechanismParam = mechanismParam;
    }

    /** RSA and ECDSA: the digest fixes the mechanism. */
    public static Kimbo11ngSignatureSpi fixed(long ckMechanism, boolean ecdsaDerEncoding) {
        return fixed(ckMechanism, ecdsaDerEncoding, null);
    }

    /**
     * As {@link #fixed(long, boolean)}, with a mechanism parameter block.
     *
     * <p>Only RSA-PSS needs one. See {@link RsaPssParams} for why jacknji11 cannot supply it.
     */
    public static Kimbo11ngSignatureSpi fixed(long ckMechanism, boolean ecdsaDerEncoding,
            byte[] mechanismParam) {
        return new Kimbo11ngSignatureSpi(key -> ckMechanism, ecdsaDerEncoding, mechanismParam);
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
        }, false, null);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof Kimbo11ngPrivateKey p11Key)) {
            throw new InvalidKeyException("Key must be a Kimbo11ngPrivateKey, got: "
                    + privateKey.getClass().getName());
        }
        if (p11Key.slot() == null) {
            throw new InvalidKeyException("Key " + p11Key.getAlias()
                    + " has no slot; it was probably deserialized.");
        }
        mechanism = resolver.resolve(p11Key);
        signingKey = p11Key;
        slot = p11Key.slot();
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
            return signOnce(data);
        } catch (Exception first) {
            switch (Pkcs11Errors.classify(first)) {
                case RETRYABLE -> {
                    // Tier 1: the session or the object handle went stale, but the token is still
                    // there. A network HSM drops a connection and this is what the next operation
                    // sees. The pool has already discarded the broken session; invalidating the
                    // handles makes the retry re-resolve the key rather than reuse a number the
                    // token may have reassigned.
                    log.info("Retrying signature for '" + signingKey.getAlias() + "' after "
                            + Pkcs11Errors.describe(first) + "; re-resolving the key handle");
                    slot.invalidateHandles();
                    signingKey.invalidateHandle();
                    try {
                        return signOnce(data);
                    } catch (Exception second) {
                        // Once. A second failure of the same kind is not a stale handle, and
                        // retrying a genuinely broken token in a loop only delays the diagnosis.
                        throw offlineIfGone(second, failure(second));
                    }
                }
                // Tier 2: the token itself is gone, or the login it was holding is. Neither can be
                // fixed here — we do not hold the PIN. Going offline is what lets EJBCA's
                // autoActivate() log in again with the credential it does hold.
                case OFFLINE -> throw offlineIfGone(first, failure(first));
                default -> throw failure(first);
            }
        }
    }

    /**
     * One attempt: borrow a session, resolve the key in it, sign.
     *
     * <p>The handle is resolved inside the lease rather than passed in, because a handle is only
     * meaningful in the session that produced it.
     */
    private byte[] signOnce(byte[] data) throws Exception {
        try (SessionLease lease = slot.borrow()) {
            CryptokiE ce = slot.ce();
            try {
                long handle = signingKey.objectHandle(ce, lease.session());
                // The one-argument CKM constructor fills in jacknji11's default parameter for the
                // mechanism, which is what every mechanism here except PSS wants.
                CKM ckm = mechanismParam == null
                        ? new CKM(mechanism)
                        : new CKM(mechanism, mechanismParam);
                ce.SignInit(lease.session(), ckm, handle);
                byte[] rawSig = ce.Sign(lease.session(), data);
                return ecdsaDerEncoding ? convertRawEcdsaToDer(rawSig) : rawSig;
            } catch (Exception e) {
                // C_SignInit may have succeeded, leaving an operation live on this session. It
                // cannot go back into the pool: the next borrower's C_SignInit would answer
                // CKR_OPERATION_ACTIVE and the failure would surface on an unrelated thread.
                lease.invalidate();
                throw e;
            }
        }
    }

    private SignatureException failure(Throwable cause) {
        return new SignatureException("PKCS#11 signing failed with mechanism 0x"
                + Long.toHexString(mechanism) + " for key " + signingKey.getAlias()
                + Pkcs11Errors.describe(cause), cause);
    }

    /**
     * Tells the crypto token the HSM is gone, when that is what the failure says.
     *
     * <p>The exception handed back is still a {@code SignatureException}, because that is what the
     * JCA contract requires of {@code engineSign} and what EJBCA's {@code SignWithWorkingAlgorithm}
     * expects to catch. The offline report is a side channel to {@code CryptoTokenImpl}, which
     * clears the keystore so EJBCA stops routing work to a CA whose HSM is not answering.
     */
    private SignatureException offlineIfGone(Throwable cause, SignatureException failure) {
        if (Pkcs11Errors.classify(cause) == Pkcs11Errors.Kind.OFFLINE) {
            slot.reportOffline("signing with '" + signingKey.getAlias() + "' failed"
                    + Pkcs11Errors.describe(cause), cause);
        }
        return failure;
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

    /**
     * Accepts PSS parameters that match what the mechanism was built with, and refuses any others.
     *
     * <p>BouncyCastle's operator layer sets these when they differ from its defaults, and the
     * inherited implementation throws {@code UnsupportedOperationException} — which would make an
     * RSA-PSS CA with a non-default salt length fail at CA creation with nothing naming PSS.
     * Accepting them silently would be worse: the mechanism parameter sent to the token is fixed
     * when the service is created, so a caller asking for a different salt length would get a
     * signature that is the right size, is not what was asked for, and fails only at the relying
     * party.
     */
    @Override
    protected void engineSetParameter(java.security.spec.AlgorithmParameterSpec params)
            throws java.security.InvalidAlgorithmParameterException {
        if (params == null) {
            return;
        }
        if (!(params instanceof java.security.spec.PSSParameterSpec pss)) {
            throw new java.security.InvalidAlgorithmParameterException(
                    "Only PSSParameterSpec is supported, got " + params.getClass().getName());
        }
        if (mechanismParam == null) {
            throw new java.security.InvalidAlgorithmParameterException(
                    "PSS parameters were supplied for a mechanism that is not RSA-PSS (0x"
                    + Long.toHexString(mechanism) + ")");
        }
        byte[] requested = RsaPssParams.forSpec(pss);
        if (!java.util.Arrays.equals(mechanismParam, requested)) {
            throw new java.security.InvalidAlgorithmParameterException(
                    "This service signs with " + RsaPssParams.describe(mechanismParam)
                    + " and was asked for " + RsaPssParams.describe(requested)
                    + ". The mechanism parameter is fixed when the Signature is created, so the"
                    + " token cannot honour a different salt length or digest here; request the"
                    + " matching SHAnnnwithRSAandMGF1 algorithm instead.");
        }
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

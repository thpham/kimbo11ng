/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.P11Slot;
import org.apache.log4j.Logger;
import ch.ithings.kimbo11ng.p11.Pkcs11Errors;
import ch.ithings.kimbo11ng.p11.SessionLease;
import ch.ithings.kimbo11ng.p11.TokenCapabilities;
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

    /** Which parameters a service accepts, which is the only way the three kinds differ. */
    private enum Kind {
        /** RSA, ECDSA, EdDSA: the mechanism, and any PSS block, are fixed by the JCA name. */
        CLASSICAL,
        /** ML-DSA, SLH-DSA: the mechanism comes from the key, and a context string is accepted. */
        PQC,
        /** {@code RSASSA-PSS}: mechanism and parameter block both come from a PSSParameterSpec. */
        RSASSA_PSS
    }

    private static final byte[] NO_CONTEXT = new byte[0];

    private final Kind kind;
    private final MechanismResolver resolver;
    private final boolean ecdsaDerEncoding;
    /** Fixed for the {@code SHAnnnwithRSAandMGF1} services; set by setParameter for RSASSA-PSS. */
    private byte[] mechanismParam;
    /** The FIPS 204/205 context string; empty, the default, sends no mechanism parameter. */
    private byte[] context = NO_CONTEXT;

    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private P11Slot slot;
    private Kimbo11ngPrivateKey signingKey;
    private long mechanism = -1;

    private Kimbo11ngSignatureSpi(Kind kind, MechanismResolver resolver, boolean ecdsaDerEncoding,
            byte[] mechanismParam) {
        this.kind = kind;
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
        return new Kimbo11ngSignatureSpi(Kind.CLASSICAL, key -> ckMechanism, ecdsaDerEncoding,
                mechanismParam);
    }

    /**
     * {@code RSASSA-PSS}, whose hash and salt length are whatever the caller's
     * {@code PSSParameterSpec} says.
     *
     * <p>This is the name BouncyCastle's composite signatures ask for as their RSA-PSS half, and it
     * cannot be one of the fixed {@code SHAnnnwithRSAandMGF1} services: the spec arrives through
     * {@code setParameter}, after the {@code Signature} exists. Signing without one is refused
     * rather than defaulted, because a PSS signature with an assumed hash verifies for nobody.
     */
    public static Kimbo11ngSignatureSpi rsassaPss() {
        return new Kimbo11ngSignatureSpi(Kind.RSASSA_PSS, null, false, null);
    }

    /** ML-DSA and SLH-DSA: the key's algorithm row fixes the mechanism. */
    public static Kimbo11ngSignatureSpi fromKeyEntry() {
        return new Kimbo11ngSignatureSpi(Kind.PQC, key -> {
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
        // Forgotten first, so a refusal below leaves nothing to sign with.
        // java.security.Signature stays in its SIGN state when initSign throws; were the previous
        // key kept, the next sign() would use it without anyone having asked.
        signingKey = null;
        slot = null;
        buffer.reset();
        if (!(privateKey instanceof Kimbo11ngPrivateKey p11Key)) {
            throw new InvalidKeyException("Key must be a Kimbo11ngPrivateKey, got: "
                    + privateKey.getClass().getName());
        }
        if (p11Key.slot() == null) {
            throw new InvalidKeyException("Key " + p11Key.getAlias()
                    + " has no slot; it was probably deserialized.");
        }
        if (kind != Kind.RSASSA_PSS) {
            // RSASSA-PSS has no mechanism until its PSSParameterSpec arrives, which may be before
            // or after this; it is not the key's to decide.
            mechanism = resolver.resolve(p11Key);
        }
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
        if (kind == Kind.RSASSA_PSS && mechanismParam == null) {
            throw new SignatureException("RSASSA-PSS needs a PSSParameterSpec before signing: the"
                    + " hash and salt length come from it, and this provider will not guess them");
        }
        if (kind == Kind.RSASSA_PSS && !slot.capabilities().canSign(mechanism)) {
            // The service is offered when the token signs with any PSS mechanism; the hash only
            // arrives with the spec. Refusing here names what is missing, where C_SignInit would
            // answer CKR_MECHANISM_INVALID and name nothing. An unprobed token answers yes.
            throw new SignatureException("RSASSA-PSS was asked for "
                    + RsaPssParams.describe(mechanismParam) + ", and the token does not advertise "
                    + TokenCapabilities.name(mechanism) + " for signing");
        }
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
        // Owns the native memory the context parameter points into; see the fence below.
        SignAdditionalContext additional =
                context.length == 0 ? null : new SignAdditionalContext(context);
        try (SessionLease lease = slot.borrow()) {
            CryptokiE ce = slot.ce();
            try {
                long handle = signingKey.objectHandle(ce, lease.session());
                // The one-argument CKM constructor fills in jacknji11's default parameter for the
                // mechanism, which is what every mechanism here except PSS, and ML-DSA with a
                // context, wants.
                CKM ckm;
                if (additional != null) {
                    ckm = additional.mechanism(mechanism);
                } else if (mechanismParam != null) {
                    ckm = new CKM(mechanism, mechanismParam);
                } else {
                    ckm = new CKM(mechanism);
                }
                try {
                    ce.SignInit(lease.session(), ckm, handle);
                } finally {
                    // The context lives in JNA memory that is freed when collected, and nothing
                    // but `additional` refers to it from Java. It has to outlive C_SignInit.
                    java.lang.ref.Reference.reachabilityFence(additional);
                }
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
     * Accepts the parameters each kind of service can honour, and refuses the rest by name.
     *
     * <ul>
     *   <li><b>A context string</b> ({@code ContextParameterSpec}), for ML-DSA and SLH-DSA only.
     *       BouncyCastle's composite signatures set one on their ML-DSA half every time; refusing it
     *       breaks them, and ignoring it gives a signature that does not verify. See
     *       {@link SignAdditionalContext}.</li>
     *   <li><b>PSS parameters</b> for {@code RSASSA-PSS}, which choose its mechanism.</li>
     *   <li><b>PSS parameters</b> for the fixed {@code SHAnnnwithRSAandMGF1} services, if they
     *       match what the mechanism was built with. BouncyCastle's operator layer sets these when
     *       they differ from its defaults, and the inherited implementation throws
     *       {@code UnsupportedOperationException} — which would make an RSA-PSS CA with a
     *       non-default salt length fail at CA creation with nothing naming PSS. Accepting them
     *       silently would be worse: the mechanism parameter sent to the token is fixed when the
     *       service is created, so a caller asking for a different salt length would get a
     *       signature that is the right size, is not what was asked for, and fails only at the
     *       relying party.</li>
     * </ul>
     */
    @Override
    protected void engineSetParameter(java.security.spec.AlgorithmParameterSpec params)
            throws java.security.InvalidAlgorithmParameterException {
        if (params == null) {
            return;
        }
        if (params instanceof org.bouncycastle.jcajce.spec.ContextParameterSpec ctx) {
            setContext(ctx.getContext());
            return;
        }
        if (!(params instanceof java.security.spec.PSSParameterSpec pss)) {
            throw new java.security.InvalidAlgorithmParameterException(
                    "Only PSSParameterSpec and ContextParameterSpec are supported, got "
                    + params.getClass().getName());
        }
        if (kind == Kind.RSASSA_PSS) {
            // Both computed before either is assigned, so a refused spec leaves the previous one.
            long pssMechanism = RsaPssParams.signMechanism(pss);
            byte[] pssParam = RsaPssParams.forSpec(pss);
            mechanism = pssMechanism;
            mechanismParam = pssParam;
            return;
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

    private void setContext(byte[] requested)
            throws java.security.InvalidAlgorithmParameterException {
        byte[] value = requested == null ? NO_CONTEXT : requested;
        if (kind != Kind.PQC) {
            if (value.length == 0) {
                // The empty context is what every signature has; asking for it changes nothing.
                return;
            }
            throw new java.security.InvalidAlgorithmParameterException(
                    "A context string applies to ML-DSA and SLH-DSA only; this is a classical "
                    + "signature, which has none");
        }
        if (value.length > SignAdditionalContext.MAX_CONTEXT_LENGTH) {
            throw new java.security.InvalidAlgorithmParameterException(
                    "FIPS 204 and 205 limit the context to "
                    + SignAdditionalContext.MAX_CONTEXT_LENGTH + " bytes, got " + value.length);
        }
        context = value.clone();
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

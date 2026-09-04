/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.p11.Pkcs11Errors;
import ch.ithings.kimbo11ng.p11.SessionLease;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CryptokiE;

import javax.crypto.MacSpi;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * HMAC through PKCS#11, so that a secret key generated on the token can be used without leaving it.
 *
 * <p>Without this the token could create a key that nothing could consume: the key is
 * {@code CKA_SENSITIVE} and not {@code CKA_EXTRACTABLE}, so software HMAC over
 * {@code getEncoded()} is not an option — that method returns {@code null} by design.
 *
 * <p>PKCS#11 models HMAC as signing: {@code C_SignInit} with {@code CKM_SHA256_HMAC} and a
 * {@code CKO_SECRET_KEY} handle, then {@code C_Sign}. This buffers and issues one
 * {@code C_Sign} per MAC rather than streaming through {@code C_SignUpdate}, for the reason
 * {@link Kimbo11ngSignatureSpi} does the same: an operation left half-open on a pooled session
 * surfaces as {@code CKR_OPERATION_ACTIVE} on an unrelated thread.
 */
public final class Kimbo11ngMacSpi extends MacSpi {

    private static final Logger log = Logger.getLogger(Kimbo11ngMacSpi.class);

    private final SecretKeyType type;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    private P11Slot slot;
    private Kimbo11ngSecretKey macKey;

    public Kimbo11ngMacSpi(SecretKeyType type) {
        if (!type.isMac()) {
            throw new IllegalArgumentException(type.jcaName() + " is not a MAC algorithm");
        }
        this.type = type;
    }

    @Override
    protected int engineGetMacLength() {
        return type.macLengthBytes();
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException(type.jcaName()
                    + " takes no algorithm parameters.");
        }
        if (!(key instanceof Kimbo11ngSecretKey p11Key)) {
            // Deliberately not falling back to a software HMAC over key.getEncoded(): a caller who
            // reached this provider asked for the token, and quietly doing the MAC in the JVM
            // would defeat the point of putting the key in an HSM.
            throw new InvalidKeyException("Key must be a Kimbo11ngSecretKey held on the token,"
                    + " got: " + (key == null ? "null" : key.getClass().getName())
                    + ". A key with extractable material should use a software provider.");
        }
        if (p11Key.slot() == null) {
            throw new InvalidKeyException("Key " + p11Key.getAlias()
                    + " has no slot; it was probably deserialized.");
        }
        macKey = p11Key;
        slot = p11Key.slot();
        buffer.reset();
    }

    @Override
    protected void engineUpdate(byte input) {
        buffer.write(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        buffer.write(input, offset, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        if (macKey == null) {
            throw new IllegalStateException("MAC not initialized");
        }
        byte[] data = buffer.toByteArray();
        buffer.reset();
        try {
            return macOnce(data);
        } catch (Exception first) {
            if (Pkcs11Errors.classify(first) == Pkcs11Errors.Kind.RETRYABLE) {
                // The session or the handle went stale while the token is still there — a network
                // HSM dropping a connection. Re-resolve and try once; a second failure of the same
                // kind is not a stale handle.
                log.info("Retrying MAC for '" + macKey.getAlias() + "' after "
                        + Pkcs11Errors.describe(first) + "; re-resolving the key handle");
                slot.invalidateHandles();
                macKey.invalidateHandle();
                try {
                    return macOnce(data);
                } catch (Exception second) {
                    throw failure(second);
                }
            }
            if (Pkcs11Errors.classify(first) == Pkcs11Errors.Kind.OFFLINE) {
                slot.reportOffline("computing a MAC with '" + macKey.getAlias() + "' failed"
                        + Pkcs11Errors.describe(first), first);
            }
            throw failure(first);
        }
    }

    private byte[] macOnce(byte[] data) throws Exception {
        try (SessionLease lease = slot.borrow()) {
            CryptokiE ce = slot.ce();
            try {
                long handle = macKey.objectHandle(ce, lease.session());
                ce.SignInit(lease.session(), new CKM(type.ckmOperation()), handle);
                return ce.Sign(lease.session(), data);
            } catch (Exception e) {
                // C_SignInit may have succeeded, leaving an operation live on this session; it
                // cannot go back into the pool.
                lease.invalidate();
                throw e;
            }
        }
    }

    /**
     * {@code engineDoFinal} declares nothing checked, so the JCA contract for a provider-internal
     * failure is {@link ProviderException}.
     */
    private ProviderException failure(Throwable cause) {
        return new ProviderException("PKCS#11 MAC failed with mechanism 0x"
                + Long.toHexString(type.ckmOperation()) + " for key " + macKey.getAlias()
                + Pkcs11Errors.describe(cause), cause);
    }

    @Override
    protected void engineReset() {
        buffer.reset();
    }
}

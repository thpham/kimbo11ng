/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.p11.SessionLease;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CryptokiE;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.UUID;

/**
 * KeyGenerator over PKCS#11: {@code C_GenerateKey}, the single-key counterpart of the
 * {@code C_GenerateKeyPair} that {@link Kimbo11ngKeyPairGeneratorSpi} drives.
 *
 * <p>This is the service EJBCA reaches when it is asked for a symmetric key. Its
 * {@code PKCS11CryptoToken} does not call the token directly either — it calls
 * {@code KeyStoreTools.generateKey}, which is {@code KeyGenerator.getInstance(alg, providerName)}
 * followed by {@code keyStore.setKeyEntry(alias, key, null)}. So the provider, not the crypto
 * token, is where symmetric generation actually lives.
 *
 * <h2>The label is provisional</h2>
 *
 * <p>The JCA hands no alias to a {@code KeyGenerator}: the caller names the key afterwards, through
 * {@code setKeyEntry}. The key is therefore created under a random label and relabelled by
 * {@link Kimbo11ngKeyStoreSpi#engineSetKeyEntry}, exactly as the key-pair path does. A crash
 * between the two leaves an orphan on the token under a {@code generated-<uuid>} label, which is
 * ugly but recognisable; the alternative — creating the object twice, or as a session object first
 * — is worse in ways that matter more.
 */
public final class Kimbo11ngKeyGeneratorSpi extends KeyGeneratorSpi {

    private static final Logger log = Logger.getLogger(Kimbo11ngKeyGeneratorSpi.class);

    private final P11Slot slot;
    private final SecretKeyType type;
    private int keyBits;

    public Kimbo11ngKeyGeneratorSpi(P11Slot slot, SecretKeyType type) {
        this.slot = slot;
        this.type = type;
        this.keyBits = type.defaultBits();
    }

    @Override
    protected void engineInit(SecureRandom random) {
        keyBits = type.defaultBits();
    }

    /**
     * Refused rather than ignored.
     *
     * <p>No {@code AlgorithmParameterSpec} means anything for the mechanisms here, and the JCA
     * gives us a checked exception the caller can act on. Accepting one silently would let a
     * caller believe a parameter had been honoured.
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(type.jcaName()
                + " on a PKCS#11 token takes no algorithm parameters; use init(int keysize).");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        try {
            keyBits = type.validateBits(keysize);
        } catch (IllegalArgumentException e) {
            // engineInit(int) declares nothing checked, and the JCA specifies
            // InvalidParameterException for a bad key size here.
            throw new java.security.InvalidParameterException(e.getMessage());
        }
    }

    @Override
    protected SecretKey engineGenerateKey() {
        // Rejected here rather than by the token: CKR_MECHANISM_INVALID from inside C_GenerateKey
        // names neither the mechanism nor the fact that another algorithm in the same table would
        // have worked. Same reasoning as requireMechanism on the key-pair path.
        if (!slot.capabilities().canGenerate(type.ckmKeyGen())) {
            throw new ProviderException("The token does not generate "
                    + type.jcaName() + " keys: it does not offer "
                    + ch.ithings.kimbo11ng.p11.TokenCapabilities.name(type.ckmKeyGen())
                    + " with CKF_GENERATE.");
        }
        byte[] keyId = KeyTemplates.newKeyId();
        String label = "generated-" + UUID.randomUUID();
        List<CKA> template = KeyTemplates.secret(label.getBytes(StandardCharsets.UTF_8), keyId,
                type, keyBits);
        try (SessionLease lease = slot.borrow()) {
            CryptokiE ce = slot.ce();
            long handle = ce.GenerateKey(lease.session(), new CKM(type.ckmKeyGen()),
                    template.toArray(new CKA[0]));
            if (log.isDebugEnabled()) {
                log.debug("Generated a " + keyBits + "-bit " + type.jcaName()
                        + " secret key: handle=" + handle + " label=" + label);
            }
            return new Kimbo11ngSecretKey(type.jcaName(), slot,
                    new P11KeyRef(keyId, label, null), handle);
        } catch (Exception e) {
            throw new ProviderException("Failed to generate a " + type.jcaName()
                    + " key on the token: " + e.getMessage(), e);
        }
    }
}

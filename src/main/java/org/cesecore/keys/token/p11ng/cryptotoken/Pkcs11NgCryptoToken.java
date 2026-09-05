/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package org.cesecore.keys.token.p11ng.cryptotoken;

import ch.ithings.kimbo11ng.CryptoTokenBridge;
import ch.ithings.kimbo11ng.CryptoTokenImpl;
import com.keyfactor.util.keys.CachingKeyStoreWrapper;
import com.keyfactor.util.keys.token.BaseCryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;
import com.keyfactor.util.keys.token.pkcs11.P11SlotUser;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;
import java.util.Set;

/**
 * PKCS#11 NG CryptoToken — EJBCA entry point.
 *
 * This FQN is hardcoded in CryptoTokenFactory; it must not be moved.
 * All logic is delegated to {@link CryptoTokenImpl}.
 */
public class Pkcs11NgCryptoToken extends BaseCryptoToken implements P11SlotUser, CryptoTokenBridge {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(Pkcs11NgCryptoToken.class);

    private transient CryptoTokenImpl impl;

    // The bridge is inherently self-referential: CryptoTokenImpl needs the protected
    // BaseCryptoToken methods this class exposes. It stores the reference without using it.
    @SuppressWarnings("this-escape")
    public Pkcs11NgCryptoToken() throws InstantiationException {
        super();
        impl = new CryptoTokenImpl(this);
        if (log.isDebugEnabled()) {
            log.debug("Pkcs11NgCryptoToken instantiated");
        }
    }

    @Override
    public void init(Properties properties, byte[] data, int id)
            throws NoSuchSlotException, CryptoTokenOfflineException {
        impl.init(properties, data, id);
    }

    @Override
    public void activate(char[] authCode)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        if (impl == null) {
            impl = new CryptoTokenImpl(this);
        }
        impl.activate(authCode);
    }

    @Override
    public void deactivate() {
        impl.deactivate();
        if (log.isDebugEnabled()) {
            log.debug("Pkcs11NgCryptoToken deactivated");
        }
    }

    @Override
    public void reset() {
        impl.reset();
    }

    @Override
    public byte[] getTokenData() {
        return null;
    }

    @Override
    public boolean permitExtractablePrivateKeyForTest() {
        return false;
    }

    @Override
    protected java.security.PublicKey readPublicKey(String alias, boolean includeHardToken)
            throws java.security.KeyStoreException, CryptoTokenOfflineException {
        java.security.PublicKey pubKey = impl.readPublicKey(alias, includeHardToken);
        if (pubKey != null) {
            return pubKey;
        }
        return super.readPublicKey(alias, includeHardToken);
    }

    // ---- CryptoTokenBridge (expose protected BaseCryptoToken methods) ----

    @Override
    public void bridgeSetKeyStore(java.security.KeyStore ks) throws java.security.KeyStoreException {
        setKeyStore(ks);
    }

    @Override
    public CachingKeyStoreWrapper bridgeGetKeyStore() {
        try {
            return getKeyStore();
        } catch (CryptoTokenOfflineException e) {
            return null;
        }
    }

    @Override
    public void bridgeSetJCAProvider(java.security.Provider provider) {
        setJCAProvider(provider);
    }

    @Override
    public void bridgeSetProperties(java.util.Properties properties) {
        setProperties(properties);
    }

    @Override
    public java.util.Properties bridgeGetProperties() {
        return getProperties();
    }

    @Override
    public void bridgeSetTokenName(String name) {
        setTokenName(name);
    }

    @Override
    public void bridgeSetId(int id) {
        setId(id);
    }

    // ---- P11SlotUser ----

    @Override
    public boolean isActive() {
        return getTokenStatus() == com.keyfactor.util.keys.token.CryptoToken.STATUS_ACTIVE;
    }

    // ---- Key management ----

    @Override
    public void deleteEntry(String alias)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException, CryptoTokenOfflineException {
        impl.deleteEntry(alias);
    }

    @Override
    public void generateKeyPair(KeyGenParams keyGenParams, String alias)
            throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        impl.generateKeyPair(keyGenParams, alias);
    }

    @Override
    public void generateKeyPair(String keySpec, String alias)
            throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        impl.generateKeyPair(keySpec, alias);
    }

    @Override
    public void generateKeyPair(AlgorithmParameterSpec spec, String alias)
            throws InvalidAlgorithmParameterException, CertificateException,
            IOException, CryptoTokenOfflineException {
        impl.generateKeyPair(spec, alias);
    }

    @Override
    public void generateKey(String algorithm, int keysize, String alias)
            throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
            CryptoTokenOfflineException {
        impl.generateKey(algorithm, keysize, alias);
    }

    @Override
    public Set<Long> getKeyUsagesFromKey(String alias, boolean isPrivate, long... keyUsages)
            throws CryptoTokenOfflineException {
        return impl.getKeyUsagesFromKey(alias, isPrivate, keyUsages);
    }

    @Override
    public Set<Long> getKeyUsagesFromPrivateKey(String alias) throws CryptoTokenOfflineException {
        return impl.getKeyUsagesFromKey(alias, true);
    }

    @Override
    public Set<Long> getKeyUsagesFromPublicKey(String alias) throws CryptoTokenOfflineException {
        return impl.getKeyUsagesFromKey(alias, false);
    }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng;

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
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;
import java.util.Set;

/**
 * The CryptoToken itself, under a name this project owns. All logic is delegated to
 * {@link CryptoTokenImpl}; this class exists to satisfy EJBCA's {@code BaseCryptoToken} contract
 * and to expose its protected methods through {@link CryptoTokenBridge}.
 *
 * <p><strong>Why this class is not in {@code org.cesecore.keys.token.p11ng.cryptotoken}.</strong>
 * That package belongs to Keyfactor, and CE 9.3.7 ships nothing in it — we supply the class EJBCA's
 * registry names. It works, and it is also the project's most fragile point: one stub class in a
 * future CE would occupy the name, and which of the two jars in {@code ejbca.ear/lib} wins is
 * unspecified. The canonical implementation therefore lives here, and
 * {@link org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken} is a thin subclass that
 * exists only to answer to the name EJBCA currently looks for.
 *
 * <p><strong>This FQN is not yet usable as a {@code tokenType} in the database.</strong>
 * {@code CryptoTokenSessionBean.getClassNameForType} resolves a stored type by scanning
 * {@code CryptoTokenFactory.getAvailableCryptoTokens()} for a registered class path that
 * {@code endsWith} it. Stock CE registers only the {@code p11ng} FQN, so a row naming this class
 * resolves to {@code null} and EJBCA substitutes a {@code NullCryptoToken} — silently. Keep
 * inserting the alias name until the registry carries an entry for this one.
 */
public class Kimbo11ngCryptoToken extends BaseCryptoToken implements P11SlotUser, CryptoTokenBridge {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(Kimbo11ngCryptoToken.class);

    private transient CryptoTokenImpl impl;

    // The bridge is inherently self-referential: CryptoTokenImpl needs the protected
    // BaseCryptoToken methods this class exposes. It stores the reference without using it.
    @SuppressWarnings("this-escape")
    public Kimbo11ngCryptoToken() throws InstantiationException {
        super();
        impl = new CryptoTokenImpl(this);
        if (log.isDebugEnabled()) {
            // getClass(), not a constant: the subclass alias should name itself in the log.
            log.debug(getClass().getSimpleName() + " instantiated");
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
            log.debug(getClass().getSimpleName() + " deactivated");
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
        return impl.getKeyUsagesFromPrivateKey(alias);
    }

    @Override
    public Set<Long> getKeyUsagesFromPublicKey(String alias) throws CryptoTokenOfflineException {
        return impl.getKeyUsagesFromPublicKey(alias);
    }

    /**
     * Refuses a key test that cannot mean anything before {@code BaseCryptoToken} picks a branch.
     *
     * <p>{@code testKeyPair} chooses between a signing test and an RSA-style encrypt/decrypt test
     * from the key-usage set. An ML-KEM key legitimately reports {@code CKA_DECRYPT} and no
     * {@code CKA_SIGN}, which selects the encryption branch — and key encapsulation is not
     * encryption, so the test fails inside a JCA {@code Cipher} with a message about padding.
     */
    @Override
    public void testKeyPair(String alias)
            throws InvalidKeyException, CryptoTokenOfflineException {
        impl.requireTestableKeyPair(alias);
        super.testKeyPair(alias);
    }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.fake;

import ch.ithings.kimbo11ng.CryptoTokenBridge;
import com.keyfactor.util.keys.CachingKeyStoreWrapper;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.util.Properties;

/**
 * Only the parts of {@code BaseCryptoToken} that {@code CryptoTokenImpl} calls back into.
 *
 * <p>The key store is wrapped in a real {@link CachingKeyStoreWrapper} rather than held directly,
 * because that wrapper caches {@code Key} objects indefinitely — a token that only worked with a
 * fresh look-up every time would pass a test that skipped it and fail inside EJBCA.
 */
public class TestBridge implements CryptoTokenBridge {

    private Properties properties = new Properties();
    private CachingKeyStoreWrapper keyStore;

    @Override
    public void bridgeSetKeyStore(KeyStore ks) throws KeyStoreException {
        this.keyStore = ks == null ? null : new CachingKeyStoreWrapper(ks, true);
    }

    @Override
    public CachingKeyStoreWrapper bridgeGetKeyStore() {
        return keyStore;
    }

    @Override
    public void bridgeSetJCAProvider(Provider provider) {
    }

    @Override
    public void bridgeSetProperties(Properties properties) {
        this.properties = properties;
    }

    @Override
    public Properties bridgeGetProperties() {
        return properties;
    }

    @Override
    public void bridgeSetTokenName(String name) {
    }

    @Override
    public void bridgeSetId(int id) {
    }
}

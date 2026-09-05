/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.CryptoTokenBridge;
import com.keyfactor.util.keys.CachingKeyStoreWrapper;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.util.Properties;

/**
 * The half of {@code BaseCryptoToken} that {@code CryptoTokenImpl} calls back into, outside a
 * container.
 *
 * <p>This is what lets the CLI drive the real crypto token rather than a parallel implementation of
 * it. Every command that generates, lists, tests or deletes a key goes through exactly the code
 * EJBCA runs, so what the tool reports is what the CA will do — which is the entire reason to have
 * the tool. A second implementation that merely called the same PKCS#11 functions would agree with
 * EJBCA right up until the moment it mattered.
 *
 * <p>The key store is wrapped in a real {@link CachingKeyStoreWrapper} for the same reason the test
 * bridge does it: that wrapper caches {@code Key} objects indefinitely, and a token that only
 * worked with a fresh lookup every time would pass here and fail inside EJBCA.
 *
 * <p>Three callbacks are deliberately inert. {@code bridgeSetJCAProvider} would register the
 * provider in {@code java.security.Security}; nothing here resolves providers by name, and the
 * command line sets {@code doNotAddP11Provider} so it is never called anyway. The token name and id
 * are EJBCA bookkeeping with no meaning in a process that holds one token.
 */
final class StandaloneBridge implements CryptoTokenBridge {

    private Properties properties = new Properties();
    private CachingKeyStoreWrapper keyStore;
    private Provider provider;

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
        this.provider = provider;
    }

    /** The provider the token installed, or {@code null} — which is the normal case here. */
    Provider provider() {
        return provider;
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

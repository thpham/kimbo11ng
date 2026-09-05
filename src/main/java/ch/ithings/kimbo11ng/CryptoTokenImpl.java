/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng;

import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.PqcMechanismProfile;
import ch.ithings.kimbo11ng.profile.ProfileResolver;
import ch.ithings.kimbo11ng.provider.CryptokiDevice;
import ch.ithings.kimbo11ng.provider.KeyTemplates;
import ch.ithings.kimbo11ng.provider.Kimbo11ngKeyStoreSpi;
import ch.ithings.kimbo11ng.provider.Kimbo11ngProvider;
import ch.ithings.kimbo11ng.provider.Kimbo11ngPublicKey;
import ch.ithings.kimbo11ng.provider.TokenRuntime;
import com.keyfactor.util.keys.CachingKeyStoreWrapper;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabelType;
import ch.ithings.kimbo11ng.slot.SlotListWrapper;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CryptokiE;
import org.pkcs11.jacknji11.LongRef;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Collections;
import java.util.Locale;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;

/**
 * The PKCS#11 NG crypto token. The EJBCA entry point
 * ({@code org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken}) is a thin delegate.
 */
public class CryptoTokenImpl {

    private static final Logger log = Logger.getLogger(CryptoTokenImpl.class);

    // Property keys, matching the PKCS11CryptoToken UI so a token can be configured the same way.
    public static final String SHLIB_LABEL_KEY = "sharedLibrary";
    public static final String SLOT_LABEL_VALUE = "slotLabelValue";
    public static final String SLOT_LABEL_TYPE = "slotLabelType";
    public static final String DO_NOT_ADD_P11_PROVIDER = "doNotAddP11Provider";
    public static final String TOKEN_FRIENDLY_NAME = "tokenFriendlyName";

    private final CryptoTokenBridge bridge;
    private volatile TokenRuntime runtime;
    private volatile Kimbo11ngProvider p11Provider;

    public CryptoTokenImpl(CryptoTokenBridge bridge) {
        this.bridge = bridge;
    }

    public void init(Properties properties, byte[] data, int id)
            throws NoSuchSlotException, CryptoTokenOfflineException {
        bridge.bridgeSetId(id);
        bridge.bridgeSetProperties(properties);
        initDevice(properties);

        String friendlyName = properties.getProperty(TOKEN_FRIENDLY_NAME);
        if (friendlyName != null && !friendlyName.isEmpty()) {
            bridge.bridgeSetTokenName(friendlyName);
        }
        if (log.isDebugEnabled()) {
            log.debug("Initialized token " + id + ": " + runtime
                    + " provider=" + p11Provider.getName());
        }
    }

    public void activate(char[] authCode)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        if (runtime == null) {
            try {
                initDevice(bridge.bridgeGetProperties());
            } catch (NoSuchSlotException e) {
                throw new CryptoTokenOfflineException("Slot not found during lazy init: "
                        + e.getMessage(), e);
            }
        }
        try {
            runtime.device().login(authCode);
            KeyStore ks = KeyStore.getInstance("PKCS11", p11Provider);
            ks.load(null, authCode);
            bridge.bridgeSetKeyStore(ks);
        } catch (CryptoTokenOfflineException e) {
            throw e;
        } catch (Exception e) {
            // TODO(phase-6): distinguish offline from bad credentials on the CKR code, and keep
            // the cause. CryptoTokenAuthenticationFailedException has no cause-carrying ctor.
            throw new CryptoTokenAuthenticationFailedException(
                    "Failed to activate the PKCS#11 NG token: " + e.getMessage());
        }
    }

    public void deactivate() {
        TokenRuntime current = runtime;
        if (current != null) {
            current.device().logout();
            Kimbo11ngKeyStoreSpi spi = current.keyStoreSpi();
            if (spi != null) {
                // Otherwise a deactivated token keeps handing out usable key handles.
                spi.clear();
            }
        }
        try {
            bridge.bridgeSetKeyStore(null);
        } catch (KeyStoreException e) {
            log.warn("Failed to clear the keystore on deactivate: " + e.getMessage());
        }
    }

    public void reset() {
        deactivate();
        TokenRuntime current = runtime;
        if (current != null) {
            current.device().close();
        }
    }

    /** Public key for an alias, or null so the caller can fall back to the certificate. */
    public PublicKey readPublicKey(String alias, boolean includeHardToken) {
        TokenRuntime current = runtime;
        Kimbo11ngKeyStoreSpi spi = current == null ? null : current.keyStoreSpi();
        return spi == null ? null : spi.getPublicKey(alias);
    }

    public void deleteEntry(String alias)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException, CryptoTokenOfflineException {
        if (bridge.bridgeGetKeyStore() == null) {
            throw new CryptoTokenOfflineException("Token is offline");
        }
        bridge.bridgeGetKeyStore().deleteEntry(alias);
    }

    public void generateKeyPair(KeyGenParams keyGenParams, String alias)
            throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        generateKeyPair(keyGenParams.getKeySpecification(), alias);
    }

    public void generateKeyPair(String keySpec, String alias)
            throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        bridge.bridgeGetKeyStore(); // triggers EJBCA's auto-activation if a PIN is configured
        TokenRuntime current = runtime;
        if (current == null) {
            throw new CryptoTokenOfflineException("Token is not initialized");
        }
        try {
            byte[] label = alias.getBytes(StandardCharsets.UTF_8);
            byte[] keyId = KeyTemplates.newKeyId();
            String upper = keySpec.toUpperCase(Locale.ROOT);

            if (keySpec.matches("\\d+") || upper.startsWith("RSA")) {
                generateRsa(current, label, keyId, parseRsaKeySize(keySpec), alias);
                return;
            }
            Optional<AlgorithmEntry> entry = current.profile().lookup(keySpec);
            if (entry.isPresent()) {
                generatePqc(current, label, keyId, entry.get(), alias);
                return;
            }
            generateEc(current, label, keyId, curveNameOf(keySpec), alias);
        } catch (InvalidAlgorithmParameterException e) {
            throw e;
        } catch (Exception e) {
            log.error("Key generation failed (keySpec=" + keySpec + " alias=" + alias + "): "
                    + e.getMessage(), e);
            throw new CryptoTokenOfflineException("Failed to generate key pair: " + e.getMessage());
        }
    }

    public void generateKeyPair(AlgorithmParameterSpec spec, String alias)
            throws InvalidAlgorithmParameterException, CertificateException,
            IOException, CryptoTokenOfflineException {
        if (spec instanceof ECGenParameterSpec ecSpec) {
            generateKeyPair(ecSpec.getName(), alias);
        } else if (spec instanceof RSAKeyGenParameterSpec rsaSpec) {
            generateKeyPair("RSA" + rsaSpec.getKeysize(), alias);
        } else {
            throw new InvalidAlgorithmParameterException(
                    "Unsupported spec type: " + spec.getClass().getName());
        }
    }

    public void generateKey(String algorithm, int keysize, String alias)
            throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
            CryptoTokenOfflineException {
        if (bridge.bridgeGetKeyStore() == null) {
            throw new CryptoTokenOfflineException("Token is offline or not activated");
        }
        throw new KeyStoreException("Symmetric key generation is not implemented");
    }

    public Set<Long> getKeyUsagesFromKey(String alias, boolean isPrivate, long... keyUsages) {
        // TODO(phase-6): read CKA_SIGN/DECRYPT/UNWRAP/ENCRYPT/VERIFY/WRAP/DERIVE. This is
        // load-bearing: BaseCryptoToken.testKeyPair branches on 0x105 (decrypt) and 0x108 (sign),
        // so an empty set makes it choose an RSA-style encryption test for every key.
        return Collections.emptySet();
    }

    // ---- generation ----

    private void generateRsa(TokenRuntime current, byte[] label, byte[] keyId, int bits,
            String alias) throws Exception {
        KeyTemplates.Pair templates = KeyTemplates.rsa(label, keyId, bits);
        long[] handles = generatePair(current, templates, CKM.RSA_PKCS_KEY_PAIR_GEN);
        CryptokiE ce = current.device().getCe();
        long session = current.device().getOrOpenSession();
        PublicKey publicKey = Kimbo11ngPublicKey.readRsaPublicKey(ce, session, handles[0]);
        register(current, alias, handles[1], "RSA", null, publicKey);
        log.info("Generated RSA-" + bits + " key pair '" + alias + "'");
    }

    private void generateEc(TokenRuntime current, byte[] label, byte[] keyId, String curveName,
            String alias) throws Exception {
        KeyTemplates.Pair templates = KeyTemplates.ec(label, keyId, curveName);
        long[] handles = generatePair(current, templates, CKM.EC_KEY_PAIR_GEN);
        CryptokiE ce = current.device().getCe();
        long session = current.device().getOrOpenSession();
        PublicKey publicKey = Kimbo11ngPublicKey.readEcPublicKey(ce, session, handles[0]);
        register(current, alias, handles[1], "EC", null, publicKey);
        log.info("Generated EC key pair '" + alias + "' on curve " + curveName);
    }

    private void generatePqc(TokenRuntime current, byte[] label, byte[] keyId,
            AlgorithmEntry entry, String alias) throws Exception {
        KeyTemplates.Pair templates = KeyTemplates.pqc(label, keyId, entry, current.profile());
        long[] handles = generatePair(current, templates, entry.ckmKeyPairGen());
        CryptokiE ce = current.device().getCe();
        long session = current.device().getOrOpenSession();
        // The entry is passed rather than re-derived from the token, so the OID recorded in the
        // SubjectPublicKeyInfo is the one the key was actually generated as.
        PublicKey publicKey = Kimbo11ngPublicKey.readPqcPublicKey(ce, session, handles[0], entry);
        register(current, alias, handles[1], entry.family().jcaName(), entry, publicKey);
        log.info("Generated " + entry.canonicalName() + " key pair '" + alias + "'");
    }

    /** @return {@code {publicHandle, privateHandle}} */
    private long[] generatePair(TokenRuntime current, KeyTemplates.Pair templates, long mechanism)
            throws Exception {
        CryptokiDevice device = current.device();
        long session = device.getOrOpenSession();
        CryptokiE ce = device.getCe();
        LongRef pubRef = new LongRef();
        LongRef privRef = new LongRef();
        // TODO(phase-2): replaced by a borrowed session lease.
        synchronized (device) {
            ce.GenerateKeyPair(session, new CKM(mechanism),
                    templates.pub(), templates.priv(), pubRef, privRef);
        }
        return new long[] {pubRef.value(), privRef.value()};
    }

    private void register(TokenRuntime current, String alias, long privHandle, String algorithm,
            AlgorithmEntry entry, PublicKey publicKey) {
        Kimbo11ngKeyStoreSpi spi = current.keyStoreSpi();
        if (spi != null) {
            spi.registerGeneratedKeyPair(alias, privHandle, algorithm, entry, publicKey);
        } else if (log.isDebugEnabled()) {
            log.debug("No KeyStore SPI yet; '" + alias + "' will appear on the next enumeration");
        }
        refreshKeyStoreCache(alias);
    }

    /**
     * Makes a freshly generated key visible to EJBCA.
     *
     * <p>{@code BaseCryptoToken.setKeyStore} wraps our KeyStore in a {@code CachingKeyStoreWrapper}
     * whose alias list is built once, at construction. EJBCA populates that cache through
     * {@code KeyStore.setKeyEntry}, but a key generated on the token is never set through the
     * KeyStore API, so the cache does not learn about it and {@code ca init} fails with
     * "No key with alias" for a key that demonstrably exists. Handing the same underlying KeyStore
     * back to {@code setKeyStore} rebuilds the wrapper and its cache.
     *
     * <p>TODO(phase-3): unwrapping the wrapper to re-wrap it is a cache-busting hack resting on a
     * deprecated accessor. Once a key is resolved from the token by {@code CKA_ID} on demand, there
     * is no cache to bust and this goes away.
     */
    @SuppressWarnings("deprecation")
    private void refreshKeyStoreCache(String alias) {
        try {
            CachingKeyStoreWrapper wrapper = bridge.bridgeGetKeyStore();
            if (wrapper != null) {
                bridge.bridgeSetKeyStore(wrapper.getKeyStore());
            }
        } catch (Exception e) {
            // Not fatal: the alias reappears on the next activation, which re-enumerates.
            log.warn("Could not refresh the keystore cache after generating '" + alias
                    + "'; it may not be visible until the token is reactivated: " + e.getMessage());
        }
    }

    // ---- init ----

    private void initDevice(Properties properties)
            throws NoSuchSlotException, CryptoTokenOfflineException {
        String libPath = properties.getProperty(SHLIB_LABEL_KEY);
        if (libPath == null || libPath.isEmpty()) {
            throw new CryptoTokenOfflineException(
                    "Property '" + SHLIB_LABEL_KEY + "' is required");
        }
        String slotLabelValue = properties.getProperty(SLOT_LABEL_VALUE, "0");
        Pkcs11SlotLabelType slotLabelType = Pkcs11SlotLabelType.getFromKey(
                properties.getProperty(SLOT_LABEL_TYPE, Pkcs11SlotLabelType.SLOT_INDEX.getKey()));
        if (slotLabelType == null) {
            slotLabelType = Pkcs11SlotLabelType.SLOT_INDEX;
        }

        long slotId;
        try {
            slotId = resolveSlotId(libPath, slotLabelType, slotLabelValue);
        } catch (NoSuchSlotException e) {
            throw e;
        } catch (Exception e) {
            throw new NoSuchSlotException("Failed to resolve slot: " + e.getMessage(), e);
        }

        PqcMechanismProfile profile = ProfileResolver.resolve(properties);
        TokenRuntime newRuntime = new TokenRuntime(new CryptokiDevice(libPath, slotId), profile);
        // Same provider object per (library, slot); only the runtime behind it changes.
        Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(newRuntime);
        this.runtime = newRuntime;
        this.p11Provider = provider;

        if (!Boolean.parseBoolean(properties.getProperty(DO_NOT_ADD_P11_PROVIDER, "false"))) {
            // BaseCryptoToken.setJCAProvider registers it in java.security.Security and throws if
            // the name cannot then be resolved, so registration is EJBCA's job, not ours.
            bridge.bridgeSetJCAProvider(provider);
        }
    }

    private long resolveSlotId(String libPath, Pkcs11SlotLabelType labelType, String labelValue)
            throws Exception {
        // TODO(phase-2): route through the module registry so the library is initialized once.
        SlotListWrapper wrapper = new SlotListWrapper(libPath);
        long[] slots = wrapper.getSlotList();
        if (slots == null || slots.length == 0) {
            throw new NoSuchSlotException("No slots found in library: " + libPath);
        }
        if (labelType == Pkcs11SlotLabelType.SLOT_NUMBER) {
            return Long.parseLong(labelValue);
        }
        if (labelType == Pkcs11SlotLabelType.SLOT_INDEX) {
            int index = Integer.parseInt(labelValue);
            if (index < 0 || index >= slots.length) {
                throw new NoSuchSlotException("Slot index " + index + " out of range (0-"
                        + (slots.length - 1) + ")");
            }
            return slots[index];
        }
        if (labelType == Pkcs11SlotLabelType.SLOT_LABEL) {
            for (long slotId : slots) {
                char[] label = wrapper.getTokenLabel(slotId);
                if (label != null && new String(label).trim().equals(labelValue.trim())) {
                    return slotId;
                }
            }
            throw new NoSuchSlotException("No slot found with label: " + labelValue);
        }
        return slots[0];
    }

    /** Strips an optional {@code EC} prefix EJBCA sometimes prepends to a curve name. */
    private static String curveNameOf(String keySpec) {
        String upper = keySpec.toUpperCase(Locale.ROOT);
        if (upper.startsWith("EC") && keySpec.length() > 2 && !upper.startsWith("ECDSA")) {
            return keySpec.substring(2).trim();
        }
        return keySpec;
    }

    private static int parseRsaKeySize(String keySpec) {
        if (keySpec.toUpperCase(Locale.ROOT).startsWith("RSA")) {
            String size = keySpec.substring(3).trim();
            return size.isEmpty() ? 2048 : Integer.parseInt(size);
        }
        return Integer.parseInt(keySpec);
    }

    public Kimbo11ngProvider getProvider() {
        return p11Provider;
    }

    public CryptokiDevice getDevice() {
        TokenRuntime current = runtime;
        return current == null ? null : current.device();
    }

    public PqcMechanismProfile getPqcProfile() {
        TokenRuntime current = runtime;
        return current == null ? null : current.profile();
    }
}

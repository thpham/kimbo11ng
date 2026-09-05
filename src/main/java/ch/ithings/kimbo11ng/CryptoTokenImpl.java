/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng;

import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.p11.Pkcs11Errors;
import ch.ithings.kimbo11ng.p11.Pkcs11Module;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import ch.ithings.kimbo11ng.p11.SessionLease;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.PqcMechanismProfile;
import ch.ithings.kimbo11ng.profile.ProfileResolver;
import ch.ithings.kimbo11ng.provider.KeyTemplates;
import ch.ithings.kimbo11ng.provider.P11KeyRef;
import ch.ithings.kimbo11ng.provider.Kimbo11ngKeyStoreSpi;
import ch.ithings.kimbo11ng.provider.Kimbo11ngProvider;
import ch.ithings.kimbo11ng.provider.Kimbo11ngPrivateKey;
import ch.ithings.kimbo11ng.provider.Kimbo11ngPublicKey;
import ch.ithings.kimbo11ng.provider.TokenRuntime;
import com.keyfactor.util.keys.CachingKeyStoreWrapper;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabelType;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
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
    private final Pkcs11ModuleRegistry modules;
    private volatile TokenRuntime runtime;
    private volatile Kimbo11ngProvider p11Provider;

    public CryptoTokenImpl(CryptoTokenBridge bridge) {
        this(bridge, Pkcs11ModuleRegistry.shared());
    }

    /** For tests, which supply a registry backed by a fake token. */
    public CryptoTokenImpl(CryptoTokenBridge bridge, Pkcs11ModuleRegistry modules) {
        this.bridge = bridge;
        this.modules = modules;
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
            // P11Slot.login classifies the CKR itself, so a missing token surfaces as offline and
            // only a rejected credential surfaces as an authentication failure. Previously every
            // failure here — including "no token in slot" — was reported as a bad PIN.
            runtime.slot().login(authCode);
            KeyStore ks = KeyStore.getInstance("PKCS11", p11Provider);
            ks.load(null, authCode);
            bridge.bridgeSetKeyStore(ks);
        } catch (CryptoTokenOfflineException | CryptoTokenAuthenticationFailedException e) {
            throw e;
        } catch (Exception e) {
            throw Pkcs11Errors.offline("Failed to activate the PKCS#11 NG token", e);
        }
    }

    /**
     * Takes the token offline for real.
     *
     * <p>Order matters and is the point of the method. The keystore goes first so nothing new can
     * be started, then the cached key handles are dropped, then the token is logged out. Doing it
     * the other way round leaves a window in which EJBCA hands out a key whose session has already
     * lost its authentication, and the signature fails somewhere unrelated.
     *
     * <p>Sessions are deliberately left open: logout ends the authentication, which is what
     * "deactivated" means, and keeping the sessions means a later activate does not have to
     * rebuild the pool. {@link #reset()} is what releases them.
     */
    public void deactivate() {
        try {
            bridge.bridgeSetKeyStore(null);
        } catch (KeyStoreException e) {
            log.warn("Failed to clear the keystore on deactivate: " + e.getMessage());
        }
        TokenRuntime current = runtime;
        if (current != null) {
            Kimbo11ngKeyStoreSpi spi = current.keyStoreSpi();
            if (spi != null) {
                // Otherwise a deactivated token keeps handing out usable key handles.
                spi.clear();
            }
            current.slot().logout();
        }
    }

    /** Deactivates, then drains the session pool. The library itself stays initialized. */
    public void reset() {
        deactivate();
        TokenRuntime current = runtime;
        if (current != null) {
            current.slot().close();
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
            requireAliasFree(current, alias);
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

    /**
     * Refuses to generate over an alias the token already uses.
     *
     * <p>PKCS#11 has no uniqueness constraint on {@code CKA_LABEL}, so without this the token ends
     * up holding two private keys with the same name. Everything then still appears to work —
     * enumeration picks one of them, arbitrarily — until a restart picks the other and the CA
     * signs with a key its certificate does not match.
     *
     * <p>The token is asked, not the local cache: another node, or an operator with a vendor tool,
     * may have created the key since this instance last enumerated.
     */
    private void requireAliasFree(TokenRuntime current, String alias)
            throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        try (SessionLease lease = current.slot().borrow()) {
            long[] existing = current.slot().ce().FindObjects(lease.session(),
                    new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
                    new CKA(CKA.LABEL, alias.getBytes(StandardCharsets.UTF_8)));
            if (existing != null && existing.length > 0) {
                throw new InvalidAlgorithmParameterException("The token already holds a private"
                        + " key with the alias '" + alias + "'. Delete it first, or choose another"
                        + " alias; generating a second key with the same label would leave two"
                        + " keys that cannot be told apart.");
            }
        }
    }

    private void generateRsa(TokenRuntime current, byte[] label, byte[] keyId, int bits,
            String alias) throws Exception {
        KeyTemplates.Pair templates = KeyTemplates.rsa(label, keyId, bits);
        generateAndRegister(current, templates, keyId, CKM.RSA_PKCS_KEY_PAIR_GEN, alias, "RSA",
                null, Kimbo11ngPublicKey::readRsaPublicKey);
        log.info("Generated RSA-" + bits + " key pair '" + alias + "'");
    }

    private void generateEc(TokenRuntime current, byte[] label, byte[] keyId, String curveName,
            String alias) throws Exception {
        KeyTemplates.Pair templates = KeyTemplates.ec(label, keyId, curveName);
        generateAndRegister(current, templates, keyId, CKM.EC_KEY_PAIR_GEN, alias, "EC", null,
                Kimbo11ngPublicKey::readEcPublicKey);
        log.info("Generated EC key pair '" + alias + "' on curve " + curveName);
    }

    private void generatePqc(TokenRuntime current, byte[] label, byte[] keyId,
            AlgorithmEntry entry, String alias) throws Exception {
        KeyTemplates.Pair templates = KeyTemplates.pqc(label, keyId, entry, current.profile());
        // The entry is passed rather than re-derived from the token, so the OID recorded in the
        // SubjectPublicKeyInfo is the one the key was actually generated as.
        generateAndRegister(current, templates, keyId, entry.ckmKeyPairGen(), alias,
                entry.family().jcaName(), entry,
                (ce, session, handle) -> Kimbo11ngPublicKey.readPqcPublicKey(ce, session, handle,
                        entry));
        log.info("Generated " + entry.canonicalName() + " key pair '" + alias + "'");
    }

    /** Reads a freshly generated public key from its object handle. */
    @FunctionalInterface
    private interface PublicKeyReader {
        PublicKey read(CryptokiE ce, long session, long handle) throws Exception;
    }

    /**
     * Generates a pair and reads its public key under a single session lease.
     *
     * <p>One lease for both steps, because the public-key handle is only meaningful in the session
     * that produced it: reading it on a different session is a different object table and, on some
     * modules, a different handle entirely.
     */
    private void generateAndRegister(TokenRuntime current, KeyTemplates.Pair templates,
            byte[] keyId, long mechanism, String alias, String algorithm, AlgorithmEntry entry,
            PublicKeyReader reader) throws Exception {
        long privHandle;
        PublicKey publicKey;
        try (SessionLease lease = current.slot().borrow()) {
            CryptokiE ce = current.slot().ce();
            LongRef pubRef = new LongRef();
            LongRef privRef = new LongRef();
            ce.GenerateKeyPair(lease.session(), new CKM(mechanism),
                    templates.pub(), templates.priv(), pubRef, privRef);
            privHandle = privRef.value();
            publicKey = reader.read(ce, lease.session(), pubRef.value());
        }
        register(current, new P11KeyRef(keyId, alias, entry), privHandle, algorithm, publicKey);
    }

    private void register(TokenRuntime current, P11KeyRef ref, long privHandle, String algorithm,
            PublicKey publicKey) {
        Kimbo11ngKeyStoreSpi spi = current.keyStoreSpi();
        if (spi != null) {
            spi.registerGeneratedKeyPair(ref.label(), ref, privHandle, algorithm, publicKey);
        } else if (log.isDebugEnabled()) {
            log.debug("No KeyStore SPI yet; '" + ref.label()
                    + "' will appear on the next enumeration");
        }
        refreshKeyStoreCache(ref.label());
    }

    /**
     * Makes a freshly generated key visible to EJBCA.
     *
     * <p>{@code BaseCryptoToken.setKeyStore} wraps our KeyStore in a {@code CachingKeyStoreWrapper}
     * whose alias list is a {@code HashMap} built once, at construction, and updated only through
     * {@code setKeyEntry} and {@code deleteEntry}. A key generated on the token never passes
     * through the KeyStore API, so the cache does not learn about it and {@code ca init} fails with
     * "No key with alias" for a key that demonstrably exists. Handing the same underlying KeyStore
     * back to {@code setKeyStore} rebuilds the wrapper and its cache.
     *
     * <p>The obvious alternative does not work: {@code CachingKeyStoreWrapper.setKeyEntry} would
     * update the cache directly, but {@code KeyStore.setKeyEntry} refuses a {@code PrivateKey}
     * without a certificate chain, and we have none. EJBCA's own {@code KeyStoreTools} gets around
     * that by minting a self-signed placeholder certificate with the new key — which an ML-KEM key
     * cannot do, because it cannot sign. So the rebuild stays.
     *
     * <p>It is cheap because {@code engineGetCertificate} answers without touching the token: the
     * rebuild reads only this SPI's in-memory maps. Were it to search the token per alias, every
     * key generation would cost one search per key already on it.
     *
     * <p>{@code getKeyStore()} is deprecated in EJBCA, and this is the one call that needs it. If
     * a future EJBCA removes it, the fallback is EJBCA's own approach in {@code KeyStoreTools}:
     * mint a self-signed placeholder certificate so {@code setKeyEntry} accepts the key. That is
     * not used here because an ML-KEM key cannot sign one.
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
        P11Slot slot = modules.get(libPath).slot(slotId, properties);
        boolean backfill = Boolean.parseBoolean(
                properties.getProperty(TokenRuntime.BACKFILL_KEY_IDS, "true"));
        TokenRuntime newRuntime = new TokenRuntime(slot, profile, backfill);
        // The signing path can see that the HSM is gone but cannot act on it; clearing EJBCA's
        // keystore is what stops work being routed to a CA whose token is not answering, and what
        // lets autoActivate() log in again with the PIN EJBCA holds and we do not.
        slot.onOffline((reason, cause) -> takeOffline(reason));
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

    /** Clears the keystore so EJBCA treats this token as offline and re-activates it later. */
    private void takeOffline(String reason) {
        try {
            bridge.bridgeSetKeyStore(null);
            TokenRuntime current = runtime;
            if (current != null && current.keyStoreSpi() != null) {
                current.keyStoreSpi().clear();
            }
            log.warn("Token taken offline: " + reason);
        } catch (KeyStoreException e) {
            log.error("Could not take the token offline after " + reason + ": " + e.getMessage(), e);
        }
    }

    private long resolveSlotId(String libPath, Pkcs11SlotLabelType labelType, String labelValue)
            throws Exception {
        // Through the registry, so this shares one C_Initialize with the slot-list wrapper EJBCA
        // asks for separately. Previously resolving a slot and then opening it initialized the
        // same library two or three times.
        Pkcs11Module module = modules.get(libPath);
        long[] slots = module.slotList();
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
                char[] label = module.tokenLabel(slotId);
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

    public P11Slot getSlot() {
        TokenRuntime current = runtime;
        return current == null ? null : current.slot();
    }

    public PqcMechanismProfile getPqcProfile() {
        TokenRuntime current = runtime;
        return current == null ? null : current.profile();
    }
}

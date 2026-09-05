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
import ch.ithings.kimbo11ng.p11.SlotResolver;
import ch.ithings.kimbo11ng.p11.TokenCapabilities;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.AlgorithmSupport;
import ch.ithings.kimbo11ng.profile.PqcMechanismProfile;
import ch.ithings.kimbo11ng.profile.ProfileResolver;
import ch.ithings.kimbo11ng.provider.KeyTemplates;
import ch.ithings.kimbo11ng.provider.P11KeyRef;
import ch.ithings.kimbo11ng.provider.Kimbo11ngKeyStoreSpi;
import ch.ithings.kimbo11ng.provider.Kimbo11ngProvider;
import ch.ithings.kimbo11ng.provider.Kimbo11ngSecretKey;
import ch.ithings.kimbo11ng.provider.PublicKeyReader;
import ch.ithings.kimbo11ng.provider.SecretKeyType;
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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

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

    /**
     * Logs in and publishes a keystore, which is what EJBCA reads as "online".
     *
     * <p>{@code authCode} is <b>not</b> zeroed here, and must not be. The array belongs to
     * {@code BaseCryptoToken}, which keeps it in {@code mAuthCode} and hands the same instance back
     * on every {@code autoActivate()} — the mechanism that brings a token back after it goes
     * offline. Clearing it would make the first recovery attempt log in with a PIN of NUL
     * characters and lock the token's user PIN after a few tries. The copy this code does own is
     * the encoded byte array inside {@link ch.ithings.kimbo11ng.p11.Pins}, which is zeroed in a
     * {@code finally} at the point of use.
     */
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
                requireMechanism(current, CKM.RSA_PKCS_KEY_PAIR_GEN, keySpec);
                generateRsa(current, label, keyId, parseRsaKeySize(keySpec), alias);
                return;
            }
            Optional<AlgorithmEntry> entry = current.profile().lookup(keySpec);
            if (entry.isPresent()) {
                requirePqcSupported(current, entry.get());
                generatePqc(current, label, keyId, entry.get(), alias);
                return;
            }
            String curveName = curveNameOf(keySpec);
            requireCurveOrBetterProfile(current, keySpec, curveName);
            requireMechanism(current, CKM.EC_KEY_PAIR_GEN, keySpec);
            generateEc(current, label, keyId, curveName, alias);
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

    /**
     * Generates a secret key on the token.
     *
     * <p>Two calls, in the order EJBCA's own {@code KeyStoreTools.generateKey} makes them: the JCA
     * hands no alias to a {@code KeyGenerator}, so the key is created under a provisional label and
     * named by {@code setKeyEntry}. Going through the JCA rather than calling {@code C_GenerateKey}
     * here is deliberate — it is the same path {@code PKCS11CryptoToken} takes, so a caller that
     * reaches the provider directly and one that comes through the crypto token get the same key.
     *
     * <p>The only consumer of this method in EJBCA is database protection, whose HMAC key this is.
     * In Community Edition nothing calls it: the one call site,
     * {@code org.cesecore.dbprotection.CachedCryptoToken}, is a pass-through that CE never
     * constructs. It is implemented anyway because the interface promises it, and because a
     * promise kept only until someone relies on it is worse than no promise.
     *
     * @param algorithm one of {@link SecretKeyType#names()}
     * @param keysize in bits, or 0 for the algorithm's default
     */
    public void generateKey(String algorithm, int keysize, String alias)
            throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
            CryptoTokenOfflineException {
        CachingKeyStoreWrapper keyStore = bridge.bridgeGetKeyStore();
        if (keyStore == null) {
            throw new CryptoTokenOfflineException("Token is offline or not activated");
        }
        TokenRuntime current = runtime;
        if (current == null) {
            throw new CryptoTokenOfflineException("Token is not initialized");
        }
        SecretKeyType type = SecretKeyType.lookup(algorithm)
                .orElseThrow(() -> new NoSuchAlgorithmException("'" + algorithm + "' is not a"
                        + " secret-key algorithm this token offers. Available: "
                        + SecretKeyType.names() + "."));
        if (!type.usableHere()) {
            // Generating it would succeed and produce a key nothing in this JVM could use: the key
            // is CKA_SENSITIVE and not CKA_EXTRACTABLE, and this provider registers no Cipher. Say
            // so now rather than leave an unusable object on the token.
            throw new NoSuchAlgorithmException(type.jcaName() + " keys can be generated on the"
                    + " token, but this provider offers no Cipher service to use one with, and the"
                    + " key is not extractable — so the key would be unusable. Use one of "
                    + SecretKeyType.names().stream().filter(n -> !n.equals(type.jcaName())).toList()
                    + ", which are backed by a Mac service.");
        }
        // Validated here rather than left to the generator, so a bad key size reports itself as a
        // bad key size. Going through KeyGenerator.init would surface it as an unchecked
        // InvalidParameterException wrapped in "failed to generate a key on the token", which
        // blames the token for the caller's argument.
        int bits;
        try {
            bits = type.validateBits(keysize);
        } catch (IllegalArgumentException e) {
            throw new KeyStoreException(e.getMessage(), e);
        }
        requireSecretAliasFree(current, alias);

        SecretKey key;
        try {
            KeyGenerator generator = KeyGenerator.getInstance(type.jcaName(), p11Provider);
            generator.init(bits);
            key = generator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw e;
        } catch (Exception e) {
            log.error("Secret key generation failed (algorithm=" + algorithm + " keysize=" + keysize
                    + " alias=" + alias + "): " + e.getMessage(), e);
            throw new KeyStoreException("Failed to generate a " + type.jcaName() + " key on the"
                    + " token: " + e.getMessage(), e);
        }
        // Names the key and puts the alias into the wrapper's cache in one step, so unlike the
        // key-pair path this needs no cache rebuild afterwards. The cache write happens only if the
        // naming succeeded, which is why the failure must not be swallowed further down.
        try {
            keyStore.setKeyEntry(alias, key, null, null);
        } catch (KeyStoreException e) {
            destroyUnnamed(current, key, alias);
            throw e;
        }
        log.info("Generated a " + type.jcaName() + " secret key '" + alias + "'");
    }

    /**
     * Destroys a secret key that was generated here and could not then be named.
     *
     * <p>Done here rather than inside {@code setSecretKeyEntry}, and the distinction is the whole
     * safety argument: this method created the object seconds ago, under a provisional
     * {@code generated-<uuid>} label, and nothing holds a reference to it. The keystore's naming
     * path cannot know that — a caller may equally be renaming a key that has served a CA for
     * years, and destroying that because a relabel was refused would be unrecoverable.
     *
     * <p>Best effort: a token that will not accept an attribute write may not accept a destroy
     * either. What is left then is an unusable {@code CKA_SENSITIVE} object under a label no alias
     * names, so the log has to carry that label for the operator to clean up by hand.
     */
    private void destroyUnnamed(TokenRuntime current, SecretKey key, String alias) {
        if (!(key instanceof Kimbo11ngSecretKey p11Key)) {
            return;
        }
        try (SessionLease lease = current.slot().borrow()) {
            CryptokiE ce = current.slot().ce();
            ce.DestroyObject(lease.session(), p11Key.objectHandle(ce, lease.session()));
            current.slot().invalidateHandles();
        } catch (Exception e) {
            log.error("Generated a secret key for '" + alias + "', could not name it, and could"
                    + " not destroy it either" + Pkcs11Errors.describe(e) + ". An unusable object"
                    + " is left on the token as " + p11Key.ref() + "; remove it with a vendor"
                    + " tool.", e);
        }
    }

    /**
     * Refuses an alias the token already uses for a secret key.
     *
     * <p>The counterpart of {@link #requireAliasFree}, and there for the same reason: PKCS#11 puts
     * no uniqueness constraint on {@code CKA_LABEL}, so without this the token ends up with two
     * secret keys of the same name and enumeration picks one of them arbitrarily. Private keys are
     * checked too — one alias must not name two different kinds of key.
     */
    private void requireSecretAliasFree(TokenRuntime current, String alias)
            throws KeyStoreException, CryptoTokenOfflineException {
        try (SessionLease lease = current.slot().borrow()) {
            byte[] label = alias.getBytes(StandardCharsets.UTF_8);
            for (long objectClass : new long[] {CKO.SECRET_KEY, CKO.PRIVATE_KEY}) {
                long[] existing = current.slot().ce().FindObjects(lease.session(),
                        new CKA(CKA.CLASS, objectClass), new CKA(CKA.LABEL, label));
                if (existing != null && existing.length > 0) {
                    throw new KeyStoreException("The token already holds a key with the alias '"
                            + alias + "'. Delete it first, or choose another alias.");
                }
            }
        }
    }

    /**
     * The {@code CKA_*} usage attributes EJBCA reasons about for a private key.
     *
     * <p>Two, not seven, and the restriction is the point. Both EJBCA consumers treat the returned
     * set as a closed vocabulary of exactly these:
     * {@code BaseCryptoToken.testKeyPair} asks {@code contains(261) && !contains(264)}, and
     * {@code CryptoTokenManagementSessionBean.getKeyUsageStringForKeyPairInfo} compares the set for
     * <em>equality</em> against {@code {261}}, {@code {264}} and {@code {261,264}}, mapping them to
     * the three {@code KeyPairInfo.KeyUsage} values and to {@code null} otherwise. Adding
     * {@code CKA_UNWRAP} — which every RSA key here has — would make that equality never match, and
     * the admin UI would show no key usage at all: worse than the empty set this replaces.
     */
    private static final long[] PRIVATE_KEY_USAGES = {CKA.DECRYPT, CKA.SIGN};

    /** The public-key counterparts. Nothing in EJBCA CE reads these; they are here to be true. */
    private static final long[] PUBLIC_KEY_USAGES = {CKA.ENCRYPT, CKA.VERIFY};

    /** Everything a private key may be marked for, when a caller asks without naming any. */
    private static final long[] ALL_PRIVATE_USAGES = {
            CKA.DECRYPT, CKA.SIGN, CKA.SIGN_RECOVER, CKA.UNWRAP, CKA.DERIVE};

    /** Everything a public key may be marked for. */
    private static final long[] ALL_PUBLIC_USAGES = {
            CKA.ENCRYPT, CKA.VERIFY, CKA.VERIFY_RECOVER, CKA.WRAP, CKA.DERIVE};

    /** @see #PRIVATE_KEY_USAGES */
    public Set<Long> getKeyUsagesFromPrivateKey(String alias) throws CryptoTokenOfflineException {
        return getKeyUsagesFromKey(alias, true, PRIVATE_KEY_USAGES);
    }

    /** @see #PUBLIC_KEY_USAGES */
    public Set<Long> getKeyUsagesFromPublicKey(String alias) throws CryptoTokenOfflineException {
        return getKeyUsagesFromKey(alias, false, PUBLIC_KEY_USAGES);
    }

    /**
     * Which of {@code keyUsages} the token has actually set on this key.
     *
     * <p>Read from the object rather than inferred from the algorithm, because the two can differ:
     * a key imported by a vendor tool, or generated by an earlier version of this code, carries
     * whatever template it was created with. What EJBCA does with the answer is decide which test
     * to run against the pair, so guessing here means running a signing test on a decryption key.
     *
     * @param keyUsages the {@code CKA_*} attributes to ask about; empty means every usage attribute
     *                  defined for the key's class
     */
    public Set<Long> getKeyUsagesFromKey(String alias, boolean isPrivate, long... keyUsages)
            throws CryptoTokenOfflineException {
        TokenRuntime current = runtime;
        if (current == null) {
            return Collections.emptySet();
        }
        long[] wanted = (keyUsages == null || keyUsages.length == 0)
                ? (isPrivate ? ALL_PRIVATE_USAGES : ALL_PUBLIC_USAGES)
                : keyUsages;
        long objectClass = isPrivate ? CKO.PRIVATE_KEY : CKO.PUBLIC_KEY;
        try (SessionLease lease = current.slot().borrow()) {
            CryptokiE ce = current.slot().ce();
            long handle = findObject(current, ce, lease.session(), objectClass, alias);
            if (handle < 0) {
                // Not an error: EJBCA asks for every alias it knows, including ones whose public
                // half a token may not hold.
                if (log.isDebugEnabled()) {
                    log.debug("No " + (isPrivate ? "private" : "public") + " key object for alias '"
                            + alias + "'; reporting no usages");
                }
                return Collections.emptySet();
            }
            Set<Long> usages = new TreeSet<>();
            for (long cka : wanted) {
                if (isAttributeTrue(ce, lease.session(), handle, cka)) {
                    usages.add(cka);
                }
            }
            return usages;
        } catch (CryptoTokenOfflineException e) {
            throw e;
        } catch (Exception e) {
            throw Pkcs11Errors.offline(
                    "Could not read the key usages for alias '" + alias + "'", e);
        }
    }

    /**
     * One attribute per call, deliberately.
     *
     * <p>A bulk {@code C_GetAttributeValue} returns non-zero if <em>any</em> requested type is
     * invalid for the object, and jacknji11 turns any non-zero return into an exception — so one
     * attribute a token does not implement would lose the answers for all the others.
     */
    private static boolean isAttributeTrue(CryptokiE ce, long session, long handle, long cka) {
        try {
            return Boolean.TRUE.equals(ce.GetAttributeValue(session, handle, cka).getValueBool());
        } catch (Exception e) {
            // CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_SENSITIVE, or a value that is not a
            // one-byte CK_BBOOL. In every case the token is not telling us this usage is granted,
            // and "not granted" is the safe reading.
            if (log.isDebugEnabled()) {
                log.debug("Attribute 0x" + Long.toHexString(cka) + " unreadable on handle " + handle
                        + ": " + e.getMessage());
            }
            return false;
        }
    }

    /**
     * The object handle for one half of an alias's key pair.
     *
     * <p>By {@code CKA_ID} through the enumerated {@link P11KeyRef} when the alias is known, which
     * is what pairs a public key with its private half even after one of them was relabelled.
     * Falls back to a label search for an alias this instance has not enumerated.
     */
    private long findObject(TokenRuntime current, CryptokiE ce, long session, long objectClass,
            String alias) {
        Kimbo11ngKeyStoreSpi spi = current.keyStoreSpi();
        P11KeyRef ref = spi == null ? null : spi.referenceFor(alias);
        long[] found = ref != null
                ? ref.findAll(ce, session, objectClass, true)
                : ce.FindObjects(session, new CKA(CKA.CLASS, objectClass),
                        new CKA(CKA.LABEL, alias.getBytes(StandardCharsets.UTF_8)));
        return (found == null || found.length == 0) ? -1 : found[0];
    }

    /**
     * Refuses a key test EJBCA cannot perform, before it picks the wrong one.
     *
     * <p>{@code BaseCryptoToken.testKeyPair} has exactly two branches — sign, or encrypt/decrypt
     * with a JCA {@code Cipher} — chosen from the usage set. An ML-KEM key reports
     * {@code CKA_DECRYPT} and no {@code CKA_SIGN}, so it lands in the encryption branch, and
     * key encapsulation is not RSA encryption: the test fails with a {@code Cipher} error that
     * says nothing about why. There is no third branch to add from here, so the honest answer is
     * to say so.
     */
    public void requireTestableKeyPair(String alias) throws InvalidKeyException {
        TokenRuntime current = runtime;
        Kimbo11ngKeyStoreSpi spi = current == null ? null : current.keyStoreSpi();
        if (spi == null) {
            return;
        }
        if (spi.isSecretKey(alias)) {
            throw new InvalidKeyException("Alias '" + alias + "' names a secret key, which has no"
                    + " public half and therefore no key pair to test.");
        }
        Optional<AlgorithmEntry> entry = spi.algorithmFor(alias);
        if (entry.isPresent() && !entry.get().canSign()) {
            throw new InvalidKeyException("Key '" + alias + "' is "
                    + entry.get().canonicalName() + ", a key-encapsulation algorithm. EJBCA's key"
                    + " test can either sign or encrypt, and neither is a KEM operation, so there"
                    + " is nothing here to test. The key pair was generated on the token and is"
                    + " enumerated normally.");
        }
    }

    // ---- generation ----

    /**
     * Refuses a post-quantum algorithm the probe excluded, naming the reason.
     *
     * <p>What this replaces: {@code ca init} with an ML-DSA-65 key on a token whose firmware does
     * not have the mechanism produced {@code CKR_MECHANISM_INVALID} from inside
     * {@code C_GenerateKeyPair}, with nothing naming the mechanism, the algorithm, or the fact that
     * fifteen other algorithms in the same profile would have worked.
     */
    private void requirePqcSupported(TokenRuntime current, AlgorithmEntry entry)
            throws InvalidAlgorithmParameterException {
        String reason = current.algorithms().rejectionReason(entry.canonicalName());
        if (reason == null) {
            return;
        }
        if (!current.algorithms().failFast()) {
            log.warn("Generating a " + entry.canonicalName() + " key even though " + reason
                    + " (" + TokenCapabilities.PROBE_FAIL_FAST + "=false). If the token rejects the"
                    + " mechanism, this is why.");
            return;
        }
        throw new InvalidAlgorithmParameterException(entry.canonicalName()
                + " cannot be generated on this token: " + reason + ". The profile in use is '"
                + current.profile().name() + "'; algorithms this token does offer are listed in"
                + " the log at token initialisation. Set " + TokenCapabilities.PROBE_FAIL_FAST
                + "=false to attempt it anyway.");
    }

    /**
     * Catches a key specification that is neither a curve nor an algorithm the active profile
     * describes, and says which profile would have described it.
     *
     * <p>Anything not RSA and not in the profile falls through to the EC path, so a token
     * configured with the wrong profile answered a request for ML-DSA-65 with "string ML-DSA-65 is
     * not an OID" — an accurate statement about the EC branch and no help at all about the actual
     * mistake, which is one property.
     */
    private void requireCurveOrBetterProfile(TokenRuntime current, String keySpec, String curveName)
            throws InvalidAlgorithmParameterException {
        if (KeyTemplates.isKnownCurve(curveName)) {
            return;
        }
        // Only on the failure path, so the ServiceLoader scan costs nothing in normal operation.
        // Every profile that knows the algorithm is named, not the first one found: which of them
        // is right for this HSM is the operator's call, and picking one to suggest would be the
        // same guess this phase exists to remove.
        List<String> knownTo = ProfileResolver.available().stream()
                .filter(p -> p.lookup(keySpec).isPresent())
                .map(PqcMechanismProfile::name)
                .sorted()
                .toList();
        if (!knownTo.isEmpty()) {
            throw new InvalidAlgorithmParameterException("'" + keySpec + "' is not a curve name,"
                    + " and the profile in use ('" + current.profile().name() + "') does not"
                    + " describe it. These profiles do: " + knownTo + ". Set "
                    + ProfileResolver.PROFILE_PROPERTY + " to whichever matches this HSM, or"
                    + " remove it and let the capability probe choose.");
        }
        throw new InvalidAlgorithmParameterException("'" + keySpec + "' is neither a curve name"
                + " this provider recognises nor an algorithm described by any installed profile"
                + " (in use: '" + current.profile().name() + "').");
    }

    /** The same check for RSA and EC, where the mechanism is fixed and there is no profile row. */
    private void requireMechanism(TokenRuntime current, long ckm, String keySpec)
            throws InvalidAlgorithmParameterException {
        AlgorithmSupport algorithms = current.algorithms();
        if (algorithms.capabilities().canGenerateKeyPair(ckm)) {
            return;
        }
        String message = "the token does not offer key-pair generation with "
                + TokenCapabilities.name(ckm);
        if (!algorithms.failFast()) {
            log.warn("Generating a '" + keySpec + "' key even though " + message + " ("
                    + TokenCapabilities.PROBE_FAIL_FAST + "=false).");
            return;
        }
        throw new InvalidAlgorithmParameterException("Cannot generate a '" + keySpec
                + "' key: " + message + ". Set " + TokenCapabilities.PROBE_FAIL_FAST
                + "=false to attempt it anyway.");
    }

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
     *
     * <p>Secret keys are checked too, exactly as {@link #requireSecretAliasFree} checks private
     * ones: one alias must not name two different kinds of key. {@code engineAliases} answers a
     * union and {@code engineSize} a sum, so an alias in both maps makes EJBCA see a keystore with
     * two entries and only one alias to reach them by.
     */
    private void requireAliasFree(TokenRuntime current, String alias)
            throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        try (SessionLease lease = current.slot().borrow()) {
            byte[] label = alias.getBytes(StandardCharsets.UTF_8);
            for (long objectClass : new long[] {CKO.PRIVATE_KEY, CKO.SECRET_KEY}) {
                long[] existing = current.slot().ce().FindObjects(lease.session(),
                        new CKA(CKA.CLASS, objectClass), new CKA(CKA.LABEL, label));
                if (existing != null && existing.length > 0) {
                    throw new InvalidAlgorithmParameterException("The token already holds a key"
                            + " with the alias '" + alias + "'. Delete it first, or choose another"
                            + " alias; generating a second key with the same label would leave two"
                            + " keys that cannot be told apart.");
                }
            }
        }
    }

    private void generateRsa(TokenRuntime current, byte[] label, byte[] keyId, int bits,
            String alias) throws Exception {
        KeyTemplates.Pair templates = KeyTemplates.rsa(label, keyId, bits);
        generateAndRegister(current, templates, keyId, CKM.RSA_PKCS_KEY_PAIR_GEN, alias, "RSA",
                null, PublicKeyReader::readRsaPublicKey);
        log.info("Generated RSA-" + bits + " key pair '" + alias + "'");
    }

    private void generateEc(TokenRuntime current, byte[] label, byte[] keyId, String curveName,
            String alias) throws Exception {
        KeyTemplates.Pair templates = KeyTemplates.ec(label, keyId, curveName);
        generateAndRegister(current, templates, keyId, CKM.EC_KEY_PAIR_GEN, alias, "EC", null,
                PublicKeyReader::readEcPublicKey);
        log.info("Generated EC key pair '" + alias + "' on curve " + curveName);
    }

    private void generatePqc(TokenRuntime current, byte[] label, byte[] keyId,
            AlgorithmEntry entry, String alias) throws Exception {
        KeyTemplates.Pair templates = KeyTemplates.pqc(label, keyId, entry, current.profile());
        // The entry is passed rather than re-derived from the token, so the OID recorded in the
        // SubjectPublicKeyInfo is the one the key was actually generated as.
        generateAndRegister(current, templates, keyId, entry.ckmKeyPairGen(), alias,
                entry.family().jcaName(), entry,
                (ce, session, handle) -> PublicKeyReader.readPqcPublicKey(ce, session, handle,
                        entry));
        log.info("Generated " + entry.canonicalName() + " key pair '" + alias + "'");
    }

    /** Reads a freshly generated public key from its object handle. */
    @FunctionalInterface
    private interface PublicKeyFetch {
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
            PublicKeyFetch reader) throws Exception {
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

        P11Slot slot = modules.get(libPath).slot(slotId, properties);
        // Before anything else is decided: a slot-level call, so it needs no session and no PIN,
        // which is what lets the algorithm table be settled at init rather than at first use.
        TokenCapabilities capabilities = slot.capabilities();
        PqcMechanismProfile profile = ProfileResolver.resolve(properties, capabilities);
        boolean failFast = Boolean.parseBoolean(
                properties.getProperty(TokenCapabilities.PROBE_FAIL_FAST, "true"));
        AlgorithmSupport algorithms = AlgorithmSupport.compute(profile, capabilities, failFast);
        log.info(algorithms.describe());

        boolean backfill = Boolean.parseBoolean(
                properties.getProperty(TokenRuntime.BACKFILL_KEY_IDS, "true"));
        // Lenient by default, and only for enumeration — generation is always strict. The one
        // thing this relaxes is a token that labels an existing key with a different OID than the
        // one we resolved, which happens for real: a token from the NIST draft era uses the
        // pre-standard ML-DSA OIDs. The length check still runs, so a key of the wrong parameter
        // set is still refused; what is allowed through is a naming disagreement on a key whose
        // material is right. An operator who wants that to be fatal sets the property.
        PublicKeyReader.Policy policy = Boolean.parseBoolean(properties.getProperty(
                PublicKeyReader.STRICT_PUBLIC_KEY, "false"))
                ? PublicKeyReader.Policy.STRICT
                : PublicKeyReader.Policy.LENIENT;
        TokenRuntime newRuntime = new TokenRuntime(slot, algorithms, backfill, policy);
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
        //
        // The resolution itself lives in SlotResolver because the CLI has to reach the same answer;
        // see that class for why a second implementation would be a hazard rather than a duplicate.
        return SlotResolver.resolve(modules.get(libPath), labelType, labelValue);
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

    /**
     * True if this alias names a {@code CKO_SECRET_KEY} rather than a key pair.
     *
     * <p>Exists because EJBCA has no such concept: every alias it sees through
     * {@code CryptoToken.getAliases} is assumed to be a key pair, and some of what it does with that
     * assumption is not recoverable. See {@code Kimbo11ngCryptoToken.getPrivateKey}.
     */
    public boolean isSecretKey(String alias) {
        TokenRuntime current = runtime;
        Kimbo11ngKeyStoreSpi spi = current == null ? null : current.keyStoreSpi();
        return spi != null && spi.isSecretKey(alias);
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

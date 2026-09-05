/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng;

import ch.ithings.kimbo11ng.profile.PqcMechanismProfile;
import ch.ithings.kimbo11ng.profile.ProfileResolver;
import ch.ithings.kimbo11ng.provider.CryptokiDevice;
import ch.ithings.kimbo11ng.provider.Kimbo11ngKeyStoreSpi;
import ch.ithings.kimbo11ng.provider.Kimbo11ngProvider;
import ch.ithings.kimbo11ng.provider.Kimbo11ngPublicKey;
import ch.ithings.kimbo11ng.slot.SlotListWrapper;
import com.keyfactor.util.keys.CachingKeyStoreWrapper;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabelType;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CryptokiE;
import org.pkcs11.jacknji11.LongRef;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;
import java.util.Set;

/**
 * Core implementation of the PKCS#11 NG CryptoToken.
 * All business logic lives here; the EJBCA entry point
 * ({@code org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken})
 * is a thin delegate that extends BaseCryptoToken and forwards to this class.
 */
public class CryptoTokenImpl {

    private static final Logger log = Logger.getLogger(CryptoTokenImpl.class);

    // Property keys (compatible with PKCS11CryptoToken UI)
    public static final String SHLIB_LABEL_KEY = "sharedLibrary";
    public static final String SLOT_LABEL_VALUE = "slotLabelValue";
    public static final String SLOT_LABEL_TYPE = "slotLabelType";
    public static final String PASSWORD_LABEL_KEY = "pin";
    public static final String ATTRIB_LABEL_KEY = "attributesFile";
    public static final String DO_NOT_ADD_P11_PROVIDER = "doNotAddP11Provider";
    public static final String TOKEN_FRIENDLY_NAME = "tokenFriendlyName";

    private final CryptoTokenBridge bridge;
    private CryptokiDevice device;
    private Kimbo11ngProvider p11Provider;
    private PqcMechanismProfile pqcProfile;

    public CryptoTokenImpl(CryptoTokenBridge bridge) {
        this.bridge = bridge;
    }

    public void init(Properties properties, byte[] data, int id) throws NoSuchSlotException, CryptoTokenOfflineException {
        if (log.isDebugEnabled()) {
            log.debug("Initializing CryptoTokenImpl id=" + id);
        }
        bridge.bridgeSetId(id);
        bridge.bridgeSetProperties(properties);
        initDevice(properties);

        String friendlyName = properties.getProperty(TOKEN_FRIENDLY_NAME);
        if (friendlyName != null && !friendlyName.isEmpty()) {
            bridge.bridgeSetTokenName(friendlyName);
        }

        if (log.isDebugEnabled()) {
            log.debug("CryptoTokenImpl initialized: lib=" + properties.getProperty(SHLIB_LABEL_KEY) +
                    " provider=" + p11Provider.getName() + " pqcProfile=" + pqcProfile);
        }
    }

    public void activate(char[] authCode)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        if (device == null) {
            try {
                log.info("CryptoTokenImpl.activate: device is null, calling initDevice");
                initDevice(bridge.bridgeGetProperties());
            } catch (NoSuchSlotException e) {
                throw new CryptoTokenOfflineException("Slot not found during lazy init: " + e.getMessage(), e);
            } catch (Exception e) {
                throw new CryptoTokenOfflineException("initDevice failed: " + e.getMessage(), e);
            }
        }
        try {
            device.login(authCode);
            KeyStore ks = KeyStore.getInstance("PKCS11", p11Provider);
            ks.load(null, authCode);
            bridge.bridgeSetKeyStore(ks);
            if (log.isDebugEnabled()) {
                log.debug("CryptoTokenImpl activated successfully");
            }
        } catch (CryptoTokenOfflineException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoTokenAuthenticationFailedException(
                    "Failed to activate PKCS#11 NG token: " + e.getMessage());
        }
    }

    public void deactivate() {
        if (device != null) {
            device.logout();
        }
        try {
            bridge.bridgeSetKeyStore(null);
        } catch (KeyStoreException e) {
            log.warn("Failed to clear keystore on deactivate: " + e.getMessage());
        }
    }

    public void reset() {
        deactivate();
        if (device != null) {
            device.close();
        }
    }

    // ---- Public key lookup without certificate ----

    public java.security.PublicKey readPublicKey(String alias, boolean includeHardToken)
            throws java.security.KeyStoreException, CryptoTokenOfflineException {
        Kimbo11ngKeyStoreSpi spi = p11Provider != null ? p11Provider.getKeyStoreSpi() : null;
        if (spi != null) {
            java.security.PublicKey pubKey = spi.getPublicKey(alias);
            if (pubKey != null) {
                return pubKey;
            }
        }
        return null; // caller falls back to super.readPublicKey()
    }

    // ---- Key management ----

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
        log.info("CryptoTokenImpl.generateKeyPair(KeyGenParams) called, alias=" + alias +
                " device=" + (device != null ? "set" : "null") +
                " p11Provider=" + (p11Provider != null ? p11Provider.getName() : "null"));
        generateKeyPair(keyGenParams.getKeySpecification(), alias);
    }

    public void generateKeyPair(String keySpec, String alias)
            throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        bridge.bridgeGetKeyStore(); // triggers autoActivate
        try {
            long session = device.getOrOpenSession();
            CryptokiE ce = device.getCe();
            byte[] labelBytes = alias.getBytes("UTF-8");

            if (keySpec.startsWith("RSA") || keySpec.matches("\\d+")) {
                generateRsaKeyPair(ce, session, labelBytes, keySpec, alias);
            } else if (keySpec.startsWith("EC") || keySpec.startsWith("secp") ||
                       keySpec.startsWith("P-") || keySpec.startsWith("prime")) {
                generateEcKeyPair(ce, session, labelBytes, keySpec, alias);
            } else if (pqcProfile.supports(keySpec)) {
                String normalized = keySpec.toUpperCase().replace("-", "").replace("_", "");
                if (normalized.startsWith("MLDSA")) {
                    generateMlDsaKeyPair(ce, session, labelBytes, keySpec, alias);
                } else if (normalized.startsWith("MLKEM")) {
                    generateMlKemKeyPair(ce, session, labelBytes, keySpec, alias);
                } else if (normalized.startsWith("SLHDSA")) {
                    generateSlhDsaKeyPair(ce, session, labelBytes, keySpec, alias);
                } else {
                    throw new InvalidAlgorithmParameterException("Unsupported PQC key specification: " + keySpec);
                }
            } else {
                throw new InvalidAlgorithmParameterException("Unsupported key specification: " + keySpec);
            }
        } catch (InvalidAlgorithmParameterException e) {
            log.error("InvalidAlgorithmParameterException generating key pair: " + e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            log.error("Exception generating key pair (keySpec=" + keySpec + " alias=" + alias + "): " + e.getMessage(), e);
            throw new CryptoTokenOfflineException("Failed to generate key pair: " + e.getMessage());
        }
    }

    public void generateKeyPair(AlgorithmParameterSpec spec, String alias)
            throws InvalidAlgorithmParameterException, CertificateException,
            IOException, CryptoTokenOfflineException {
        if (spec instanceof java.security.spec.ECGenParameterSpec) {
            generateKeyPair("EC" + ((java.security.spec.ECGenParameterSpec) spec).getName(), alias);
        } else if (spec instanceof java.security.spec.RSAKeyGenParameterSpec) {
            generateKeyPair("RSA" + ((java.security.spec.RSAKeyGenParameterSpec) spec).getKeysize(), alias);
        } else {
            throw new InvalidAlgorithmParameterException("Unsupported spec type: " + spec.getClass().getName());
        }
    }

    public void generateKey(String algorithm, int keysize, String alias)
            throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
            CryptoTokenOfflineException {
        if (bridge.bridgeGetKeyStore() == null) {
            throw new CryptoTokenOfflineException("Token is offline or not activated");
        }
        throw new KeyStoreException("Symmetric key generation not yet implemented");
    }

    public Set<Long> getKeyUsagesFromKey(String alias, boolean isPrivate, long... keyUsages) {
        return java.util.Collections.emptySet();
    }

    // ---- Private helpers ----

    private void generateRsaKeyPair(CryptokiE ce, long session, byte[] labelBytes,
            String keySpec, String alias) throws Exception {
        int keySize = parseRsaKeySize(keySpec);
        CKA[] pubTemplate = {
            new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
            new CKA(CKA.KEY_TYPE, CKK.RSA),
            new CKA(CKA.LABEL, labelBytes),
            new CKA(CKA.MODULUS_BITS, (long) keySize),
            new CKA(CKA.PUBLIC_EXPONENT, java.math.BigInteger.valueOf(65537).toByteArray()),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.VERIFY, true),
            new CKA(CKA.ENCRYPT, true),
            new CKA(CKA.WRAP, true)
        };
        CKA[] privTemplate = {
            new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
            new CKA(CKA.KEY_TYPE, CKK.RSA),
            new CKA(CKA.LABEL, labelBytes),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.DECRYPT, true),
            new CKA(CKA.UNWRAP, true)
        };
        LongRef pubRef = new LongRef();
        LongRef privRef = new LongRef();
        synchronized (device) {
            ce.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN),
                    pubTemplate, privTemplate, pubRef, privRef);
        }
        log.info("Generated RSA-" + keySize + " key pair on HSM with alias=" + alias +
                " privHandle=" + privRef.value() + " pubHandle=" + pubRef.value());
        java.security.PublicKey rsaPubKey = Kimbo11ngPublicKey.readRsaPublicKey(ce, session, pubRef.value());
        registerKeyPairInSpi(alias, privRef.value(), "RSA", rsaPubKey);
    }

    private void generateEcKeyPair(CryptokiE ce, long session, byte[] labelBytes,
            String keySpec, String alias) throws Exception {
        String curveName = keySpec.startsWith("EC") ? keySpec.substring(2).trim() : keySpec;
        byte[] ecParamsDer = encodeEcParams(curveName);
        CKA[] pubTemplate = {
            new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
            new CKA(CKA.KEY_TYPE, CKK.EC),
            new CKA(CKA.LABEL, labelBytes),
            new CKA(CKA.EC_PARAMS, ecParamsDer),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.VERIFY, true)
        };
        CKA[] privTemplate = {
            new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
            new CKA(CKA.KEY_TYPE, CKK.EC),
            new CKA(CKA.LABEL, labelBytes),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.SIGN, true)
        };
        LongRef pubRef = new LongRef();
        LongRef privRef = new LongRef();
        synchronized (device) {
            ce.GenerateKeyPair(session, new CKM(CKM.EC_KEY_PAIR_GEN),
                    pubTemplate, privTemplate, pubRef, privRef);
        }
        log.info("Generated EC key pair (curve=" + curveName + ") on HSM with alias=" + alias +
                " privHandle=" + privRef.value() + " pubHandle=" + pubRef.value());
        java.security.PublicKey ecPubKey = Kimbo11ngPublicKey.readEcPublicKey(ce, session, pubRef.value());
        registerKeyPairInSpi(alias, privRef.value(), "EC", ecPubKey);
    }

    private void generateMlDsaKeyPair(CryptokiE ce, long session, byte[] labelBytes,
            String keySpec, String alias) throws Exception {
        long paramSet = pqcProfile.resolveMlDsaParamSet(keySpec);
        CKA[] pubTemplate = {
            new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
            new CKA(CKA.KEY_TYPE, pqcProfile.ckkMlDsa()),
            new CKA(CKA.LABEL, labelBytes),
            new CKA(pqcProfile.ckaParameterSet(), paramSet),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.VERIFY, true)
        };
        CKA[] privTemplate = {
            new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
            new CKA(CKA.KEY_TYPE, pqcProfile.ckkMlDsa()),
            new CKA(CKA.LABEL, labelBytes),
            new CKA(pqcProfile.ckaParameterSet(), paramSet),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.SIGN, true)
        };
        LongRef pubRef = new LongRef();
        LongRef privRef = new LongRef();
        synchronized (device) {
            ce.GenerateKeyPair(session, new CKM(pqcProfile.ckmMlDsaKeyPairGen()),
                    pubTemplate, privTemplate, pubRef, privRef);
        }
        log.info("Generated ML-DSA key pair (" + keySpec + ") on HSM with alias=" + alias +
                " privHandle=" + privRef.value() + " pubHandle=" + pubRef.value());
        java.security.PublicKey pubKey = Kimbo11ngPublicKey.readPqcPublicKey(ce, session, pubRef.value(), keySpec);
        registerKeyPairInSpi(alias, privRef.value(), "ML-DSA", pubKey);
    }

    private void generateMlKemKeyPair(CryptokiE ce, long session, byte[] labelBytes,
            String keySpec, String alias) throws Exception {
        long paramSet = pqcProfile.resolveMlKemParamSet(keySpec);
        CKA[] pubTemplate = {
            new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
            new CKA(CKA.KEY_TYPE, pqcProfile.ckkMlKem()),
            new CKA(CKA.LABEL, labelBytes),
            new CKA(pqcProfile.ckaParameterSet(), paramSet),
            new CKA(CKA.TOKEN, true)
        };
        CKA[] privTemplate = {
            new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
            new CKA(CKA.KEY_TYPE, pqcProfile.ckkMlKem()),
            new CKA(CKA.LABEL, labelBytes),
            new CKA(pqcProfile.ckaParameterSet(), paramSet),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.EXTRACTABLE, false)
        };
        LongRef pubRef = new LongRef();
        LongRef privRef = new LongRef();
        synchronized (device) {
            ce.GenerateKeyPair(session, new CKM(pqcProfile.ckmMlKemKeyPairGen()),
                    pubTemplate, privTemplate, pubRef, privRef);
        }
        log.info("Generated ML-KEM key pair (" + keySpec + ") on HSM with alias=" + alias +
                " privHandle=" + privRef.value() + " pubHandle=" + pubRef.value());
        java.security.PublicKey pubKey = Kimbo11ngPublicKey.readPqcPublicKey(ce, session, pubRef.value(), keySpec);
        registerKeyPairInSpi(alias, privRef.value(), "ML-KEM", pubKey);
    }

    private void generateSlhDsaKeyPair(CryptokiE ce, long session, byte[] labelBytes,
            String keySpec, String alias) throws Exception {
        long paramSet = pqcProfile.resolveSlhDsaParamSet(keySpec);
        CKA[] pubTemplate = {
            new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
            new CKA(CKA.KEY_TYPE, pqcProfile.ckkSlhDsa()),
            new CKA(CKA.LABEL, labelBytes),
            new CKA(pqcProfile.ckaParameterSet(), paramSet),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.VERIFY, true)
        };
        CKA[] privTemplate = {
            new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
            new CKA(CKA.KEY_TYPE, pqcProfile.ckkSlhDsa()),
            new CKA(CKA.LABEL, labelBytes),
            new CKA(pqcProfile.ckaParameterSet(), paramSet),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.SIGN, true)
        };
        LongRef pubRef = new LongRef();
        LongRef privRef = new LongRef();
        synchronized (device) {
            ce.GenerateKeyPair(session, new CKM(pqcProfile.ckmSlhDsaKeyPairGen()),
                    pubTemplate, privTemplate, pubRef, privRef);
        }
        log.info("Generated SLH-DSA key pair (" + keySpec + ") on HSM with alias=" + alias +
                " privHandle=" + privRef.value() + " pubHandle=" + pubRef.value());
        java.security.PublicKey pubKey = Kimbo11ngPublicKey.readPqcPublicKey(ce, session, pubRef.value(), keySpec);
        registerKeyPairInSpi(alias, privRef.value(), "SLH-DSA", pubKey);
    }

    // TODO(phase-3): unwrapping the CachingKeyStoreWrapper to re-wrap it is a cache-busting hack
    // that relies on a deprecated accessor. Registering the key by CKA_ID removes the need.
    @SuppressWarnings("deprecation")
    private void registerKeyPairInSpi(String alias, long privHandle, String algorithm,
            java.security.PublicKey pubKey) {
        Kimbo11ngKeyStoreSpi spi = p11Provider != null ? p11Provider.getKeyStoreSpi() : null;
        if (spi != null) {
            spi.registerGeneratedKeyPair(alias, privHandle, algorithm, pubKey);
        }
        try {
            java.security.KeyStore underlying = bridge.bridgeGetKeyStore().getKeyStore();
            bridge.bridgeSetKeyStore(underlying);
        } catch (Exception e) {
            log.warn("Could not refresh keystore cache after key generation: " + e.getMessage());
        }
    }

    private void initDevice(Properties properties) throws NoSuchSlotException, CryptoTokenOfflineException {
        String libPath = properties.getProperty(SHLIB_LABEL_KEY);
        if (libPath == null || libPath.isEmpty()) {
            throw new CryptoTokenOfflineException("Property '" + SHLIB_LABEL_KEY + "' is required");
        }
        String slotLabelValue = properties.getProperty(SLOT_LABEL_VALUE, "0");
        String slotLabelTypeStr = properties.getProperty(SLOT_LABEL_TYPE,
                Pkcs11SlotLabelType.SLOT_INDEX.getKey());
        Pkcs11SlotLabelType slotLabelType = Pkcs11SlotLabelType.getFromKey(slotLabelTypeStr);
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
        device = new CryptokiDevice(libPath, slotId);
        p11Provider = new Kimbo11ngProvider(device);
        pqcProfile = ProfileResolver.resolve(properties, device);

        boolean doNotAdd = Boolean.parseBoolean(
                properties.getProperty(DO_NOT_ADD_P11_PROVIDER, "false"));
        if (!doNotAdd) {
            if (Security.getProvider(p11Provider.getName()) == null) {
                Security.addProvider(p11Provider);
            }
        }
        bridge.bridgeSetJCAProvider(p11Provider);
    }

    private long resolveSlotId(String libPath, Pkcs11SlotLabelType labelType, String labelValue)
            throws Exception {
        SlotListWrapper wrapper = new SlotListWrapper(libPath);
        long[] slots = wrapper.getSlotList();
        if (slots == null || slots.length == 0) {
            throw new NoSuchSlotException("No slots found in library: " + libPath);
        }
        if (labelType == Pkcs11SlotLabelType.SLOT_NUMBER) {
            return Long.parseLong(labelValue);
        } else if (labelType == Pkcs11SlotLabelType.SLOT_INDEX) {
            int idx = Integer.parseInt(labelValue);
            if (idx < 0 || idx >= slots.length) {
                throw new NoSuchSlotException("Slot index " + idx + " out of range (0-" + (slots.length - 1) + ")");
            }
            return slots[idx];
        } else if (labelType == Pkcs11SlotLabelType.SLOT_LABEL) {
            for (long slotId : slots) {
                char[] label = wrapper.getTokenLabel(slotId);
                if (label != null && new String(label).trim().equals(labelValue.trim())) {
                    return slotId;
                }
            }
            throw new NoSuchSlotException("No slot found with label: " + labelValue);
        } else {
            return slots[0];
        }
    }

    private static byte[] encodeEcParams(String curveName) throws Exception {
        String oid = resolveEcOid(curveName);
        return new ASN1ObjectIdentifier(oid).getEncoded();
    }

    private static String resolveEcOid(String name) {
        switch (name.toUpperCase().replace("-", "").replace("_", "")) {
            case "P256": case "SECP256R1": case "PRIME256V1": return "1.2.840.10045.3.1.7";
            case "P384": case "SECP384R1": return "1.3.132.0.34";
            case "P521": case "SECP521R1": return "1.3.132.0.35";
            case "SECP256K1": return "1.3.132.0.10";
            case "BRAINPOOLP256R1": return "1.3.36.3.3.2.8.1.1.7";
            case "BRAINPOOLP384R1": return "1.3.36.3.3.2.8.1.1.11";
            case "BRAINPOOLP512R1": return "1.3.36.3.3.2.8.1.1.13";
            default:
                org.bouncycastle.asn1.x9.X9ECParameters x9 = ECNamedCurveTable.getByName(name);
                if (x9 != null) {
                    ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID(name);
                    if (oid != null) return oid.getId();
                }
                return name;
        }
    }

    private static int parseRsaKeySize(String keySpec) {
        if (keySpec.startsWith("RSA")) {
            String sizeStr = keySpec.substring(3).trim();
            if (sizeStr.isEmpty()) return 2048;
            return Integer.parseInt(sizeStr);
        }
        return Integer.parseInt(keySpec);
    }

    public Kimbo11ngProvider getProvider() {
        return p11Provider;
    }

    public CryptokiDevice getDevice() {
        return device;
    }

    public PqcMechanismProfile getPqcProfile() {
        return pqcProfile;
    }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.CkULong;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.PqcMechanismProfile;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CryptokiE;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.ConcurrentHashMap;

/**
 * KeyStore over a PKCS#11 token.
 *
 * <p>Key algorithms are resolved through the profile's algorithm table rather than a hardcoded
 * set of {@code CKK} values, so a token using vendor key types is read correctly.
 *
 * <p>The maps are concurrent because EJBCA generates keys on one thread and signs on others.
 */
public final class Kimbo11ngKeyStoreSpi extends KeyStoreSpi {

    private static final Logger log = Logger.getLogger(Kimbo11ngKeyStoreSpi.class);

    private final TokenRuntime runtime;
    private final Map<String, Kimbo11ngPrivateKey> privateKeys = new ConcurrentHashMap<>();
    private final Map<String, PublicKey> publicKeys = new ConcurrentHashMap<>();

    public Kimbo11ngKeyStoreSpi(TokenRuntime runtime) {
        this.runtime = runtime;
    }

    private CryptokiDevice device() {
        return runtime.device();
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws UnrecoverableKeyException {
        return privateKeys.get(alias);
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        // EJBCA keeps issued certificates in its database, not on the token.
        return null;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        // Previously this searched the token and discarded the result, costing a round trip for
        // nothing. TODO(phase-3): parse CKA_VALUE into an X509Certificate when one is present.
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        // TODO(phase-3): read CKA_START_DATE. Returning 'now' was worse than returning nothing.
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
        if (!(key instanceof Kimbo11ngPrivateKey p11Key)) {
            return;
        }
        try {
            long session = device().getOrOpenSession();
            CryptokiE ce = device().getCe();
            byte[] labelBytes = alias.getBytes(StandardCharsets.UTF_8);

            ce.SetAttributeValue(session, p11Key.getObjectHandle(), new CKA(CKA.LABEL, labelBytes));

            // Relabel the matching public key, located by the shared CKA_ID written at
            // generation. Previously this relied on the provider remembering the last generated
            // handle pair, which was wrong under concurrent generation.
            byte[] keyId = readKeyId(ce, session, p11Key.getObjectHandle());
            if (keyId != null) {
                long[] pubHandles = ce.FindObjects(session,
                        new CKA(CKA.CLASS, CKO.PUBLIC_KEY), new CKA(CKA.ID, keyId));
                if (pubHandles != null) {
                    for (long handle : pubHandles) {
                        ce.SetAttributeValue(session, handle, new CKA(CKA.LABEL, labelBytes));
                    }
                }
            }

            privateKeys.put(alias, new Kimbo11ngPrivateKey(p11Key.getObjectHandle(),
                    p11Key.getAlgorithm(), alias, device(), p11Key.entry().orElse(null)));
        } catch (Exception e) {
            log.error("Failed to label key entry '" + alias + "': " + e.getMessage(), e);
        }
    }

    private static byte[] readKeyId(CryptokiE ce, long session, long handle) {
        try {
            return ce.GetAttributeValue(session, handle, CKA.ID).getValue();
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("No CKA_ID on handle " + handle + ": " + e.getMessage());
            }
            return null;
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
        throw new UnsupportedOperationException("Cannot set raw key bytes on a PKCS#11 token");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) {
        if (log.isDebugEnabled()) {
            log.debug("engineSetCertificateEntry ignored for alias " + alias);
        }
    }

    @Override
    public void engineDeleteEntry(String alias) {
        try {
            long session = device().getOrOpenSession();
            CryptokiE ce = device().getCe();
            byte[] labelBytes = alias.getBytes(StandardCharsets.UTF_8);
            // TODO(phase-3): scope deletion by CKA_ID so unrelated objects sharing a label
            // survive, and remove certificate objects too.
            for (long objectClass : new long[] {CKO.PRIVATE_KEY, CKO.PUBLIC_KEY}) {
                long[] handles = ce.FindObjects(session,
                        new CKA(CKA.CLASS, objectClass), new CKA(CKA.LABEL, labelBytes));
                if (handles != null) {
                    for (long handle : handles) {
                        ce.DestroyObject(session, handle);
                    }
                }
            }
            privateKeys.remove(alias);
            publicKeys.remove(alias);
        } catch (Exception e) {
            log.error("Failed to delete entry '" + alias + "': " + e.getMessage(), e);
        }
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(privateKeys.keySet());
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return privateKeys.containsKey(alias);
    }

    @Override
    public int engineSize() {
        return privateKeys.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return privateKeys.containsKey(alias);
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) {
        // The token is the store.
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException {
        privateKeys.clear();
        publicKeys.clear();

        if (!device().isLoggedIn()) {
            if (password == null || password.length == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("engineLoad without a PIN on a logged-out token; no keys enumerated");
                }
                return;
            }
            try {
                device().login(password);
            } catch (Exception e) {
                throw new IOException("Failed to log in to the PKCS#11 token: "
                        + e.getMessage(), e);
            }
        }
        try {
            enumerateKeys();
        } catch (Exception e) {
            throw new IOException("Failed to enumerate keys on the PKCS#11 token: "
                    + e.getMessage(), e);
        }
    }

    private void enumerateKeys() throws Exception {
        long session = device().getOrOpenSession();
        CryptokiE ce = device().getCe();
        PqcMechanismProfile profile = runtime.profile();

        long[] privHandles = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.PRIVATE_KEY));
        if (privHandles == null) {
            return;
        }

        for (long handle : privHandles) {
            try {
                CKA[] attrs = ce.GetAttributeValue(session, handle, CKA.LABEL, CKA.KEY_TYPE);
                byte[] labelBytes = attrs[0].getValue();
                Long keyTypeBoxed = CkULong.typeCode(attrs[1]);
                if (keyTypeBoxed == null) {
                    log.warn("Skipping key handle " + handle + ": no CKA_KEY_TYPE");
                    continue;
                }
                long keyType = keyTypeBoxed;
                String alias = labelBytes != null
                        ? new String(labelBytes, StandardCharsets.UTF_8).trim()
                        : "key-" + handle;

                Optional<AlgorithmEntry> entry = Optional.empty();
                String algorithm;
                if (keyType == CKK.RSA) {
                    algorithm = "RSA";
                } else if (keyType == CKK.EC) {
                    algorithm = "EC";
                } else {
                    entry = profile.lookupByKeyType(keyType,
                            readParameterSet(ce, session, handle, profile));
                    if (entry.isEmpty()) {
                        log.warn("Skipping key '" + alias + "' (handle " + handle
                                + "): profile " + profile.name() + " does not describe CKK 0x"
                                + Long.toHexString(keyType)
                                + ". It cannot be used without knowing its algorithm.");
                        continue;
                    }
                    algorithm = entry.get().family().jcaName();
                }

                privateKeys.put(alias, new Kimbo11ngPrivateKey(handle, algorithm, alias,
                        device(), entry.orElse(null)));
                readMatchingPublicKey(ce, session, alias, labelBytes, keyType, entry)
                        .ifPresent(pub -> publicKeys.put(alias, pub));

                if (log.isDebugEnabled()) {
                    log.debug("Loaded key alias=" + alias + " algorithm=" + algorithm);
                }
            } catch (Exception e) {
                log.warn("Failed to process key handle " + handle + ": " + e.getMessage());
            }
        }
    }

    private static OptionalLong readParameterSet(CryptokiE ce, long session, long handle,
            PqcMechanismProfile profile) {
        try {
            Long value = CkULong.typeCode(
                    ce.GetAttributeValue(session, handle, profile.ckaParameterSet()));
            return value == null ? OptionalLong.empty() : OptionalLong.of(value);
        } catch (Exception e) {
            // Expected on tokens that encode the parameter set in the mechanism instead.
            if (log.isDebugEnabled()) {
                log.debug("No parameter-set attribute on handle " + handle + ": " + e.getMessage());
            }
            return OptionalLong.empty();
        }
    }

    private Optional<PublicKey> readMatchingPublicKey(CryptokiE ce, long session, String alias,
            byte[] labelBytes, long keyType, Optional<AlgorithmEntry> entry) {
        try {
            long[] pubHandles = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
                    new CKA(CKA.LABEL, labelBytes != null ? labelBytes : new byte[0]));
            if (pubHandles == null || pubHandles.length == 0) {
                return Optional.empty();
            }
            long pubHandle = pubHandles[0];
            if (keyType == CKK.RSA) {
                return Optional.of(Kimbo11ngPublicKey.readRsaPublicKey(ce, session, pubHandle));
            }
            if (keyType == CKK.EC) {
                return Optional.of(Kimbo11ngPublicKey.readEcPublicKey(ce, session, pubHandle));
            }
            if (entry.isPresent()) {
                return Optional.of(
                        Kimbo11ngPublicKey.readPqcPublicKey(ce, session, pubHandle, entry.get()));
            }
            return Optional.empty();
        } catch (Exception e) {
            log.warn("Could not read the public key for alias '" + alias + "': " + e.getMessage());
            return Optional.empty();
        }
    }

    /** Registers a freshly generated pair without a full re-enumeration. */
    public void registerGeneratedKeyPair(String alias, long privHandle, String algorithm,
            AlgorithmEntry entry, PublicKey publicKey) {
        privateKeys.put(alias,
                new Kimbo11ngPrivateKey(privHandle, algorithm, alias, device(), entry));
        if (publicKey != null) {
            publicKeys.put(alias, publicKey);
        }
    }

    public PublicKey getPublicKey(String alias) {
        return publicKeys.get(alias);
    }

    /** Drops cached keys; used when the token is deactivated. */
    public void clear() {
        privateKeys.clear();
        publicKeys.clear();
    }
}

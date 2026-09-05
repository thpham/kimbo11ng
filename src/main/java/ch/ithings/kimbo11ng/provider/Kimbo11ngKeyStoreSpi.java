/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.CkULong;
import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.p11.SessionLease;
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

    private P11Slot slot() {
        return runtime.slot();
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws UnrecoverableKeyException {
        return privateKeys.get(alias);
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        return null;
    }

    /**
     * Always {@code null}, and deliberately without asking the token.
     *
     * <p>EJBCA keeps issued certificates in its database; nothing in it expects to find one here,
     * and a chain could not be reconstructed anyway, since PKCS#11 stores certificates as
     * independent objects with no ordering between them.
     *
     * <p>Searching the token per alias would also be quietly expensive: EJBCA rebuilds its
     * {@code CachingKeyStoreWrapper} cache after every key generation, and the rebuild calls this
     * for every alias. Answering from memory keeps that rebuild free.
     *
     * <p>What the original code did was the worst of both: it searched the token and then discarded
     * the result.
     */
    @Override
    public Certificate engineGetCertificate(String alias) {
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        // CKA_START_DATE is a validity date the operator may set, not a creation timestamp, and
        // most tokens leave it empty. Returning 'now' — what this used to do — was a fabrication.
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
        if (!(key instanceof Kimbo11ngPrivateKey p11Key)) {
            return;
        }
        try (SessionLease lease = slot().borrow()) {
            long session = lease.session();
            CryptokiE ce = slot().ce();
            byte[] labelBytes = alias.getBytes(StandardCharsets.UTF_8);
            P11KeyRef ref = p11Key.ref();

            // Both halves get the new label, located by the CKA_ID they share. Relabelling only
            // the private key would leave enumeration unable to pair them again after a restart.
            for (long objectClass : new long[] {CKO.PRIVATE_KEY, CKO.PUBLIC_KEY}) {
                for (long handle : ref.findAll(ce, session, objectClass)) {
                    ce.SetAttributeValue(session, handle, new CKA(CKA.LABEL, labelBytes));
                }
            }

            P11KeyRef renamed = new P11KeyRef(ref.ckaId(), alias, ref.entry().orElse(null));
            privateKeys.put(alias, new Kimbo11ngPrivateKey(p11Key.getAlgorithm(), slot(), renamed));
            PublicKey pub = publicKeys.remove(p11Key.getAlias());
            if (pub != null) {
                publicKeys.put(alias, pub);
            }
        } catch (Exception e) {
            log.error("Failed to label key entry '" + alias + "': " + e.getMessage(), e);
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

    /**
     * Removes one key pair and its certificate from the token.
     *
     * <p>Scoped by {@code CKA_ID} when the key has one. Deleting by label — what this used to do —
     * destroys every object that happens to share the name, and a label is an EJBCA alias that an
     * operator may reuse. Deleting one CA's key because another CA's key was named the same is not
     * recoverable.
     */
    @Override
    public void engineDeleteEntry(String alias) {
        Kimbo11ngPrivateKey key = privateKeys.get(alias);
        if (key == null) {
            log.warn("Not deleting '" + alias + "': no such key in this keystore");
            return;
        }
        try (SessionLease lease = slot().borrow()) {
            long session = lease.session();
            CryptokiE ce = slot().ce();
            P11KeyRef ref = key.ref();
            if (!ref.hasCkaId()) {
                log.warn("Deleting '" + alias + "' by label: it carries no CKA_ID, so any other"
                        + " object with the same label will be removed with it.");
            }
            int destroyed = 0;
            // The certificate too: leaving it behind means the next key generated under this alias
            // enumerates with the previous key's certificate attached to it.
            for (long objectClass : new long[] {CKO.PRIVATE_KEY, CKO.PUBLIC_KEY, CKO.CERTIFICATE}) {
                for (long handle : ref.findAll(ce, session, objectClass)) {
                    ce.DestroyObject(session, handle);
                    destroyed++;
                }
            }
            log.info("Deleted " + destroyed + " token object(s) for alias '" + alias + "'");
        } catch (Exception e) {
            log.error("Failed to delete entry '" + alias + "': " + e.getMessage(), e);
        } finally {
            privateKeys.remove(alias);
            publicKeys.remove(alias);
            slot().invalidateHandles();
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

        if (!slot().isLoggedIn()) {
            if (password == null || password.length == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("engineLoad without a PIN on a logged-out token; no keys enumerated");
                }
                return;
            }
            try {
                slot().login(password);
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
        // One lease for the whole enumeration: the outer FindObjects and the per-key attribute
        // reads and public-key lookups are a single logical scan, and splitting them across
        // sessions would let another thread delete a key between the two halves.
        try (SessionLease lease = slot().borrow()) {
            enumerateKeys(lease.session());
        }
    }

    private void enumerateKeys(long session) {
        CryptokiE ce = slot().ce();
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

                P11KeyRef ref = referenceFor(ce, session, handle, alias, entry.orElse(null));
                privateKeys.put(alias,
                        new Kimbo11ngPrivateKey(algorithm, slot(), ref, handle));
                readMatchingPublicKey(ce, session, alias, ref, keyType, entry)
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

    /**
     * Builds the durable reference for a key found on the token, writing a {@code CKA_ID} onto a
     * legacy key that has none.
     *
     * <p>The backfill is what lets keys generated before kimbo11ng wrote ids stop depending on
     * their label. It is optional ({@code kimbo11ng.keyid.backfill}) and it may be refused by the
     * token, in which case the key keeps working by label — an existing CA must not break because
     * its HSM will not accept an attribute change.
     */
    private P11KeyRef referenceFor(CryptokiE ce, long session, long handle, String alias,
            AlgorithmEntry entry) {
        byte[] existingId = P11KeyRef.readCkaId(ce, session, handle);
        P11KeyRef ref = new P11KeyRef(existingId, alias, entry);
        if (existingId != null || !runtime.backfillKeyIds()) {
            return ref;
        }
        byte[] newId = KeyTemplates.newKeyId();
        P11KeyRef backfilled = Kimbo11ngPrivateKey.backfillCkaId(ce, session, handle, ref, newId);
        if (!backfilled.hasCkaId()) {
            return ref;
        }
        // The public half must get the same id, or it becomes unfindable the moment the private
        // key stops being looked up by label — which is precisely what the backfill just changed.
        // Found by label here because that is all the pair has in common until this write lands.
        for (long pubHandle : ref.findAll(ce, session, CKO.PUBLIC_KEY, true)) {
            try {
                ce.SetAttributeValue(session, pubHandle, new CKA(CKA.ID, newId));
            } catch (Exception e) {
                log.warn("Wrote a CKA_ID onto '" + alias + "' but not onto its public key ("
                        + e.getMessage() + "); the pair will still be matched by label.");
            }
        }
        return backfilled;
    }

    private Optional<PublicKey> readMatchingPublicKey(CryptokiE ce, long session, String alias,
            P11KeyRef ref, long keyType, Optional<AlgorithmEntry> entry) {
        try {
            // By CKA_ID when there is one: a public key whose label was edited separately from its
            // private half would otherwise be missed, and the alias would load without a public key.
            long[] pubHandles = ref.findAll(ce, session, CKO.PUBLIC_KEY, true);
            if (pubHandles.length == 0) {
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
    public void registerGeneratedKeyPair(String alias, P11KeyRef ref, long privHandle,
            String algorithm, PublicKey publicKey) {
        privateKeys.put(alias, new Kimbo11ngPrivateKey(algorithm, slot(), ref, privHandle));
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

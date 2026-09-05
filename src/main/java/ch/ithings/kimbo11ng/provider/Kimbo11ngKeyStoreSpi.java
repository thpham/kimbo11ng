/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.CkULong;
import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.p11.Pkcs11Errors;
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
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
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

    /**
     * Secret keys, kept apart from {@link #privateKeys} rather than in one map of {@code Key}.
     *
     * <p>They are a different object class on the token ({@code CKO_SECRET_KEY}), they are found by
     * a different search, and every caller that walks the private keys — key usages, the public-key
     * pairing, the algorithm lookup — means asymmetric keys specifically. One map would have made
     * each of those quietly wrong for a secret key rather than simply not finding it.
     */
    private final Map<String, Kimbo11ngSecretKey> secretKeys = new ConcurrentHashMap<>();

    public Kimbo11ngKeyStoreSpi(TokenRuntime runtime) {
        this.runtime = runtime;
    }

    private P11Slot slot() {
        return runtime.slot();
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws UnrecoverableKeyException {
        Key key = privateKeys.get(alias);
        return key != null ? key : secretKeys.get(alias);
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
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
            throws KeyStoreException {
        if (key instanceof Kimbo11ngSecretKey secretKey) {
            setSecretKeyEntry(alias, secretKey);
            return;
        }
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

    /**
     * Gives a freshly generated secret key its alias.
     *
     * <p>This is the second half of symmetric key generation, and the JCA splits it that way: a
     * {@code KeyGenerator} is handed no name, so {@link Kimbo11ngKeyGeneratorSpi} creates the object
     * under a provisional label and the caller names it here. EJBCA's own
     * {@code KeyStoreTools.generateKey} performs exactly these two calls in sequence.
     *
     * <p>Unlike the key-pair case there is one object to relabel, not two — a secret key has no
     * public half to keep in step.
     *
     * <p>Failure is thrown, never logged. Returning quietly does not keep EJBCA from holding the
     * alias: {@code CachingKeyStoreWrapper.setKeyEntry} adds it to its cache after the delegate
     * returns, so a silent return produces exactly the state it was meant to avoid — a name for a
     * key the token does not have under it, discovered on first use. Only an exception stops the
     * cache write.
     *
     * @throws KeyStoreException if the token would not give the object the caller's alias
     */
    private void setSecretKeyEntry(String alias, Kimbo11ngSecretKey secretKey)
            throws KeyStoreException {
        try (SessionLease lease = slot().borrow()) {
            long session = lease.session();
            CryptokiE ce = slot().ce();
            byte[] labelBytes = alias.getBytes(StandardCharsets.UTF_8);
            P11KeyRef ref = secretKey.ref();
            int relabelled = 0;
            for (long handle : ref.findAll(ce, session, CKO.SECRET_KEY)) {
                ce.SetAttributeValue(session, handle, new CKA(CKA.LABEL, labelBytes));
                relabelled++;
            }
            if (relabelled == 0) {
                // The generator wrote a CKA_ID and this search uses it, so finding nothing means
                // the object is gone.
                throw new KeyStoreException("Cannot name secret key '" + alias + "': no"
                        + " CKO_SECRET_KEY object matches " + ref + " on the token.");
            }
            secretKeys.put(alias,
                    new Kimbo11ngSecretKey(secretKey.getAlgorithm(), slot(),
                            new P11KeyRef(ref.ckaId(), alias, null)));
            log.info("Registered secret key '" + alias + "' (" + secretKey.getAlgorithm() + ")");
        } catch (KeyStoreException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyStoreException("Failed to label secret key entry '" + alias + "'"
                    + Pkcs11Errors.describe(e) + ". The key exists on the token under the"
                    + " generator's provisional label " + secretKey.ref() + ".", e);
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
     *
     * <h2>A refusal has to reach the caller</h2>
     *
     * <p>A partition that answers {@code CKR_ACTION_PROHIBITED} leaves the key on the token. If that
     * is swallowed, {@code CachingKeyStoreWrapper.deleteEntry} still drops the alias from its cache
     * once this returns, and EJBCA then holds no name for a key the HSM does — so nothing will ever
     * delete it, and the next generation under that alias produces an indistinguishable twin. The
     * in-memory maps are therefore cleared only when every object found was actually destroyed.
     *
     * @throws KeyStoreException if the token refused to destroy any of the alias's objects
     */
    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        Kimbo11ngPrivateKey key = privateKeys.get(alias);
        if (key == null) {
            if (secretKeys.containsKey(alias)) {
                deleteSecretEntry(alias);
                return;
            }
            log.warn("Not deleting '" + alias + "': no such key in this keystore");
            return;
        }
        // The certificate too: leaving it behind means the next key generated under this alias
        // enumerates with the previous key's certificate attached to it.
        long[] classes = {CKO.PRIVATE_KEY, CKO.PUBLIC_KEY, CKO.CERTIFICATE};
        int[] destroyed = new int[classes.length];
        try (SessionLease lease = slot().borrow()) {
            long session = lease.session();
            CryptokiE ce = slot().ce();
            P11KeyRef ref = key.ref();
            if (!ref.hasCkaId()) {
                log.warn("Deleting '" + alias + "' by label: it carries no CKA_ID, so any other"
                        + " object with the same label will be removed with it.");
            }
            for (int i = 0; i < classes.length; i++) {
                for (long handle : ref.findAll(ce, session, classes[i])) {
                    ce.DestroyObject(session, handle);
                    destroyed[i]++;
                }
            }
            log.info("Deleted " + summarize(classes, destroyed) + " for alias '" + alias + "'");
        } catch (Exception e) {
            // The alias stays: whatever survived on the token is still findable under it.
            slot().invalidateHandles();
            throw new KeyStoreException("Failed to delete '" + alias + "' from the token"
                    + Pkcs11Errors.describe(e) + ". Destroyed before the failure: "
                    + summarize(classes, destroyed) + ". The alias is kept, because the objects"
                    + " that remain would otherwise be unreachable.", e);
        }
        privateKeys.remove(alias);
        publicKeys.remove(alias);
        slot().invalidateHandles();
    }

    /**
     * The secret-key half of {@link #engineDeleteEntry}: one object class, no public half.
     *
     * @throws KeyStoreException if the token refused to destroy the key
     */
    private void deleteSecretEntry(String alias) throws KeyStoreException {
        Kimbo11ngSecretKey key = secretKeys.get(alias);
        int destroyed = 0;
        try (SessionLease lease = slot().borrow()) {
            long session = lease.session();
            CryptokiE ce = slot().ce();
            P11KeyRef ref = key.ref();
            if (!ref.hasCkaId()) {
                log.warn("Deleting secret key '" + alias + "' by label: it carries no CKA_ID, so"
                        + " any other object with the same label will be removed with it.");
            }
            for (long handle : ref.findAll(ce, session, CKO.SECRET_KEY)) {
                ce.DestroyObject(session, handle);
                destroyed++;
            }
            log.info("Deleted " + destroyed + " secret-key object(s) for alias '" + alias + "'");
        } catch (Exception e) {
            slot().invalidateHandles();
            throw new KeyStoreException("Failed to delete secret key '" + alias + "' from the"
                    + " token" + Pkcs11Errors.describe(e) + ". Destroyed before the failure: "
                    + destroyed + " secret-key object(s). The alias is kept, because the key is"
                    + " still there.", e);
        }
        secretKeys.remove(alias);
        slot().invalidateHandles();
    }

    /** {@code "1 CKO_PRIVATE_KEY, 1 CKO_PUBLIC_KEY, 0 CKO_CERTIFICATE object(s)"}. */
    private static String summarize(long[] classes, int[] destroyed) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < classes.length; i++) {
            sb.append(i == 0 ? "" : ", ").append(destroyed[i]).append(' ')
                    .append(CKO.L2S(classes[i]));
        }
        return sb.append(" object(s)").toString();
    }

    /**
     * Every alias this keystore holds, asymmetric and symmetric.
     *
     * <p>A union rather than two enumerations, because {@code CachingKeyStoreWrapper} builds its
     * whole alias cache from this one call: an alias missing here is an alias EJBCA reports as
     * absent even though the token holds the key.
     */
    @Override
    public Enumeration<String> engineAliases() {
        if (secretKeys.isEmpty()) {
            return Collections.enumeration(privateKeys.keySet());
        }
        Set<String> all = new LinkedHashSet<>(privateKeys.keySet());
        all.addAll(secretKeys.keySet());
        return Collections.enumeration(all);
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return privateKeys.containsKey(alias) || secretKeys.containsKey(alias);
    }

    @Override
    public int engineSize() {
        // Sum, not union: an alias cannot name both a private and a secret key here, because
        // generation refuses an alias the token already uses for either.
        return privateKeys.size() + secretKeys.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return engineContainsAlias(alias);
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
        secretKeys.clear();

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
            enumerateSecretKeys(lease.session());
        }
    }

    /**
     * Loads the {@code CKO_SECRET_KEY} objects on the token.
     *
     * <p>A separate pass rather than a wider search, because the two classes share almost nothing:
     * a secret key has no public half to pair, no algorithm row to resolve, and no
     * {@code CKA_KEY_TYPE} that identifies the operation it will be used for.
     *
     * <h2>What the algorithm name means here</h2>
     *
     * <p>It names the <em>key type</em> — {@code AES} or {@code GenericSecret} — and not the MAC or
     * cipher the key will serve. PKCS#11 does not record that: a {@code CKK_GENERIC_SECRET} object
     * is equally an HmacSHA256 and an HmacSHA512 key, and the mechanism is chosen by the
     * {@code Mac} service at use, not by the key. Naming it {@code HmacSHA256} on a guess would
     * make a key that was generated for SHA-512 report the wrong algorithm forever after a restart.
     */
    private void enumerateSecretKeys(long session) {
        CryptokiE ce = slot().ce();
        long[] handles = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.SECRET_KEY));
        if (handles == null) {
            return;
        }
        for (long handle : handles) {
            try {
                CKA[] attrs = ce.GetAttributeValue(session, handle, CKA.LABEL, CKA.KEY_TYPE);
                byte[] labelBytes = attrs[0].getValue();
                Long keyType = CkULong.typeCode(attrs[1]);
                if (keyType == null) {
                    log.warn("Skipping secret key handle " + handle + ": no CKA_KEY_TYPE");
                    continue;
                }
                String algorithm;
                if (keyType == CKK.AES) {
                    algorithm = "AES";
                } else if (keyType == CKK.GENERIC_SECRET) {
                    algorithm = "GenericSecret";
                } else {
                    log.warn("Skipping secret key handle " + handle + ": CKK 0x"
                            + Long.toHexString(keyType) + " is not a key type this provider can"
                            + " use. It stays on the token, untouched.");
                    continue;
                }
                String alias = labelBytes != null
                        ? new String(labelBytes, StandardCharsets.UTF_8).trim()
                        : "secret-" + handle;
                byte[] ckaId = P11KeyRef.readCkaId(ce, session, handle);
                secretKeys.put(alias, new Kimbo11ngSecretKey(algorithm, slot(),
                        new P11KeyRef(ckaId, alias, null), handle));
                if (log.isDebugEnabled()) {
                    log.debug("Loaded secret key alias=" + alias + " algorithm=" + algorithm);
                }
            } catch (Exception e) {
                log.warn("Failed to process secret key handle " + handle + ": " + e.getMessage());
            }
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
                return Optional.of(PublicKeyReader.readRsaPublicKey(ce, session, pubHandle));
            }
            if (keyType == CKK.EC) {
                return Optional.of(PublicKeyReader.readEcPublicKey(ce, session, pubHandle));
            }
            if (entry.isPresent()) {
                return Optional.of(
                        PublicKeyReader.readPqcPublicKey(ce, session, pubHandle, entry.get(),
                                runtime.publicKeyPolicy()));
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

    /**
     * The durable reference for an alias, or {@code null} if this keystore has not seen it.
     *
     * <p>Exposed so that reads which are not key operations — the key-usage attributes, say — can
     * find both halves of a pair by the {@code CKA_ID} they share rather than by a label either of
     * them may have been renamed under.
     */
    public P11KeyRef referenceFor(String alias) {
        Kimbo11ngPrivateKey key = privateKeys.get(alias);
        return key == null ? null : key.ref();
    }

    /** The post-quantum algorithm row for an alias; empty for RSA, EC, and unknown aliases. */
    public Optional<AlgorithmEntry> algorithmFor(String alias) {
        Kimbo11ngPrivateKey key = privateKeys.get(alias);
        return key == null ? Optional.empty() : key.entry();
    }

    /** True if this alias names a secret key rather than a key pair. */
    public boolean isSecretKey(String alias) {
        return secretKeys.containsKey(alias);
    }

    /** Drops cached keys; used when the token is deactivated. */
    public void clear() {
        privateKeys.clear();
        publicKeys.clear();
        secretKeys.clear();
    }
}

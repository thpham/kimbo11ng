/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.P11Slot;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CryptokiE;

import javax.crypto.SecretKey;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.KeyException;
import java.util.Objects;

/**
 * A handle to a secret key that stays inside the token.
 *
 * <p>The counterpart of {@link Kimbo11ngPrivateKey} for {@code CKO_SECRET_KEY} objects, and it
 * exists for the same reason: an object handle is a session-scoped number, not an identity, so the
 * durable {@link P11KeyRef} is what the key is and the handle is a cache re-resolved whenever the
 * slot says handles are stale.
 *
 * <h2>getEncoded returns null, and that is load-bearing</h2>
 *
 * <p>{@link SecretKey} is a {@code SecretKey} whether or not it can show its bytes, and the JCA
 * contract allows {@code null} for a key that cannot be extracted. Returning anything else here
 * would be a lie: the key is generated {@code CKA_SENSITIVE} and not {@code CKA_EXTRACTABLE}, so
 * the bytes are not available to this JVM at all — {@code C_GetAttributeValue} on
 * {@code CKA_VALUE} answers {@code CKR_ATTRIBUTE_SENSITIVE}.
 *
 * <p>Callers that need the bytes therefore fail with a {@code NullPointerException} rather than a
 * wrong MAC, which is the failure mode to prefer. {@link Kimbo11ngMacSpi} takes the key by handle
 * and never asks.
 */
public final class Kimbo11ngSecretKey implements SecretKey {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(Kimbo11ngSecretKey.class);

    private final String algorithm;
    private final transient P11Slot slot;
    private final transient P11KeyRef ref;

    /** The handle last resolved, with the generation it was resolved under. */
    private transient volatile CachedHandle cached;

    private record CachedHandle(long generation, long handle) {
    }

    public Kimbo11ngSecretKey(String algorithm, P11Slot slot, P11KeyRef ref) {
        this.algorithm = algorithm;
        this.slot = slot;
        this.ref = Objects.requireNonNull(ref, "ref");
    }

    /** A key whose handle is already known — the freshly generated case. */
    public Kimbo11ngSecretKey(String algorithm, P11Slot slot, P11KeyRef ref, long knownHandle) {
        this(algorithm, slot, ref);
        this.cached = new CachedHandle(slot == null ? 0L : slot.handleGeneration(), knownHandle);
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "PKCS#11";
    }

    /** @see Kimbo11ngSecretKey the class comment, for why this is not the key material */
    @Override
    public byte[] getEncoded() {
        return null;
    }

    public String getAlias() {
        return ref.label();
    }

    public P11KeyRef ref() {
        return ref;
    }

    /** The slot this key belongs to, or {@code null} on a deserialized key. */
    public P11Slot slot() {
        return slot;
    }

    /**
     * The object handle to use in {@code session}, resolved again if the slot's handles have been
     * invalidated since it was last looked up.
     *
     * @throws KeyException if the token no longer holds this key
     */
    public long objectHandle(CryptokiE ce, long session) throws KeyException {
        long generation = slot.handleGeneration();
        CachedHandle current = cached;
        if (current != null && current.generation() == generation) {
            return current.handle();
        }
        long handle = ref.resolve(ce, session, CKO.SECRET_KEY);
        if (handle < 0) {
            throw new KeyException("The token no longer holds a secret key for alias '"
                    + ref.label() + "' (" + ref + "). It may have been deleted, or the token "
                    + "replaced with one that does not contain it.");
        }
        cached = new CachedHandle(generation, handle);
        if (log.isDebugEnabled()) {
            log.debug("Resolved secret key '" + ref.label() + "' to handle " + handle
                    + " at generation " + generation);
        }
        return handle;
    }

    /** Forgets the cached handle so the next use resolves it again. */
    public void invalidateHandle() {
        cached = null;
    }

    /**
     * Refuses serialization, for the reason {@link Kimbo11ngPrivateKey} does: the slot and the
     * reference are transient, so a deserialized key names nothing.
     */
    private void writeObject(ObjectOutputStream out) throws NotSerializableException {
        throw new NotSerializableException(getClass().getName()
                + " must not be serialized: it names an object inside an HSM, which no other JVM"
                + " can reach.");
    }

    /** Identity is the key on the token, not the Java object. */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Kimbo11ngSecretKey other)) {
            return false;
        }
        return ref.equals(other.ref) && algorithm.equals(other.algorithm)
                && Objects.equals(slotKey(), other.slotKey());
    }

    @Override
    public int hashCode() {
        return Objects.hash(ref, algorithm, slotKey());
    }

    private String slotKey() {
        return slot == null ? null : slot.libPath() + "#" + slot.slotId();
    }

    @Override
    public String toString() {
        CachedHandle current = cached;
        return "Kimbo11ngSecretKey{alias=" + ref.label() + " algorithm=" + algorithm
                + " handle=" + (current == null ? "<unresolved>" : current.handle()) + "}";
    }
}

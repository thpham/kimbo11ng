/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;
import org.pkcs11.jacknji11.CryptokiE;

import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.KeyException;
import java.security.PrivateKey;
import java.util.Objects;
import java.util.Optional;

/**
 * A handle to a private key that stays inside the token.
 *
 * <p>Deliberately implements none of {@code RSAPrivateKey}, {@code ECPrivateKey} or
 * {@code DHPrivateKey}: EJBCA's {@code KeyTools.isPrivateKeyExtractable} inspects exactly those
 * interfaces, and a token key that appeared to expose its private value would be refused.
 *
 * <h2>The handle is a cache, not the identity</h2>
 *
 * <p>EJBCA's {@code CachingKeyStoreWrapper} holds the {@code Key} objects it gets from us in a
 * {@code HashMap} for the life of the crypto token, so one of these can outlive several sessions
 * and, on a network HSM, several connections. Storing a bare object handle in it means the CA signs
 * with a handle the token may since have reassigned. The durable {@link P11KeyRef} is the identity;
 * the handle is re-resolved whenever the slot says cached handles are stale.
 */
public final class Kimbo11ngPrivateKey implements PrivateKey {

    private static final long serialVersionUID = 3L;
    private static final Logger log = Logger.getLogger(Kimbo11ngPrivateKey.class);

    private final String algorithm;
    private final transient P11Slot slot;
    private final transient P11KeyRef ref;

    /** The handle last resolved, with the generation it was resolved under. */
    private transient volatile CachedHandle cached;

    private record CachedHandle(long generation, long handle) {
    }

    public Kimbo11ngPrivateKey(String algorithm, P11Slot slot, P11KeyRef ref) {
        this.algorithm = algorithm;
        this.slot = slot;
        this.ref = Objects.requireNonNull(ref, "ref");
    }

    /**
     * A key whose handle is already known — the freshly generated case, where the object was just
     * created and there is nothing to look up.
     */
    public Kimbo11ngPrivateKey(String algorithm, P11Slot slot, P11KeyRef ref, long knownHandle) {
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

    /** The algorithm row for a post-quantum key; empty for RSA and EC. */
    public Optional<AlgorithmEntry> entry() {
        return ref.entry();
    }

    /**
     * The object handle to use in {@code session}, resolved again if the slot's handles have been
     * invalidated since it was last looked up.
     *
     * @throws KeyException if the token no longer holds this key
     */
    public long objectHandle(CryptokiE ce, long session) throws KeyException {
        // Read before the lookup, so an invalidation racing with it is not lost: the next caller
        // sees a mismatch and resolves again rather than trusting a handle from the older world.
        long generation = slot.handleGeneration();
        CachedHandle current = cached;
        if (current != null && current.generation() == generation) {
            return current.handle();
        }
        long handle = ref.resolve(ce, session);
        if (handle < 0) {
            throw new KeyException("The token no longer holds a private key for alias '"
                    + ref.label() + "' (" + ref + "). It may have been deleted, or the token "
                    + "replaced with one that does not contain it.");
        }
        cached = new CachedHandle(generation, handle);
        if (log.isDebugEnabled()) {
            log.debug("Resolved '" + ref.label() + "' to handle " + handle
                    + " at generation " + generation);
        }
        return handle;
    }

    /** Forgets the cached handle so the next use resolves it again. */
    public void invalidateHandle() {
        cached = null;
    }

    /**
     * Writes {@code CKA_ID} onto a legacy key that has none, so later lookups can use it.
     *
     * <p>Best effort by design. HSM policies commonly forbid changing attributes on a token object
     * after creation, and a Luna partition can be configured exactly that way; a CA must keep
     * working on a key it cannot relabel. The refusal is logged and the key continues to resolve
     * by label.
     *
     * @return the reference to use from now on — carrying the new id if it was written, unchanged
     *         if the token refused
     */
    static P11KeyRef backfillCkaId(CryptokiE ce, long session, long handle, P11KeyRef ref,
            byte[] newId) {
        try {
            ce.SetAttributeValue(session, handle, new CKA(CKA.ID, newId));
            log.info("Wrote a CKA_ID onto legacy key '" + ref.label()
                    + "'; it now resolves by id rather than by label");
            return ref.withCkaId(newId);
        } catch (CKRException e) {
            // 0x1B is CKR_ACTION_PROHIBITED, which jacknji11 1.3.1 does not define; a token
            // whose policy forbids attribute changes answers one or the other.
            if (e.getCKR() == CKR.ATTRIBUTE_READ_ONLY || e.getCKR() == 0x1BL) {
                log.warn("Cannot write CKA_ID onto '" + ref.label() + "': the token treats it as"
                        + " read-only. The key stays resolvable by label, which works but cannot"
                        + " distinguish two keys that share one.");
            } else {
                log.warn("Could not write CKA_ID onto '" + ref.label() + "': " + e.getMessage());
            }
            return ref;
        } catch (Exception e) {
            log.warn("Could not write CKA_ID onto '" + ref.label() + "': " + e.getMessage());
            return ref;
        }
    }

    /**
     * Refuses serialization. The slot and the reference are transient, so a deserialized key would
     * carry nothing usable and fail at signing time with a {@code NullPointerException} far from
     * the cause.
     */
    private void writeObject(ObjectOutputStream out) throws NotSerializableException {
        throw new NotSerializableException(getClass().getName()
                + " must not be serialized: it names an object inside an HSM, which no other JVM"
                + " can reach.");
    }

    /**
     * Identity is the key on the token, not the Java object.
     *
     * <p>Two references to the same token object must compare equal even when one of them has
     * re-resolved its handle since — which is exactly what the old handle-based identity got wrong
     * after a session was replaced.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Kimbo11ngPrivateKey other)) {
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
        return "Kimbo11ngPrivateKey{alias=" + ref.label() + " algorithm=" + algorithm
                + " handle=" + (current == null ? "<unresolved>" : current.handle()) + "}";
    }
}

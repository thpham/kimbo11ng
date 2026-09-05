/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CryptokiE;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

/**
 * How a key is found on the token, as opposed to where it happened to be last time.
 *
 * <p>An object handle is not an identity. PKCS#11 leaves handle lifetime to the implementation:
 * SoftHSM hands out stable ones, other modules renumber objects when a session is replaced, and
 * nothing in the API promises otherwise. Caching a handle for the life of a JVM — which is what
 * {@code CachingKeyStoreWrapper} does with the {@code Key} objects we hand it — is therefore a bet
 * on the module, and losing it means signing with the wrong object or failing with
 * {@code CKR_OBJECT_HANDLE_INVALID} at the worst possible moment.
 *
 * <p>A reference is durable instead: {@code CKA_ID} first, {@code CKA_LABEL} as a fallback. The
 * handle becomes a cache that can always be rebuilt.
 *
 * <h2>Why CKA_ID and not only the label</h2>
 *
 * <p>The label is the EJBCA alias, and EJBCA lets an operator rename it. {@code CKA_ID} is written
 * once at generation into both halves of the pair and never changes, which is also what lets the
 * public key be found for a private key whose label was edited, and what lets deletion remove
 * exactly one key pair rather than everything that happens to share a name.
 */
public final class P11KeyRef {

    private static final Logger log = Logger.getLogger(P11KeyRef.class);

    private final byte[] ckaId;
    private final String label;
    private final AlgorithmEntry entry;

    /**
     * @param ckaId the key's {@code CKA_ID}, or {@code null} for a legacy key generated before
     *              kimbo11ng wrote one — those resolve by label only
     * @param entry the post-quantum algorithm row, or {@code null} for RSA and EC
     */
    public P11KeyRef(byte[] ckaId, String label, AlgorithmEntry entry) {
        this.ckaId = ckaId == null ? null : ckaId.clone();
        this.label = label;
        this.entry = entry;
    }

    /** A copy of the key id, or {@code null} for a legacy key that has none. */
    public byte[] ckaId() {
        return ckaId == null ? null : ckaId.clone();
    }

    public boolean hasCkaId() {
        return ckaId != null && ckaId.length > 0;
    }

    public String label() {
        return label;
    }

    public Optional<AlgorithmEntry> entry() {
        return Optional.ofNullable(entry);
    }

    byte[] labelBytes() {
        return label.getBytes(StandardCharsets.UTF_8);
    }

    /** The same reference with a key id it did not have, after a successful backfill. */
    P11KeyRef withCkaId(byte[] newId) {
        return new P11KeyRef(newId, label, entry);
    }

    /**
     * Finds the private key on the token.
     *
     * @return the object handle, or -1 if the token no longer holds this key
     */
    public long resolve(CryptokiE ce, long session) {
        if (hasCkaId()) {
            long byId = findOne(ce, session, new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
                    new CKA(CKA.ID, ckaId));
            if (byId >= 0) {
                return byId;
            }
            // Falling through to the label is deliberate. An operator who re-imported a key, or a
            // module that does not persist CKA_ID the way we wrote it, should not leave a CA dead
            // when the key is plainly there under its name.
            if (log.isDebugEnabled()) {
                log.debug("No object with CKA_ID for '" + label + "'; falling back to the label");
            }
        }
        return findOne(ce, session, new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
                new CKA(CKA.LABEL, labelBytes()));
    }

    /**
     * Objects of {@code objectClass} belonging to this key: by id when there is one, else label.
     *
     * <p>Strict: no fallback. Deletion uses this, and falling back to the label there would destroy
     * whatever else happens to share the name.
     */
    long[] findAll(CryptokiE ce, long session, long objectClass) {
        return findAll(ce, session, objectClass, false);
    }

    /**
     * @param labelFallback also search by label when the id matches nothing. For pairing a public
     *        key with its private half, where finding the wrong same-label object is recoverable
     *        and finding none is not — never for deletion.
     */
    long[] findAll(CryptokiE ce, long session, long objectClass, boolean labelFallback) {
        if (hasCkaId()) {
            long[] byId = ce.FindObjects(session,
                    new CKA(CKA.CLASS, objectClass), new CKA(CKA.ID, ckaId));
            if (byId != null && byId.length > 0) {
                return byId;
            }
            if (!labelFallback) {
                return new long[0];
            }
        }
        long[] byLabel = ce.FindObjects(session,
                new CKA(CKA.CLASS, objectClass), new CKA(CKA.LABEL, labelBytes()));
        return byLabel == null ? new long[0] : byLabel;
    }

    private static long findOne(CryptokiE ce, long session, CKA... criteria) {
        long[] found = ce.FindObjects(session, criteria);
        return (found == null || found.length == 0) ? -1 : found[0];
    }

    /**
     * Reads {@code CKA_ID} from an object, or {@code null} when it has none.
     *
     * <p>Absent is normal for a key generated before kimbo11ng wrote ids, and for tokens that do
     * not report the attribute at all.
     */
    static byte[] readCkaId(CryptokiE ce, long session, long handle) {
        try {
            byte[] id = ce.GetAttributeValue(session, handle, CKA.ID).getValue();
            return (id == null || id.length == 0) ? null : id;
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("No CKA_ID on handle " + handle + ": " + e.getMessage());
            }
            return null;
        }
    }

    @Override
    public String toString() {
        return "P11KeyRef{label=" + label
                + (hasCkaId() ? " id=" + hex(ckaId) : " id=<none>") + "}";
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof P11KeyRef other)) {
            return false;
        }
        return Arrays.equals(ckaId, other.ckaId) && label.equals(other.label);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(ckaId) + label.hashCode();
    }
}

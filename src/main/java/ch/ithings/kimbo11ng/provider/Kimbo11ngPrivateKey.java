/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;

import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.util.Optional;

/**
 * A handle to a private key that stays inside the token.
 *
 * <p>Deliberately implements none of {@code RSAPrivateKey}, {@code ECPrivateKey} or
 * {@code DHPrivateKey}: EJBCA's {@code KeyTools.isPrivateKeyExtractable} inspects exactly those
 * interfaces, and a token key that appeared to expose its private value would be refused.
 */
public final class Kimbo11ngPrivateKey implements PrivateKey {

    private static final long serialVersionUID = 2L;

    private final long objectHandle;
    private final String algorithm;
    private final String alias;
    private final transient P11Slot slot;
    private final transient AlgorithmEntry entry;

    public Kimbo11ngPrivateKey(long objectHandle, String algorithm, String alias, P11Slot slot) {
        this(objectHandle, algorithm, alias, slot, null);
    }

    /**
     * @param entry the post-quantum algorithm this key was generated as, or {@code null} for RSA
     *              and EC, whose signing mechanism follows from the requested digest instead
     */
    public Kimbo11ngPrivateKey(long objectHandle, String algorithm, String alias, P11Slot slot,
            AlgorithmEntry entry) {
        this.objectHandle = objectHandle;
        this.algorithm = algorithm;
        this.alias = alias;
        this.slot = slot;
        this.entry = entry;
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

    public long getObjectHandle() {
        return objectHandle;
    }

    public String getAlias() {
        return alias;
    }

    /** The slot this handle belongs to, or {@code null} on a deserialized key. */
    public P11Slot slot() {
        return slot;
    }

    /** The algorithm row for a post-quantum key; empty for RSA and EC. */
    public Optional<AlgorithmEntry> entry() {
        return Optional.ofNullable(entry);
    }

    /**
     * Refuses serialization. The slot and algorithm row are transient, so a deserialized key
     * would carry a handle into a session that no longer exists and fail at signing time with a
     * {@code NullPointerException} far from the cause.
     */
    private void writeObject(ObjectOutputStream out) throws NotSerializableException {
        throw new NotSerializableException(getClass().getName()
                + " must not be serialized: a PKCS#11 object handle is only valid within the "
                + "session that produced it.");
    }

    @Override
    public String toString() {
        return "Kimbo11ngPrivateKey{alias=" + alias + " algorithm=" + algorithm
                + " handle=" + objectHandle + "}";
    }
}

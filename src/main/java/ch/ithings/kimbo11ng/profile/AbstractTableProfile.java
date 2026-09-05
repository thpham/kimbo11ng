/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.profile;

import ch.ithings.kimbo11ng.p11.CkULong;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;

/**
 * Lookup logic shared by every {@link PqcMechanismProfile}. Subclasses supply only the table.
 *
 * <p>The indexes are built once at construction and validated as they are built, so a table with a
 * duplicate name, or two entries a token could not tell apart, fails fast at class-load rather
 * than producing a mislabelled key much later.
 */
public abstract class AbstractTableProfile implements PqcMechanismProfile {

    private final List<AlgorithmEntry> entries;
    private final Map<String, AlgorithmEntry> byNormalizedName = new HashMap<>();
    private final Map<String, AlgorithmEntry> byKeyTypeAndParamSet = new HashMap<>();

    protected AbstractTableProfile(Collection<AlgorithmEntry> entries) {
        this.entries = List.copyOf(entries);
        for (AlgorithmEntry entry : this.entries) {
            AlgorithmEntry clash = byNormalizedName.put(entry.normalizedName(), entry);
            if (clash != null) {
                throw new IllegalStateException(getClass().getSimpleName() + ": two entries share the name "
                        + entry.canonicalName() + " (" + clash + " and " + entry + ")");
            }
            String reverseKey = reverseKey(entry.ckkKeyType(), entry.ckpParameterSet());
            AlgorithmEntry ambiguous = byKeyTypeAndParamSet.put(reverseKey, entry);
            if (ambiguous != null) {
                throw new IllegalStateException(getClass().getSimpleName() + ": "
                        + entry.canonicalName() + " and "
                        + ambiguous.canonicalName() + " are indistinguishable on the token — both are"
                        + " CKK 0x" + Long.toHexString(entry.ckkKeyType()) + " with parameter set "
                        + entry.ckpParameterSet()
                        + ". A key of either would be read back as the wrong algorithm.");
            }
        }
    }

    /**
     * Both halves are normalised to unsigned 32 bits, so a vendor key type read back from a token
     * as a sign-extended negative matches the positive constant its profile table declares. See
     * {@link ch.ithings.kimbo11ng.p11.CkULong} for why the binding produces the negative.
     */
    private static String reverseKey(long ckk, OptionalLong ckp) {
        return CkULong.typeCode(ckk) + "/"
                + (ckp.isPresent() ? Long.toString(CkULong.typeCode(ckp.getAsLong())) : "-");
    }

    @Override
    public final Collection<AlgorithmEntry> entries() {
        return entries;
    }

    @Override
    public final Optional<AlgorithmEntry> lookup(String keySpec) {
        return Optional.ofNullable(byNormalizedName.get(AlgorithmEntry.normalize(keySpec)));
    }

    @Override
    public final Optional<AlgorithmEntry> lookupByKeyType(long ckk, OptionalLong ckp) {
        AlgorithmEntry exact = byKeyTypeAndParamSet.get(reverseKey(ckk, ckp));
        if (exact != null) {
            return Optional.of(exact);
        }
        // The token reported no parameter set. Resolve only if this key type has exactly one
        // entry; otherwise report nothing rather than picking a default, because the caller can
        // still disambiguate by public-key length and a guess here would be silently wrong.
        if (ckp.isEmpty()) {
            long normalized = CkULong.typeCode(ckk);
            List<AlgorithmEntry> candidates = entries.stream()
                    .filter(e -> CkULong.typeCode(e.ckkKeyType()) == normalized)
                    .toList();
            if (candidates.size() == 1) {
                return Optional.of(candidates.get(0));
            }
        }
        return Optional.empty();
    }

    /**
     * Entries of one family whose public key is exactly {@code length} bytes. ML-DSA and ML-KEM
     * sizes are unique per parameter set, so this identifies the key on its own; SLH-DSA sizes
     * identify only the security level, so it narrows rather than resolves.
     */
    public final List<AlgorithmEntry> byPublicKeyLength(PqcFamily family, int length) {
        return entries.stream()
                .filter(e -> e.family() == family && e.publicKeyLength() == length)
                .toList();
    }

    @Override
    public String toString() {
        return name() + " (" + entries.size() + " algorithms)";
    }
}

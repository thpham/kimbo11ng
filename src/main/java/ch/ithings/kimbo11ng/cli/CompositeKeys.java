/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.provider.Kimbo11ngProvider.CompositeAlgorithm;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import org.bouncycastle.jcajce.interfaces.MLDSAKey;
import org.cesecore.keys.token.CryptoTokenCompositeWrapper;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * EJBCA's composite keys, as the command-line tool sees them on a token.
 *
 * <p>EJBCA's {@code CryptoTokenCompositeWrapper} presents two token keys, {@code <base>-COMPQ} and
 * {@code <base>-COMPC}, as one {@code <base>-COMPOSITE} key; the CLI drives the crypto token
 * underneath it, so it sees the two halves and has to put them together the same way. The
 * composite-to-halves direction is EJBCA's own code, so the two cannot name a key differently; the
 * inverse, which EJBCA does not expose, is tested against it.
 *
 * <p>Which composites exist, and which this token can sign, is the provider's table
 * ({@code Kimbo11ngProvider.compositeAlgorithms()}). Nothing here lists them.
 */
final class CompositeKeys {

    /** A composite alias and the two token aliases behind it. */
    record Halves(String composite, String pq, String classical) {
    }

    /**
     * A half's alias: the base, which half, and EJBCA's optional key-sequence suffix. Same shape as
     * EJBCA's {@code -COMPOSITE([0-9A-Z]*)$}, and case-sensitive like it.
     */
    private static final Pattern HALF = Pattern.compile("^(.+)-COMP([QC])([0-9A-Z]*)$");

    /** The spellings EC keys come back under, folded onto the one the provider's table uses. */
    private static final Map<String, String> CURVE_ALIASES = Map.of(
            "prime256v1", "secp256r1", "p-256", "secp256r1",
            "p-384", "secp384r1", "p-521", "secp521r1");

    private static final Set<String> ML_DSA = Set.of("ML-DSA-44", "ML-DSA-65", "ML-DSA-87");

    private CompositeKeys() {
    }

    /** The halves of a composite alias, or empty if EJBCA would not call it one. */
    static Optional<Halves> halvesOf(String alias) {
        if (alias == null || !CryptoTokenCompositeWrapper.isCompositeAlias(alias)) {
            return Optional.empty();
        }
        return Optional.of(new Halves(alias,
                CryptoTokenCompositeWrapper.getPqcComponentAlias(alias),
                CryptoTokenCompositeWrapper.getClassicalComponentAlias(alias)));
    }

    /** The composite alias a {@code -COMPQ} or {@code -COMPC} alias belongs to, or empty. */
    static Optional<String> compositeOf(String halfAlias) {
        if (halfAlias == null) {
            return Optional.empty();
        }
        Matcher matcher = HALF.matcher(halfAlias);
        return matcher.matches()
                ? Optional.of(matcher.group(1) + "-COMPOSITE" + matcher.group(3))
                : Optional.empty();
    }

    /** {@code ML-DSA-44}, {@code ML-DSA-65} or {@code ML-DSA-87}; null for any other key. */
    static String mlDsaKeySpecOf(PublicKey key) {
        if (!(key instanceof MLDSAKey mlDsa)) {
            return null;
        }
        String name = mlDsa.getParameterSpec().getName().toUpperCase(Locale.ROOT);
        return ML_DSA.contains(name) ? name : null;
    }

    /**
     * The classical half's key spec, in the spelling the provider's table uses: an RSA modulus
     * size, a curve name, or {@code Ed25519}/{@code Ed448}. Null for anything else. Any RSA size
     * and any named curve come back as what they are; whether the pair is a defined composite is
     * {@link #match}'s question, not this one's.
     */
    static String classicalKeySpecOf(PublicKey key) {
        if (key instanceof RSAPublicKey rsa) {
            return String.valueOf(rsa.getModulus().bitLength());
        }
        if (key instanceof ECPublicKey) {
            String curve = AlgorithmTools.getKeySpecification(key);
            if (curve == null) {
                return null;
            }
            return CURVE_ALIASES.getOrDefault(curve.toLowerCase(Locale.ROOT), curve);
        }
        if (key != null && ("Ed25519".equals(key.getAlgorithm())
                || "Ed448".equals(key.getAlgorithm()))) {
            return key.getAlgorithm();
        }
        return null;
    }

    /**
     * The composite whose two halves have these keys' specs, offered by this token or not; empty
     * when no defined composite pairs them.
     */
    static Optional<CompositeAlgorithm> match(List<CompositeAlgorithm> table, PublicKey pq,
            PublicKey classical) {
        String pqSpec = mlDsaKeySpecOf(pq);
        String classicalSpec = classicalKeySpecOf(classical);
        if (pqSpec == null || classicalSpec == null) {
            return Optional.empty();
        }
        return table.stream()
                .filter(row -> row.mlDsaKeySpec().equals(pqSpec)
                        && row.classicalKeySpec().equals(classicalSpec))
                .findFirst();
    }

    /** The table row with this JCA name, or empty. */
    static Optional<CompositeAlgorithm> byName(List<CompositeAlgorithm> table, String name) {
        return table.stream().filter(row -> row.name().equals(name)).findFirst();
    }
}

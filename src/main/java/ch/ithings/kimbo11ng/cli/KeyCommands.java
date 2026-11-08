/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.CryptoTokenImpl;
import ch.ithings.kimbo11ng.provider.Kimbo11ngKeyStoreSpi;
import ch.ithings.kimbo11ng.provider.Kimbo11ngProvider;
import ch.ithings.kimbo11ng.provider.Kimbo11ngProvider.CompositeAlgorithm;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.List;
import java.util.Locale;

/**
 * The commands that create and exercise keys.
 *
 * <p>All three go through {@code CryptoTokenImpl}, not through PKCS#11 directly, so a key made here
 * is indistinguishable from one EJBCA made: same {@code CKA_ID} binding the halves, same label
 * convention, same refusal when the token cannot do the algorithm. A CLI that generated keys its
 * own way would produce keys the CA could not use, which is the failure mode this whole tool exists
 * to catch.
 */
final class KeyCommands {

    private KeyCommands() {
    }

    static List<Command> all() {
        return List.of(generateKeyPair(), generateKey(), testKeyPair());
    }

    private static Command generateKeyPair() {
        return Command.sessionLevel("generatekeypair",
                "Generates a key pair on the token under the given alias.",
                List.of(Opt.arg("alias", "<name>", "Alias for the new key pair. Required."),
                        Opt.arg("key-spec", "<spec>",
                                "What to generate. Takes exactly what the crypto token takes: "
                                        + "RSA4096 or a bare key size, an EC curve name such as "
                                        + "secp384r1, or a post-quantum name such as ML-DSA-65. "
                                        + "A composite such as MLDSA44-RSA2048-PSS-SHA256 makes "
                                        + "both halves, and needs an alias ending in -COMPOSITE. "
                                        + "Required.")),
                (env, args) -> {
                    String alias = args.require("alias");
                    String keySpec = args.require("key-spec");
                    try (TokenHandle handle = TokenHandle.session(env, args)) {
                        List<CompositeAlgorithm> table =
                                handle.token().getProvider().compositeAlgorithms();
                        boolean compositeSpec = CompositeKeys.byName(table, keySpec).isPresent()
                                || Kimbo11ngProvider.excludedComposites().containsKey(keySpec);
                        java.util.Optional<CompositeKeys.Halves> halves =
                                CompositeKeys.halvesOf(alias);
                        if (compositeSpec || halves.isPresent()) {
                            generateComposite(env, handle, alias, halves, keySpec, table);
                            return;
                        }
                        handle.token().generateKeyPair(keySpec, alias);
                        env.out().println("Generated key pair with alias " + alias);
                    }
                });
    }

    /**
     * The two halves of a composite, named so EJBCA shows them as one {@code -COMPOSITE} key —
     * the way Keyfactor documents for composite keys made outside EJBCA.
     *
     * <p>All or nothing: an orphan half is invisible in EJBCA and still holds its alias, so if the
     * second half cannot be made the first is removed again.
     */
    private static void generateComposite(CliEnv env, TokenHandle handle, String alias,
            java.util.Optional<CompositeKeys.Halves> named, String keySpec,
            List<CompositeAlgorithm> table) throws Exception {
        if (named.isEmpty()) {
            throw CliException.usage(keySpec + " is a composite key spec, so the alias must end in"
                    + " -COMPOSITE (for example " + alias + "-COMPOSITE): that is how EJBCA finds"
                    + " the two halves and shows them as one key.");
        }
        CompositeKeys.Halves halves = named.get();
        String excluded = Kimbo11ngProvider.excludedComposites().get(keySpec);
        if (excluded != null) {
            throw new CliException(keySpec + " is not offered: " + excluded + ".");
        }
        CompositeAlgorithm composite = CompositeKeys.byName(table, keySpec).orElseThrow(() ->
                CliException.usage("Alias " + alias + " ends in -COMPOSITE, which EJBCA reads as a"
                        + " composite key, so --key-spec must name a composite such as"
                        + " MLDSA44-RSA2048-PSS-SHA256, not " + keySpec + "."));
        if (!composite.offered()) {
            throw new CliException("This token cannot sign " + composite.name() + ": the provider"
                    + " does not offer both of its halves here, so a key of it could not be used."
                    + " Run capabilities to see which signature services this token has.");
        }
        for (String half : List.of(halves.pq(), halves.classical())) {
            if (handle.keyStore().getKey(half, null) != null) {
                throw new CliException("Alias " + half + " already exists on the token, and "
                        + halves.composite() + " needs both " + halves.pq() + " and "
                        + halves.classical() + " free. Delete it with deleteobject --alias " + half
                        + ", or choose another alias.");
            }
        }

        CryptoTokenImpl token = handle.token();
        String classical = describeKeySpec(composite.classicalKeySpec());
        token.generateKeyPair(composite.mlDsaKeySpec(), halves.pq());
        try {
            token.generateKeyPair(composite.classicalKeySpec(), halves.classical());
        } catch (Exception e) {
            String cleanup;
            try {
                token.deleteEntry(halves.pq());
                cleanup = "Removed " + halves.pq() + " again, so no half is left behind.";
            } catch (Exception deletion) {
                cleanup = "Could not remove " + halves.pq() + " ("
                        + CompositeDiagnosis.reason(deletion) + "); delete it with deleteobject"
                        + " --alias " + halves.pq() + ".";
            }
            throw new CliException("Generated " + halves.pq() + " (" + composite.mlDsaKeySpec()
                    + "), but " + halves.classical() + " (" + classical + ") failed: "
                    + CompositeDiagnosis.reason(e) + ". " + cleanup);
        }
        env.out().println("Generated composite key pair " + halves.composite() + ": "
                + halves.pq() + " (" + composite.mlDsaKeySpec() + ") and " + halves.classical()
                + " (" + classical + ")");
    }

    /** {@code RSA 2048} for an RSA size, the curve or Edwards name as it stands otherwise. */
    private static String describeKeySpec(String keySpec) {
        return keySpec.matches("\\d+") ? "RSA " + keySpec : keySpec;
    }

    private static Command generateKey() {
        return Command.sessionLevel("generatekey",
                "Generates a symmetric key on the token under the given alias.",
                List.of(Opt.arg("alias", "<name>", "Alias for the new key. Required."),
                        Opt.arg("key-spec", "<alg>",
                                "Algorithm: AES, or one of HmacSHA256, HmacSHA384, HmacSHA512. "
                                        + "Required."),
                        Opt.arg("key-size", "<bits>",
                                "Key length in bits. Defaults to the algorithm's own default.")),
                (env, args) -> {
                    String alias = args.require("alias");
                    String algorithm = args.require("key-spec");
                    int bits = args.getInt("key-size", 0);
                    try (TokenHandle handle = TokenHandle.session(env, args)) {
                        handle.token().generateKey(algorithm, bits, alias);
                        env.out().println("Generated " + algorithm + " key with alias " + alias);
                    }
                });
    }

    /**
     * Sign once with the key, verify the result, and say so.
     *
     * <p>The check EJBCA's {@code HsmKeepAliveWorker} runs on a schedule, on demand and without a
     * running CA. An alias that fails here is one the CA will refuse to use, and the reason is
     * printed rather than left in a server log.
     *
     * <p>A {@code -COMPOSITE} alias is signed as the composite EJBCA would make of its two halves;
     * see {@link #testComposite}, which also says, when it fails, which half failed and why.
     */
    private static Command testKeyPair() {
        return Command.sessionLevel("testkeypair",
                "Signs and verifies a test message with one key, the way EJBCA tests it. A"
                        + " -COMPOSITE alias is signed as the composite of its two halves.",
                List.of(Opt.arg("alias", "<name>", "Alias to test. Required."),
                        Opt.arg("signature-algorithm", "<alg>",
                                "Signature algorithm. Defaults to one derived from the key.")),
                (env, args) -> {
                    String alias = args.require("alias");
                    try (TokenHandle handle = TokenHandle.session(env, args)) {
                        java.util.Optional<CompositeKeys.Halves> composite =
                                CompositeKeys.halvesOf(alias);
                        if (composite.isPresent()) {
                            testComposite(env, handle, composite.get(),
                                    args.get("signature-algorithm", null));
                            return;
                        }
                        // The key first, then the algorithm: resolving the algorithm needs the key
                        // to exist, and doing it the other way round reports a missing alias as
                        // "cannot tell what algorithm this uses", which sends the reader looking
                        // for the wrong problem.
                        PrivateKey privateKey = privateKey(handle, alias);
                        String algorithm = signatureAlgorithm(handle.token(), alias,
                                args.get("signature-algorithm", null));
                        PublicKey publicKey = handle.token().readPublicKey(alias, true);
                        if (publicKey == null) {
                            throw new CliException("Alias '" + alias + "' has no readable public"
                                    + " key, so a signature over it cannot be verified. EJBCA will"
                                    + " refuse this key for the same reason.");
                        }
                        byte[] message = ("kimbo11ng test " + alias)
                                .getBytes(StandardCharsets.UTF_8);
                        Signature signer = Signature.getInstance(algorithm,
                                handle.token().getProvider());
                        signer.initSign(privateKey);
                        signer.update(message);
                        byte[] signature = signer.sign();

                        Signature verifier = verifier(algorithm);
                        verifier.initVerify(publicKey);
                        verifier.update(message);
                        if (!verifier.verify(signature)) {
                            throw new CliException("Alias '" + alias + "' signed with " + algorithm
                                    + ", but the signature did not verify against the public key on"
                                    + " the token. The two halves of this key pair do not match.");
                        }
                        env.out().println("Alias " + alias + " signed and verified with "
                                + algorithm + " (" + signature.length + " byte signature)");
                    }
                });
    }

    /**
     * Sign and verify once with a composite, built from its two token halves exactly as EJBCA's
     * {@code CryptoTokenCompositeWrapper} builds it — so a pass here is the signature a CA with
     * this key would make, both halves on the token and the ML-DSA half with its context.
     *
     * <p>Everything that can be told from the keys alone is refused before anything is signed: a
     * missing half, a pair no composite defines, a composite this token cannot sign, and a
     * {@code --signature-algorithm} that names another composite than this pair's.
     */
    static void testComposite(CliEnv env, TokenHandle handle, CompositeKeys.Halves halves,
            String explicit) throws Exception {
        CryptoTokenImpl token = handle.token();
        List<String> missing = new java.util.ArrayList<>();
        for (String half : List.of(halves.pq(), halves.classical())) {
            if (handle.keyStore().getKey(half, null) == null) {
                missing.add(half);
            }
        }
        if (!missing.isEmpty()) {
            throw new CliException("Composite alias '" + halves.composite() + "' is two keys on the"
                    + " token, " + halves.pq() + " (ML-DSA) and " + halves.classical()
                    + " (classical), and " + String.join(" and ", missing)
                    + (missing.size() == 1 ? " is" : " are") + " missing. EJBCA will not show this"
                    + " composite either. Run listkeypairs to see what the slot holds.");
        }
        for (String half : List.of(halves.pq(), halves.classical())) {
            // Before the public-key check: a secret key has none, and "no readable public key"
            // would send the reader after a broken key pair that is not there.
            if (token.isSecretKey(half)) {
                throw new CliException(half + " is a secret key, so '" + halves.composite()
                        + "' is not a defined composite: both halves have to be key pairs."
                        + nextStep(halves));
            }
        }
        PublicKey pqPublic = token.readPublicKey(halves.pq(), true);
        PublicKey classicalPublic = token.readPublicKey(halves.classical(), true);
        if (pqPublic == null || classicalPublic == null) {
            throw new CliException("Composite alias '" + halves.composite() + "' has a half with no"
                    + " readable public key, so its signature cannot be verified. EJBCA will refuse"
                    + " it for the same reason.");
        }
        List<CompositeAlgorithm> table = token.getProvider().compositeAlgorithms();
        CompositeAlgorithm composite = CompositeKeys.match(table, pqPublic, classicalPublic)
                .orElseThrow(() -> new CliException(halves.pq() + " (" + describe(pqPublic, true)
                        + ") and " + halves.classical() + " (" + describe(classicalPublic, false)
                        + ") are not a defined composite: no composite ML-DSA algorithm pairs"
                        + " these two keys, so EJBCA cannot sign with '" + halves.composite()
                        + "'." + nextStep(halves)));
        if (explicit != null && !explicit.isBlank() && !explicit.trim().equals(composite.name())) {
            throw CliException.usage("--signature-algorithm " + explicit.trim() + " does not match"
                    + " this pair: " + halves.composite() + " is " + composite.name() + ".");
        }
        if (!composite.offered()) {
            throw new CliException("This token cannot sign " + composite.name() + ": the provider"
                    + " does not offer both of its halves here. Run capabilities to see which"
                    + " signature services this token has.");
        }
        PrivateKey pqPrivate = privateKey(handle, halves.pq());
        PrivateKey classicalPrivate = privateKey(handle, halves.classical());
        PrivateKey compositePrivate = new CompositePrivateKey(
                new ASN1ObjectIdentifier(composite.oid()), pqPrivate, classicalPrivate);
        PublicKey compositePublic = new CompositePublicKey(
                new ASN1ObjectIdentifier(composite.oid()), pqPublic, classicalPublic);

        byte[] message = ("kimbo11ng test " + halves.composite()).getBytes(StandardCharsets.UTF_8);
        byte[] signature;
        try {
            Signature signer = Signature.getInstance(composite.name(), token.getProvider());
            signer.initSign(compositePrivate);
            signer.update(message);
            signature = signer.sign();
        } catch (java.security.GeneralSecurityException | RuntimeException e) {
            // The diagnosis runs only here and below, so a passing composite costs one signature.
            throw new CliException("Alias '" + halves.composite() + "' could not be signed with "
                    + composite.name() + ": " + CompositeDiagnosis.reason(e) + ". "
                    + CompositeDiagnosis.diagnose(token.getProvider(), composite, pqPrivate,
                            pqPublic, classicalPrivate, classicalPublic));
        }

        Signature verifier = verifier(composite.name());
        verifier.initVerify(compositePublic);
        verifier.update(message);
        if (!verifier.verify(signature)) {
            throw new CliException("Alias '" + halves.composite() + "' signed with "
                    + composite.name() + ", but the composite signature did not verify. "
                    + CompositeDiagnosis.diagnose(token.getProvider(), composite, pqPrivate,
                            pqPublic, classicalPrivate, classicalPublic));
        }
        env.out().println("Alias " + halves.composite() + " signed and verified with "
                + composite.name() + " (" + signature.length + " byte signature)");
    }

    /** The way out of a pair that is no composite, as the closing sentence of its refusal. */
    private static String nextStep(CompositeKeys.Halves halves) {
        return " Delete the halves with deleteobject --alias " + halves.pq() + " and"
                + " deleteobject --alias " + halves.classical() + ", then make a matching pair"
                + " with generatekeypair --alias " + halves.composite() + " --key-spec <one of"
                + " the composites capabilities lists>.";
    }

    /** What a half is, for a message: its key spec where it has one, its algorithm otherwise. */
    private static String describe(PublicKey key, boolean pq) {
        String spec = pq
                ? CompositeKeys.mlDsaKeySpecOf(key)
                : CompositeKeys.classicalKeySpecOf(key);
        return spec == null ? key.getAlgorithm() : describeKeySpec(spec);
    }

    /**
     * A {@code Signature} for verifying, resolved anywhere but the token.
     *
     * <p>{@code Kimbo11ngSignatureSpi.engineInitVerify} refuses outright, and deliberately: EJBCA
     * verifies with BouncyCastle, because a verification is a public-key operation with nothing to
     * protect and no reason to spend an HSM round trip. Asking the token here would fail on the
     * first key tested, so the CLI does what EJBCA does and lets the JCA pick the provider from the
     * algorithm name.
     */
    static Signature verifier(String algorithm) throws Exception {
        return Signature.getInstance(algorithm);
    }

    /** The private key for an alias, with a message that says what to do when it is not one. */
    static PrivateKey privateKey(TokenHandle handle, String alias) throws Exception {
        if (handle.token().isSecretKey(alias)) {
            throw new CliException("Alias '" + alias + "' names a secret key, which signs through a"
                    + " Mac rather than a Signature. This command works on key pairs.");
        }
        java.security.Key key = handle.keyStore().getKey(alias, null);
        if (key == null) {
            throw new CliException("No key on the token under alias '" + alias
                    + "'. Run listkeypairs to see the aliases this slot publishes.");
        }
        if (!(key instanceof PrivateKey privateKey)) {
            throw new CliException("Alias '" + alias + "' resolved to a "
                    + key.getClass().getSimpleName() + ", not a private key.");
        }
        return privateKey;
    }

    /**
     * The signature algorithm to use for an alias.
     *
     * <p>An explicit {@code --signature-algorithm} always wins. Otherwise it comes from the key
     * store SPI's own view of the key, which is the same lookup the crypto token does when EJBCA
     * asks it to sign — so the default here is the algorithm the CA would pick.
     */
    static String signatureAlgorithm(CryptoTokenImpl token, String alias, String explicit)
            throws Exception {
        if (explicit != null && !explicit.isBlank()) {
            return explicit.trim();
        }
        Kimbo11ngKeyStoreSpi spi = token.getKeyStoreSpi();
        if (spi != null) {
            var entry = spi.algorithmFor(alias);
            if (entry.isPresent()) {
                // ML-KEM generates perfectly well and then has nothing to sign with, because it is
                // key encapsulation and not a signature scheme. Without this the JCA lookup fails
                // as "no such algorithm: ML-KEM-768 for provider Kimbo11ng-…", which reads as a
                // gap in this provider rather than as a question that does not apply to the key.
                if (!entry.get().canSign()) {
                    throw new CliException("Alias '" + alias + "' holds an "
                            + entry.get().canonicalName() + " key, and " + entry.get().family().jcaName()
                            + " is key encapsulation, not signing — there is no signature to test."
                            + " Its operations are " + entry.get().ops().stream().map(Enum::name)
                                    .sorted().collect(java.util.stream.Collectors.joining(", "))
                            + ", which capabilities also reports.");
                }
                return entry.get().canonicalName();
            }
        }
        PublicKey publicKey = token.readPublicKey(alias, true);
        if (publicKey == null) {
            throw new CliException("Cannot tell what algorithm alias '" + alias + "' uses;"
                    + " pass --signature-algorithm.");
        }
        String algorithm = publicKey.getAlgorithm().toUpperCase(Locale.ROOT);
        if (algorithm.startsWith("RSA")) {
            return "SHA256withRSA";
        }
        if (algorithm.startsWith("EC")) {
            return "SHA256withECDSA";
        }
        // A post-quantum key: the JCA name and the algorithm name are the same thing.
        return publicKey.getAlgorithm();
    }
}

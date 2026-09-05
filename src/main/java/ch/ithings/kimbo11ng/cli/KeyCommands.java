/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.CryptoTokenImpl;
import ch.ithings.kimbo11ng.provider.Kimbo11ngKeyStoreSpi;

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
                                        + "Required.")),
                (env, args) -> {
                    String alias = args.require("alias");
                    String keySpec = args.require("key-spec");
                    try (TokenHandle handle = TokenHandle.session(env, args)) {
                        handle.token().generateKeyPair(keySpec, alias);
                        env.out().println("Generated key pair with alias " + alias);
                    }
                });
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
     */
    private static Command testKeyPair() {
        return Command.sessionLevel("testkeypair",
                "Signs and verifies a test message with one key, the way EJBCA tests it.",
                List.of(Opt.arg("alias", "<name>", "Alias to test. Required."),
                        Opt.arg("signature-algorithm", "<alg>",
                                "Signature algorithm. Defaults to one derived from the key.")),
                (env, args) -> {
                    String alias = args.require("alias");
                    try (TokenHandle handle = TokenHandle.session(env, args)) {
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
        Kimbo11ngKeyStoreSpi spi = token.getProvider().getKeyStoreSpi();
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

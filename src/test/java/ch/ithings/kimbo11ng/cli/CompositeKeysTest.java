/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.provider.Kimbo11ngProvider.CompositeAlgorithm;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.keys.token.CryptoTokenCompositeWrapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Recognising EJBCA's composite keys from what is on the token.
 *
 * <p>The naming has to be EJBCA's exactly: a key the CLI names differently is a key EJBCA does not
 * see as a composite at all. So the composite-to-halves direction is EJBCA's own code, and the
 * inverse is checked against it rather than against a restatement of the rule.
 */
@DisplayName("composite key recognition")
class CompositeKeysTest {

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static PublicKey key(String algorithm, AlgorithmParameterSpec spec) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm,
                BouncyCastleProvider.PROVIDER_NAME);
        if (spec != null) {
            generator.initialize(spec);
        }
        return generator.generateKeyPair().getPublic();
    }

    private static PublicKey rsa(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA",
                BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(bits);
        return generator.generateKeyPair().getPublic();
    }

    @Test
    @DisplayName("finds the halves of a composite alias the way EJBCA names them")
    void halvesFollowEjbcaNaming() {
        CompositeKeys.Halves plain = CompositeKeys.halvesOf("foo-COMPOSITE").orElseThrow();
        assertEquals("foo-COMPOSITE", plain.composite());
        assertEquals("foo-COMPQ", plain.pq());
        assertEquals("foo-COMPC", plain.classical());

        CompositeKeys.Halves sequenced =
                CompositeKeys.halvesOf("signKey-COMPOSITE00001").orElseThrow();
        assertEquals("signKey-COMPQ00001", sequenced.pq());
        assertEquals("signKey-COMPC00001", sequenced.classical());

        assertTrue(CompositeKeys.halvesOf("foo").isEmpty());
        assertTrue(CompositeKeys.halvesOf("foo-composite").isEmpty(),
                "EJBCA's pattern is case-sensitive, so this is an ordinary alias");
    }

    @Test
    @DisplayName("maps a half back to its composite exactly as EJBCA maps the other way")
    void inverseAgreesWithEjbca() {
        for (String composite : List.of("foo-COMPOSITE", "signKey-COMPOSITE00001",
                "a-b-COMPOSITEAB12")) {
            assertEquals(Optional.of(composite), CompositeKeys.compositeOf(
                    CryptoTokenCompositeWrapper.getPqcComponentAlias(composite)), composite);
            assertEquals(Optional.of(composite), CompositeKeys.compositeOf(
                    CryptoTokenCompositeWrapper.getClassicalComponentAlias(composite)), composite);
        }
    }

    @Test
    @DisplayName("ignores aliases that are not composite halves")
    void compositeOfIgnoresOtherAliases() {
        for (String alias : List.of("foo", "foo-COMPOSITE", "foo-compq", "foo-COMPQ-x")) {
            assertTrue(CompositeKeys.compositeOf(alias).isEmpty(), alias);
        }
    }

    @Test
    @DisplayName("reads each half's key spec from its public key")
    void keySpecsFromKeys() throws Exception {
        assertEquals("ML-DSA-65",
                CompositeKeys.mlDsaKeySpecOf(key("ML-DSA", MLDSAParameterSpec.ml_dsa_65)));
        assertEquals("3072", CompositeKeys.classicalKeySpecOf(rsa(3072)));
        assertEquals("secp384r1", CompositeKeys.classicalKeySpecOf(
                key("EC", new ECGenParameterSpec("secp384r1"))));
        assertEquals("brainpoolP256r1", CompositeKeys.classicalKeySpecOf(
                key("EC", new ECGenParameterSpec("brainpoolP256r1"))));
        assertEquals("Ed448", CompositeKeys.classicalKeySpecOf(key("Ed448", null)));
        assertEquals("Ed25519", CompositeKeys.classicalKeySpecOf(key("Ed25519", null)));
        assertNull(CompositeKeys.classicalKeySpecOf(key("ML-DSA", MLDSAParameterSpec.ml_dsa_44)),
                "an ML-DSA key is no classical half");
        assertNull(CompositeKeys.mlDsaKeySpecOf(rsa(2048)),
                "an RSA key is no ML-DSA half, whatever its alias says");
    }

    @Test
    @DisplayName("reads a P-256 key as secp256r1 whatever spelling made it")
    void curveSpellingsNormalise() throws Exception {
        for (String spelling : List.of("prime256v1", "P-256", "secp256r1")) {
            assertEquals("secp256r1", CompositeKeys.classicalKeySpecOf(
                    key("EC", new ECGenParameterSpec(spelling))), spelling);
        }
    }

    @Test
    @DisplayName("matches a pair of keys to the one composite row with both specs")
    void matchFindsTheRow() throws Exception {
        List<CompositeAlgorithm> table = List.of(
                new CompositeAlgorithm("MLDSA44-RSA2048-PSS-SHA256", "1.3.6.1.5.5.7.6.37",
                        "ML-DSA-44", "2048", "SHA256withRSAandMGF1", true),
                new CompositeAlgorithm("MLDSA65-ECDSA-P384-SHA512", "1.3.6.1.5.5.7.6.46",
                        "ML-DSA-65", "secp384r1", "SHA384withECDSA", false));
        PublicKey mlDsa44 = key("ML-DSA", MLDSAParameterSpec.ml_dsa_44);

        assertEquals("MLDSA44-RSA2048-PSS-SHA256",
                CompositeKeys.match(table, mlDsa44, rsa(2048)).orElseThrow().name());
        assertTrue(CompositeKeys.match(table, mlDsa44, rsa(4096)).isEmpty(),
                "ML-DSA-44 with RSA 4096 is no defined composite");
        assertEquals("MLDSA65-ECDSA-P384-SHA512", CompositeKeys.match(table,
                key("ML-DSA", MLDSAParameterSpec.ml_dsa_65),
                key("EC", new ECGenParameterSpec("secp384r1"))).orElseThrow().name(),
                "a row the token cannot sign is still matched; offered decides what to say");
        assertEquals("MLDSA65-ECDSA-P384-SHA512",
                CompositeKeys.byName(table, "MLDSA65-ECDSA-P384-SHA512").orElseThrow().name());
        assertTrue(CompositeKeys.byName(table, "MLDSA87-Ed448-SHAKE256").isEmpty());
    }
}

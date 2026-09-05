/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.Pkcs11v32Profile;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLDSAKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.LongRef;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Security;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * What OID a lenient read publishes when the token labels a key with a different one.
 *
 * <p>{@link PublicKeyReader.Policy#LENIENT} tolerates a token whose {@code SubjectPublicKeyInfo}
 * names a pre-standard OID, and that tolerance is deliberate. What it must never do is publish
 * that OID: the length check that admitted the key was run against the resolved
 * {@link AlgorithmEntry}, so the entry's parameter set is the only one the material is known to
 * support. Publishing the token's OID instead yields a certificate whose SubjectPublicKeyInfo
 * names a parameter set the key does not have, and nothing downstream re-checks it.
 */
@DisplayName("Lenient public key OID")
class LenientPublicKeyOidTest {

    private TestSlot fixture;
    private FakeToken fake;
    private final Pkcs11v32Profile profile = new Pkcs11v32Profile();

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void openSlot() throws Exception {
        fake = new FakeToken();
        fixture = new TestSlot(fake).loggedIn();
    }

    private long generate(AlgorithmEntry entry) throws Exception {
        KeyTemplates.Pair templates = KeyTemplates.pqc(
                entry.canonicalName().getBytes(StandardCharsets.UTF_8),
                KeyTemplates.newKeyId(), entry, profile);
        return fixture.onSession((ce, session) -> {
            LongRef pub = new LongRef();
            LongRef priv = new LongRef();
            ce.GenerateKeyPair(session, new CKM(entry.ckmKeyPairGen()),
                    templates.pub(), templates.priv(), pub, priv);
            return pub.value();
        });
    }

    private PublicKey readLenient(long handle, AlgorithmEntry entry) throws Exception {
        return fixture.onSession((ce, session) -> PublicKeyReader.readPqcPublicKey(
                ce, session, handle, entry, PublicKeyReader.Policy.LENIENT));
    }

    @Test
    @DisplayName("publishes the resolved entry's OID, not the OID the token labelled the key with")
    void lenientReadDoesNotPublishTheTokensOid() throws Exception {
        AlgorithmEntry entry = profile.lookup("ML-DSA-65").orElseThrow();
        AlgorithmEntry other = profile.lookup("ML-DSA-44").orElseThrow();
        // The token wraps genuine ML-DSA-65 material (1952 bytes) in a SubjectPublicKeyInfo that
        // names ML-DSA-44. Only the ML-DSA-65 length was ever verified, so ML-DSA-65 is the only
        // parameter set this material is known to support.
        fake.pqcSpkiOid(other.oid().getId());
        long handle = generate(entry);

        PublicKey key = readLenient(handle, entry);
        assertInstanceOf(MLDSAKey.class, key, "LENIENT must still accept the key");

        SubjectPublicKeyInfo published = SubjectPublicKeyInfo.getInstance(key.getEncoded());
        assertEquals(entry.oid(), published.getAlgorithm().getAlgorithm(),
                "the OID in the encoding is the one EJBCA writes into the certificate");
        assertEquals(entry.publicKeyLength(), published.getPublicKeyData().getOctets().length,
                "the material must survive the re-wrap untouched");
        assertEquals("ML-DSA-65", ((MLDSAKey) key).getParameterSpec().getName()
                .toUpperCase(Locale.ROOT));
    }
}

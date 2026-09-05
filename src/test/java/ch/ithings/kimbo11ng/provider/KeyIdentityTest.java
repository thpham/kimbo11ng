/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.fake.FakeToken;
import ch.ithings.kimbo11ng.fake.TestSlot;
import ch.ithings.kimbo11ng.profile.Pkcs11v32Profile;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.LongRef;

import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.Security;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A key survives losing the handle it was found under.
 *
 * <p>An object handle is not an identity — PKCS#11 leaves its lifetime to the implementation, and
 * EJBCA's {@code CachingKeyStoreWrapper} holds our {@code Key} objects for the life of the crypto
 * token. On a network HSM that is long enough for the connection behind them to be replaced.
 */
@DisplayName("durable key identity")
class KeyIdentityTest {

    private TestSlot fixture;
    private final Pkcs11v32Profile profile = new Pkcs11v32Profile();

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void openSlot() throws Exception {
        fixture = new TestSlot(new FakeToken()).loggedIn();
    }

    private Kimbo11ngKeyStoreSpi load() throws Exception {
        Kimbo11ngKeyStoreSpi spi = new Kimbo11ngKeyStoreSpi(
                new TokenRuntime(fixture.slot(), profile));
        spi.engineLoad(null, null);
        return spi;
    }

    /** Generates through the production templates, with a CKA_ID. @return the private handle */
    private long generateRsa(String alias) throws Exception {
        KeyTemplates.Pair t = KeyTemplates.rsa(alias.getBytes(StandardCharsets.UTF_8),
                KeyTemplates.newKeyId(), 2048);
        return fixture.onSession((ce, session) -> {
            LongRef pub = new LongRef();
            LongRef priv = new LongRef();
            ce.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN),
                    t.pub(), t.priv(), pub, priv);
            return priv.value();
        });
    }

    /** Creates a key pair the way a pre-kimbo11ng tool would: labelled, with no CKA_ID. */
    private long generateLegacyRsa(String alias) throws Exception {
        byte[] label = alias.getBytes(StandardCharsets.UTF_8);
        CKA[] pub = {
            new CKA(CKA.CLASS, CKO.PUBLIC_KEY), new CKA(CKA.KEY_TYPE, CKK.RSA),
            new CKA(CKA.LABEL, label), new CKA(CKA.MODULUS_BITS, 2048L),
            new CKA(CKA.TOKEN, true),
        };
        CKA[] priv = {
            new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.KEY_TYPE, CKK.RSA),
            new CKA(CKA.LABEL, label), new CKA(CKA.TOKEN, true), new CKA(CKA.SIGN, true),
        };
        return fixture.onSession((ce, session) -> {
            LongRef pubRef = new LongRef();
            LongRef privRef = new LongRef();
            ce.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), pub, priv,
                    pubRef, privRef);
            return privRef.value();
        });
    }

    @Nested
    @DisplayName("resolution")
    class Resolution {

        @Test
        @DisplayName("re-resolves the handle after the slot invalidates it")
        void reResolvesAfterInvalidation() throws Exception {
            long handle = generateRsa("signKey");
            Kimbo11ngPrivateKey key = (Kimbo11ngPrivateKey) load().engineGetKey("signKey", null);
            assertEquals(handle, fixture.onSession(key::objectHandle));

            fixture.slot().invalidateHandles();

            // Same key, looked up again rather than trusted from the cache. On a token that
            // renumbers objects this is the difference between signing and CKR_OBJECT_HANDLE_INVALID.
            assertEquals(handle, fixture.onSession(key::objectHandle));
        }

        @Test
        @DisplayName("finds the key by CKA_ID even when its label has been changed")
        void survivesARename() throws Exception {
            generateRsa("signKey");
            Kimbo11ngPrivateKey key = (Kimbo11ngPrivateKey) load().engineGetKey("signKey", null);
            long original = fixture.onSession(key::objectHandle);

            // An operator renaming the alias through a vendor tool. The label is EJBCA's alias and
            // is editable; CKA_ID is written once at generation and is not.
            fixture.onSession((ce, session) -> {
                ce.SetAttributeValue(session, original,
                        new CKA(CKA.LABEL, "renamed".getBytes(StandardCharsets.UTF_8)));
                return null;
            });
            fixture.slot().invalidateHandles();

            assertEquals(original, fixture.onSession(key::objectHandle));
        }

        @Test
        @DisplayName("reports a key that is no longer on the token instead of returning a handle")
        void deletedKeyIsReported() throws Exception {
            long handle = generateRsa("signKey");
            Kimbo11ngPrivateKey key = (Kimbo11ngPrivateKey) load().engineGetKey("signKey", null);

            fixture.onSession((ce, session) -> {
                ce.DestroyObject(session, handle);
                return null;
            });
            fixture.slot().invalidateHandles();

            KeyException e = assertThrows(KeyException.class,
                    () -> fixture.onSession(key::objectHandle));
            assertTrue(e.getMessage().contains("signKey"), e.getMessage());
        }

        @Test
        @DisplayName("identity is the key on the token, not the handle it was found under")
        void equalityIgnoresTheHandle() throws Exception {
            long handle = generateRsa("signKey");
            Kimbo11ngPrivateKey a = (Kimbo11ngPrivateKey) load().engineGetKey("signKey", null);
            Kimbo11ngPrivateKey b = (Kimbo11ngPrivateKey) load().engineGetKey("signKey", null);

            assertEquals(a, b);
            assertEquals(a.hashCode(), b.hashCode());
            assertNotEquals(a, new Kimbo11ngPrivateKey("RSA", fixture.slot(),
                    new P11KeyRef(null, "other", null), handle));
        }

        @Test
        @DisplayName("refuses to be serialized")
        void notSerializable() throws Exception {
            generateRsa("signKey");
            Object key = load().engineGetKey("signKey", null);
            try (ObjectOutputStream out = new ObjectOutputStream(new ByteArrayOutputStream())) {
                // A deserialized key would name an object inside an HSM no other JVM can reach,
                // and would fail at signing time with an NPE far from the cause.
                assertThrows(NotSerializableException.class, () -> out.writeObject(key));
            }
        }
    }

    @Nested
    @DisplayName("legacy keys")
    class Legacy {

        @Test
        @DisplayName("loads a key that has no CKA_ID and writes one onto it")
        void backfillsAMissingKeyId() throws Exception {
            generateLegacyRsa("oldKey");

            Kimbo11ngPrivateKey key = (Kimbo11ngPrivateKey) load().engineGetKey("oldKey", null);

            assertNotNull(key, "an existing CA's key must keep working");
            assertTrue(key.ref().hasCkaId(),
                    "the key should have been given an id so it no longer depends on its label");
            // And the id must actually be on the token, not only in memory.
            long handle = fixture.onSession(key::objectHandle);
            assertArrayEquals(key.ref().ckaId(),
                    fixture.onSession((ce, session) ->
                            ce.GetAttributeValue(session, handle, CKA.ID).getValue()));
        }

        @Test
        @DisplayName("keeps the public key findable after backfilling the private one")
        void backfillCoversBothHalves() throws Exception {
            generateLegacyRsa("oldKey");

            Kimbo11ngKeyStoreSpi spi = load();
            Kimbo11ngPrivateKey key = (Kimbo11ngPrivateKey) spi.engineGetKey("oldKey", null);

            // The regression this pins, found by upgrading a live EJBCA over keys the original
            // build had created: writing CKA_ID onto the private key alone orphans the public one,
            // because the pair is looked up by id from then on. The alias then loads with no
            // public key, and EJBCA reports the key as not existing at all.
            assertNotNull(spi.getPublicKey("oldKey"),
                    "the public half must still be paired after the backfill");
            long pubHandle = fixture.onSession((ce, session) ->
                    key.ref().findAll(ce, session, CKO.PUBLIC_KEY)[0]);
            assertArrayEquals(key.ref().ckaId(), fixture.onSession((ce, session) ->
                    ce.GetAttributeValue(session, pubHandle, CKA.ID).getValue()),
                    "both halves must carry the same id");
        }

        @Test
        @DisplayName("still pairs the public key when only the private one could be given an id")
        void publicKeyFoundByLabelWhenItHasNoId() throws Exception {
            generateLegacyRsa("oldKey");
            Kimbo11ngKeyStoreSpi spi = load();
            Kimbo11ngPrivateKey key = (Kimbo11ngPrivateKey) spi.engineGetKey("oldKey", null);

            // Strip the id back off the public half, standing in for a token that accepted the
            // write on one object and refused it on the other.
            long pubHandle = fixture.onSession((ce, session) ->
                    ce.FindObjects(session, new CKA(CKA.CLASS, CKO.PUBLIC_KEY),
                            new CKA(CKA.LABEL, "oldKey".getBytes(StandardCharsets.UTF_8)))[0]);
            fixture.onSession((ce, session) -> {
                ce.SetAttributeValue(session, pubHandle, new CKA(CKA.ID, new byte[0]));
                return null;
            });

            int withFallback = fixture.onSession((ce, session) ->
                    key.ref().findAll(ce, session, CKO.PUBLIC_KEY, true).length);
            int strict = fixture.onSession((ce, session) ->
                    key.ref().findAll(ce, session, CKO.PUBLIC_KEY).length);
            assertEquals(1, withFallback,
                    "pairing must fall back to the label rather than report no public key");
            assertEquals(0, strict,
                    "deletion must not fall back: it would destroy same-label objects");
        }

        @Test
        @DisplayName("keeps working when the token refuses to accept a CKA_ID")
        void readOnlyAttributesAreNotFatal() throws Exception {
            generateLegacyRsa("oldKey");
            // An audited HSM partition can forbid changing attributes on a token object. A CA
            // running on such a token must not stop working because of a housekeeping write.
            fixture.token().readOnlyAttributes(CKA.ID);

            Kimbo11ngPrivateKey key = (Kimbo11ngPrivateKey) load().engineGetKey("oldKey", null);

            assertNotNull(key);
            assertFalse(key.ref().hasCkaId());
            assertTrue(fixture.onSession(key::objectHandle) > 0,
                    "it must still resolve, by label");
        }

        @Test
        @DisplayName("leaves the key alone when backfill is switched off")
        void backfillCanBeDisabled() throws Exception {
            generateLegacyRsa("oldKey");
            Kimbo11ngKeyStoreSpi spi = new Kimbo11ngKeyStoreSpi(
                    new TokenRuntime(fixture.slot(), profile, false));
            spi.engineLoad(null, null);

            Kimbo11ngPrivateKey key = (Kimbo11ngPrivateKey) spi.engineGetKey("oldKey", null);
            assertNotNull(key);
            assertFalse(key.ref().hasCkaId(), "no attribute should have been written");
        }
    }

    @Nested
    @DisplayName("recovery")
    class Recovery {

        @Test
        @DisplayName("produces a valid signature after the session dies mid-operation")
        void survivesASessionDroppedWhileSigning() throws Exception {
            long handle = generateRsa("signKey");
            Kimbo11ngKeyStoreSpi spi = load();
            Kimbo11ngPrivateKey key = (Kimbo11ngPrivateKey) spi.engineGetKey("signKey", null);
            java.security.PublicKey pub = spi.getPublicKey("signKey");

            Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                    new TokenRuntime(fixture.slot(), profile));
            Signature signer = Signature.getInstance("SHA256withRSA", provider);
            signer.initSign(key);
            signer.update("kimbo11ng".getBytes(StandardCharsets.UTF_8));

            // The HSM drops the connection between init and sign. Tier 1: the token is still
            // there, so the right answer is a new session and a re-resolved handle, not a failed
            // signature reported to whichever CA request happened to arrive first.
            fixture.token().killSessionsAfter(0);

            byte[] signature = signer.sign();

            Signature verifier = Signature.getInstance("SHA256withRSA",
                    BouncyCastleProvider.PROVIDER_NAME);
            verifier.initVerify(pub);
            verifier.update("kimbo11ng".getBytes(StandardCharsets.UTF_8));
            assertTrue(verifier.verify(signature),
                    "the retried signature must be valid, not merely produced");
            assertNotEquals(0, handle);
        }

        @Test
        @DisplayName("takes the token offline when the token itself is gone")
        void missingTokenGoesOffline() throws Exception {
            generateRsa("signKey");
            Kimbo11ngPrivateKey key = (Kimbo11ngPrivateKey) load().engineGetKey("signKey", null);

            StringBuilder reported = new StringBuilder();
            fixture.slot().onOffline((reason, cause) -> reported.append(reason));

            Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                    new TokenRuntime(fixture.slot(), profile));
            Signature signer = Signature.getInstance("SHA256withRSA", provider);
            signer.initSign(key);
            signer.update(new byte[] {1, 2, 3});
            fixture.token().failNextWith(CKR.TOKEN_NOT_PRESENT);

            assertThrows(java.security.SignatureException.class, signer::sign);

            // Tier 2: no retry can help, and we do not hold the PIN. Reporting it is what lets
            // EJBCA stop routing work here and re-activate with the credential it does hold.
            assertTrue(reported.toString().contains("signKey"),
                    () -> "offline was not reported: '" + reported + "'");
        }

        @Test
        @DisplayName("does not retry a failure that retrying cannot fix")
        void fatalFailureIsNotRetried() throws Exception {
            generateRsa("signKey");
            Kimbo11ngPrivateKey key = (Kimbo11ngPrivateKey) load().engineGetKey("signKey", null);
            StringBuilder reported = new StringBuilder();
            fixture.slot().onOffline((reason, cause) -> reported.append(reason));

            Kimbo11ngProvider provider = Kimbo11ngProvider.forToken(
                    new TokenRuntime(fixture.slot(), profile));
            Signature signer = Signature.getInstance("SHA256withRSA", provider);
            signer.initSign(key);
            signer.update(new byte[] {1, 2, 3});
            fixture.token().failNextWith(CKR.MECHANISM_INVALID);

            assertThrows(java.security.SignatureException.class, signer::sign);
            assertEquals("", reported.toString(),
                    "a mechanism the token will never accept is a configuration fault, not a "
                            + "reason to take a CA offline");
        }
    }

    @Nested
    @DisplayName("deletion")
    class Deletion {

        @Test
        @DisplayName("removes only the named key pair, not everything sharing its label")
        void deleteIsScopedByKeyId() throws Exception {
            generateRsa("signKey");
            // A second key pair with the same label. PKCS#11 has no uniqueness constraint on
            // CKA_LABEL, so this is legal, and deleting by label would destroy both.
            long other = fixture.onSession((ce, session) -> {
                KeyTemplates.Pair t = KeyTemplates.rsa("signKey".getBytes(StandardCharsets.UTF_8),
                        KeyTemplates.newKeyId(), 2048);
                LongRef pub = new LongRef();
                LongRef priv = new LongRef();
                ce.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN),
                        t.pub(), t.priv(), pub, priv);
                return priv.value();
            });

            Kimbo11ngKeyStoreSpi spi = load();
            // With two keys under one label, enumeration resolves the alias to one of them —
            // arbitrarily. Which one is not the point; the point is that deleting it removes that
            // pair and only that pair.
            Kimbo11ngPrivateKey resolved = (Kimbo11ngPrivateKey) spi.engineGetKey("signKey", null);
            long doomed = fixture.onSession(resolved::objectHandle);

            spi.engineDeleteEntry("signKey");

            assertFalse(spi.engineContainsAlias("signKey"));
            long[] survivors = fixture.onSession((ce, session) -> ce.FindObjects(session,
                    new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
                    new CKA(CKA.LABEL, "signKey".getBytes(StandardCharsets.UTF_8))));
            assertEquals(1, survivors.length,
                    "deleting by label would have destroyed both key pairs");
            assertNotEquals(doomed, survivors[0], "the wrong pair was deleted");
            assertTrue(survivors[0] == other || survivors[0] == doomed - 2,
                    "the survivor must be the other generated pair");
        }

        @Test
        @DisplayName("removes the public half too, so a later alias cannot inherit it")
        void deleteRemovesBothHalves() throws Exception {
            generateRsa("signKey");
            load().engineDeleteEntry("signKey");

            for (long objectClass : new long[] {CKO.PRIVATE_KEY, CKO.PUBLIC_KEY}) {
                long[] left = fixture.onSession((ce, session) -> ce.FindObjects(session,
                        new CKA(CKA.CLASS, objectClass),
                        new CKA(CKA.LABEL, "signKey".getBytes(StandardCharsets.UTF_8))));
                assertEquals(0, left == null ? 0 : left.length,
                        "object class 0x" + Long.toHexString(objectClass) + " was left behind");
            }
        }

        @Test
        @DisplayName("does nothing for an alias it does not hold")
        void deletingAnUnknownAliasIsSafe() throws Exception {
            generateRsa("signKey");
            Kimbo11ngKeyStoreSpi spi = load();

            spi.engineDeleteEntry("nonexistent");

            assertTrue(spi.engineContainsAlias("signKey"),
                    "an unknown alias must not take anything else with it");
        }
    }

    @Test
    @DisplayName("has no certificates to report, and does not ask the token for them")
    void certificatesAreNotReadFromTheToken() throws Exception {
        generateRsa("signKey");
        Kimbo11ngKeyStoreSpi spi = load();
        int findsBefore = fixture.token().findObjectsCalls();

        assertNull(spi.engineGetCertificate("signKey"));
        assertNull(spi.engineGetCertificateChain("signKey"));
        assertNull(spi.engineGetCreationDate("signKey"));
        assertFalse(spi.engineIsCertificateEntry("signKey"));

        // EJBCA rebuilds its keystore cache after every key generation, and that rebuild asks for
        // each alias's certificate. A token search here would make every keygen cost one search
        // per key already present.
        assertEquals(findsBefore, fixture.token().findObjectsCalls());
    }
}

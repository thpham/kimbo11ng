/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.it;

import ch.ithings.kimbo11ng.CryptoTokenImpl;
import ch.ithings.kimbo11ng.fake.TestBridge;
import ch.ithings.kimbo11ng.p11.NativeProviderFactory;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.provider.Kimbo11ngKeyStoreSpi;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * kimbo11ng and Thales's own JSP provider, on the same partition, checking each other's work.
 *
 * <p>This exists to answer one question before anyone files a support ticket: <em>is it kimbo11ng
 * or is it the HSM?</em> Every other test in this project can only compare kimbo11ng against
 * itself or against BouncyCastle. Here the reference is the vendor's own stack talking to the same
 * token, which makes a disagreement attributable.
 *
 * <p>The third test is the important one. {@link ch.ithings.kimbo11ng.profile.ThalesLunaProfile}
 * was written from Thales's documentation, not from observation — every constant in it is a claim.
 * Having {@code LunaProvider} generate a key and then reading it back through kimbo11ng is the only
 * check in this repository that can <em>falsify</em> that table, because neither side of the
 * comparison came from the table.
 *
 * <p><b>No build dependency on Thales.</b> {@code LunaProvider.jar} is not in any public
 * repository, so it is loaded from a path at run time and used through the standard JCA interfaces
 * — one reflective constructor call and nothing else. That keeps {@code mvn verify} buildable by
 * anyone and keeps a proprietary jar out of the dependency tree.
 *
 * <pre>
 * export ChrystokiConfigurationPath=/usr/local/luna/config
 * export LD_LIBRARY_PATH=/usr/local/luna/libs/64:/usr/local/luna/jsp/64
 * mvn verify -Pit \
 *   -Dkimbo11ng.it.lib=/usr/local/luna/libs/64/libCryptoki2.so \
 *   -Dkimbo11ng.it.slotType=SLOT_LABEL -Dkimbo11ng.it.slot=my-partition \
 *   -Dkimbo11ng.it.pin=userpin \
 *   -Dkimbo11ng.it.luna.jsp=/usr/local/luna/jsp/LunaProvider.jar
 * </pre>
 *
 * <p>{@code LD_LIBRARY_PATH} must cover {@code libLunaAPI.so} as well as the Cryptoki library:
 * HotSpot seeds {@code java.library.path} from it, and the JSP provider fails its static
 * initialiser without the bridge.
 */
@Tag("hsm")
@DisplayName("Luna JSP cross-check")
@EnabledIfSystemProperty(named = "kimbo11ng.it.luna.jsp", matches = ".+",
        disabledReason = "set -Dkimbo11ng.it.luna.jsp to Thales's LunaProvider.jar")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LunaJspCrossCheckIT {

    private static final String LIB = HsmItConfig.get(HsmItConfig.LIB, "");
    private static final String SLOT = HsmItConfig.get(HsmItConfig.SLOT, "0");
    private static final String SLOT_TYPE = HsmItConfig.get(HsmItConfig.SLOT_TYPE, "SLOT_INDEX");
    private static final String PIN = HsmItConfig.get(HsmItConfig.PIN, "");
    private static final String JSP_JAR = HsmItConfig.get(HsmItConfig.LUNA_JSP, "");

    /**
     * How the Luna keystore is told which partition to open. {@code tokenlabel:} is the form that
     * matches {@code SLOT_LABEL} on our side; {@code slot:} matches an index or number.
     */
    private static String lunaKeyStoreSelector() {
        String partition = HsmItConfig.get(HsmItConfig.LUNA_PARTITION, SLOT);
        return "SLOT_LABEL".equals(SLOT_TYPE) ? "tokenlabel:" + partition : "slot:" + partition;
    }

    private CryptoTokenImpl impl;
    private KeyStore lunaKeyStore;
    private Provider lunaProvider;
    private final List<String> aliases = new ArrayList<>();

    @BeforeAll
    void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void openBothSides() throws Exception {
        assertTrue(Files.isReadable(Path.of(LIB)),
                () -> HsmItConfig.LIB + " is '" + LIB + "', which is not a readable file");
        Path jar = Path.of(JSP_JAR);
        assertTrue(Files.isReadable(jar),
                () -> HsmItConfig.LUNA_JSP + " is '" + JSP_JAR + "', which is not a readable file");

        // Our side.
        Properties properties = new Properties();
        properties.setProperty(CryptoTokenImpl.SHLIB_LABEL_KEY, LIB);
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_TYPE, SLOT_TYPE);
        properties.setProperty(CryptoTokenImpl.SLOT_LABEL_VALUE, SLOT);
        properties.setProperty(CryptoTokenImpl.DO_NOT_ADD_P11_PROVIDER, "true");
        impl = new CryptoTokenImpl(new TestBridge(),
                new Pkcs11ModuleRegistry(NativeProviderFactory.jna()));
        impl.init(properties, null, 73);
        impl.activate(PIN.toCharArray());

        // Thales's side. The provider is instantiated reflectively so nothing here needs
        // LunaProvider.jar at compile time; from that point on it is ordinary JCA.
        lunaProvider = loadLunaProvider(jar);
        lunaKeyStore = KeyStore.getInstance("Luna", lunaProvider);
        lunaKeyStore.load(
                new ByteArrayInputStream(lunaKeyStoreSelector().getBytes(StandardCharsets.UTF_8)),
                PIN.toCharArray());
    }

    private Provider loadLunaProvider(Path jar) throws Exception {
        @SuppressWarnings("resource") // Closing it would unload the provider still in use.
        URLClassLoader loader = new URLClassLoader(new URL[] {jar.toUri().toURL()},
                LunaJspCrossCheckIT.class.getClassLoader());
        Provider provider = (Provider) Class
                .forName("com.safenetinc.luna.provider.LunaProvider", true, loader)
                .getDeclaredConstructor()
                .newInstance();
        // Thales documents LunaSlotManager as needing the provider registered for some paths.
        // Registering is harmless when it is not needed, and a confusing failure when it is.
        if (Security.getProvider(provider.getName()) == null) {
            Security.addProvider(provider);
        }
        return provider;
    }

    @AfterEach
    void cleanUp() {
        for (String alias : aliases) {
            try {
                impl.deleteEntry(alias);
            } catch (Exception e) {
                System.err.println("could not delete '" + alias + "' through kimbo11ng: " + e);
            }
            try {
                if (lunaKeyStore != null && lunaKeyStore.containsAlias(alias)) {
                    lunaKeyStore.deleteEntry(alias);
                }
            } catch (Exception e) {
                System.err.println("could not delete '" + alias + "' through LunaProvider: " + e);
            }
        }
        aliases.clear();
        if (impl != null) {
            impl.reset();
            impl = null;
        }
        if (lunaProvider != null) {
            Security.removeProvider(lunaProvider.getName());
            lunaProvider = null;
        }
    }

    private String alias(String suffix) {
        String alias = "xcheck-" + suffix;
        aliases.add(alias);
        return alias;
    }

    private Kimbo11ngKeyStoreSpi reEnumerate() throws Exception {
        Kimbo11ngKeyStoreSpi keyStore = impl.getProvider().getKeyStoreSpi();
        keyStore.clear();
        keyStore.engineLoad(null, PIN.toCharArray());
        return keyStore;
    }

    // ------------------------------------------------------------------ 1. same partition

    @Test
    @DisplayName("both providers are looking at the same partition")
    void sameToken() throws Exception {
        // Everything below is meaningless if the two are addressing different partitions, and the
        // symptom of that would be a stream of "key not found" failures that read like real bugs.
        String alias = alias("presence");
        impl.generateKeyPair("2048", alias);

        assertTrue(lunaKeyStore.containsAlias(alias),
                () -> "kimbo11ng created '" + alias + "' but the Luna keystore opened with '"
                        + lunaKeyStoreSelector() + "' does not see it. The two are addressing"
                        + " different partitions — check " + HsmItConfig.SLOT + " against "
                        + HsmItConfig.LUNA_PARTITION + ".");
        assertTrue(Collections.list(lunaKeyStore.aliases()).contains(alias),
                "the alias is not enumerated, only resolvable — Luna's keystore is inconsistent");
    }

    // ------------------------------------------------------------------ 2. we sign, Thales verifies

    @Test
    @DisplayName("Thales verifies what kimbo11ng signed")
    void thalesVerifiesOurSignatures() throws Exception {
        crossVerify(alias("rsa"), "2048", "SHA256withRSA");
        crossVerify(alias("ec"), "secp256r1", "SHA256withECDSA");

        for (AlgorithmEntry entry : impl.getProvider().runtime().algorithms().supported()) {
            if (entry.canSign()) {
                crossVerify(alias(entry.canonicalName()), entry.canonicalName(),
                        entry.canonicalName());
            }
        }
    }

    /** Generates and signs through kimbo11ng; verifies through the vendor's provider. */
    private void crossVerify(String alias, String keySpec, String jcaName) throws Exception {
        impl.generateKeyPair(keySpec, alias);
        byte[] message = ("kimbo11ng cross-check " + alias).getBytes(StandardCharsets.UTF_8);

        Kimbo11ngKeyStoreSpi ours = reEnumerate();
        PrivateKey ourPrivate = (PrivateKey) ours.engineGetKey(alias, PIN.toCharArray());
        assertNotNull(ourPrivate, "kimbo11ng found no private key for " + alias);
        Signature signer = Signature.getInstance(jcaName, impl.getProvider());
        signer.initSign(ourPrivate);
        signer.update(message);
        byte[] signature = signer.sign();

        // The vendor's provider, reading its own public key off the same token. If this fails, the
        // signature is malformed in a way that only a relying party would otherwise notice.
        PublicKey theirPublic = lunaKeyStore.getCertificate(alias) != null
                ? lunaKeyStore.getCertificate(alias).getPublicKey()
                : ours.getPublicKey(alias);
        Signature verifier = Signature.getInstance(jcaName, lunaProvider);
        verifier.initVerify(theirPublic);
        verifier.update(message);
        assertTrue(verifier.verify(signature),
                jcaName + ": Thales's provider rejects a signature kimbo11ng made on its own token."
                        + " The mechanism or its encoding is wrong on our side.");
    }

    // ------------------------------------------------------------------ 3. the falsifiable one

    @Test
    @DisplayName("kimbo11ng reads a key Thales generated, at the OID and length the profile claims")
    void weReadWhatThalesGenerated() throws Exception {
        List<AlgorithmEntry> supported = impl.getProvider().runtime().algorithms().supported();
        assertTrue(supported.stream().anyMatch(AlgorithmEntry::canSign),
                "the probe kept no signing algorithm, so there is nothing to cross-check");

        for (AlgorithmEntry entry : supported) {
            if (!entry.canSign()) {
                continue;
            }
            String alias = alias("theirs-" + entry.canonicalName());

            // Generated entirely by Thales's stack, with Thales's own idea of the algorithm name.
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(entry.canonicalName(), lunaProvider);
            KeyPair pair = kpg.generateKeyPair();
            lunaKeyStore.setKeyEntry(alias, pair.getPrivate(), PIN.toCharArray(), null);

            // Read back through kimbo11ng, which resolves the parameter set from CKA_KEY_TYPE plus
            // the profile's parameter-set attribute — the table under test, applied to a key the
            // table had no part in creating.
            Kimbo11ngKeyStoreSpi ours = reEnumerate();
            assertTrue(ours.engineContainsAlias(alias),
                    () -> "kimbo11ng cannot see the " + entry.canonicalName()
                            + " key Thales just created");
            PublicKey pub = ours.getPublicKey(alias);
            assertNotNull(pub, "no public key for " + alias);

            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pub.getEncoded());
            assertEquals(entry.oid(), spki.getAlgorithm().getAlgorithm(),
                    () -> "ThalesLunaProfile claims OID " + entry.oid() + " for "
                            + entry.canonicalName() + ", but a key the HSM generated under that"
                            + " name reads back as " + spki.getAlgorithm().getAlgorithm()
                            + ". The profile is wrong, not the HSM.");
            assertEquals(entry.publicKeyLength(), spki.getPublicKeyData().getOctets().length,
                    () -> "ThalesLunaProfile claims " + entry.publicKeyLength() + " bytes for "
                            + entry.canonicalName() + "; the HSM produced "
                            + spki.getPublicKeyData().getOctets().length
                            + ". The parameter set the profile maps to is not the one the HSM used.");
        }
    }
}

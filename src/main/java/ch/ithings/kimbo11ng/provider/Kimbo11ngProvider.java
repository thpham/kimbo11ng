/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.p11.Pkcs11v30;
import ch.ithings.kimbo11ng.p11.TokenCapabilities;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKM;

import java.security.Provider;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * JCA provider for one PKCS#11 slot.
 *
 * <p>Exactly one instance exists per (library, slot) for the life of the JVM, and re-initialising
 * a token swaps its {@link TokenRuntime} rather than creating a new provider — see
 * {@link TokenRuntime} for why that is required rather than merely tidy.
 *
 * <p>Signature services are registered from the profile's algorithm table, so a vendor profile
 * automatically gets the right set of algorithms and the right mechanism behind each one.
 *
 * <p>{@code final} on purpose: {@code putService} is called from the constructor, which would be a
 * {@code this}-escape if the class could be subclassed.
 */
public final class Kimbo11ngProvider extends Provider {

    private static final long serialVersionUID = 2L;
    private static final Logger log = Logger.getLogger(Kimbo11ngProvider.class);

    private static final ConcurrentMap<String, Kimbo11ngProvider> INSTANCES =
            new ConcurrentHashMap<>();

    /**
     * The capability-dependent services currently registered, as {@code "type:algorithm"}, so that
     * re-pointing this provider at a runtime with a different algorithm set can withdraw the ones
     * that no longer apply.
     *
     * <p>Without this the services stay frozen at whatever the first runtime for this (library,
     * slot) supported, while {@link #runtime()} reports the new one — a provider that answers
     * accurately about its token and inaccurately about itself.
     *
     * <p>Only the services whose presence depends on the token are tracked: {@code Signature},
     * {@code Mac} and {@code KeyGenerator}. {@code KeyStore}, the digests and the key-pair
     * generators are registered unconditionally and have nothing to withdraw.
     *
     * <p>{@code transient} because {@link Provider} is {@link java.io.Serializable} and this is a
     * cache of what was registered, rebuilt from the runtime on every {@code registerServices}.
     */
    private final transient Set<String> registeredServices = ConcurrentHashMap.newKeySet();

    /**
     * A classical signature service: the JCA name EJBCA asks for, the mechanism behind it, whether
     * the token's raw {@code r||s} output needs DER-wrapping, the mechanism parameter block, and
     * the OIDs it also answers to.
     *
     * @param mechanismParam non-null only for RSA-PSS; see {@link RsaPssParams}
     * @param oidAliases OIDs this algorithm must also answer to, or empty.
     *        <p>BouncyCastle's operator layer resolves a signer from an {@code AlgorithmIdentifier},
     *        and {@code OperatorHelper} only turns that back into a JCA name for the algorithms its
     *        own table knows; for the rest it asks the provider for the OID <em>as the algorithm
     *        name</em>. So a service registered under its name alone is invisible to
     *        {@code JcaContentSignerBuilder} — which is the path EJBCA signs every certificate
     *        through — and CA creation fails with "no such algorithm: 2.16.840.1.101.3.4.3.14".
     *        Signing and verifying directly through {@code Signature.getInstance} works throughout,
     *        which is what makes this worth stating: the plain round trip does not reveal it.
     */
    private record ClassicalSignature(String jcaName, long mechanism, boolean ecdsaDerEncoding,
            byte[] mechanismParam, List<String> oidAliases) {

        ClassicalSignature(String jcaName, long mechanism, boolean ecdsaDerEncoding,
                byte[] mechanismParam) {
            this(jcaName, mechanism, ecdsaDerEncoding, mechanismParam, List.of());
        }
    }

    /**
     * RSA, RSA-PSS and ECDSA services. Standard across tokens, so unlike the post-quantum set these
     * do not come from the profile.
     *
     * <p>The JCA names are the {@code AlgorithmConstants.SIGALG_*} spellings EJBCA uses. Provider
     * lookup is case-insensitive, so {@code SHA256WithRSA} finds {@code SHA256withRSA}; the
     * {@code andMGF1} suffix, however, is a distinct algorithm and had to be registered separately.
     */
    private static final List<ClassicalSignature> CLASSICAL_SIGNATURES = List.of(
            new ClassicalSignature("SHA1withRSA",     CKM.SHA1_RSA_PKCS,   false, null),
            new ClassicalSignature("SHA256withRSA",   CKM.SHA256_RSA_PKCS, false, null),
            new ClassicalSignature("SHA384withRSA",   CKM.SHA384_RSA_PKCS, false, null),
            new ClassicalSignature("SHA512withRSA",   CKM.SHA512_RSA_PKCS, false, null),
            // SHA-3 is not exotic here: AlgorithmTools offers these three for every RSA key, so
            // without them an administrator can configure a CA EJBCA will then fail to sign with.
            new ClassicalSignature("SHA3-256withRSA", Pkcs11v30.CKM_SHA3_256_RSA_PKCS, false, null,
                    List.of("2.16.840.1.101.3.4.3.14")),
            new ClassicalSignature("SHA3-384withRSA", Pkcs11v30.CKM_SHA3_384_RSA_PKCS, false, null,
                    List.of("2.16.840.1.101.3.4.3.15")),
            new ClassicalSignature("SHA3-512withRSA", Pkcs11v30.CKM_SHA3_512_RSA_PKCS, false, null,
                    List.of("2.16.840.1.101.3.4.3.16")),
            new ClassicalSignature("SHA256withRSAandMGF1", CKM.SHA256_RSA_PKCS_PSS, false,
                    RsaPssParams.sha256()),
            new ClassicalSignature("SHA384withRSAandMGF1", CKM.SHA384_RSA_PKCS_PSS, false,
                    RsaPssParams.sha384()),
            new ClassicalSignature("SHA512withRSAandMGF1", CKM.SHA512_RSA_PKCS_PSS, false,
                    RsaPssParams.sha512()),
            // ECDSA_SHA1, not the raw ECDSA: this provider never digests — engineUpdate buffers and
            // engineSign hands the buffer to C_Sign — so the raw mechanism would have the token
            // treat a whole TBSCertificate as if it were the SHA-1 of one.
            new ClassicalSignature("SHA1withECDSA",   CKM.ECDSA_SHA1,      true,  null),
            new ClassicalSignature("SHA256withECDSA", CKM.ECDSA_SHA256,    true,  null),
            new ClassicalSignature("SHA384withECDSA", CKM.ECDSA_SHA384,    true,  null),
            new ClassicalSignature("SHA224withECDSA", CKM.ECDSA_SHA224,    true,  null,
                    List.of("1.2.840.10045.4.3.1")),
            new ClassicalSignature("SHA512withECDSA", CKM.ECDSA_SHA512,    true,  null),
            new ClassicalSignature("SHA3-256withECDSA", Pkcs11v30.CKM_ECDSA_SHA3_256, true, null,
                    List.of("2.16.840.1.101.3.4.3.10")),
            new ClassicalSignature("SHA3-384withECDSA", Pkcs11v30.CKM_ECDSA_SHA3_384, true, null,
                    List.of("2.16.840.1.101.3.4.3.11")),
            new ClassicalSignature("SHA3-512withECDSA", Pkcs11v30.CKM_ECDSA_SHA3_512, true, null,
                    List.of("2.16.840.1.101.3.4.3.12")),
            // EdDSA is pure: CKM_EDDSA takes the message, not a digest, and returns R||S as a
            // fixed-width pair that goes into a certificate unchanged — so no DER re-wrap, unlike
            // ECDSA. One mechanism serves both curves; the key decides which, and the two services
            // exist because Ed25519 and Ed448 are distinct JCA algorithms.
            new ClassicalSignature("Ed25519", CKM.EDDSA, false, null,
                    List.of("1.3.101.112")),
            new ClassicalSignature("Ed448", CKM.EDDSA, false, null,
                    List.of("1.3.101.113")));

    /** The PSS mechanisms behind {@code RSASSA-PSS}; it is offered if the token signs with any. */
    private static final List<Long> PSS_MECHANISMS = List.of(CKM.SHA256_RSA_PKCS_PSS,
            CKM.SHA384_RSA_PKCS_PSS, CKM.SHA512_RSA_PKCS_PSS);

    private static final String RSASSA_PSS = "RSASSA-PSS";

    /**
     * A composite ML-DSA signature (draft-ietf-lamps-pq-composite-sigs), offered when this provider
     * offers both halves.
     *
     * @param mlDsa     the ML-DSA service the post-quantum half needs
     * @param classical the service whose presence means the token can sign the classical half. For
     *                  the PSS rows that is the fixed {@code SHAnnnwithRSAandMGF1} service with the
     *                  hash BouncyCastle's {@code PSSParameterSpec} for the row names — BC itself asks
     *                  for {@code RSASSA-PSS}, which is offered whenever any PSS mechanism is, and so
     *                  says nothing about whether this hash is there.
     * @param classicalKeySpec the classical half's key, in the spelling
     *                  {@code CryptoTokenImpl.generateKeyPair} takes: an RSA size, a curve name, or
     *                  {@code Ed25519}/{@code Ed448}
     */
    private record CompositeSignature(String name, String oid, String mlDsa, String classical,
            String classicalKeySpec) {
    }

    /**
     * One composite this provider knows, as a tool outside EJBCA needs to see it: what the two
     * halves are, and whether this token can sign it.
     *
     * <p>The command-line tool generates, tests and lists composite keys from this and from
     * nothing else, so it cannot disagree with what the provider registers.
     *
     * @param name               the JCA name, e.g. {@code MLDSA44-RSA2048-PSS-SHA256}
     * @param oid                its OID, dotted
     * @param mlDsaKeySpec       the post-quantum half's key spec, e.g. {@code ML-DSA-44}
     * @param classicalKeySpec   the classical half's key spec: an RSA size, a curve name, or
     *                           {@code Ed25519}/{@code Ed448}
     * @param classicalSignature the service the classical half is signed with on its own
     * @param offered            whether this provider registers the composite for this token
     */
    public record CompositeAlgorithm(String name, String oid, String mlDsaKeySpec,
            String classicalKeySpec, String classicalSignature, boolean offered) {
    }

    /**
     * The composites BouncyCastle implements that this provider deliberately never offers, with why.
     * The pre-hash forms are not listed: they are a different signature, not a refused choice.
     */
    private static final Map<String, String> EXCLUDED_COMPOSITES = excluded();

    private static Map<String, String> excluded() {
        String reason = "EJBCA does not support the legacy PKCS#1 v1.5 signature scheme with"
                + " composite keys; an RSA classical half always signs with PSS";
        Map<String, String> map = new LinkedHashMap<>();
        map.put("MLDSA44-RSA2048-PKCS15-SHA256", reason);
        map.put("MLDSA65-RSA3072-PKCS15-SHA512", reason);
        map.put("MLDSA65-RSA4096-PKCS15-SHA512", reason);
        return Collections.unmodifiableMap(map);
    }

    /**
     * Every pure composite BouncyCastle 1.84 implements, with the halves its {@code CompositeIndex}
     * pairs it with — except two families, left out on purpose:
     *
     * <ul>
     *   <li>The pre-hash ({@code HashMLDSA…}) forms. EJBCA's composite wrapper produces none of
     *       their OIDs, and they are a different signature under different OIDs.</li>
     *   <li>The three RSA PKCS#1 v1.5 forms ({@code …-PKCS15-…}). Keyfactor: "EJBCA does not support
     *       the legacy PKCS#1 v1.5 signature scheme with composite keys"; an RSA classical half
     *       always signs with PSS. Offering them would be surface EJBCA never asks for.</li>
     * </ul>
     *
     * {@code CompositeSignatureTest.tableMatchesBouncyCastle} fails if a BouncyCastle upgrade adds a
     * row this table lacks, and {@code noPkcs15Composites} if the excluded set changes.
     */
    private static final List<CompositeSignature> COMPOSITE_SIGNATURES = List.of(
            new CompositeSignature("MLDSA44-RSA2048-PSS-SHA256", "1.3.6.1.5.5.7.6.37",
                    "ML-DSA-44", "SHA256withRSAandMGF1", "2048"),
            new CompositeSignature("MLDSA44-Ed25519-SHA512", "1.3.6.1.5.5.7.6.39",
                    "ML-DSA-44", "Ed25519", "Ed25519"),
            new CompositeSignature("MLDSA44-ECDSA-P256-SHA256", "1.3.6.1.5.5.7.6.40",
                    "ML-DSA-44", "SHA256withECDSA", "secp256r1"),
            new CompositeSignature("MLDSA65-RSA3072-PSS-SHA512", "1.3.6.1.5.5.7.6.41",
                    "ML-DSA-65", "SHA256withRSAandMGF1", "3072"),
            new CompositeSignature("MLDSA65-RSA4096-PSS-SHA512", "1.3.6.1.5.5.7.6.43",
                    "ML-DSA-65", "SHA384withRSAandMGF1", "4096"),
            new CompositeSignature("MLDSA65-ECDSA-P256-SHA512", "1.3.6.1.5.5.7.6.45",
                    "ML-DSA-65", "SHA256withECDSA", "secp256r1"),
            new CompositeSignature("MLDSA65-ECDSA-P384-SHA512", "1.3.6.1.5.5.7.6.46",
                    "ML-DSA-65", "SHA384withECDSA", "secp384r1"),
            new CompositeSignature("MLDSA65-ECDSA-brainpoolP256r1-SHA512", "1.3.6.1.5.5.7.6.47",
                    "ML-DSA-65", "SHA256withECDSA", "brainpoolP256r1"),
            new CompositeSignature("MLDSA65-Ed25519-SHA512", "1.3.6.1.5.5.7.6.48",
                    "ML-DSA-65", "Ed25519", "Ed25519"),
            new CompositeSignature("MLDSA87-ECDSA-P384-SHA512", "1.3.6.1.5.5.7.6.49",
                    "ML-DSA-87", "SHA384withECDSA", "secp384r1"),
            new CompositeSignature("MLDSA87-ECDSA-brainpoolP384r1-SHA512", "1.3.6.1.5.5.7.6.50",
                    "ML-DSA-87", "SHA384withECDSA", "brainpoolP384r1"),
            new CompositeSignature("MLDSA87-Ed448-SHAKE256", "1.3.6.1.5.5.7.6.51",
                    "ML-DSA-87", "Ed448", "Ed448"),
            new CompositeSignature("MLDSA87-RSA3072-PSS-SHA512", "1.3.6.1.5.5.7.6.52",
                    "ML-DSA-87", "SHA256withRSAandMGF1", "3072"),
            new CompositeSignature("MLDSA87-RSA4096-PSS-SHA512", "1.3.6.1.5.5.7.6.53",
                    "ML-DSA-87", "SHA384withRSAandMGF1", "4096"),
            new CompositeSignature("MLDSA87-ECDSA-P521-SHA512", "1.3.6.1.5.5.7.6.54",
                    "ML-DSA-87", "SHA512withECDSA", "secp521r1"));

    /**
     * Digest services, as {@code {standardName, alias...}}.
     *
     * <p>The dashless spellings are the ones BouncyCastle's {@code MessageDigestUtils} asks for;
     * the OIDs are what a {@code DigestAlgorithmIdentifier} resolves to.
     */
    private static final List<String[]> DIGESTS = List.of(
            new String[] {"SHA-1",   "SHA1",   "SHA",  "1.3.14.3.2.26"},
            new String[] {"SHA-256", "SHA256", "2.16.840.1.101.3.4.2.1"},
            new String[] {"SHA-384", "SHA384", "2.16.840.1.101.3.4.2.2"},
            new String[] {"SHA-512", "SHA512", "2.16.840.1.101.3.4.2.3"},
            // Needed by the same operator layer as the four above: a CA signing with
            // SHA3-256withRSA has BouncyCastle ask this provider for "SHA3-256" by name, and the
            // failure without it is "no such algorithm" at CA creation, not at signing.
            new String[] {"SHA3-256", "SHA3256", "2.16.840.1.101.3.4.2.8"},
            new String[] {"SHA3-384", "SHA3384", "2.16.840.1.101.3.4.2.9"},
            new String[] {"SHA3-512", "SHA3512", "2.16.840.1.101.3.4.2.10"});

    private final transient AtomicReference<TokenRuntime> runtime = new AtomicReference<>();

    /**
     * The provider for this runtime's slot, creating it on first use and otherwise re-pointing the
     * existing one. The returned instance's name is stable, which is what EJBCA relies on.
     */
    public static Kimbo11ngProvider forToken(TokenRuntime newRuntime) {
        String name = nameFor(newRuntime);
        Kimbo11ngProvider provider = INSTANCES.computeIfAbsent(name,
                n -> new Kimbo11ngProvider(n, newRuntime));
        TokenRuntime previous = provider.runtime.getAndSet(newRuntime);
        if (previous != null && previous != newRuntime) {
            if (log.isDebugEnabled()) {
                log.debug("Re-pointed provider " + name + " from " + previous + " to "
                        + newRuntime);
            }
            provider.resyncServices(newRuntime);
        }
        return provider;
    }

    /**
     * Brings the capability-dependent services back in line after the runtime was swapped.
     *
     * <p>The instance is cached per (library, slot) and its name has to stay stable because EJBCA
     * holds on to it, so a differing algorithm set cannot be handled by making a second provider.
     * Re-initialising the same slot under a different profile — an operator changing
     * {@code kimbo11ng.pqc.profile}, or a probe that now sees different firmware — otherwise leaves
     * this provider advertising the first profile's algorithms forever.
     *
     * <p>Only a genuine difference triggers the work: {@code forToken} runs on every init and
     * activate, and churning services under concurrent lookups for no reason is its own hazard.
     */
    private synchronized void resyncServices(TokenRuntime newRuntime) {
        Set<String> wanted = serviceSurface(newRuntime);
        if (wanted.equals(registeredServices)) {
            return;
        }
        for (String key : Set.copyOf(registeredServices)) {
            if (!wanted.contains(key)) {
                int colon = key.indexOf(':');
                Service stale = getService(key.substring(0, colon), key.substring(colon + 1));
                if (stale != null) {
                    removeService(stale);
                }
            }
        }
        // Re-runs the whole registration: putService replaces an entry with the same type and
        // algorithm, so the services that did not change are simply rebound to the new runtime.
        registerServices(newRuntime);
        log.info("Provider " + getName() + " now offers " + wanted.size()
                + " token-dependent services after re-pointing to profile "
                + newRuntime.profile().name());
    }

    /** The {@code "type:algorithm"} keys a runtime should be offering. */
    private static Set<String> serviceSurface(TokenRuntime runtime) {
        TokenCapabilities capabilities = runtime.algorithms().capabilities();
        Set<String> keys = new LinkedHashSet<>();
        for (ClassicalSignature row : CLASSICAL_SIGNATURES) {
            if (capabilities.canSign(row.mechanism())) {
                keys.add("Signature:" + row.jcaName());
            }
        }
        if (signsAnyPss(capabilities)) {
            keys.add("Signature:" + RSASSA_PSS);
        }
        for (AlgorithmEntry entry : runtime.algorithms().supported()) {
            if (entry.canSign()) {
                keys.add("Signature:" + entry.canonicalName());
            }
        }
        for (CompositeSignature row : COMPOSITE_SIGNATURES) {
            if (bothHalvesOffered(row, keys)) {
                keys.add("Signature:" + row.name());
            }
        }
        for (SecretKeyType type : SecretKeyType.all()) {
            if (capabilities.canGenerate(type.ckmKeyGen())) {
                keys.add("KeyGenerator:" + type.jcaName());
            }
            if (type.isMac() && capabilities.canSign(type.ckmOperation())) {
                keys.add("Mac:" + type.jcaName());
            }
        }
        return keys;
    }

    /**
     * Every composite this provider knows, in table order, each marked with whether it is
     * registered for this token — the list a tool outside EJBCA reads instead of keeping its own.
     * A composite the token cannot sign is still listed, with {@code offered} false, so a caller
     * can tell "this token cannot" from "no such composite".
     */
    public List<CompositeAlgorithm> compositeAlgorithms() {
        return COMPOSITE_SIGNATURES.stream()
                .map(row -> new CompositeAlgorithm(row.name(), row.oid(), row.mlDsa(),
                        row.classicalKeySpec(), row.classical(),
                        getService("Signature", row.name()) != null))
                .toList();
    }

    /**
     * The composites deliberately never offered, each with the reason, in a stable order. Not in
     * {@link #compositeAlgorithms()}: they are refused choices, not unsupported ones.
     */
    public static Map<String, String> excludedComposites() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(EXCLUDED_COMPOSITES));
    }

    /**
     * The two services a composite is gated on, as {@code [mlDsa, classical]}, or null for a
     * composite this provider does not offer. Package-private, for the test that checks every row
     * against BouncyCastle's own pairing table: a wrong row is invisible to any signing test.
     */
    static List<String> compositeHalves(String compositeName) {
        return COMPOSITE_SIGNATURES.stream()
                .filter(row -> row.name().equals(compositeName))
                .map(row -> List.of(row.mlDsa(), row.classical()))
                .findFirst().orElse(null);
    }

    private static boolean signsAnyPss(TokenCapabilities capabilities) {
        return PSS_MECHANISMS.stream().anyMatch(capabilities::canSign);
    }

    /** Whether {@code offered}, a set of {@code "type:algorithm"} keys, has both of the row's halves. */
    private static boolean bothHalvesOffered(CompositeSignature row, Set<String> offered) {
        return offered.contains("Signature:" + row.mlDsa())
                && offered.contains("Signature:" + row.classical());
    }

    private static String nameFor(TokenRuntime runtime) {
        return "Kimbo11ng-" + runtime.slot().libraryName()
                + "-slot" + runtime.slot().slotId();
    }

    private Kimbo11ngProvider(String name, TokenRuntime initialRuntime) {
        super(name, "1.0", "kimbo11ng PKCS#11 provider for "
                + initialRuntime.slot().libPath()
                + " slot " + initialRuntime.slot().slotId());
        this.runtime.set(initialRuntime);
        registerServices(initialRuntime);
    }

    /** The current runtime. Never null after construction. */
    public TokenRuntime runtime() {
        return runtime.get();
    }

    public P11Slot getSlot() {
        return runtime.get().slot();
    }

    public Kimbo11ngKeyStoreSpi getKeyStoreSpi() {
        return runtime.get().keyStoreSpi();
    }

    private void registerServices(TokenRuntime initialRuntime) {
        putService(new Service(this, "KeyStore", "PKCS11",
                Kimbo11ngKeyStoreSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                TokenRuntime current = runtime.get();
                Kimbo11ngKeyStoreSpi spi = new Kimbo11ngKeyStoreSpi(current);
                current.adoptKeyStoreSpi(spi);
                return spi;
            }
        });

        // A service is registered only if the token will sign with its mechanism. An unprobed
        // token answers yes to everything, so nothing is lost when the probe could not run; what
        // this avoids is advertising an algorithm the firmware does not have, which EJBCA would
        // pick and then fail on. Signature.getInstance throwing NoSuchAlgorithmException is
        // recoverable for SignWithWorkingAlgorithm — it tries the next algorithm — where a
        // CKR_MECHANISM_INVALID mid-signature is not.
        TokenCapabilities capabilities = initialRuntime.algorithms().capabilities();
        registeredServices.clear();
        int classical = 0;
        for (ClassicalSignature row : CLASSICAL_SIGNATURES) {
            if (!capabilities.canSign(row.mechanism())) {
                if (log.isDebugEnabled()) {
                    log.debug("Not registering " + row.jcaName() + ": the token does not sign with "
                            + TokenCapabilities.name(row.mechanism()));
                }
                continue;
            }
            putService(new Service(this, "Signature", row.jcaName(),
                    Kimbo11ngSignatureSpi.class.getName(),
                    row.oidAliases().isEmpty() ? null : row.oidAliases(), null) {
                @Override
                public Object newInstance(Object constructorParameter) {
                    return Kimbo11ngSignatureSpi.fixed(row.mechanism(), row.ecdsaDerEncoding(),
                            row.mechanismParam());
                }
            });
            registeredServices.add("Signature:" + row.jcaName());
            classical++;
        }

        // RSASSA-PSS takes its hash from a PSSParameterSpec rather than its name, which is how
        // BouncyCastle's composite signatures ask for their RSA-PSS half.
        if (signsAnyPss(capabilities)) {
            putService(new Service(this, "Signature", RSASSA_PSS,
                    Kimbo11ngSignatureSpi.class.getName(), null, null) {
                @Override
                public Object newInstance(Object constructorParameter) {
                    return Kimbo11ngSignatureSpi.rsassaPss();
                }
            });
            registeredServices.add("Signature:" + RSASSA_PSS);
        }

        // One signature service per signing algorithm the token can actually do — the profile
        // table already intersected with the probe, so an algorithm the firmware lacks is not
        // advertised here either. The mechanism is resolved from the key at init, so nothing here
        // needs to know it.
        int registered = 0;
        for (AlgorithmEntry entry : initialRuntime.algorithms().supported()) {
            if (!entry.canSign()) {
                continue;
            }
            putService(new Service(this, "Signature", entry.canonicalName(),
                    Kimbo11ngSignatureSpi.class.getName(), null, null) {
                @Override
                public Object newInstance(Object constructorParameter) {
                    return Kimbo11ngSignatureSpi.fromKeyEntry();
                }
            });
            registeredServices.add("Signature:" + entry.canonicalName());
            registered++;
        }

        // Composite ML-DSA, for EJBCA's CryptoTokenCompositeWrapper. Only where both halves are on
        // offer, which the loops above have just decided: a composite whose classical half the
        // firmware lacks would be picked by EJBCA and then fail mid-signature.
        int composite = 0;
        for (CompositeSignature row : COMPOSITE_SIGNATURES) {
            if (!bothHalvesOffered(row, registeredServices)) {
                continue;
            }
            org.bouncycastle.asn1.ASN1ObjectIdentifier oid =
                    new org.bouncycastle.asn1.ASN1ObjectIdentifier(row.oid());
            putService(new Service(this, "Signature", row.name(),
                    Kimbo11ngCompositeSignatureSpi.class.getName(), List.of(row.oid()), null) {
                @Override
                public Object newInstance(Object constructorParameter) {
                    return new Kimbo11ngCompositeSignatureSpi(row.name(), oid,
                            Kimbo11ngProvider.this);
                }
            });
            registeredServices.add("Signature:" + row.name());
            composite++;
        }

        // Digests, in software, because BouncyCastle's operator layer resolves every helper it
        // needs from the provider it was handed — and building an RSA-PSS signer needs one. See
        // DelegatingMessageDigestSpi for why they are not sent to the token.
        for (String[] digest : DIGESTS) {
            String standardName = digest[0];
            List<String> aliases = List.of(digest).subList(1, digest.length);
            putService(new Service(this, "MessageDigest", standardName,
                    DelegatingMessageDigestSpi.class.getName(), aliases, null) {
                @Override
                public Object newInstance(Object constructorParameter) {
                    return new DelegatingMessageDigestSpi(standardName);
                }
            });
        }

        putService(new Service(this, "KeyPairGenerator", "RSA",
                Kimbo11ngKeyPairGeneratorSpi.RSA.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngKeyPairGeneratorSpi.RSA(runtime.get().slot());
            }
        });
        putService(new Service(this, "KeyPairGenerator", "EC",
                Kimbo11ngKeyPairGeneratorSpi.EC.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngKeyPairGeneratorSpi.EC(runtime.get().slot());
            }
        });

        // Symmetric keys. Registered only when the token will generate them, for the same reason
        // the signature services are: EJBCA's symmetric path is
        // KeyGenerator.getInstance(alg, providerName) followed by setKeyEntry, so a
        // NoSuchAlgorithmException here is a clear refusal at the call site, where
        // CKR_MECHANISM_INVALID from inside C_GenerateKey would name nothing.
        //
        // The Mac services are what make those keys worth generating: the key is CKA_SENSITIVE and
        // not CKA_EXTRACTABLE, so nothing outside the token can use it. A KeyGenerator without a
        // Mac would produce keys no caller could consume.
        int symmetric = 0;
        for (SecretKeyType type : SecretKeyType.all()) {
            if (capabilities.canGenerate(type.ckmKeyGen())) {
                putService(new Service(this, "KeyGenerator", type.jcaName(),
                        Kimbo11ngKeyGeneratorSpi.class.getName(), null, null) {
                    @Override
                    public Object newInstance(Object constructorParameter) {
                        return new Kimbo11ngKeyGeneratorSpi(runtime.get().slot(), type);
                    }
                });
                registeredServices.add("KeyGenerator:" + type.jcaName());
                symmetric++;
            }
            if (type.isMac() && capabilities.canSign(type.ckmOperation())) {
                putService(new Service(this, "Mac", type.jcaName(),
                        Kimbo11ngMacSpi.class.getName(), null, null) {
                    @Override
                    public Object newInstance(Object constructorParameter) {
                        return new Kimbo11ngMacSpi(type);
                    }
                });
                registeredServices.add("Mac:" + type.jcaName());
                symmetric++;
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Registered provider " + getName() + " with " + classical + " of "
                    + CLASSICAL_SIGNATURES.size() + " classical and " + registered
                    + " post-quantum signature services, " + composite + " composite ones, plus "
                    + symmetric
                    + " symmetric ones, from profile " + initialRuntime.profile().name());
        }
    }
}

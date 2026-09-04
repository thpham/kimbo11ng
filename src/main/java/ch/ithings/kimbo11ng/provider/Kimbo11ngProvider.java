/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.p11.TokenCapabilities;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKM;

import java.security.Provider;
import java.util.LinkedHashSet;
import java.util.List;
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
     * the token's raw {@code r||s} output needs DER-wrapping, and the mechanism parameter block.
     *
     * @param mechanismParam non-null only for RSA-PSS; see {@link RsaPssParams}
     */
    private record ClassicalSignature(String jcaName, long mechanism, boolean ecdsaDerEncoding,
            byte[] mechanismParam) {
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
            new ClassicalSignature("SHA256withRSAandMGF1", CKM.SHA256_RSA_PKCS_PSS, false,
                    RsaPssParams.sha256()),
            new ClassicalSignature("SHA384withRSAandMGF1", CKM.SHA384_RSA_PKCS_PSS, false,
                    RsaPssParams.sha384()),
            new ClassicalSignature("SHA512withRSAandMGF1", CKM.SHA512_RSA_PKCS_PSS, false,
                    RsaPssParams.sha512()),
            new ClassicalSignature("SHA1withECDSA",   CKM.ECDSA,           true,  null),
            new ClassicalSignature("SHA256withECDSA", CKM.ECDSA_SHA256,    true,  null),
            new ClassicalSignature("SHA384withECDSA", CKM.ECDSA_SHA384,    true,  null),
            new ClassicalSignature("SHA512withECDSA", CKM.ECDSA_SHA512,    true,  null));

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
            new String[] {"SHA-512", "SHA512", "2.16.840.1.101.3.4.2.3"});

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
        for (AlgorithmEntry entry : runtime.algorithms().supported()) {
            if (entry.canSign()) {
                keys.add("Signature:" + entry.canonicalName());
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
                    Kimbo11ngSignatureSpi.class.getName(), null, null) {
                @Override
                public Object newInstance(Object constructorParameter) {
                    return Kimbo11ngSignatureSpi.fixed(row.mechanism(), row.ecdsaDerEncoding(),
                            row.mechanismParam());
                }
            });
            registeredServices.add("Signature:" + row.jcaName());
            classical++;
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
                    + " post-quantum signature services, plus " + symmetric
                    + " symmetric ones, from profile " + initialRuntime.profile().name());
        }
    }
}

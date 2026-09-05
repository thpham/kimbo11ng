/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKM;

import java.security.Provider;
import java.util.List;
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

    /** RSA and ECDSA services: {@code {jcaName, CKM, isEcdsa}}. Standard across tokens. */
    private static final List<Object[]> CLASSICAL_SIGNATURES = List.of(
            new Object[] {"SHA1withRSA",     CKM.SHA1_RSA_PKCS,   false},
            new Object[] {"SHA256withRSA",   CKM.SHA256_RSA_PKCS, false},
            new Object[] {"SHA384withRSA",   CKM.SHA384_RSA_PKCS, false},
            new Object[] {"SHA512withRSA",   CKM.SHA512_RSA_PKCS, false},
            new Object[] {"SHA1withECDSA",   CKM.ECDSA,           true},
            new Object[] {"SHA256withECDSA", CKM.ECDSA_SHA256,    true},
            new Object[] {"SHA384withECDSA", CKM.ECDSA_SHA384,    true},
            new Object[] {"SHA512withECDSA", CKM.ECDSA_SHA512,    true});

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
        if (previous != null && previous != newRuntime && log.isDebugEnabled()) {
            log.debug("Re-pointed provider " + name + " from " + previous + " to " + newRuntime);
        }
        return provider;
    }

    private static String nameFor(TokenRuntime runtime) {
        return "Kimbo11ng-" + runtime.device().getLibraryName()
                + "-slot" + runtime.device().getSlotId();
    }

    private Kimbo11ngProvider(String name, TokenRuntime initialRuntime) {
        super(name, "1.0", "kimbo11ng PKCS#11 provider for "
                + initialRuntime.device().getLibPath()
                + " slot " + initialRuntime.device().getSlotId());
        this.runtime.set(initialRuntime);
        registerServices(initialRuntime);
    }

    /** The current runtime. Never null after construction. */
    public TokenRuntime runtime() {
        return runtime.get();
    }

    public CryptokiDevice getDevice() {
        return runtime.get().device();
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

        for (Object[] row : CLASSICAL_SIGNATURES) {
            String jcaName = (String) row[0];
            long mechanism = (Long) row[1];
            boolean isEcdsa = (Boolean) row[2];
            putService(new Service(this, "Signature", jcaName,
                    Kimbo11ngSignatureSpi.class.getName(), null, null) {
                @Override
                public Object newInstance(Object constructorParameter) {
                    return Kimbo11ngSignatureSpi.fixed(mechanism, isEcdsa);
                }
            });
        }

        // One signature service per signing algorithm the profile describes. The mechanism is
        // resolved from the key at init, so nothing here needs to know it.
        int registered = 0;
        for (AlgorithmEntry entry : initialRuntime.profile().entries()) {
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
            registered++;
        }

        putService(new Service(this, "KeyPairGenerator", "RSA",
                Kimbo11ngKeyPairGeneratorSpi.RSA.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngKeyPairGeneratorSpi.RSA(runtime.get().device());
            }
        });
        putService(new Service(this, "KeyPairGenerator", "EC",
                Kimbo11ngKeyPairGeneratorSpi.EC.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngKeyPairGeneratorSpi.EC(runtime.get().device());
            }
        });

        if (log.isDebugEnabled()) {
            log.debug("Registered provider " + getName() + " with "
                    + CLASSICAL_SIGNATURES.size() + " classical and " + registered
                    + " post-quantum signature services from profile "
                    + initialRuntime.profile().name());
        }
    }
}

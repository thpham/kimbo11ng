/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import org.apache.log4j.Logger;

import java.security.Provider;

/**
 * JCA Security Provider backed by PKCS#11 JNA bindings.
 * Registered per-slot, providing KeyStore, Signature, and KeyPairGenerator services.
 */
public class Kimbo11ngProvider extends Provider {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(Kimbo11ngProvider.class);

    // Provider is Serializable, but a live PKCS#11 device and its keystore state are not:
    // a deserialized provider would hold handles into a session that no longer exists.
    private final transient CryptokiDevice device;
    private transient Kimbo11ngKeyStoreSpi keyStoreSpi;

    // Track last generated key pair handles for setKeyEntry labeling
    private long lastGeneratedPrivHandle = -1;
    private long lastGeneratedPubHandle = -1;

    // TODO(phase-1): the provider becomes a stable facade holding an AtomicReference<TokenRuntime>
    // and registers its services from the algorithm table, which removes this escape.
    @SuppressWarnings("this-escape")
    public Kimbo11ngProvider(CryptokiDevice device) {
        super("Kimbo11ng-" + device.getLibraryName() + "-slot" + device.getSlotId(),
                "1.0",
                "Kimbo11ng PKCS#11 Provider for " + device.getLibPath() + " slot " + device.getSlotId());
        this.device = device;
        registerServices();
    }

    private void registerServices() {
        final Kimbo11ngProvider self = this;

        // KeyStore
        putService(new Provider.Service(this, "KeyStore", "PKCS11",
                Kimbo11ngKeyStoreSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                keyStoreSpi = new Kimbo11ngKeyStoreSpi(device);
                return keyStoreSpi;
            }
        });

        // Signature algorithms - RSA
        putService(new Provider.Service(this, "Signature", "SHA1withRSA",
                Kimbo11ngSignatureSpi.SHA1withRSA.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SHA1withRSA();
            }
        });
        putService(new Provider.Service(this, "Signature", "SHA256withRSA",
                Kimbo11ngSignatureSpi.SHA256withRSA.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SHA256withRSA();
            }
        });
        putService(new Provider.Service(this, "Signature", "SHA384withRSA",
                Kimbo11ngSignatureSpi.SHA384withRSA.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SHA384withRSA();
            }
        });
        putService(new Provider.Service(this, "Signature", "SHA512withRSA",
                Kimbo11ngSignatureSpi.SHA512withRSA.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SHA512withRSA();
            }
        });

        // Signature algorithms - ECDSA
        putService(new Provider.Service(this, "Signature", "SHA1withECDSA",
                Kimbo11ngSignatureSpi.SHA1withECDSA.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SHA1withECDSA();
            }
        });
        putService(new Provider.Service(this, "Signature", "SHA256withECDSA",
                Kimbo11ngSignatureSpi.SHA256withECDSA.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SHA256withECDSA();
            }
        });
        putService(new Provider.Service(this, "Signature", "SHA384withECDSA",
                Kimbo11ngSignatureSpi.SHA384withECDSA.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SHA384withECDSA();
            }
        });
        putService(new Provider.Service(this, "Signature", "SHA512withECDSA",
                Kimbo11ngSignatureSpi.SHA512withECDSA.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SHA512withECDSA();
            }
        });

        // Signature algorithms - ML-DSA (FIPS 204)
        putService(new Provider.Service(this, "Signature", "ML-DSA-44",
                Kimbo11ngSignatureSpi.MLDSA44.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.MLDSA44();
            }
        });
        putService(new Provider.Service(this, "Signature", "ML-DSA-65",
                Kimbo11ngSignatureSpi.MLDSA65.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.MLDSA65();
            }
        });
        putService(new Provider.Service(this, "Signature", "ML-DSA-87",
                Kimbo11ngSignatureSpi.MLDSA87.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.MLDSA87();
            }
        });

        // Signature algorithms - SLH-DSA (FIPS 205)
        putService(new Provider.Service(this, "Signature", "SLH-DSA-SHA2-128S",
                Kimbo11ngSignatureSpi.SLHDSA_SHA2_128S.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SLHDSA_SHA2_128S();
            }
        });
        putService(new Provider.Service(this, "Signature", "SLH-DSA-SHAKE-128S",
                Kimbo11ngSignatureSpi.SLHDSA_SHAKE_128S.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SLHDSA_SHAKE_128S();
            }
        });
        putService(new Provider.Service(this, "Signature", "SLH-DSA-SHA2-128F",
                Kimbo11ngSignatureSpi.SLHDSA_SHA2_128F.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SLHDSA_SHA2_128F();
            }
        });
        putService(new Provider.Service(this, "Signature", "SLH-DSA-SHAKE-128F",
                Kimbo11ngSignatureSpi.SLHDSA_SHAKE_128F.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SLHDSA_SHAKE_128F();
            }
        });
        putService(new Provider.Service(this, "Signature", "SLH-DSA-SHA2-192S",
                Kimbo11ngSignatureSpi.SLHDSA_SHA2_192S.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SLHDSA_SHA2_192S();
            }
        });
        putService(new Provider.Service(this, "Signature", "SLH-DSA-SHAKE-192S",
                Kimbo11ngSignatureSpi.SLHDSA_SHAKE_192S.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SLHDSA_SHAKE_192S();
            }
        });
        putService(new Provider.Service(this, "Signature", "SLH-DSA-SHA2-192F",
                Kimbo11ngSignatureSpi.SLHDSA_SHA2_192F.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SLHDSA_SHA2_192F();
            }
        });
        putService(new Provider.Service(this, "Signature", "SLH-DSA-SHAKE-192F",
                Kimbo11ngSignatureSpi.SLHDSA_SHAKE_192F.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SLHDSA_SHAKE_192F();
            }
        });
        putService(new Provider.Service(this, "Signature", "SLH-DSA-SHA2-256S",
                Kimbo11ngSignatureSpi.SLHDSA_SHA2_256S.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SLHDSA_SHA2_256S();
            }
        });
        putService(new Provider.Service(this, "Signature", "SLH-DSA-SHAKE-256S",
                Kimbo11ngSignatureSpi.SLHDSA_SHAKE_256S.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SLHDSA_SHAKE_256S();
            }
        });
        putService(new Provider.Service(this, "Signature", "SLH-DSA-SHA2-256F",
                Kimbo11ngSignatureSpi.SLHDSA_SHA2_256F.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SLHDSA_SHA2_256F();
            }
        });
        putService(new Provider.Service(this, "Signature", "SLH-DSA-SHAKE-256F",
                Kimbo11ngSignatureSpi.SLHDSA_SHAKE_256F.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngSignatureSpi.SLHDSA_SHAKE_256F();
            }
        });

        // KeyPairGenerator
        putService(new Provider.Service(this, "KeyPairGenerator", "RSA",
                Kimbo11ngKeyPairGeneratorSpi.RSA.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngKeyPairGeneratorSpi.RSA(device, self);
            }
        });
        putService(new Provider.Service(this, "KeyPairGenerator", "EC",
                Kimbo11ngKeyPairGeneratorSpi.EC.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Kimbo11ngKeyPairGeneratorSpi.EC(device, self);
            }
        });

        if (log.isDebugEnabled()) {
            log.debug("Registered Kimbo11ngProvider: " + getName());
        }
    }

    public CryptokiDevice getDevice() {
        return device;
    }

    public Kimbo11ngKeyStoreSpi getKeyStoreSpi() {
        return keyStoreSpi;
    }

    public void setLastGeneratedHandles(long privHandle, long pubHandle) {
        this.lastGeneratedPrivHandle = privHandle;
        this.lastGeneratedPubHandle = pubHandle;
        if (keyStoreSpi != null) {
            keyStoreSpi.setLastGeneratedHandles(privHandle, pubHandle);
        }
    }
}

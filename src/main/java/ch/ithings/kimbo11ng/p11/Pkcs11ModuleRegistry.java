/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * One {@link Pkcs11Module} per library file, for the life of the JVM.
 *
 * <p>Keyed by canonical path, so {@code /usr/lib/softhsm/libsofthsm2.so} reached through a symlink
 * and through its real path are recognised as the same library rather than initialised twice.
 *
 * <p>The registry is an object rather than a bag of statics so that tests can hold their own,
 * backed by a fake, without leaking modules between test methods. Production goes through
 * {@link #shared()}, which is what makes "initialise each library exactly once" true across the
 * whole deployment — EJBCA's slot-list factory and every crypto token resolve through the same
 * instance.
 */
public final class Pkcs11ModuleRegistry {

    private static final Logger log = Logger.getLogger(Pkcs11ModuleRegistry.class);

    private static final Pkcs11ModuleRegistry SHARED =
            new Pkcs11ModuleRegistry(NativeProviderFactory.jna());

    private final NativeProviderFactory factory;
    private final ConcurrentMap<String, Pkcs11Module> modules = new ConcurrentHashMap<>();
    /** Guards module construction. Separate from the map, whose own locking it does not share. */
    private final Object loadLock = new Object();

    public Pkcs11ModuleRegistry(NativeProviderFactory factory) {
        this.factory = factory;
    }

    /** The process-wide registry. */
    public static Pkcs11ModuleRegistry shared() {
        return SHARED;
    }

    /**
     * The module for a library, loading and initialising it on first use.
     *
     * <p>Failures are not cached: a library that could not be initialised because its client
     * daemon was not yet up must succeed on a later attempt without a restart.
     */
    public Pkcs11Module get(String libPath) throws CryptoTokenOfflineException {
        String key = canonicalize(libPath);
        Pkcs11Module existing = modules.get(key);
        if (existing != null) {
            return existing;
        }
        // Constructed under a lock so two tokens racing on the same library cannot both call
        // C_Initialize. computeIfAbsent cannot be used here because the mapping function may not
        // throw a checked exception, and swallowing an initialisation failure is exactly the
        // behaviour being fixed.
        synchronized (loadLock) {
            Pkcs11Module module = modules.get(key);
            if (module != null) {
                return module;
            }
            module = new Pkcs11Module(key, factory);
            modules.put(key, module);
            return module;
        }
    }

    /** Loaded modules, for diagnostics and tests. */
    public Collection<Pkcs11Module> loaded() {
        return List.copyOf(modules.values());
    }

    /** Whether this library has been loaded already, without loading it. */
    public boolean isLoaded(String libPath) {
        return modules.containsKey(canonicalize(libPath));
    }

    private static String canonicalize(String libPath) {
        try {
            return new File(libPath).getCanonicalPath();
        } catch (IOException e) {
            // A path we cannot canonicalize is still a usable key; it just will not be recognised
            // as the same library when reached by another route.
            if (log.isDebugEnabled()) {
                log.debug("Cannot canonicalize " + libPath + "; using it as given: "
                        + e.getMessage());
            }
            return new File(libPath).getAbsolutePath();
        }
    }
}

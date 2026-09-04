/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import org.pkcs11.jacknji11.NativeProvider;
import org.pkcs11.jacknji11.jna.JNA;

/**
 * Creates the {@link NativeProvider} that backs a PKCS#11 library.
 *
 * <p>This is the seam that separates kimbo11ng from the native world. In production the
 * {@linkplain #jna() default} loads the shared library through JNA; tests substitute an in-memory
 * token so the full stack — sessions, key identity, algorithm registry, capability probing — can be
 * exercised without hardware, and so that HSM behaviours a soft token never exhibits (dropped
 * sessions, raw {@code CKA_EC_POINT}, absent {@code CKA_PARAMETER_SET}, vendor mechanisms) can be
 * simulated deliberately.
 */
@FunctionalInterface
public interface NativeProviderFactory {

    /**
     * Opens the PKCS#11 library at {@code libraryPath}.
     *
     * <p>Implementations must not call {@code C_Initialize}; that is the caller's responsibility so
     * that a single library shared by several slots is initialized exactly once.
     *
     * @param libraryPath absolute path to the PKCS#11 shared library
     * @return a provider bound to that library, never {@code null}
     */
    NativeProvider create(String libraryPath);

    /** The production factory: loads the shared library through JNA. */
    static NativeProviderFactory jna() {
        return JNA::new;
    }
}

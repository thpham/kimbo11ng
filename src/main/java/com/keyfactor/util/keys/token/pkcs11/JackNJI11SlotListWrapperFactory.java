/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package com.keyfactor.util.keys.token.pkcs11;

import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import ch.ithings.kimbo11ng.slot.SlotListWrapper;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.apache.log4j.Logger;

import java.io.File;

/**
 * EJBCA's SPI entry point for enumerating PKCS#11 slots, backed by JackNJI11.
 *
 * <p>This fully-qualified name is registered in {@code META-INF/services} and must not move.
 *
 * <p>Priority 2 outranks the SunPKCS11-backed factory's 1, which has a consequence worth stating
 * plainly: EJBCA's <em>classic</em> {@code PKCS11CryptoToken} resolves its slots through this class
 * too, for every PKCS#11 library in the deployment, not only the ones kimbo11ng manages. That is
 * why {@link Pkcs11ModuleRegistry} never calls {@code C_Finalize} — the library we would be
 * finalising may be one SunPKCS11 is actively using.
 */
public class JackNJI11SlotListWrapperFactory implements PKCS11SlotListWrapperFactory {

    private static final Logger log = Logger.getLogger(JackNJI11SlotListWrapperFactory.class);

    @Override
    public int getPriority() {
        return 2;
    }

    @Override
    public PKCS11SlotListWrapper getInstance(File file) {
        // No cache here any more: the registry keys modules by canonical path and holds the only
        // caches worth having. The wrapper itself is a stateless view, so making a new one is free
        // and cannot go stale.
        String path = file.getPath();
        try {
            return new SlotListWrapper(Pkcs11ModuleRegistry.shared().get(path));
        } catch (CryptoTokenOfflineException e) {
            log.error("Could not load the PKCS#11 library " + path
                    + "; reporting no slots for this attempt: " + e.getMessage(), e);
            return new EmptySlotList(path);
        }
    }

    /**
     * What we hand back when the library will not load at all.
     *
     * <p>EJBCA's interface has no way to say "ask again later", so the failure has to look like an
     * empty slot list. It is not remembered: the next call re-enters the registry and retries the
     * load, so a library whose driver was not yet up recovers on its own.
     */
    private record EmptySlotList(String path) implements PKCS11SlotListWrapper {

        @Override
        public long[] getSlotList() {
            return new long[0];
        }

        @Override
        public char[] getTokenLabel(long slotId) {
            return new char[0];
        }
    }
}

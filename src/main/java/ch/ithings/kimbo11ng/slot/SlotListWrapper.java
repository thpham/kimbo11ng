/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.slot;

import ch.ithings.kimbo11ng.p11.Pkcs11Module;
import ch.ithings.kimbo11ng.p11.Pkcs11ModuleRegistry;
import com.keyfactor.util.keys.token.pkcs11.PKCS11SlotListWrapper;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.apache.log4j.Logger;

/**
 * EJBCA's slot-list view of a PKCS#11 library, backed by the shared {@link Pkcs11Module}.
 *
 * <p>Holds no state of its own. It used to own a second {@code Cryptoki} and a second
 * {@code C_Initialize} for a library a crypto token had already initialised, plus its own caches —
 * one of which cached failure: a slot list that could not be read once was remembered as "no
 * slots" for the life of the JVM.
 *
 * <p>The interface it implements cannot report failure, only emptiness, which is why the module's
 * exceptions are turned into an empty answer here and logged loudly. That is EJBCA's contract, not
 * a choice: {@code PKCS11SlotListWrapper.getSlotList()} returns {@code long[]}.
 */
public final class SlotListWrapper implements PKCS11SlotListWrapper {

    private static final Logger log = Logger.getLogger(SlotListWrapper.class);

    private final Pkcs11Module module;

    public SlotListWrapper(String libPath) throws CryptoTokenOfflineException {
        this(Pkcs11ModuleRegistry.shared().get(libPath));
    }

    public SlotListWrapper(Pkcs11Module module) {
        this.module = module;
    }

    @Override
    public long[] getSlotList() {
        try {
            return module.slotList();
        } catch (CryptoTokenOfflineException e) {
            // Not cached: the next call asks the token again, so a library whose client daemon was
            // not yet up recovers without restarting the application server.
            log.error("Could not read the slot list from " + module.path()
                    + "; reporting no slots for this attempt: " + e.getMessage(), e);
            return new long[0];
        }
    }

    @Override
    public char[] getTokenLabel(long slotId) {
        try {
            return module.tokenLabel(slotId);
        } catch (CryptoTokenOfflineException e) {
            log.error("Could not read the token label for slot " + slotId + " of "
                    + module.path() + ": " + e.getMessage(), e);
            return new char[0];
        }
    }

    public String getLibPath() {
        return module.path();
    }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.slot;

import ch.ithings.kimbo11ng.p11.NativeProviderFactory;
import com.keyfactor.util.keys.token.pkcs11.PKCS11SlotListWrapper;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.pkcs11.jacknji11.CryptokiE;
import org.pkcs11.jacknji11.Cryptoki;

import java.util.HashMap;
import java.util.Map;

/**
 * PKCS11SlotListWrapper implementation using JackNJI11 JNA backend.
 * Uses a specific PKCS#11 library path rather than the global SunPKCS11 provider,
 * enabling multiple HSM libraries simultaneously.
 */
public class SlotListWrapper implements PKCS11SlotListWrapper {

    private static final Logger log = Logger.getLogger(SlotListWrapper.class);

    private final String libPath;
    private final CryptokiE ce;
    private long[] cachedSlots;
    private final Map<Long, char[]> labelCache = new HashMap<>();

    public SlotListWrapper(String libPath) {
        this(libPath, NativeProviderFactory.jna());
    }

    public SlotListWrapper(String libPath, NativeProviderFactory providerFactory) {
        this.libPath = libPath;
        Cryptoki cryptoki = new Cryptoki(providerFactory.create(libPath));
        this.ce = new CryptokiE(cryptoki);
        try {
            ce.Initialize();
            if (log.isDebugEnabled()) {
                log.debug("Initialized PKCS#11 library: " + libPath);
            }
        } catch (Exception e) {
            log.warn("Failed to initialize PKCS#11 library " + libPath + ": " + e.getMessage());
        }
    }

    @Override
    public synchronized long[] getSlotList() {
        if (cachedSlots != null) {
            return cachedSlots;
        }
        try {
            cachedSlots = ce.GetSlotList(true);
            if (log.isDebugEnabled()) {
                log.debug("Got " + (cachedSlots != null ? cachedSlots.length : 0) +
                        " slots from library: " + libPath);
            }
            return cachedSlots;
        } catch (Exception e) {
            log.error("Failed to get slot list from " + libPath + ": " + e.getMessage(), e);
            cachedSlots = new long[0];
            return cachedSlots;
        }
    }

    @Override
    public synchronized char[] getTokenLabel(long slotId) {
        if (labelCache.containsKey(slotId)) {
            return labelCache.get(slotId);
        }
        try {
            CK_TOKEN_INFO info = ce.GetTokenInfo(slotId);
            String labelStr = (info.label != null) ? new String(info.label, "UTF-8").trim() : "";
            char[] trimmed = labelStr.toCharArray();
            labelCache.put(slotId, trimmed);
            return trimmed;
        } catch (Exception e) {
            log.error("Failed to get token info for slot " + slotId + ": " + e.getMessage(), e);
            return new char[0];
        }
    }

    public CryptokiE getCryptokiE() {
        return ce;
    }

    public String getLibPath() {
        return libPath;
    }
}

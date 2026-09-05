/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.NativeProviderFactory;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.CryptokiE;
import org.pkcs11.jacknji11.Cryptoki;
import org.pkcs11.jacknji11.CKU;

import java.io.File;

/**
 * Session and slot lifecycle manager for a specific PKCS#11 library and slot.
 * Wraps CryptokiE to manage the session state for one slot.
 */
public class CryptokiDevice {

    private static final Logger log = Logger.getLogger(CryptokiDevice.class);

    private final String libPath;
    private final long slotId;
    private final CryptokiE ce;
    private long session = -1;
    private boolean loggedIn = false;

    public CryptokiDevice(String libPath, long slotId) {
        this(libPath, slotId, NativeProviderFactory.jna());
    }

    public CryptokiDevice(String libPath, long slotId, NativeProviderFactory providerFactory) {
        this.libPath = libPath;
        this.slotId = slotId;
        Cryptoki cryptoki = new Cryptoki(providerFactory.create(libPath));
        this.ce = new CryptokiE(cryptoki);
        try {
            ce.Initialize();
            if (log.isDebugEnabled()) {
                log.debug("Initialized CryptokiDevice for library: " + libPath + " slot: " + slotId);
            }
        } catch (Exception e) {
            // Already initialized is acceptable (CKR_CRYPTOKI_ALREADY_INITIALIZED)
            if (log.isDebugEnabled()) {
                log.debug("CryptokiDevice init (may already be initialized): " + e.getMessage());
            }
        }
    }

    /**
     * Creates a CryptokiDevice from an existing CryptokiE instance (reuse from slot list wrapper).
     */
    public CryptokiDevice(CryptokiE ce, String libPath, long slotId) {
        this.ce = ce;
        this.libPath = libPath;
        this.slotId = slotId;
    }

    public synchronized long getOrOpenSession() throws Exception {
        if (session >= 0) {
            return session;
        }
        // Open R/W session: CKF_SERIAL_SESSION | CKF_RW_SESSION
        session = ce.OpenSession(slotId,
                CK_SESSION_INFO.CKF_SERIAL_SESSION | CK_SESSION_INFO.CKF_RW_SESSION,
                null, null);
        if (log.isDebugEnabled()) {
            log.debug("Opened session " + session + " on slot " + slotId);
        }
        return session;
    }

    public synchronized void login(char[] pin) throws Exception {
        if (loggedIn) {
            return;
        }
        long s = getOrOpenSession();
        byte[] pinBytes = new String(pin).getBytes("UTF-8");
        try {
            ce.Login(s, CKU.USER, pinBytes);
        } catch (Exception e) {
            // CKR_USER_ALREADY_LOGGED_IN (0x00000100) means the slot is already
            // authenticated from another session in this process - acceptable.
            String msg = e.getMessage();
            if (msg != null && (msg.contains("0x00000100") || msg.contains("CKR_USER_ALREADY_LOGGED_IN"))) {
                if (log.isDebugEnabled()) {
                    log.debug("Slot " + slotId + " already logged in (CKR_USER_ALREADY_LOGGED_IN) - proceeding");
                }
            } else {
                throw e;
            }
        }
        loggedIn = true;
        if (log.isDebugEnabled()) {
            log.debug("Logged in to slot " + slotId);
        }
    }

    public synchronized void logout() {
        if (!loggedIn || session < 0) {
            return;
        }
        try {
            ce.Logout(session);
            loggedIn = false;
            if (log.isDebugEnabled()) {
                log.debug("Logged out from slot " + slotId);
            }
        } catch (Exception e) {
            log.warn("Failed to logout from slot " + slotId + ": " + e.getMessage());
        }
    }

    public synchronized void close() {
        if (session < 0) {
            return;
        }
        try {
            if (loggedIn) {
                ce.Logout(session);
                loggedIn = false;
            }
            ce.CloseSession(session);
            session = -1;
            if (log.isDebugEnabled()) {
                log.debug("Closed session on slot " + slotId);
            }
        } catch (Exception e) {
            log.warn("Failed to close session on slot " + slotId + ": " + e.getMessage());
            session = -1;
        }
    }

    public CryptokiE getCe() {
        return ce;
    }

    public long getSlotId() {
        return slotId;
    }

    public String getLibPath() {
        return libPath;
    }

    public String getLibraryName() {
        return new File(libPath).getName().replaceAll("[^a-zA-Z0-9_-]", "_");
    }

    public synchronized boolean isLoggedIn() {
        return loggedIn;
    }
}

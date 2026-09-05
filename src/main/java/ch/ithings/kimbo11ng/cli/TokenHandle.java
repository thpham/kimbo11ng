/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.CryptoTokenImpl;
import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.p11.Pkcs11Module;
import ch.ithings.kimbo11ng.p11.SlotResolver;
import com.keyfactor.util.keys.CachingKeyStoreWrapper;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabelType;

import java.util.Arrays;
import java.util.Properties;

/**
 * One command's access to a token: the library, the resolved slot, and — for the commands that need
 * one — a logged-in crypto token.
 *
 * <p>Three levels, because PKCS#11 has three and conflating them is what makes HSM problems hard to
 * place. {@link #library} needs only a path, and answers whether the {@code .so} loads at all.
 * {@link #slot} adds a slot id and a mechanism list, and needs no PIN — which is why
 * {@code capabilities} can report what an HSM supports before anyone has a credential for it.
 * {@link #session} adds the login, and is the only level where keys exist.
 *
 * <p>A failure at one level is a different problem from a failure at the next, and the commands are
 * split along the same seam so the error names which one it was.
 */
final class TokenHandle implements AutoCloseable {

    private final CryptoTokenImpl token;
    private final P11Slot slot;
    private final StandaloneBridge bridge;

    private TokenHandle(CryptoTokenImpl token, P11Slot slot, StandaloneBridge bridge) {
        this.token = token;
        this.slot = slot;
        this.bridge = bridge;
    }

    /** The library, initialized, with no slot chosen. */
    static Pkcs11Module library(CliEnv env, Args args) throws Exception {
        return env.modules().get(args.require("lib-file"));
    }

    /** The slot id this command line names, without opening a session or logging in. */
    static long slotId(CliEnv env, Args args) throws Exception {
        Pkcs11Module module = library(env, args);
        Pkcs11SlotLabelType type = Pkcs11SlotLabelType.getFromKey(
                args.tokenProperties(args.require("lib-file")).getProperty("slotLabelType"));
        return SlotResolver.resolve(module, type, args.get("slot", "0"));
    }

    /**
     * An initialized crypto token, not logged in.
     *
     * <p>Enough for anything that reads the token's own description of itself — mechanisms, flags,
     * the resolved algorithm profile — none of which requires a credential.
     */
    static TokenHandle slot(CliEnv env, Args args) throws Exception {
        StandaloneBridge bridge = new StandaloneBridge();
        CryptoTokenImpl token = new CryptoTokenImpl(bridge, env.modules());
        Properties properties = args.tokenProperties(args.require("lib-file"));
        token.init(properties, null, 0);
        return new TokenHandle(token, token.getSlot(), bridge);
    }

    /**
     * An initialized, activated crypto token.
     *
     * <p>The PIN is zeroed before this returns, whether or not the login succeeded, so the only
     * copy that outlives the call is the one PKCS#11 holds inside the token.
     */
    static TokenHandle session(CliEnv env, Args args) throws Exception {
        TokenHandle handle = slot(env, args);
        char[] pin = env.pin(args);
        try {
            handle.token.activate(pin);
        } catch (Exception e) {
            handle.close();
            throw e;
        } finally {
            if (pin != null) {
                Arrays.fill(pin, '\0');
            }
        }
        return handle;
    }

    CryptoTokenImpl token() {
        return token;
    }

    P11Slot slot() {
        return slot;
    }

    /**
     * The key store the token published on activation, which is the alias view EJBCA itself sees.
     *
     * @throws CliException if the token is not activated, which for a caller that used
     *                      {@link #session} means the login silently produced no key store
     */
    CachingKeyStoreWrapper keyStore() throws CliException {
        CachingKeyStoreWrapper keyStore = bridge.bridgeGetKeyStore();
        if (keyStore == null) {
            throw new CliException("The token is not activated, so it has no keys to show."
                    + " This normally means the PIN was accepted but the token then went offline.");
        }
        return keyStore;
    }

    @Override
    public void close() {
        token.reset();
    }
}

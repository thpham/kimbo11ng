/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package org.cesecore.keys.token.p11ng.cryptotoken;

import ch.ithings.kimbo11ng.Kimbo11ngCryptoToken;

/**
 * Name-compatibility alias. Carries no logic — see {@link Kimbo11ngCryptoToken}.
 *
 * <p>This FQN is what EJBCA registers and looks for:
 * {@code CryptoTokenFactory}'s constructor calls
 * {@code addAvailableCryptoToken("org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken",
 * "PKCS#11 NG", true, true)}, and CE 9.3.7 ships no class under it. So this file occupies a package
 * belonging to Keyfactor, which is what makes the integration work and also what makes it fragile:
 * a single stub class in a future CE would claim the name, and which of the two jars in
 * {@code ejbca.ear/lib} the classloader picks is unspecified.
 *
 * <p>Keeping the implementation in {@code ch.ithings.kimbo11ng} and this class empty means that
 * scenario costs us a redirect, not a rewrite. It stays the database-facing name for now:
 * {@code CryptoTokenSessionBean.getClassNameForType} resolves a stored {@code tokenType} by
 * scanning the registry for a class path that {@code endsWith} it, and only this FQN is registered.
 *
 * <p>{@code serialVersionUID} stays at {@code 1L} — the value this FQN has always carried — because
 * a subclass's is independent of its parent's, and rows already in the database name this class.
 */
public class Pkcs11NgCryptoToken extends Kimbo11ngCryptoToken {

    private static final long serialVersionUID = 1L;

    public Pkcs11NgCryptoToken() throws InstantiationException {
        super();
    }
}

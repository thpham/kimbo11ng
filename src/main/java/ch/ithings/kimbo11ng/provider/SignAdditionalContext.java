/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.Pkcs11v32;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import org.pkcs11.jacknji11.CKM;

/**
 * The {@code CK_SIGN_ADDITIONAL_CONTEXT} block that carries an ML-DSA or SLH-DSA context string.
 *
 * <pre>
 * typedef struct CK_SIGN_ADDITIONAL_CONTEXT {
 *     CK_HEDGE_TYPE   hedgeVariant;
 *     CK_BYTE_PTR     pContext;
 *     CK_ULONG        ulContextLen;
 * } CK_SIGN_ADDITIONAL_CONTEXT;
 * </pre>
 *
 * <p>Unlike {@link RsaPssParams} this cannot be a {@code byte[]}: {@code pContext} is a pointer, so
 * the context has to live in native memory and the block has to hold its address. Both are JNA
 * {@link Memory}, and this object owns both — it must stay reachable until {@code C_SignInit} has
 * returned, which is what {@link #mechanism} documents and its caller enforces.
 *
 * <p>The layout is packed, with {@code CK_ULONG} at the platform's {@code unsigned long} width:
 * the same convention jacknji11 uses for its own {@code CK_MECHANISM}, and the one PKCS#11 headers
 * declare on Windows. On 64-bit Linux every field is eight bytes and packing changes nothing.
 *
 * <h2>Why it is sent only for a non-empty context</h2>
 *
 * <p>Plain ML-DSA keeps sending no parameter, as it always has; see
 * {@code VENDOR_PROFILE_CHECKLIST.md}, "The ML-DSA signing parameters". A token that
 * rejected an unexpected parameter would otherwise fail every ML-DSA signature, to say nothing it
 * could not already say without one. A composite signature is different: draft-ietf-lamps-pq-
 * composite-sigs binds its domain label into the ML-DSA half through this context, so without it
 * the signature does not verify at all.
 *
 * <p>{@code hedgeVariant} is {@link Pkcs11v32#CKH_HEDGE_PREFERRED}, which is zero and so is also
 * what a token assumes when nothing is sent — the context is the only thing that changes.
 */
final class SignAdditionalContext {

    /** FIPS 204 and 205 both limit the context to 255 bytes. */
    static final int MAX_CONTEXT_LENGTH = 255;

    private final Memory context;
    private final Memory block;

    SignAdditionalContext(byte[] contextBytes) {
        if (contextBytes.length == 0 || contextBytes.length > MAX_CONTEXT_LENGTH) {
            throw new IllegalArgumentException("context must be 1.." + MAX_CONTEXT_LENGTH
                    + " bytes, got " + contextBytes.length);
        }
        context = new Memory(contextBytes.length);
        context.write(0, contextBytes, 0, contextBytes.length);

        int ulong = Native.LONG_SIZE;
        block = new Memory(2L * ulong + Native.POINTER_SIZE);
        block.setNativeLong(0, new NativeLong(Pkcs11v32.CKH_HEDGE_PREFERRED));
        block.setPointer(ulong, context);
        block.setNativeLong(ulong + Native.POINTER_SIZE, new NativeLong(contextBytes.length));
    }

    /**
     * The mechanism with this block as its parameter.
     *
     * <p>The returned {@code CKM} points into memory this object owns, and JNA frees a
     * {@link Memory} when it is collected. Keep this object reachable until the PKCS#11 call that
     * uses the mechanism has returned.
     */
    CKM mechanism(long ckm) {
        return new CKM(ckm, block);
    }
}

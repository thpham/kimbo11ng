/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Encoding a PIN for {@code C_Login} without leaving a copy behind.
 *
 * <p>{@code new String(pin).getBytes(UTF_8)} — what this replaces — puts the PIN into an immutable
 * String that cannot be cleared and lives until the collector happens to reclaim it, and then into
 * an intermediate byte array that is never cleared either. Every heap dump, core file and swap page
 * taken in between contains the HSM credential in plain text.
 *
 * <p>The caller owns the returned array and must zero it in a {@code finally}.
 */
public final class Pins {

    private Pins() {
    }

    /**
     * UTF-8 bytes of {@code pin}, via a CharBuffer so no String is ever constructed.
     *
     * <p>Any intermediate buffer is zeroed before it is discarded, so the only remaining copy is
     * the array handed back.
     */
    public static byte[] encodeUtf8(char[] pin) {
        if (pin == null) {
            return new byte[0];
        }
        CharBuffer chars = CharBuffer.wrap(pin);
        CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder()
                // A PIN is a credential, not text to be repaired: silently substituting '?' for an
                // unencodable character would send the token a different secret than the operator
                // typed and report the failure as a wrong PIN.
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        ByteBuffer buffer;
        try {
            buffer = encoder.encode(chars);
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException(
                    "The PIN contains characters that cannot be encoded as UTF-8", e);
        }
        byte[] out = new byte[buffer.remaining()];
        buffer.get(out);
        if (buffer.hasArray()) {
            Arrays.fill(buffer.array(), (byte) 0);
        }
        return out;
    }
}

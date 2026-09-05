/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabelType;

/**
 * Turning EJBCA's slot reference — a type and a value — into a PKCS#11 slot id.
 *
 * <p>Lives here rather than inside the crypto token because two callers need the same answer: the
 * token, when EJBCA initialises it, and the CLI, when it reports which slot an invocation will act
 * on. Two implementations of this would be a bug waiting to happen — a tool whose diagnosis
 * addresses a different slot than the CA is worse than no tool.
 *
 * <p>All three reference types go through {@link Pkcs11Module#slotList()}, so this shares the
 * library's single {@code C_Initialize} with everything else in the JVM.
 */
public final class SlotResolver {

    private SlotResolver() {
    }

    /**
     * The slot id {@code labelValue} names.
     *
     * @param labelType how to read {@code labelValue}; {@code null} is treated as
     *                  {@link Pkcs11SlotLabelType#SLOT_INDEX}, matching the crypto token's default
     * @throws NoSuchSlotException if the library reports no slots, or none matching
     */
    public static long resolve(Pkcs11Module module, Pkcs11SlotLabelType labelType,
            String labelValue) throws NoSuchSlotException, CryptoTokenOfflineException {
        long[] slots = module.slotList();
        if (slots == null || slots.length == 0) {
            throw new NoSuchSlotException("No slots found in library: " + module.path());
        }
        if (labelType == Pkcs11SlotLabelType.SLOT_NUMBER) {
            return parseNumber(labelValue, "slot number");
        }
        if (labelType == Pkcs11SlotLabelType.SLOT_LABEL) {
            for (long slotId : slots) {
                char[] label = module.tokenLabel(slotId);
                if (label != null && new String(label).trim().equals(labelValue.trim())) {
                    return slotId;
                }
            }
            throw new NoSuchSlotException("No slot found with label: " + labelValue);
        }
        int index = (int) parseNumber(labelValue, "slot index");
        if (index < 0 || index >= slots.length) {
            throw new NoSuchSlotException("Slot index " + index + " out of range (0-"
                    + (slots.length - 1) + ")");
        }
        return slots[index];
    }

    /**
     * A number, or a {@link NoSuchSlotException} naming what was expected.
     *
     * <p>Previously a {@code NumberFormatException} escaped from here, which EJBCA surfaces as a
     * stack trace with no mention of the slot at all.
     */
    private static long parseNumber(String value, String what) throws NoSuchSlotException {
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            throw new NoSuchSlotException("Expected a " + what + ", got '" + value + "'");
        }
    }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.fake;

import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CK_C_INITIALIZE_ARGS;
import org.pkcs11.jacknji11.CK_INFO;
import org.pkcs11.jacknji11.CK_MECHANISM_INFO;
import org.pkcs11.jacknji11.CK_NOTIFY;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.CK_SLOT_INFO;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.pkcs11.jacknji11.LongRef;
import org.pkcs11.jacknji11.NativePointer;
import org.pkcs11.jacknji11.NativeProvider;

/**
 * Adapter that answers {@code CKR_FUNCTION_NOT_SUPPORTED} to all 67 PKCS#11 entry points.
 *
 * <p>{@link FakeToken} overrides only the subset kimbo11ng actually calls. Anything it forgets to
 * implement therefore fails loudly as an unsupported function rather than silently returning
 * {@code CKR_OK} with an empty result — which is how a test double quietly starts lying.
 */
abstract class UnsupportedNativeProvider implements NativeProvider {

    private static final long NOPE = CKR.FUNCTION_NOT_SUPPORTED;

    @Override public long C_Initialize(CK_C_INITIALIZE_ARGS a) { return NOPE; }
    @Override public long C_Finalize(NativePointer p) { return NOPE; }
    @Override public long C_GetInfo(CK_INFO i) { return NOPE; }
    @Override public long C_GetSlotList(boolean t, long[] l, LongRef c) { return NOPE; }
    @Override public long C_GetSlotInfo(long s, CK_SLOT_INFO i) { return NOPE; }
    @Override public long C_GetTokenInfo(long s, CK_TOKEN_INFO i) { return NOPE; }
    @Override public long C_WaitForSlotEvent(long f, LongRef s, NativePointer p) { return NOPE; }
    @Override public long C_GetMechanismList(long s, long[] m, LongRef c) { return NOPE; }
    @Override public long C_GetMechanismInfo(long s, long t, CK_MECHANISM_INFO i) { return NOPE; }
    @Override public long C_InitToken(long s, byte[] p, long l, byte[] lab) { return NOPE; }
    @Override public long C_InitPIN(long s, byte[] p, long l) { return NOPE; }
    @Override public long C_SetPIN(long s, byte[] o, long ol, byte[] n, long nl) { return NOPE; }
    @Override public long C_OpenSession(long s, long f, NativePointer a, CK_NOTIFY n, LongRef h) { return NOPE; }
    @Override public long C_CloseSession(long s) { return NOPE; }
    @Override public long C_CloseAllSessions(long s) { return NOPE; }
    @Override public long C_GetSessionInfo(long s, CK_SESSION_INFO i) { return NOPE; }
    @Override public long C_GetOperationState(long s, byte[] o, LongRef l) { return NOPE; }
    @Override public long C_SetOperationState(long s, byte[] o, long l, long e, long a) { return NOPE; }
    @Override public long C_Login(long s, long u, byte[] p, long l) { return NOPE; }
    @Override public long C_Logout(long s) { return NOPE; }
    @Override public long C_CreateObject(long s, CKA[] t, long c, LongRef o) { return NOPE; }
    @Override public long C_CopyObject(long s, long o, CKA[] t, long c, LongRef n) { return NOPE; }
    @Override public long C_DestroyObject(long s, long o) { return NOPE; }
    @Override public long C_GetObjectSize(long s, long o, LongRef z) { return NOPE; }
    @Override public long C_GetAttributeValue(long s, long o, CKA[] t, long c) { return NOPE; }
    @Override public long C_SetAttributeValue(long s, long o, CKA[] t, long c) { return NOPE; }
    @Override public long C_FindObjectsInit(long s, CKA[] t, long c) { return NOPE; }
    @Override public long C_FindObjects(long s, long[] o, long m, LongRef c) { return NOPE; }
    @Override public long C_FindObjectsFinal(long s) { return NOPE; }
    @Override public long C_EncryptInit(long s, CKM m, long k) { return NOPE; }
    @Override public long C_Encrypt(long s, byte[] d, long dl, byte[] e, LongRef el) { return NOPE; }
    @Override public long C_EncryptUpdate(long s, byte[] p, long pl, byte[] e, LongRef el) { return NOPE; }
    @Override public long C_EncryptFinal(long s, byte[] e, LongRef el) { return NOPE; }
    @Override public long C_DecryptInit(long s, CKM m, long k) { return NOPE; }
    @Override public long C_Decrypt(long s, byte[] e, long el, byte[] d, LongRef dl) { return NOPE; }
    @Override public long C_DecryptUpdate(long s, byte[] e, long el, byte[] d, LongRef dl) { return NOPE; }
    @Override public long C_DecryptFinal(long s, byte[] d, LongRef dl) { return NOPE; }
    @Override public long C_DigestInit(long s, CKM m) { return NOPE; }
    @Override public long C_Digest(long s, byte[] d, long dl, byte[] g, LongRef gl) { return NOPE; }
    @Override public long C_DigestUpdate(long s, byte[] p, long pl) { return NOPE; }
    @Override public long C_DigestKey(long s, long k) { return NOPE; }
    @Override public long C_DigestFinal(long s, byte[] g, LongRef gl) { return NOPE; }
    @Override public long C_SignInit(long s, CKM m, long k) { return NOPE; }
    @Override public long C_Sign(long s, byte[] d, long dl, byte[] g, LongRef gl) { return NOPE; }
    @Override public long C_SignUpdate(long s, byte[] p, long pl) { return NOPE; }
    @Override public long C_SignFinal(long s, byte[] g, LongRef gl) { return NOPE; }
    @Override public long C_SignRecoverInit(long s, CKM m, long k) { return NOPE; }
    @Override public long C_SignRecover(long s, byte[] d, long dl, byte[] g, LongRef gl) { return NOPE; }
    @Override public long C_VerifyInit(long s, CKM m, long k) { return NOPE; }
    @Override public long C_Verify(long s, byte[] d, long dl, byte[] g, long gl) { return NOPE; }
    @Override public long C_VerifyUpdate(long s, byte[] p, long pl) { return NOPE; }
    @Override public long C_VerifyFinal(long s, byte[] g, long gl) { return NOPE; }
    @Override public long C_VerifyRecoverInit(long s, CKM m, long k) { return NOPE; }
    @Override public long C_VerifyRecover(long s, byte[] g, long gl, byte[] d, LongRef dl) { return NOPE; }
    @Override public long C_DigestEncryptUpdate(long s, byte[] p, long pl, byte[] e, LongRef el) { return NOPE; }
    @Override public long C_DecryptDigestUpdate(long s, byte[] e, long el, byte[] p, LongRef pl) { return NOPE; }
    @Override public long C_SignEncryptUpdate(long s, byte[] p, long pl, byte[] e, LongRef el) { return NOPE; }
    @Override public long C_DecryptVerifyUpdate(long s, byte[] e, long el, byte[] p, LongRef pl) { return NOPE; }
    @Override public long C_GenerateKey(long s, CKM m, CKA[] t, long c, LongRef k) { return NOPE; }
    @Override public long C_GenerateKeyPair(long s, CKM m, CKA[] pub, long pc, CKA[] pri, long ric, LongRef pubk, LongRef prik) { return NOPE; }
    @Override public long C_WrapKey(long s, CKM m, long w, long k, byte[] b, LongRef bl) { return NOPE; }
    @Override public long C_UnwrapKey(long s, CKM m, long u, byte[] w, long wl, CKA[] t, long c, LongRef k) { return NOPE; }
    @Override public long C_DeriveKey(long s, CKM m, long b, CKA[] t, long c, LongRef k) { return NOPE; }
    @Override public long C_SeedRandom(long s, byte[] d, long dl) { return NOPE; }
    @Override public long C_GenerateRandom(long s, byte[] d, long dl) { return NOPE; }
    @Override public long C_GetFunctionStatus(long s) { return NOPE; }
    @Override public long C_CancelFunction(long s) { return NOPE; }
}

/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.p11;

import java.util.Map;

/**
 * Names for the PKCS#11 mechanisms Keyfactor's jacknji11 1.3.1 does not know.
 *
 * <h2>What this is for</h2>
 *
 * <p>Diagnosis, and nothing else. No code branches on anything here: these are the labels
 * {@code kimbo11ng-cli capabilities --mechanisms} prints, and they exist so that asking an HSM what
 * it can do produces an inventory rather than a column of hex. That question is the first step of
 * qualifying a token, and a dump where RSA reads {@code CKM_RSA_PKCS_KEY_PAIR_GEN} and the next
 * forty lines read {@code 0x0000001f} answers it badly — it suggests the rest is less well
 * understood, when in fact only the bindings are behind.
 *
 * <p>Deliberately separate from {@link Pkcs11v30} and {@link Pkcs11v32}. Those hold the handful of
 * values this project <em>uses</em>, hand-entered with their provenance argued one by one. This is
 * a lookup table for values nothing here calls, and mixing the two would blur a distinction worth
 * keeping: a wrong constant there is a bug, a wrong name here is a misleading log line.
 *
 * <h2>Provenance</h2>
 *
 * <p><strong>Generated, not typed.</strong> Every entry is the OASIS PKCS#11 v3.2 header
 * (oasis-tcs/pkcs11, {@code working/headers/pkcs11t.h}, {@code CRYPTOKI_VERSION} 3.2.0) minus the
 * mechanisms jacknji11 1.3.1 already names through {@code CKM.L2S}. Generating it is the point:
 * 198 hand-copied numbers is exactly the drift this project keeps closing elsewhere.
 *
 * <p>Regenerating on a header bump means re-deriving that difference, not editing rows. Vendor
 * mechanisms ({@code 0x80000000} and above) are excluded by construction — no standard name can be
 * right for them, and printing one over a vendor number would be a confident lie about what the
 * token was asked for.
 *
 * <p>Captured on 2026-09-19. What none of this establishes is whether a token implements any of it;
 * the mechanism probe answers that half, and a correct name next to an absent mechanism looks
 * exactly like a correct name next to a working one.
 */
public final class Pkcs11MechanismNames {

    private Pkcs11MechanismNames() {
    }

    private static final Map<Long, String> NAMES = Map.ofEntries(
            Map.entry(0x00000013L, "CKM_DSA_SHA224"),
            Map.entry(0x00000014L, "CKM_DSA_SHA256"),
            Map.entry(0x00000015L, "CKM_DSA_SHA384"),
            Map.entry(0x00000016L, "CKM_DSA_SHA512"),
            Map.entry(0x00000018L, "CKM_DSA_SHA3_224"),
            Map.entry(0x00000019L, "CKM_DSA_SHA3_256"),
            Map.entry(0x0000001AL, "CKM_DSA_SHA3_384"),
            Map.entry(0x0000001BL, "CKM_DSA_SHA3_512"),
            Map.entry(0x00000048L, "CKM_SHA512_224"),
            Map.entry(0x00000049L, "CKM_SHA512_224_HMAC"),
            Map.entry(0x0000004AL, "CKM_SHA512_224_HMAC_GENERAL"),
            Map.entry(0x0000004BL, "CKM_SHA512_224_KEY_DERIVATION"),
            Map.entry(0x0000004CL, "CKM_SHA512_256"),
            Map.entry(0x0000004DL, "CKM_SHA512_256_HMAC"),
            Map.entry(0x0000004EL, "CKM_SHA512_256_HMAC_GENERAL"),
            Map.entry(0x0000004FL, "CKM_SHA512_256_KEY_DERIVATION"),
            Map.entry(0x00000050L, "CKM_SHA512_T"),
            Map.entry(0x00000051L, "CKM_SHA512_T_HMAC"),
            Map.entry(0x00000052L, "CKM_SHA512_T_HMAC_GENERAL"),
            Map.entry(0x00000053L, "CKM_SHA512_T_KEY_DERIVATION"),
            Map.entry(0x00000060L, "CKM_SHA3_256_RSA_PKCS"),
            Map.entry(0x00000061L, "CKM_SHA3_384_RSA_PKCS"),
            Map.entry(0x00000062L, "CKM_SHA3_512_RSA_PKCS"),
            Map.entry(0x00000063L, "CKM_SHA3_256_RSA_PKCS_PSS"),
            Map.entry(0x00000064L, "CKM_SHA3_384_RSA_PKCS_PSS"),
            Map.entry(0x00000065L, "CKM_SHA3_512_RSA_PKCS_PSS"),
            Map.entry(0x00000066L, "CKM_SHA3_224_RSA_PKCS"),
            Map.entry(0x00000067L, "CKM_SHA3_224_RSA_PKCS_PSS"),
            Map.entry(0x000002B0L, "CKM_SHA3_256"),
            Map.entry(0x000002B1L, "CKM_SHA3_256_HMAC"),
            Map.entry(0x000002B2L, "CKM_SHA3_256_HMAC_GENERAL"),
            Map.entry(0x000002B3L, "CKM_SHA3_256_KEY_GEN"),
            Map.entry(0x000002B5L, "CKM_SHA3_224"),
            Map.entry(0x000002B6L, "CKM_SHA3_224_HMAC"),
            Map.entry(0x000002B7L, "CKM_SHA3_224_HMAC_GENERAL"),
            Map.entry(0x000002B8L, "CKM_SHA3_224_KEY_GEN"),
            Map.entry(0x000002C0L, "CKM_SHA3_384"),
            Map.entry(0x000002C1L, "CKM_SHA3_384_HMAC"),
            Map.entry(0x000002C2L, "CKM_SHA3_384_HMAC_GENERAL"),
            Map.entry(0x000002C3L, "CKM_SHA3_384_KEY_GEN"),
            Map.entry(0x000002D0L, "CKM_SHA3_512"),
            Map.entry(0x000002D1L, "CKM_SHA3_512_HMAC"),
            Map.entry(0x000002D2L, "CKM_SHA3_512_HMAC_GENERAL"),
            Map.entry(0x000002D3L, "CKM_SHA3_512_KEY_GEN"),
            Map.entry(0x00000378L, "CKM_TLS_PRF"),
            Map.entry(0x00000397L, "CKM_SHA3_256_KEY_DERIVATION"),
            Map.entry(0x00000398L, "CKM_SHA3_224_KEY_DERIVATION"),
            Map.entry(0x00000399L, "CKM_SHA3_384_KEY_DERIVATION"),
            Map.entry(0x0000039AL, "CKM_SHA3_512_KEY_DERIVATION"),
            Map.entry(0x0000039BL, "CKM_SHAKE_128_KEY_DERIVATION"),
            Map.entry(0x0000039CL, "CKM_SHAKE_256_KEY_DERIVATION"),
            Map.entry(0x000003D6L, "CKM_TLS10_MAC_SERVER"),
            Map.entry(0x000003D7L, "CKM_TLS10_MAC_CLIENT"),
            Map.entry(0x000003D8L, "CKM_TLS12_MAC"),
            Map.entry(0x000003D9L, "CKM_TLS12_KDF"),
            Map.entry(0x000003E0L, "CKM_TLS12_MASTER_KEY_DERIVE"),
            Map.entry(0x000003E1L, "CKM_TLS12_KEY_AND_MAC_DERIVE"),
            Map.entry(0x000003E2L, "CKM_TLS12_MASTER_KEY_DERIVE_DH"),
            Map.entry(0x000003E3L, "CKM_TLS12_KEY_SAFE_DERIVE"),
            Map.entry(0x000003E4L, "CKM_TLS_MAC"),
            Map.entry(0x000003E5L, "CKM_TLS_KDF"),
            Map.entry(0x00000650L, "CKM_SEED_KEY_GEN"),
            Map.entry(0x00000651L, "CKM_SEED_ECB"),
            Map.entry(0x00000652L, "CKM_SEED_CBC"),
            Map.entry(0x00000653L, "CKM_SEED_MAC"),
            Map.entry(0x00000654L, "CKM_SEED_MAC_GENERAL"),
            Map.entry(0x00000655L, "CKM_SEED_CBC_PAD"),
            Map.entry(0x00000656L, "CKM_SEED_ECB_ENCRYPT_DATA"),
            Map.entry(0x00000657L, "CKM_SEED_CBC_ENCRYPT_DATA"),
            Map.entry(0x00001012L, "CKM_KEA_DERIVE"),
            Map.entry(0x0000140BL, "CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS"),
            Map.entry(0x00001053L, "CKM_ECDH_AES_KEY_WRAP"),
            Map.entry(0x00001054L, "CKM_RSA_AES_KEY_WRAP"),
            Map.entry(0x00001090L, "CKM_BLOWFISH_KEY_GEN"),
            Map.entry(0x00001091L, "CKM_BLOWFISH_CBC"),
            Map.entry(0x00001092L, "CKM_TWOFISH_KEY_GEN"),
            Map.entry(0x00001093L, "CKM_TWOFISH_CBC"),
            Map.entry(0x00001094L, "CKM_BLOWFISH_CBC_PAD"),
            Map.entry(0x00001095L, "CKM_TWOFISH_CBC_PAD"),
            Map.entry(0x00001200L, "CKM_GOSTR3410_KEY_PAIR_GEN"),
            Map.entry(0x00001201L, "CKM_GOSTR3410"),
            Map.entry(0x00001202L, "CKM_GOSTR3410_WITH_GOSTR3411"),
            Map.entry(0x00001203L, "CKM_GOSTR3410_KEY_WRAP"),
            Map.entry(0x00001204L, "CKM_GOSTR3410_DERIVE"),
            Map.entry(0x00001210L, "CKM_GOSTR3411"),
            Map.entry(0x00001211L, "CKM_GOSTR3411_HMAC"),
            Map.entry(0x00001220L, "CKM_GOST28147_KEY_GEN"),
            Map.entry(0x00001221L, "CKM_GOST28147_ECB"),
            Map.entry(0x00001222L, "CKM_GOST28147"),
            Map.entry(0x00001223L, "CKM_GOST28147_MAC"),
            Map.entry(0x00001224L, "CKM_GOST28147_KEY_WRAP"),
            Map.entry(0x00001225L, "CKM_CHACHA20_KEY_GEN"),
            Map.entry(0x00001226L, "CKM_CHACHA20"),
            Map.entry(0x00001227L, "CKM_POLY1305_KEY_GEN"),
            Map.entry(0x00001228L, "CKM_POLY1305"),
            Map.entry(0x00002003L, "CKM_DSA_PROBABILISTIC_PARAMETER_GEN"),
            Map.entry(0x00002004L, "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN"),
            Map.entry(0x00002005L, "CKM_DSA_FIPS_G_GEN"),
            Map.entry(0x00002104L, "CKM_AES_OFB"),
            Map.entry(0x00002105L, "CKM_AES_CFB64"),
            Map.entry(0x00002106L, "CKM_AES_CFB8"),
            Map.entry(0x00002107L, "CKM_AES_CFB128"),
            Map.entry(0x00002108L, "CKM_AES_CFB1"),
            Map.entry(0x0000210BL, "CKM_AES_KEY_WRAP_KWP"),
            Map.entry(0x0000210CL, "CKM_AES_KEY_WRAP_PKCS7"),
            Map.entry(0x00004001L, "CKM_RSA_PKCS_TPM_1_1"),
            Map.entry(0x00004002L, "CKM_RSA_PKCS_OAEP_TPM_1_1"),
            Map.entry(0x00004003L, "CKM_SHA_1_KEY_GEN"),
            Map.entry(0x00004004L, "CKM_SHA224_KEY_GEN"),
            Map.entry(0x00004005L, "CKM_SHA256_KEY_GEN"),
            Map.entry(0x00004006L, "CKM_SHA384_KEY_GEN"),
            Map.entry(0x00004007L, "CKM_SHA512_KEY_GEN"),
            Map.entry(0x00004008L, "CKM_SHA512_224_KEY_GEN"),
            Map.entry(0x00004009L, "CKM_SHA512_256_KEY_GEN"),
            Map.entry(0x0000400AL, "CKM_SHA512_T_KEY_GEN"),
            Map.entry(0x0000400BL, "CKM_NULL"),
            Map.entry(0x0000400CL, "CKM_BLAKE2B_160"),
            Map.entry(0x0000400DL, "CKM_BLAKE2B_160_HMAC"),
            Map.entry(0x0000400EL, "CKM_BLAKE2B_160_HMAC_GENERAL"),
            Map.entry(0x0000400FL, "CKM_BLAKE2B_160_KEY_DERIVE"),
            Map.entry(0x00004010L, "CKM_BLAKE2B_160_KEY_GEN"),
            Map.entry(0x00004011L, "CKM_BLAKE2B_256"),
            Map.entry(0x00004012L, "CKM_BLAKE2B_256_HMAC"),
            Map.entry(0x00004013L, "CKM_BLAKE2B_256_HMAC_GENERAL"),
            Map.entry(0x00004014L, "CKM_BLAKE2B_256_KEY_DERIVE"),
            Map.entry(0x00004015L, "CKM_BLAKE2B_256_KEY_GEN"),
            Map.entry(0x00004016L, "CKM_BLAKE2B_384"),
            Map.entry(0x00004017L, "CKM_BLAKE2B_384_HMAC"),
            Map.entry(0x00004018L, "CKM_BLAKE2B_384_HMAC_GENERAL"),
            Map.entry(0x00004019L, "CKM_BLAKE2B_384_KEY_DERIVE"),
            Map.entry(0x0000401AL, "CKM_BLAKE2B_384_KEY_GEN"),
            Map.entry(0x0000401BL, "CKM_BLAKE2B_512"),
            Map.entry(0x0000401CL, "CKM_BLAKE2B_512_HMAC"),
            Map.entry(0x0000401DL, "CKM_BLAKE2B_512_HMAC_GENERAL"),
            Map.entry(0x0000401EL, "CKM_BLAKE2B_512_KEY_DERIVE"),
            Map.entry(0x0000401FL, "CKM_BLAKE2B_512_KEY_GEN"),
            Map.entry(0x00004020L, "CKM_SALSA20"),
            Map.entry(0x00004021L, "CKM_CHACHA20_POLY1305"),
            Map.entry(0x00004022L, "CKM_SALSA20_POLY1305"),
            Map.entry(0x00004023L, "CKM_X3DH_INITIALIZE"),
            Map.entry(0x00004024L, "CKM_X3DH_RESPOND"),
            Map.entry(0x00004025L, "CKM_X2RATCHET_INITIALIZE"),
            Map.entry(0x00004026L, "CKM_X2RATCHET_RESPOND"),
            Map.entry(0x00004027L, "CKM_X2RATCHET_ENCRYPT"),
            Map.entry(0x00004028L, "CKM_X2RATCHET_DECRYPT"),
            Map.entry(0x00004029L, "CKM_XEDDSA"),
            Map.entry(0x0000402AL, "CKM_HKDF_DERIVE"),
            Map.entry(0x0000402BL, "CKM_HKDF_DATA"),
            Map.entry(0x0000402CL, "CKM_HKDF_KEY_GEN"),
            Map.entry(0x0000402DL, "CKM_SALSA20_KEY_GEN"),
            Map.entry(0x00001047L, "CKM_ECDSA_SHA3_224"),
            Map.entry(0x00001048L, "CKM_ECDSA_SHA3_256"),
            Map.entry(0x00001049L, "CKM_ECDSA_SHA3_384"),
            Map.entry(0x0000104AL, "CKM_ECDSA_SHA3_512"),
            Map.entry(0x00001056L, "CKM_EC_MONTGOMERY_KEY_PAIR_GEN"),
            Map.entry(0x0000402EL, "CKM_IKE2_PRF_PLUS_DERIVE"),
            Map.entry(0x0000402FL, "CKM_IKE_PRF_DERIVE"),
            Map.entry(0x00004030L, "CKM_IKE1_PRF_DERIVE"),
            Map.entry(0x00004031L, "CKM_IKE1_EXTENDED_DERIVE"),
            Map.entry(0x00004032L, "CKM_HSS_KEY_PAIR_GEN"),
            Map.entry(0x00004033L, "CKM_HSS"),
            Map.entry(0x00004034L, "CKM_XMSS_KEY_PAIR_GEN"),
            Map.entry(0x00004035L, "CKM_XMSSMT_KEY_PAIR_GEN"),
            Map.entry(0x00004036L, "CKM_XMSS"),
            Map.entry(0x00004037L, "CKM_XMSSMT"),
            Map.entry(0x00004038L, "CKM_ECDH_X_AES_KEY_WRAP"),
            Map.entry(0x00004039L, "CKM_ECDH_COF_AES_KEY_WRAP"),
            Map.entry(0x0000403AL, "CKM_PUB_KEY_FROM_PRIV_KEY"),
            Map.entry(0x0000000FL, "CKM_ML_KEM_KEY_PAIR_GEN"),
            Map.entry(0x00000017L, "CKM_ML_KEM"),
            Map.entry(0x0000001CL, "CKM_ML_DSA_KEY_PAIR_GEN"),
            Map.entry(0x0000001DL, "CKM_ML_DSA"),
            Map.entry(0x0000001FL, "CKM_HASH_ML_DSA"),
            Map.entry(0x00000023L, "CKM_HASH_ML_DSA_SHA224"),
            Map.entry(0x00000024L, "CKM_HASH_ML_DSA_SHA256"),
            Map.entry(0x00000025L, "CKM_HASH_ML_DSA_SHA384"),
            Map.entry(0x00000026L, "CKM_HASH_ML_DSA_SHA512"),
            Map.entry(0x00000027L, "CKM_HASH_ML_DSA_SHA3_224"),
            Map.entry(0x00000028L, "CKM_HASH_ML_DSA_SHA3_256"),
            Map.entry(0x00000029L, "CKM_HASH_ML_DSA_SHA3_384"),
            Map.entry(0x0000002AL, "CKM_HASH_ML_DSA_SHA3_512"),
            Map.entry(0x0000002BL, "CKM_HASH_ML_DSA_SHAKE128"),
            Map.entry(0x0000002CL, "CKM_HASH_ML_DSA_SHAKE256"),
            Map.entry(0x0000002DL, "CKM_SLH_DSA_KEY_PAIR_GEN"),
            Map.entry(0x0000002EL, "CKM_SLH_DSA"),
            Map.entry(0x00000034L, "CKM_HASH_SLH_DSA"),
            Map.entry(0x00000036L, "CKM_HASH_SLH_DSA_SHA224"),
            Map.entry(0x00000037L, "CKM_HASH_SLH_DSA_SHA256"),
            Map.entry(0x00000038L, "CKM_HASH_SLH_DSA_SHA384"),
            Map.entry(0x00000039L, "CKM_HASH_SLH_DSA_SHA512"),
            Map.entry(0x0000003AL, "CKM_HASH_SLH_DSA_SHA3_224"),
            Map.entry(0x0000003BL, "CKM_HASH_SLH_DSA_SHA3_256"),
            Map.entry(0x0000003CL, "CKM_HASH_SLH_DSA_SHA3_384"),
            Map.entry(0x0000003DL, "CKM_HASH_SLH_DSA_SHA3_512"),
            Map.entry(0x0000003EL, "CKM_HASH_SLH_DSA_SHAKE128"),
            Map.entry(0x0000003FL, "CKM_HASH_SLH_DSA_SHAKE256"),
            Map.entry(0x00000056L, "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE"),
            Map.entry(0x00000057L, "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH"));

    /** The specification name for {@code ckm}, or {@code null} if this table does not have one. */
    public static String get(long ckm) {
        return NAMES.get(ckm);
    }
}

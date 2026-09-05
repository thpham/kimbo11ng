# Adding an HSM vendor

Everything kimbo11ng needs to know about a vendor's post-quantum support lives in one table. This
is the checklist for filling one in, and the record of what was found for Thales Luna.

Adding a vendor should not require writing logic. If it does, the variation belongs in
`AlgorithmEntry`, not in an override on the profile.

## 1. Do you need a profile at all?

Probably not. `Pkcs11v32Profile` describes PKCS#11 v3.2 as written, and the capability probe added
in Phase 5 narrows that table to whatever the token actually advertises, with the matching `CKF_*`
flag. A token that implements the specification correctly and supports a subset of the algorithms
already works: the subset is discovered, not configured.

Write a profile when the token disagrees with v3.2 on a **constant** — a key type, a mechanism, the
parameter-set attribute, or how parameter sets are distinguished. Write one *anyway* when you want
the vendor's limits stated in code rather than discovered at runtime; that is why
`ThalesLunaProfile` exists even though Luna needs no remapping.

## 2. What to find out

For each algorithm the firmware supports:

| Field | Where it comes from | Notes |
| --- | --- | --- |
| `canonicalName` | EJBCA's `AlgorithmConstants.KEYALGORITHM_*` | Must match exactly; this is the string EJBCA asks for. |
| `family` | `PqcFamily` | ML-DSA, ML-KEM or SLH-DSA. |
| `ckkKeyType` | vendor docs / `C_GetAttributeValue` on a key | Vendor-defined values sit at or above `CKK_VENDOR_DEFINED` (0x80000000) and come back sign-extended — see `CkULong`. |
| `ckmKeyPairGen` | vendor docs / `C_GetMechanismList` | Separate from the signing mechanism on purpose: a vendor may shift one and not the other. |
| `ckmOperation` | vendor docs | Signing for ML-DSA and SLH-DSA, encapsulation for ML-KEM. |
| `ckpParameterSet` | vendor docs | `OptionalLong.empty()` if the vendor encodes the parameter set in the mechanism instead. Empty is fully supported, not a gap. |
| `oid` | FIPS 203/204/205 | Does **not** vary by vendor. Copy from `Pkcs11v32Profile`. |
| `publicKeyLength` | FIPS 203/204/205 | Does **not** vary by vendor. This is the check that catches a parameter set resolved wrongly before the wrong OID reaches a certificate. |
| `ops` | the algorithm | Signature families sign; ML-KEM must not, or a `Signature` service gets registered for a key-establishment algorithm. |

Then override `ckaParameterSet()` if the attribute id is not v3.2's `0x61D`.

## 3. The acceptance criterion

Subclass `ProfileConformanceKit` (in `src/test/java/ch/ithings/kimbo11ng/profile/`) and return the
profile. That is the whole test. The kit runs two kinds of check:

- **The table against itself and against FIPS** — public-key lengths, NIST OID arcs, unique names
  and OIDs, key-spec round trips, and that no two rows share a key type *and* a parameter set,
  since that pair is all reverse lookup has after a restart.
- **The table against a token** — `FakeToken.profile(...)` rebuilds the fake out of the profile's
  own constants, so the fake answers *only* that numbering, and a real `CryptoTokenImpl` is driven
  through generate, re-enumerate and sign for every row.

The second half is the one that matters. A vendor table that is perfectly self-consistent and wrong
about the hardware passes every static assertion there is.

`VendorTestProfileConformanceTest` is the proof that the design holds: `VendorTestProfile` uses
vendor-defined key types and mechanisms above `0x80000000`, shifts generation and signing
independently, and distinguishes parameter sets by mechanism rather than by a shared attribute. It
passes the kit unmodified.

## 4. Then run it against the hardware

`HsmConformanceIT` is the day-one script:

```bash
mvn verify -Pit \
  -Dkimbo11ng.it.lib=/usr/safenet/lunaclient/lib/libCryptoki2_64.so \
  -Dkimbo11ng.it.slot=0 \
  -Dkimbo11ng.it.pin=userpin
```

Without `kimbo11ng.it.lib` it skips. The same assertions run on every build against the fake as
`HsmContractFakeTest`, so the harness cannot rot between hardware sessions. What the hardware adds
is the answer to everything the fake can only assume — above all, whether a post-quantum signature
made on the HSM verifies with BouncyCastle.

## 5. Divergence matrix: which fake knob simulates which real behaviour

The fake exists to make hardware behaviours reproducible without hardware. Each knob below was
added because some token does the thing, and each is the reason a corresponding production path
exists.

| Fake knob | Real behaviour it stands in for | What breaks without the handling |
| --- | --- | --- |
| `profile(PqcMechanismProfile)` | A vendor that numbers post-quantum mechanisms and key types its own way. | The table is never exercised end to end; a wrong constant is only found on hardware. |
| `vendorMechanism(standard, vendor)` | A token that answers a standard operation under a vendor mechanism id. | Signing initialises with a mechanism the token rejects. |
| `hideMechanism(...)` | Firmware without an algorithm — **Luna 7.9.x has no SLH-DSA**. | Generation fails with `CKR_MECHANISM_INVALID` at CA-creation time instead of at init. |
| `underReportMechanism(ckm)` | A mechanism present but omitted from `C_GetMechanismList`, typically behind a policy. | Fail-fast refuses an algorithm the token can actually do, with no way out. |
| `mechanismFlags(ckm, flags)` | A mechanism listed but not usable for the operation wanted — present for verify, not for sign. | A presence-only probe registers a service that fails at first use. |
| `undescribableMechanism(ckm)` | `C_GetMechanismInfo` failing for a mechanism the list contains. | The probe aborts and the whole token looks unusable. |
| `failMechanismList(ckr)` | A token that declines to enumerate mechanisms at all. | Either a crash at init, or — worse — treating "unknown" as "unsupported" and taking a working HSM out of service. |
| `ecPointEncoding(RAW)` | Tokens that return `CKA_EC_POINT` as the bare point rather than DER-wrapped. Both are seen in the wild. | The public key is decoded from the wrong offset; measured at 23.2% failure before the length-based decoder. |
| `omitAttribute(cka)` | A token that does not implement `CKA_PARAMETER_SET` (pre-v3.2 firmware). | The parameter set is guessed, and the certificate names the wrong algorithm. |
| `emptyAttribute(cka)` | An attribute present but zero-length. | A length-based decoder reads past the end of the buffer. |
| `readOnlyAttributes(...)` | An HSM policy that refuses `C_SetAttributeValue` on token objects. | `CKA_ID` backfill on a legacy key fails the whole operation instead of degrading to label-only. |
| `pqcSpkiOid(oid)` | A token that returns `CKA_VALUE` already wrapped in a `SubjectPublicKeyInfo`, sometimes under a pre-standard OID. | The raw bytes get wrapped twice, or a draft-era OID is accepted silently. |
| `killSessionsAfter(n)` | A session dropped mid-operation — a network HSM's connection, or an idle timeout. | The cached handle is stale forever and every subsequent signature fails. |
| `failNextWith(ckr)` | Any transient `CKR_*`. Used to drive the two-tier recovery: reopen-and-retry versus go-offline-and-let-EJBCA-reactivate. | A recoverable blip takes the CA offline, or an unrecoverable one is retried forever. |

## Thales Luna — findings

Firmware **7.9.0** or later, Luna HSM Client **10.9.0** or later.

**Luna needs no constant remapping.** It implements post-quantum keys with the standard PKCS#11
v3.2 numbering:

| | Value | Same as v3.2? |
| --- | --- | --- |
| `CKK_ML_DSA` | `0x4A` | yes |
| `CKK_ML_KEM` | `0x49` | yes |
| `CKM_ML_DSA_KEY_PAIR_GEN` | `0x1C` | yes |
| `CKM_ML_DSA` | `0x1D` | yes |
| `CKM_ML_KEM_KEY_PAIR_GEN` | `0x0F` | yes |
| `CKM_ML_KEM` | `0x17` | yes |
| `CKA_PARAMETER_SET` | `0x61D`, with `CKP_*` 1/2/3 per family | yes |

So a Luna works correctly under the default profile: the probe keeps the six ML-DSA and ML-KEM rows
and excludes the twelve SLH-DSA ones. `ThalesLunaProfile` records the same six rows explicitly, so
that the absence of SLH-DSA is a stated fact rather than a runtime discovery. It is selected with
`kimbo11ng.pqc.profile=thales-luna`; auto-detection will not choose it over `pkcs11v32`, which is
correct — the two agree on every algorithm they share.

**Limits found (7.9.x):**

- **No SLH-DSA**, and no published roadmap for it.
- **ML-DSA private keys cannot be wrapped or unwrapped.** kimbo11ng never wraps a private key, so
  this does not affect certificate signing.
- The one vendor mechanism is `CKM_EXTMU_ML_DSA` (`0x80000175`), for external-mu signing.
  kimbo11ng does not use it.
- Luna's ML-KEM proprietary surface is the `CA_EncapsulateKey` / `CA_DecapsulateKey` **functions**,
  not different mechanism constants. kimbo11ng does not encapsulate — ML-KEM here is generation and
  enumeration only, because EJBCA CE has no key-encapsulation path.

Sources: Luna HSM Firmware 7.9.0 Customer Release Notes; the ML-DSA and ML-KEM programming guides
and the "Post Quantum Algorithms" page in the Luna SDK documentation at `thalesdocs.com`.

**Not yet verified against hardware.** Everything above is from vendor documentation. Running
`HsmConformanceIT` against a Luna is what turns it into a fact, and the failure will name which row
is wrong.

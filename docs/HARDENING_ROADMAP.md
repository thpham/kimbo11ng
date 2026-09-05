# Hardening the PKCS#11 NG foundation

Nine dependency-ordered phases taking the EJBCA PQC crypto token from a single-session SoftHSM
prototype to a thread-safe, fail-fast, vendor-agnostic base that `ThalesLunaProfile` can drop into
as a table of constants.

|            |                                                      |
| ---------- | ---------------------------------------------------- |
| **Target** | EJBCA CE 9.3.7, JackNJI11 1.3.1, BouncyCastle 1.80.2 |
| **Status** | Phase 0 complete. Phases 1–8 not started.            |

> This plan was drafted, then adversarially reviewed against the actual EJBCA bytecode in
> `deps/ejbca/*.jar`. The review changed it materially — see [Plan revisions](#plan-revisions).

---

## Why

The audit found the token unsafe as a foundation for a real HSM:

- **One shared PKCS#11 session for all threads.** `C_FindObjectsInit`/`C_SignInit` are per-session
  state machines; concurrent CA signing and key enumeration interleave into `CKR_OPERATION_ACTIVE`.
- **Session-scoped object handles cached forever.** A network Luna drops sessions routinely; every
  cached handle then yields `CKR_OBJECT_HANDLE_INVALID` with no recovery path.
- **The vendor-profile abstraction is bypassed where it matters.** `Kimbo11ngSignatureSpi` hardcodes
  `0x1D`/`0x2E`; `enumerateKeys` hardcodes `0x4A`/`0x49`/`0x4B`. Five of fourteen profile methods are
  never called from `src/main` at all.
- **Silent parameter-set defaults.** An unreadable `CKA_PARAMETER_SET` makes every ML-DSA key claim
  the ML-DSA-65 OID, which can put a mislabelled `AlgorithmIdentifier` into an issued certificate.
- **An EC point decoder measured at 23.2% failure** on raw `CKA_EC_POINT` (2,000 real P-256 keys).
  SoftHSM DER-wraps, so the suite never sees it.
- **A fat JAR shipping 6,032 BouncyCastle classes** into the same EAR classloader as EJBCA's own.

## Target architecture

| Layer  | Component           | Owns                                                                                                                        |
| ------ | ------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **L0** | `Pkcs11Module`      | One refcounted instance per canonical library path; `C_Initialize`, slot and mechanism caches.                              |
| **L1** | `SessionPool`       | Per (module, slot): session lifecycle, login state, borrow leases. A lease is the unit of mutual exclusion.                 |
| **L2** | `P11KeyRef`         | Durable key identity (`CKA_ID`) and handle re-resolution.                                                                   |
| **L3** | `AlgorithmRegistry` | One immutable row per algorithm: CKK, CKM keygen, CKM sign, CKP, NIST OID, FIPS key length. Every constant in the codebase. |
| **L4** | `PublicKeyReader`   | Per-family decoding driven by the registry row; EC point decoding, SPKI wrapping, length cross-validation.                  |
| **L5** | `TokenCapabilities` | Probe via `C_GetMechanismList` + `C_GetMechanismInfo` flags; the effective supported set, and fail-fast at init.            |
| **L6** | JCA + CryptoToken   | Provider, KeyStore, Signature, KeyPairGenerator SPIs and the EJBCA bridge. Owns nothing cryptographic.                      |

---

## Plan revisions

Eleven corrections from reading the EJBCA bytecode. The five that changed the design:

| Finding                                                                                                                                                                             | Correction                                                                                                                                                                                                                            |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BaseCryptoToken.setProvider` calls `Security.addProvider` itself and throws if the name will not resolve; `KeyTools` and `SignWithWorkingAlgorithm` look providers up **by name**. | Global registration **stays**. The real bug is the inverse: after `reset()` the old instance remains registered and EJBCA signs through a zombie. Fix is a stable **facade per (lib, slot)** over an `AtomicReference<TokenRuntime>`. |
| `AlgorithmTools.getSignatureAlgorithms` uses `instanceof MLDSAKey`/`SLHDSAKey` and returns `emptyList()` otherwise.                                                                 | **Delete `RawPqcPublicKey`.** An opaque PQC key can never be signed with, so the fallback is a dead end.                                                                                                                              |
| Our slot-list factory is priority 2 vs SunP11's 1, so EJBCA's classic PKCS11CryptoToken uses it for **every** library — SunPKCS11 is a silent co-user.                              | **Never call `C_Finalize`** in normal operation.                                                                                                                                                                                      |
| `C_Login` on an already-logged-in token returns `CKR_USER_ALREADY_LOGGED_IN` without checking the PIN.                                                                              | No implementation can re-validate. The fix is a **truthful `deactivate()`**, not a re-check. The "no PIN in a heap dump" gate is unachievable — `BaseCryptoToken` holds `mAuthCode` itself.                                           |
| `testKeyPair` branches on the key-usage set containing `0x105` (decrypt) or `0x108` (sign).                                                                                         | `getKeyUsagesFromKey` is **load-bearing**, not a nicety: an ML-DSA key reporting an empty set gets an RSA-style encryption test.                                                                                                      |

Also: phases reordered so the **algorithm registry comes before** the session pool (it defines the
types the later phases consume and is the strategic Luna enabler); `C_Verify` dropped from scope
(EJBCA verifies with BC, never asking our provider); and the "EJBCA's BC may be too old" risk
downgraded — `x509-common-util` links against `MLDSAKey`, and the container ships **1.80.2**.

---

## Phase 0 — Safety net and build hardening ✅

No behaviour change. Made refactoring safe and the artifact safe to deploy.

| Task                             | Result                                                                                                                                                        |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0.1 `NativeProviderFactory` seam | `CryptokiDevice` / `SlotListWrapper` accept an injected provider; default is `JNA::new`.                                                                      |
| 0.2 `FakeToken`                  | In-memory PKCS#11 v3.2 token at the `NativeProvider` seam. Real BC keys for RSA/EC; exact FIPS-length material for PQC. Enforces per-session operation state. |
| 0.3 Fault knobs                  | `ecPointEncoding(RAW\|DER)`, `omitAttribute`, `readOnlyAttributes`, `vendorMechanism`, `killSessionsAfter`, `failNextWith`.                                   |
| 0.4 Measure EJBCA's BC           | **1.80.2** (`bcprov/bcpkix/bctls/bcutil-jdk18on-1.80.2.jar`), available on Maven Central.                                                                     |
| 0.5 Thin the artifact            | **6,369 files / 19.7 MB → 97 files / 184 KB.** `ArtifactContentsIT` asserts it ships only our own classes.                                                    |
| 0.6 Build gates                  | `release=17`, `-Xlint:all -Werror` (zero warnings), enforcer, duplicate-finder, SpotBugs + find-sec-bugs, JaCoCo floor, reproducible timestamps.              |
| 0.7 CI gates PRs                 | `just build` now runs `mvn clean verify`, so every gate runs on pull requests. None of it needs Docker.                                                       |
| 0.8 Characterization tests       | `FakeTokenTest` (protocol + knobs), `CryptokiDeviceTest` (generate → read public key → sign via JCA → verify with BC).                                        |

**Two duplicate-dependency defects found and fixed**, both the same class of bug as the
BouncyCastle one and both invisible before the artifact gate existed:

- `bcprov` was `compile` at **1.80** while the container ships **1.80.2**.
- `jna` was `compile` at **5.13.0** while the container ships **5.12.1**. Two JNA copies in one
  classloader fail with _"native library already loaded in another classloader"_.

Both are now `provided` at the container's exact version.

**Measured deltas**

|                                                                  | Before                | After             |
| ---------------------------------------------------------------- | --------------------- | ----------------- |
| Artifact                                                         | 6,369 files / 19.7 MB | 97 files / 184 KB |
| Unit tests                                                       | 117                   | 141               |
| Line coverage                                                    | 0.09                  | 0.25              |
| Branch coverage                                                  | 0.25                  | 0.30              |
| `CryptokiDevice` / `Kimbo11ngProvider` / `Kimbo11ngSignatureSpi` | 0% / 0% / 0%          | 58% / 90% / 72%   |

Two debt registers were created, and both must shrink to empty:
[`src/spotbugs/exclude.xml`](../src/spotbugs/exclude.xml) — every entry names the phase that removes
it — and the `@SuppressWarnings` sites in `Kimbo11ngProvider`, `Pkcs11NgCryptoToken` and
`CryptoTokenImpl`, each carrying a `TODO(phase-N)`.

---

## Phase 1 — Algorithm registry and provider facade

_The Luna enabler. Needs Phase 0._

- **1.1** `AlgorithmEntry` record: canonical name, family, `ckkKeyType`, `ckmKeyPairGen`, `ckmOperation`,
  `OptionalLong ckpParameterSet`, NIST OID, FIPS public-key length, ops, JCA names.
- **1.2** `AbstractTableProfile` owns all lookup; a profile supplies only `entries()` and
  `ckaParameterSet()`. **Nullable CKP matters** — Luna may encode the variant in the mechanism.
- **1.3** `KeyTemplates`: one builder for all templates (replaces five copies), adds `CKA_ID`, merges
  `KeyGenParams` attribute maps then `kimbo11ng.attr.*` overrides.
- **1.4** `TokenRuntime` + provider facade per (lib, slot) over an `AtomicReference`.
- **1.5** Table-driven `Provider.Service` registration; delete the 15 static SPI subclasses; add
  RSA-PSS (`SHA{256,384,512}withRSAandMGF1`).
- **1.6** `enumerateKeys` uses `lookupByKeyType`; **delete `RawPqcPublicKey`**.
- **1.7** `ProfileResolver` → `ServiceLoader`; drop `Class.forName` on config strings.

**Gate** — table-completeness test over every `AlgorithmConstants.KEYALGORITHM_*` we advertise · a
fake profile with shifted CKMs signs and enumerates correctly · provider identity stable across 10
init/reset cycles.

## Phase 2 — Module lifecycle and session pool

- **2.1** `Pkcs11Module` per canonical path, refcounted; `C_Initialize` once; caches that never cache
  failures. **No `C_Finalize`** except an optional shutdown hook.
- **2.2** One initialization path — `SlotListWrapper` and `resolveSlotId` both via the registry.
- **2.3** `SessionPool`: `AutoCloseable` leases, bounded, borrow timeout, `min=1` so login state
  survives eviction.
- **2.4** Every call inside a lease; delete `synchronized (device)`; maps → `ConcurrentHashMap`.
- **2.5** `Pkcs11Errors` keyed on `CKRException.getCKR()`, always preserving the cause.
- **2.6** Truthful `deactivate()`: drain, logout, close, clear, `setKeyStore(null)`.

**Gate** — 32-thread mix: 0 `CKR_OPERATION_ACTIVE` · `C_Initialize` once for N devices · `C_Finalize`
never · transient slot-list failure recovers.

## Phase 3 — Durable key identity and recovery

- **3.1** `P11KeyRef` (`CKA_ID` = 16 random bytes set **in the template**, no post-generation
  mutation); label fallback and optional backfill for legacy keys.
- **3.2** Two-tier recovery: reopen/re-resolve/retry once, else go offline so EJBCA re-activates.
- **3.3** Duplicate-alias rejection; delete scoped by `CKA_ID`, including certificates.
- **3.4** `engineGetCertificate` parses `CKA_VALUE` or returns null without an HSM round trip.

**Gate** — injected session death mid-sign still returns a valid signature · legacy key resolves and
backfills, and still resolves when `CKA_ID` is read-only · existing demo keys keep working.

## Phase 4 — Public-key construction correctness

- **4.1** EC: accept the OCTET STRING unwrap only if it consumes the whole buffer; validate against
  the curve's field size; bounds-check.
- **4.2/4.3** Prefer the caller's fully-qualified keySpec; cross-validate `CKA_VALUE.length` against
  the registry (ML-DSA 1312/1952/2592, ML-KEM 800/1184/1568). **No default branches.**
- **4.4** SPKI detection by full parse-and-consume.
- **4.5** Probe the container's BC for PQC `KeyFactory` support; WARN, never a silent debug line.

**Gate** — RAW and DER EC matrix both at 0% failure · a missing `CKA_PARAMETER_SET` on an ML-DSA-44
key yields a named error, never an ML-DSA-65 OID.

## Phase 5 — Capability probing and fail-fast

- **5.1** `TokenCapabilities` checking `CKF_SIGN` / `CKF_GENERATE_KEY_PAIR`, not mere presence.
- **5.2** Intersect the table with the token at init; log it; fail fast naming the missing CKM.
- **5.3** Profile auto-detection by probe score.
- **5.4** Reject key specs outside the effective set.

## Phase 6 — Secrets, key usages, log hygiene

- **6.1** PIN via `CharsetEncoder`, zeroed in `finally`; never a `String`.
- **6.2** `getKeyUsagesFromKey` returns the true CKA constants (`0x105`/`0x108` drive `testKeyPair`).
- **6.3** Log redaction via `LogRedactionUtils`; per-keygen INFO → DEBUG.

## Phase 7 — Coverage that matches the claims

- Full algorithm matrix on the fake (3 ML-DSA, 3 ML-KEM, 12 SLH-DSA, RSA 2048/3072/4096, all curves).
- Concurrency suite, 100 consecutive green runs.
- IT: add ML-DSA-44 and ML-DSA-87 root CAs — either would have caught the parameter-set default.
- README reconciled: ML-KEM is generation/enumeration only (no KEM SPI).

## Phase 8 — ThalesLunaProfile foundation

- **8.1** `ProfileConformanceKit`: an abstract test any profile must pass.
- **8.2** `ThalesLunaProfile` as a table stub plus a checklist of the vendor constants needed.
- **8.3** `HsmConformanceIT` (tag `hsm`) against any real library via `-Dkimbo11ng.it.lib`.
- **8.4** Documented map from fake knobs to the Luna behaviours they simulate.

---

## Verification

Per phase: `mvn verify` (unit + `ArtifactContentsIT`, no Docker) then `just ci` (docker-build, up,
create-token, `mvn verify -Pit`). Both green before a phase merges.

Additionally — after Phase 2, `just deploy` into a running stack and `just create-token` twice, to
exercise the facade swap; after Phase 3, restart with keys generated by the _old_ JAR present, to
prove the migration path.

## Standing rules

- Every behaviour change ships behind a kill-switch property; existing EJBCA-written property names
  are unchanged.
- No `C_Finalize` in normal operation. No silent parameter-set or OID defaults. No `catch (Exception)`
  at an HSM boundary without mapping through `Pkcs11Errors`.
- JCA algorithm names come from `AlgorithmConstants`, never hand-typed.
- FQNs pinned by EJBCA stay put: `org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken`
  (a string in `CryptoTokenFactory`) and
  `com.keyfactor.util.keys.token.pkcs11.JackNJI11SlotListWrapperFactory` (`META-INF/services`).

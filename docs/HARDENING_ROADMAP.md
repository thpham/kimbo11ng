# Hardening the PKCS#11 NG foundation

Nine dependency-ordered phases taking the EJBCA PQC crypto token from a single-session SoftHSM
prototype to a thread-safe, fail-fast, vendor-agnostic base that `ThalesLunaProfile` can drop into
as a table of constants.

|            |                                                      |
| ---------- | ---------------------------------------------------- |
| **Target** | EJBCA CE 9.3.7, JackNJI11 1.3.1, BouncyCastle 1.80.2 |
| **Status** | Phases 0–7 complete. Phase 8 not started.           |

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
| `testKeyPair` branches on the key-usage set containing `0x105` (decrypt) or `0x108` (sign).                                                                                         | Re-read in phase 6 and **restated**: the predicate is `contains(261) && !contains(264)`, so an empty set selects the *signing* test, not an encryption test. The real consumer that constrains the design is `getKeyUsageStringForKeyPairInfo`, which compares the set for equality. See [Phase 6](#phase-6--secrets-key-usages-log-hygiene-). |

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

## Phase 1 — Algorithm registry and provider facade ✅

_The Luna enabler. Needs Phase 0._

**Landed.** 149 unit tests and the 18-test `EjbcaContainerIT` green; coverage floor raised from
LINE 0.25 / BRANCH 0.30 to 0.45 / 0.35.

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

**Gate** — met, except as noted in 1.5 below.

### What the implementation changed, and why

Four things came out of building this that the plan did not anticipate. Each is a decision, not an
oversight.

**RSA-PSS was not implemented (1.5).** Everything else in 1.5 landed: the 15 static SPI subclasses
are gone and services are registered from the profile table. PSS needs a correctly encoded
`CK_RSA_PKCS_PSS_PARAMS`, and the only way to know an encoding is right is to sign with it and have
a relying party verify — which needs IT coverage that does not exist yet. Untested signature code in
a CA is worse than absent, so `SHA{256,384,512}withRSAandMGF1` is deferred with its IT to phase 7.
Nothing regressed: PSS was not supported before either.

**`CkULong` — vendor constants read back negative.** JackNJI11 1.3.1 decodes `CK_ULONG` with
`int`-typed shifts, so every value with bit 31 set is sign-extended (measured: `0x80000100` reads
back as `0xFFFFFFFF80000100`, and anything ≥ 2³² truncates to zero). Nothing has noticed because every
*standard* CKK/CKM/CKA is below `0x80000000` — but `CKK_VENDOR_DEFINED`, `CKM_VENDOR_DEFINED` and
`CKA_VENDOR_DEFINED` are all exactly `0x80000000`, so **every** vendor-defined constant is affected.
A Luna table written with the vendor's own constants would never match what the token reports, and
every such key would be skipped at enumeration as "profile does not describe CKK". Fixed at the read
boundary before the first vendor table exists rather than after.

**Public-key length validation was pulled forward from 4.2.** Measured against the deployed
BouncyCastle: 1312 bytes of ML-DSA-44 material presented under the ML-DSA-87 OID is accepted without
complaint, and the resulting key reports itself as ML-DSA-87. EJBCA would write that OID into the
certificate. Since no component downstream catches this, the check cannot wait for phase 4 — it is
the only defence against the exact failure this whole review was about. Phase 4 still owns the
`kimbo11ng.strict.publickey` policy split and the EC point decoder.

**The keystore cache refresh had to stay.** `BaseCryptoToken.setKeyStore` wraps our KeyStore in a
`CachingKeyStoreWrapper` whose alias list is built once. EJBCA populates it through
`KeyStore.setKeyEntry`, which a key generated on the token never goes through, so `ca init` fails
with "No key with alias" for a key that demonstrably exists. Dropping the phase-0 cache-bust broke
the IT; it is restored, still marked `TODO(phase-3)`, because resolving keys by `CKA_ID` on demand
is what actually removes the need for it.

**One template bug the fake had been hiding.** `CKA_EC_PARAMS` was being sent on the EC *private*
key generation template. For `CKM_EC_KEY_PAIR_GEN` the curve is an input to the public template
only and the token derives the private copy, so this sets a read-only attribute: SoftHSMv3 answers
`CKR_ATTRIBUTE_READ_ONLY` and fails the whole generation. The fake accepted it, so the unit suite
passed a template no real token would take. The fake now enforces the rule.

## Phase 2 — Module lifecycle and session pool ✅

**Landed.** 208 unit tests and the 18-test `EjbcaContainerIT` green; coverage floor raised from
LINE 0.45 / BRANCH 0.35 to 0.66 / 0.55. `CryptokiDevice` is gone, replaced by
`Pkcs11Module` + `SessionPool` + `P11Slot`; no `synchronized (device)` remains anywhere.

- **2.1** `Pkcs11Module` per canonical path, refcounted; `C_Initialize` once; caches that never cache
  failures. **No `C_Finalize`** except an optional shutdown hook.
- **2.2** One initialization path — `SlotListWrapper` and `resolveSlotId` both via the registry.
- **2.3** `SessionPool`: `AutoCloseable` leases, bounded, borrow timeout, `min=1` so login state
  survives eviction.
- **2.4** Every call inside a lease; delete `synchronized (device)`; maps → `ConcurrentHashMap`.
- **2.5** `Pkcs11Errors` keyed on `CKRException.getCKR()`, always preserving the cause.
- **2.6** Truthful `deactivate()`: drain, logout, close, clear, `setKeyStore(null)`.

**Gate** — met. `ConcurrentTokenAccessTest` runs 32 threads signing, enumerating and generating
against a 6-session pool with zero `CKR_OPERATION_ACTIVE` and no leaked leases;
`Pkcs11ModuleRegistryTest` pins one `C_Initialize` per library (including under a 16-thread race),
zero `C_Finalize`, and slot-list failures that recover on the next call.

### What the implementation changed, and why

**`kimbo11ng.sessions.min` was dropped.** The plan specified it so the pool could not evict itself
to zero and lose the token's login state. The pool has no eviction policy at all — a session it
opens is kept until it breaks or the pool drains — so the property would have guarded against
nothing. A knob that changes no behaviour is worse than no knob, because someone will eventually
set it and believe it did something. The invariant it was meant to protect is now structural and
asserted in `SessionPoolTest`. `kimbo11ng.sessions.max` (8) ships as planned, plus
`kimbo11ng.sessions.borrowTimeoutSeconds` (30), which the plan's "borrow timeout" required but did
not name.

**PIN handling was pulled forward from 6.1.** The pool owns `C_Login` now, so the choice was to
write `new String(pin).getBytes(UTF_8)` into new code and undo it two phases later, or do it once.
`Pins.encodeUtf8` encodes through a `CharBuffer`, never constructs a String, zeroes its
intermediate buffer, and rejects rather than substitutes an unencodable character — a `?` silently
replacing a character sends the token a different secret than the operator typed and reports the
result as a wrong PIN.

**A slot has to be reopenable after `reset()`.** Caught by a test, not by review: `P11Slot` first
cached its `SessionPool` in a field, and `reset()` drains that pool and drops it from the module.
EJBCA calls `reset()` and then `activate()` on the same crypto token object, so the cached
reference left the token permanently offline until the application server restarted. The pool is
now looked up per use.

**Two more gaps in the fake, both found by tests that should have failed and did not.** The fake
did not apply fault injection to `C_OpenSession`, `C_GetSlotList` or `C_GetTokenInfo` — exactly the
three calls where a missing token or a disconnected HSM client first reports itself, so none of
those scenarios could be simulated at all. All three are gated now.

## Phase 3 — Durable key identity and recovery ✅

**Landed.** 228 unit tests and the 18-test `EjbcaContainerIT` green; coverage floor raised from
LINE 0.66 / BRANCH 0.55 to 0.69 / 0.58. A key is now found by `CKA_ID` rather than remembered by
handle, and a dropped session no longer costs a signature.

- **3.1** `P11KeyRef` (`CKA_ID` = 16 random bytes set **in the template**, no post-generation
  mutation); label fallback and optional backfill for legacy keys.
- **3.2** Two-tier recovery: reopen/re-resolve/retry once, else go offline so EJBCA re-activates.
- **3.3** Duplicate-alias rejection; delete scoped by `CKA_ID`, including certificates.
- **3.4** `engineGetCertificate` parses `CKA_VALUE` or returns null without an HSM round trip.

**Gate** — met, and one item was verified against a real EJBCA rather than only the fake: see
"the migration test earned its place" below.

### What the implementation changed, and why

**The plan's reason for removing the keystore cache-bust was wrong.** It said resolving keys by
`CKA_ID` would remove the need. It does not: `CachingKeyStoreWrapper` caches the *alias list* in a
`HashMap` built once at construction, updated only through `setKeyEntry` and `deleteEntry`. That is
on EJBCA's side and has nothing to do with how we find a key. The obvious replacement does not work
either — `KeyStore.setKeyEntry` refuses a `PrivateKey` without a certificate chain, and EJBCA's own
`KeyStoreTools` only gets around that by minting a self-signed placeholder certificate with the new
key, which an ML-KEM key cannot do because it cannot sign. The rebuild stays, now documented with
that reasoning instead of a TODO that would never have come true. It is cheap because
`engineGetCertificate` answers from memory.

**Certificate reading was dropped from 3.4.** The plan offered a choice — parse `CKA_VALUE` into an
`X509Certificate`, or return null without a round trip — and the second is right here. EJBCA keeps
certificates in its database and never looks for one on the token; a chain could not be
reconstructed anyway, since PKCS#11 stores certificates as unordered independent objects. Worse,
EJBCA rebuilds its keystore cache after every key generation and that rebuild asks for each alias's
certificate, so reading the token here would make every keygen cost one search per key already on
it. Deletion still removes `CKO_CERTIFICATE` objects, which is cheap and correct.

**The migration test earned its place.** Running the plan's own verification step — generate keys
with the *original* build, upgrade the JAR, restart — found a bug no unit test had: the backfill
wrote `CKA_ID` onto the private key and not its public half. Since the pair is looked up by id from
that moment on, the public key became unfindable, the alias loaded with no public key, and EJBCA
reported both keys as not existing. Both halves are written now, `findAll` takes an explicit
label-fallback flag (on for pairing, off for deletion, where falling back would destroy same-label
objects), and two regression tests pin it. Verified end to end afterwards: keys created by the
original build enumerate, get backfilled and sign after an in-place upgrade.

**One correction to something stated earlier in this document's history:** `CachingKeyStoreWrapper.getKeyStore()`
is deprecated. An initial bytecode check suggested otherwise; the compiler settled it under
`-Werror`. The suppression is back, with a note on what to do if EJBCA removes the method.

**Gate detail** — injected session death mid-sign still returns a valid signature · legacy key resolves and
backfills, and still resolves when `CKA_ID` is read-only · existing demo keys keep working.

## Phase 4 — Public-key construction correctness ✅

- **4.1** EC: accept the OCTET STRING unwrap only if it consumes the whole buffer; validate against
  the curve's field size; bounds-check.
- **4.2/4.3** Prefer the caller's fully-qualified keySpec; cross-validate `CKA_VALUE.length` against
  the registry (ML-DSA 1312/1952/2592, ML-KEM 800/1184/1568). **No default branches.**
- **4.4** SPKI detection by full parse-and-consume.
- **4.5** Probe the container's BC for PQC `KeyFactory` support; WARN, never a silent debug line.

**Gate** — met. The matrix runs 250 keys per curve per encoding across P-256/P-384/P-521 plus
secp256k1 and three Brainpool curves, at 0% failure. 250 rather than 2,000 because the old
heuristic failed with p ≈ 0.25 per key, so 250 leaves it about a 10^-31 chance of passing by luck;
2,000 would cost eight times the runtime to reach the same conclusion.

### What the implementation changed, and why

**The failure rate was re-measured, and its nature had been described wrongly.** Running the old
heuristic against 2,000 freshly generated P-256 keys: 490 failed, 24.5% — consistent with the
recorded 23.2% and with the 64/256 the arithmetic predicts. But **every one of the 490 threw**;
none silently produced a wrong point. The earlier description of this defect, in this document and
in the code comments, said it "returns a truncated point" that a caller would then use. In practice
it does not: the truncated buffer is not a valid point length, so BouncyCastle rejects it. What an
operator actually saw was a quarter of their EC keys refusing to load. The silent variant is
possible — it needs the truncated content to be a valid encoding in its own right, which for a
65-byte input means X[0] = 33 and X[1] ∈ {2, 3}, about 1 in 33,000 — but it was not what was
happening. The severity is unchanged; the diagnosis is now accurate.

**`CKA_EC_PARAMS` explicit parameters are now handled.** The old code cast the parsed object
straight to an `ASN1ObjectIdentifier`, so a token reporting explicit curve parameters — which some
HSMs do for curves they have no OID for — failed with a `ClassCastException` rather than anything
diagnosable. Both arms of the X9.62 CHOICE are read, and `implicitlyCA` is refused by name.

**Points are now checked to be on the curve.** BouncyCastle does not call `ECPoint.isValid()` for
you. A point off the curve is the classic invalid-curve attack input, and the token's word for it
was previously taken.

**Enumeration defaults to lenient, generation is always strict.** `kimbo11ng.strict.publickey`
governs only the reading of keys that already exist. The case it relaxes is real: a token from the
NIST draft era labels an ML-DSA key with a pre-standard OID, and refusing to start a CA over a
naming disagreement on a key whose material is correct is the wrong trade. The length check runs
under both policies, so a key of the wrong parameter set is still refused — that is the check that
keeps a wrong OID out of a certificate.

**Gate detail** — RAW and DER EC matrix both at 0% failure · a missing `CKA_PARAMETER_SET` on an ML-DSA-44
key yields a named error, never an ML-DSA-65 OID.

## Phase 5 — Capability probing and fail-fast ✅

- **5.1** `TokenCapabilities` checking `CKF_SIGN` / `CKF_GENERATE_KEY_PAIR`, not mere presence.
- **5.2** Intersect the table with the token at init; log it; fail fast naming the missing CKM.
- **5.3** Profile auto-detection by probe score.
- **5.4** Reject key specs outside the effective set.

**Gate** — met. Against the live SoftHSMv3: auto-detection selects `pkcs11v32` on its own
("18 of its 18 algorithms are advertised by the token") and the effective table is logged at init.
Against the fake: a token missing `CKM_ML_DSA_KEY_PAIR_GEN` excludes exactly the three ML-DSA rows
and keeps the other fifteen; a synthetic vendor profile discovered through `META-INF/services` is
auto-selected for a token that answers only vendor mechanisms.

### What the implementation changed, and why

**The probe reads flags, and the flags matter.** Measured on SoftHSMv3, `CKM_ML_KEM` (0x17) is
advertised with `0x30000000` — encapsulate and decapsulate — and no `CKF_SIGN`. A probe testing
presence alone would have called that key signable. Conversely `CKM_EC_KEY_PAIR_GEN` reports
`0x01910000`, generation plus EC curve flags, and `CKM_ML_DSA` reports `0x2800`, sign plus verify.
The min/max key sizes are no use at all: the same token gives `128`–`256` for `CKM_ML_DSA`, which
are security strengths, not key lengths. Only the mechanism and its flags are read.

**Init does not fail; generation does.** The plan had `kimbo11ng.probe.failFast` fail `init` when a
configured algorithm is missing. There is no configured algorithm at init — a key specification
arrives with the request — and failing init would take a token offline for RSA and EC too, neither
of which comes from the profile table at all. An RSA/EC-only HSM is a legitimate deployment. So the
refusal moved to `generateKeyPair`, which is where an algorithm is actually named, and the property
governs that. What init does is log the effective table, once, as a single event.

**An unanswered probe is not a "no".** A token that will not answer `C_GetMechanismList` yields
`TokenCapabilities.unknown`, which answers yes to everything and says so in the logged table
(`NOT PROBED: …`). An empty capability set would have meant "this token does nothing" and taken a
working HSM out of service over a mechanism list it declined to give. For the same reason a
mechanism that is listed but not describable — some modules answer `CKR_MECHANISM_INVALID` for
their own vendor mechanisms — counts as present with unknown flags, and a failed probe is never
cached, unlike a successful one.

**Ties in auto-detection are not broken.** Two profiles matching the same number of algorithms
means their mechanism constants overlap on this token, and choosing either is a guess about whose
numbering is in force — the same class of guess that put a wrong OID in a certificate. The built-in
profile is used and both candidates are named. An explicit `kimbo11ng.pqc.profile` always wins over
the probe: a module may under-report a mechanism gated by a partition policy, and overriding an
operator on that evidence is worse than honouring a wrong choice, which at least fails where it was
configured. `FakeToken` grew `underReportMechanism` to model exactly that, distinct from
`hideMechanism`, which is firmware that genuinely lacks the mechanism.

**The wrong-profile message now names the right profile.** Anything that is neither RSA nor in the
active profile falls through to the EC branch, so a token configured with `thales-luna` answered a
request for ML-DSA-65 with "string ML-DSA-65 is not an OID" — true of that branch and no help about
the mistake, which is one property. Verified against the live stack, it now reads: *'ML-DSA-65' is
not a curve name, and the profile in use ('thales-luna') does not describe it. These profiles do:
[pkcs11v32]. Set kimbo11ng.pqc.profile to whichever matches this HSM, or remove it and let the
capability probe choose.* Every profile that knows the algorithm is listed, not the first one
`ServiceLoader` returned.

**BouncyCastle is probed too, and only its successes are cached.** An algorithm the deployed BC has
no `KeyFactory` for is excluded up front — this is what replaced the deleted `RawPqcPublicKey`,
rather than wrapping a key EJBCA cannot sign with. A negative answer depends on which providers
happen to be registered when it is asked, so caching one would let the order in which EJBCA
registers BouncyCastle and initialises tokens decide whether PQC works at all.

**Gate detail** — live SoftHSMv3 auto-detects `pkcs11v32` at 18/18 and the deliberate
`thales-luna` misconfiguration is refused by name, then works again on restore · a hidden
generation mechanism excludes three rows, a `CKF_SIGN`-less `CKM_SLH_DSA` excludes twelve, and
ML-KEM survives both · 18 ITs green.

## Phase 6 — Secrets, key usages, log hygiene ✅

- **6.1** PIN via `CharsetEncoder`, zeroed in `finally`; never a `String`.
- **6.2** `getKeyUsagesFromKey` returns the true CKA constants (`0x105`/`0x108` drive `testKeyPair`).
- **6.3** Log redaction via `LogRedactionUtils`; per-keygen INFO → DEBUG.
- **6.4** Dead constants removed; `Kimbo11ngPrivateKey` identity on `(libPath, slot, ckaId)`.

**Gate** — met, with the expectation itself corrected (below). Against the fake: an RSA private key
reports `{261, 264}`, EC and ML-DSA `{264}`, ML-KEM `{261}`. Against the live stack: `cryptotoken
testkey` passes for RSA and ML-DSA and refuses an ML-KEM key by name. A source scan gate now fails
the build if any credential is turned into a `String` or reaches a log statement.

### What the implementation changed, and why

**Two of the four items were already done.** 6.1 landed with the session pool in phase 2 —
`Pins.encodeUtf8` encodes through a `CharBuffer` and `SessionPool.login` zeroes the bytes in a
`finally` — and 6.4's `Kimbo11ngPrivateKey.equals`/`hashCode` on `(libPath, slot, ckaId)` landed
with key identity in phase 3, along with the removal of `PASSWORD_LABEL_KEY` and `ATTRIB_LABEL_KEY`.
What phase 6 adds for them is a standing gate: `SecretHygieneTest` scans `src/main/java` for a
credential passed to `new String(…)`/`String.valueOf(…)` and for any log statement naming a
credential or the token `Properties` — which carry `pin=`. Verified by introducing each violation
and watching the gate name the file and line. SpotBugs has no detector for either, and no runtime
test can observe a heap that no longer holds the reference, so the source is the only place the
property is visible.

**The stated reason for 6.2 was wrong, and the real contract is narrower.**
`BaseCryptoToken.testKeyPair` computes `usages.contains(261) && !usages.contains(264)` and runs the
encrypt/decrypt test only when that is true. The empty set every EJBCA CE token returns — including
`PKCS11CryptoToken`, `SoftCryptoToken` and `AzureCryptoToken`, all of which return `new TreeSet<>()`
— makes it **false**, so today everything already gets the *signing* test. The plan, and the TODO
comment this replaces, said an empty set selects an RSA-style encryption test for every key. It does
not. The real gain is elsewhere: a decryption-only key currently gets a signing test it cannot pass,
and EJBCA has no key-usage information to show.

**A second consumer decides the design, and the plan's gate would have broken it.**
`CryptoTokenManagementSessionBean.getKeyUsageStringForKeyPairInfo` compares the returned set for
**equality** against `{261}`, `{264}` and `{261,264}`, mapping them to `KeyPairInfo.KeyUsage`
`ENCRYPT`, `SIGN` and `SIGN_ENCRYPT`, and to `null` for anything else — that is what the admin UI
shows per key. The plan's gate expected an RSA key to report `{0x105, 0x107, 0x108}`; that includes
`CKA_UNWRAP`, the equality would never match, and the UI would show no usage at all, which is worse
than the empty set. So `getKeyUsagesFromPrivateKey` is restricted to the two constants EJBCA
compares against, and `getKeyUsagesFromKey(alias, isPrivate)` with no attributes named still reports
the full set for a caller that wants it.

**Attributes are read one per call.** A bulk `C_GetAttributeValue` returns non-zero if any requested
type is invalid for the object, and jacknji11 turns any non-zero return into an exception — so one
attribute a token does not implement would take the whole answer with it. The hot path asks for two.

**Implementing this is what makes ML-KEM need intercepting.** An ML-KEM private key honestly reports
`CKA_DECRYPT` and no `CKA_SIGN`, which is exactly the predicate that selects the encryption branch —
so the change that makes the answer true is also the change that routes a KEM key into a JCA
`Cipher`. `Pkcs11NgCryptoToken.testKeyPair` now refuses first, naming the algorithm and saying that
neither branch is a KEM operation and the key is otherwise fine. Verified live: `cryptotoken testkey`
exits 1 with that message for ML-KEM-768 and still passes for ML-DSA-65 and RSA-2048. The RSA case
is the one that had to be checked — `{261, 264}` contains 261, and had the predicate been
`contains(261)` alone, every RSA CA key would have moved to the encryption branch.

**`LogRedactionUtils` was dropped, deliberately.** It redacts subject DNs and subject alternative
names, and `getContentLogSafe` returns a flat `<redacted>` whenever the global PII flag is set. A
crypto-token alias is an operator-chosen key name, not certificate PII: running aliases through it
would blank every alias in the token log while protecting nothing, and would put a dependency on
`LogRedactionConfigurationCache` — an EJBCA singleton — into a path the unit tests exercise. Nothing
here ever sees a certificate subject. An audit of every non-debug log statement found nothing that
leaks; the `SecretHygieneTest` gate is what keeps it that way.

**Per-keygen INFO stayed at INFO.** The plan demoted it to DEBUG as noise. Key generation on this
token is CA key generation: rare, irreversible, and performed against hardware. One line recording
it is a log an operator wants, not one they have to filter.

**Gate detail** — RSA `{261,264}`, EC `{264}`, ML-DSA `{264}`, ML-KEM `{261}` · a key usage the
token does not implement does not lose the others · both halves found by `CKA_ID`, so a relabelled
public key is still read · live `testkey` refuses ML-KEM and passes ML-DSA and RSA · 19 ITs green.

## Phase 7 — Coverage that matches the claims ✅

- Full algorithm matrix on the fake (3 ML-DSA, 3 ML-KEM, 12 SLH-DSA, RSA 2048/3072/4096, all curves).
- Concurrency suite, 100 consecutive green runs.
- IT: add ML-DSA-44 and ML-DSA-87 root CAs — either would have caught the parameter-set default.
- README reconciled: ML-KEM is generation/enumeration only (no KEM SPI).
- **RSA-PSS**, deferred from 1.5.

**Gate** — met. 388 unit tests, 4 artifact tests, 23 ITs. The concurrency soak ran 100/100 green in
475 s. Every algorithm the README lists has a test that generates it, re-enumerates it, and hands it
to EJBCA's own `AlgorithmTools`.

### What the implementation changed, and why

**RSA-PSS needed three things, and only the first was in the plan.** The mechanism parameter was
expected: `CKM_SHA*_RSA_PKCS_PSS` takes a `CK_RSA_PKCS_PSS_PARAMS` block and `CKM.DEFAULT_PARAMS`
covers only the CBC IVs and OAEP, so `new CKM(SHA256_RSA_PKCS_PSS)` sends a null parameter and the
token answers `CKR_MECHANISM_PARAM_INVALID`. The other two surfaced only by running it:

1. *BouncyCastle asks this provider for a `MessageDigest`.* EJBCA signs a certificate through
   `JcaContentSignerBuilder(...).setProvider(p)`, which resolves every helper from `p`, and for PSS
   that includes `MessageDigest.getInstance("SHA256")`. CA creation failed with *"cannot create
   signer: no such algorithm: SHA256 for provider Kimbo11ng-…"* — a message naming neither PSS nor
   the missing service. The provider now registers SHA-1/256/384/512, computed in software:
   digesting public data in an HSM protects nothing and costs a round trip, and the signing
   mechanism digests on the token anyway. Found by the IT, then reproduced as a unit test.
2. *`engineSetParameter(AlgorithmParameterSpec)` was inherited and throws.* BouncyCastle sets PSS
   parameters when they differ from its defaults. It now accepts a spec matching what the service
   will send and refuses any other by name — accepting silently would produce a signature of the
   right size with the wrong salt, which fails only at the relying party.

**The salt length is the digest length.** Nothing in this codebase can detect a wrong one: the
provider never verifies. So every PSS test signs on the token and verifies with BouncyCastle, and
the IT issues a real certificate and checks its OID is `1.2.840.113549.1.1.10`.

**Signature services are now capability-gated.** A service is registered only if the token
advertises its mechanism with `CKF_SIGN`. `Signature.getInstance` throwing
`NoSuchAlgorithmException` is recoverable for `SignWithWorkingAlgorithm`, which moves to the next
candidate; a `CKR_MECHANISM_INVALID` in the middle of signing is not.

**Two of the matrix's expectations were wrong about real behaviour, and the code was right.**
BouncyCastle names a post-quantum key by its parameter set, so an ML-DSA-44 key reports
`getAlgorithm() == "ML-DSA-44"`, not `"ML-DSA"` — the `PqcFamily.jcaName()` javadoc claimed
otherwise and has been corrected; nothing depends on it, because `AlgorithmTools` dispatches on
`instanceof`. And EJBCA reports a curve by its X9.62 name, so a key generated as `secp256r1` comes
back as `prime256v1`; the matrix compares curve OIDs rather than names.

**`Kimbo11ngKeyPairGeneratorSpi` was registered and never executed — 0 of 24 lines.** Writing its
first test found a real defect: an unknown curve name reached `new ASN1ObjectIdentifier(...)` and
escaped `generateKeyPair` as a raw `IllegalArgumentException` reading "string not-a-curve not an
OID". It is now refused at `initialize`, where the JCA gives a checked exception the caller can act
on, and anything else inside `generateKeyPair` is wrapped as the `ProviderException` the contract
requires. The curve check is shared with the phase-5 call site rather than duplicated.

**The facade swap cannot be an integration test.** Only the admin UI's Save button reaches
`saveCryptoToken`; `cryptotoken setpin --update` was tried and does not re-init. `ProviderIdentityTest`
asserts it against the same code path instead — one provider object across ten init cycles, the
name resolving to the live object rather than a zombie, and signing still working after a swap. The
manual `just deploy` plus re-provision procedure from phase 2 remains the end-to-end check.

**The soak is a knob, not a separate harness.** `-Dkimbo11ng.soak.runs=100` repeats the same
fault-injection test the ordinary build runs once, so the soak cannot drift from what is tested
every day. The invariants asserted are the ones that matter under fault: no `CKR_OPERATION_ACTIVE`,
the pool still usable afterwards, every lease returned. Individual operations are allowed to
fail — a delete racing a sign legitimately does.

**Gate detail** — 34-case algorithm matrix at 0 failures · every registered signature algorithm
verified by BouncyCastle, and through `JcaContentSignerBuilder` · concurrency soak 100/100 ·
23 ITs including ML-DSA-44, ML-DSA-87, EC P-384 and RSA-PSS root CAs · coverage floor 0.79/0.68.

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
prove the migration path; after Phase 5, set `kimbo11ng.pqc.profile=thales-luna` on the live token
and confirm the refusal names `pkcs11v32`, then restore and confirm auto-detection reports 18/18.

## Standing rules

- Every behaviour change ships behind a kill-switch property; existing EJBCA-written property names
  are unchanged.
- No `C_Finalize` in normal operation. No silent parameter-set or OID defaults. No `catch (Exception)`
  at an HSM boundary without mapping through `Pkcs11Errors`.
- JCA algorithm names come from `AlgorithmConstants`, never hand-typed.
- FQNs pinned by EJBCA stay put: `org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken`
  (a string in `CryptoTokenFactory`) and
  `com.keyfactor.util.keys.token.pkcs11.JackNJI11SlotListWrapperFactory` (`META-INF/services`).

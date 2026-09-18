# EJBCA upstream: what kimbo11ng depends on, and what to watch

kimbo11ng is loaded by EJBCA, not the other way round, so it breaks when EJBCA changes something it
never promised to keep. This file records those things: the baseline each release was measured
against, the behaviours that matter, how to detect a change, and what to do about it.

Everything here was read from the release's own jars and source, not from release notes. The jars in
`Keyfactor/ejbca-ce` `lib/` at a release tag are byte-identical to the ones in
`keyfactor/ejbca-ce:<version>` (checked for 9.6.3: `cryptotokens-impl`, `cryptotokens-api`,
`x509-common-util`, `bcprov`, `jacknji11`, `jna`), so a checkout is enough to compare two releases
without pulling either image.

## Compile target

**`maven.compiler.release` is the Java version of the pinned EJBCA image's runtime**, and
`requireJavaVersion` in the enforcer rule is the same number. The compiler resolves only APIs that
exist there, so the artifact cannot call something the container lacks, and the bytecode is never
newer than the JVM that loads it.

| EJBCA CE | Image runtime | `release` | Measured |
| --- | --- | --- | --- |
| 9.3.7 | OpenJDK 17.0.16 | 17 | 2026-09-18, `java -version` in `keyfactor/ejbca-ce:9.3.7` |
| **9.6.3** | **OpenJDK 21.0.10** | **21** | 2026-09-18, `java -version` in `keyfactor/ejbca-ce:9.6.3` |

Move it in the same commit as the image digest: `pom.xml` (`maven.compiler.release`, enforcer
`requireJavaVersion`), `.github/workflows/ci.yml` (`JAVA_VERSION` must be at least the release), and
the prerequisites line in the README.

## Baseline

| | 9.3.7 | 9.6.3 |
| --- | --- | --- |
| `cryptotokens-api` / `-impl` | 3.0.0 | **4.1.0** |
| `x509-common-util` | 5.3.5 | **5.11.1** |
| BouncyCastle | 1.80.2 | **1.84** |
| `jacknji11` | 1.3.1 | 1.3.1, byte-identical |
| `jna` | 5.12.1 | 5.12.1, byte-identical |
| `commons-lang` (2.x) | present | **removed**, only `commons-lang3` 3.20.0 |
| log4j | 2.20.0 | 2.25.4 (`log4j-1.2-api` bridge kept, so `org.apache.log4j.Logger` still resolves) |
| `PKCS11CryptoToken`, `AzureCryptoToken` in `cryptotokens-impl` | present | **removed** |
| Startup check on non-Soft/Null token types | none | **present** |
| Image runtime | Java 17 | **Java 21** |

Every EJBCA class kimbo11ng imports has an identical signature in both releases
(`scripts/api-diff.sh`: 29 classes checked, 28 `SAME`). The exception is `CryptoToken`, which it
inherits rather than imports, and which gained default methods and constants — see W5.

## Behaviours to watch

Each has an ID that the code, tests and commits can cite. **Status** is what is known today; the
runtime rows stay "unverified" until the Docker suite has run against the image.

### W1. The startup check that refuses HSM tokens — **the blocker**

`StartupSingletonBean.checkHsmTokensNotUsedInCommunityEdition()` throws `IllegalStateException` and
aborts deployment when `!isRunningEnterprise() && hasNonCeSupportedTokenTypes()`. The query is
`tokenType NOT IN (SoftCryptoToken, NullCryptoToken)` (`CE_SUPPORTED_TOKEN_TYPES` in
`CryptoTokenSessionBean`). `Pkcs11NgCryptoToken` is not in that set, so **kimbo11ng cannot run on
9.6.3 without lifting it.** 9.3.7 has no such check. It is the only caller of
`hasNonCeSupportedTokenTypes`; the Admin UI and CLI have no other edition gate.

- **Detect:** `git grep -n hasNonCeSupportedTokenTypes` in the release; `javap -p -c` on
  `StartupSingletonBean` in `ejbca-ejb.jar`.
- **Response:** the image build patches that one method out of the official `ejbca-ejb.jar` and fails
  if the method is not found (`docker/ejbca-hsm/`). A moved or renamed method makes the build loud
  instead of the CA silently refusing to start.
- **Watch for:** the check moving into `CryptoTokenSessionBean`, a second check on the token
  *create* path, or the check becoming a licence check rather than a type check. Each needs a new
  anchor, and the last is a decision for a person, not a patch.
- **Status:** verified end to end on 2026-09-18. With the overlay, `keyfactor/ejbca-ce:9.6.3` starts
  with a `Pkcs11NgCryptoToken` row in the database. The control (same image, same database, the
  original `ejbca-ejb.jar` mounted over the patched one) fails deployment with
  `EJBCA Community Edition does not support HSM crypto tokens`, so the patch is what makes the
  difference. The class file the patcher writes is a bare `return` and nothing else in the jar
  changes.

### W2. Token classes are found by string, in a package Keyfactor owns

`CryptoTokenFactory` registers `org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken`,
`org.cesecore.keys.token.PKCS11CryptoToken` and `AzureCryptoToken` by name and keeps an entry only
if the class loads. The registration list is identical in shape in both releases; 9.6.3 differs in
that the last two classes are absent from the jar (W1's companion — see `docker/ejbca-hsm/`).

- **Detect:** `scripts/api-diff.sh` prints the registrations for both releases.
- **Watch for:** Keyfactor shipping a stub `Pkcs11NgCryptoToken` in a CE jar. Two classes with one
  name in `ejbca.ear/lib` load in an unspecified order. The alias is deliberately empty
  (`Pkcs11NgCryptoToken` extends `Kimbo11ngCryptoToken`) so that case costs a redirect, not a
  rewrite. See also `docs/JACKNJI11_PROVENANCE.md`.
- **Guard:** `docker/ejbca-hsm/build.sh` fails the image build if any jar on the EAR classpath already
  contains `PKCS11CryptoToken`, `AzureCryptoToken` or `AzureProvider`, so the overlay can never add a
  second copy of a class Keyfactor starts shipping again.
- **Status:** verified statically for 9.6.3; no collision when building the overlay.

### W3. The stored token type comes from `getConcreteClass().getSimpleName()`

9.6.3 wraps tokens in `CryptoTokenCompositeWrapper` (composite classical + PQC key aliases in the
Admin UI). `CryptoTokenSessionBean.mergeCryptoToken` and `CryptoTokenManagementSessionBean` ask
`getConcreteClass()`, and the token type written to the database is that class's simple name. It must
stay `Pkcs11NgCryptoToken`: any other value is a row the W1 check counts as an unsupported type, and
`getClassNameForType` resolves stored types by `endsWith`.

- **The wrapper hides overrides it does not forward.** `CryptoTokenFactory.createTokenFromClass`
  constructs the token and wraps it, for every type. `CryptoTokenCompositeWrapper` extends
  `BaseCryptoToken` and forwards the token methods, **except `testKeyPair`**. So on EJBCA's paths
  (`cryptotoken testkey`, the Admin UI, `HsmKeepAliveWorker`) `BaseCryptoToken.testKeyPair` runs on
  the wrapper and `Kimbo11ngCryptoToken.testKeyPair` is never called. Measured 2026-09-18:
  `ejbca.sh cryptotoken testkey` on an ML-KEM alias still fails, as it must, but with EJBCA's
  `No algorithm in the available list could be used for private key of algorithm ML-KEM` in place of
  kimbo11ng's "key-encapsulation" explanation, which 9.3.7 showed. `EjbcaContainerIT` now asserts the
  failure and the algorithm name; the explanation is asserted at unit level.
  Audit of kimbo11ng's other overrides: every one is forwarded by the wrapper (`getPrivateKey`,
  `deleteEntry`, `generateKeyPair`, `generateKey`, `getKeyUsagesFrom*`, lifecycle), so the
  secret-key guard in `getPrivateKey` still protects `HsmKeepAliveWorker`. A new override of a
  `BaseCryptoToken` method the wrapper does not forward would be silently bypassed the same way.
- **Detect:** after creating a token through the Admin UI or CLI, read `CryptoTokenData.tokenType`;
  `javap` the wrapper for the methods it declares.
- **Status:** verified. `EjbcaContainerIT.tokenCreatedThroughEjbca_isStoredAsPkcs11Ng` creates a token
  with EJBCA's own CLI and reads `tokenType` from the database, then generates and lists a key; the
  `testKeyPair` bypass is measured as above.

### W4. BouncyCastle gets stricter about post-quantum keys

BC 1.84 runs FIPS 203's encapsulation-key modulus check when decoding an ML-KEM public key. 1.80.2
did not, so it accepted random bytes of the right length. kimbo11ng builds a `SubjectPublicKeyInfo`
from the token's raw `CKA_VALUE` and decodes it with BC, so **a token that emits an invalid ML-KEM
key now fails at key generation and enumeration.** Real tokens emit valid keys; the in-memory
`FakeToken` did not, and now generates genuine ones.

- **Detect:** unit tests; `AlgorithmSupport` probes at start-up whether BC can materialise each
  family and excludes, with a reason, those it cannot.
- **Watch for:** the same tightening for ML-DSA and SLH-DSA (their public keys are still accepted as
  arbitrary bytes of the right length), and BC removing or renaming `MLKEMParameterSpec.fromName`.
- **Status:** hit and fixed on 9.6.3.

### W5. `CryptoToken` key-usage handling now knows ML-KEM

x509-common-util 5.11.1 adds `CKA_ENCAPSULATE` (1587) / `CKA_DECAPSULATE` (1588) and per-algorithm
usage sets to `CryptoToken`, turns `getKeyUsagesFrom*` into default methods, and makes
`BaseCryptoToken.testKeyPair` choose the encryption test when the private key's usages contain 261
*or 1588* (and not 264). The 9.3.7 predicate was `contains(261) && !contains(264)`.

- **Effect on kimbo11ng:** `Kimbo11ngCryptoToken.testKeyPair` refuses ML-KEM before calling the
  base class, so a KEM key still never reaches that encryption test. That guard is now doing more
  work, not less.
- **`kimbo11ng.pqc.kemUsage` stays `both`.** Settled from source on 2026-09-18. What EJBCA sees is
  `getKeyUsagesFromPrivateKey`, and kimbo11ng asks the token only for `{CKA_DECRYPT, CKA_SIGN}`
  whatever `kemUsage` says, so the encapsulation attributes never reach EJBCA and the new 1588 branch
  in `BaseCryptoToken.testKeyPair` is never taken for these keys. The label the UI shows comes from
  `CryptoTokenManagementSessionBean.getKeyUsageStringForKeyPairInfo`, which in 9.6.3 is unchanged and
  still recognises only `{261}`, `{264}` and `{261,264}`. With `both` or `legacy` an ML-KEM key
  reports `{261}` and shows as ENCRYPT; with `v32` it has no `CKA_DECRYPT`, reports `{}`, and shows no
  usage. Revisit only if that method learns 1588.
- **Also new:** `getKeyAttestation`, `isInstanceOf`, `getConcreteToken`, `getConcreteClass`,
  `clearCache`. All are defaults; nothing to implement.
- **Status:** guard verified by the unit suite; UI behaviour unverified.

### W6. `USE_P11NG_AS_P11` does nothing in Community Edition

`CryptoTokenSessionBean` reads the environment variable `USE_P11NG_AS_P11` to load stored
`PKCS11CryptoToken` rows as `Pkcs11NgCryptoToken`. It only acts when
`org.cesecore.dbprotection.ProtectedDataIntegrityImpl` is on the classpath, which is how the code
tells Enterprise from Community, so **in CE the switch is inert**. Confirmed 2026-09-18: with the
variable set on a 9.6.3 container holding a `PKCS11CryptoToken` row there is no "Migrating
PKCS11CryptoToken" log line, and the token keeps working through the classic class. Moving an existing
SunPKCS11 token onto kimbo11ng is therefore a manual edit of the row's `tokenType`, not something
EJBCA will do. Do not supply that Enterprise class to make the switch work: much other code branches
on the same probe.

- **Watch for:** the probe changing to something a CE build can satisfy.

### W7. jacknji11 and JNA ship in the EAR

kimbo11ng compiles against both as `provided`. They are byte-identical in 9.3.7 and 9.6.3. If a
release stops shipping jacknji11 the artifact fails to load; the contingency, rehearsed on 2026-09-05
and still valid, is in `docs/JACKNJI11_PROVENANCE.md`. A second copy of JNA in one classloader fails
with "native library already loaded in another classloader", so the version must not drift from the
container's.

- **Detect:** the `md5sum` of both jars in the new image against the old.

### W8. CA token key purposes changed

`CAToken` in 9.6.3 tolerates a missing alias for the key-encrypt purpose as well as the alternative
signing one, renames "hybrid" to Chimera/Catalyst in comments, adds a default alias for the
alternative signing key, and drops the legacy CA-token upgrade code.

- **Effect:** none expected on kimbo11ng, which does not look at CA token properties. The hybrid
  (RSA/EC + ML-DSA) integration test is the check.
- **Status:** verified on 9.6.3: the hybrid, ML-DSA, SLH-DSA, EC and RSA-PSS CAs all issue.

### W9. The Java runtime

See [Compile target](#compile-target). A move from 21 to a later LTS is a `release` bump. Do not
raise `release` ahead of the image: nothing would fail to compile, and the artifact would fail to
load.

### W10. Where the classic slot lister is registered

`PKCS11SlotListWrapperFactory` implementations are found through
`META-INF/services/com.keyfactor.util.keys.token.pkcs11.PKCS11SlotListWrapperFactory`. The
SunPKCS11 lister (`SunP11SlotListWrapperFactory`) is registered that way from `cryptotokens-api` in
both 9.3.7 and 9.6.3. `cesecore-common` also carried an empty file of that name in 9.3.7 and does
not in 9.6.3, which changes nothing. kimbo11ng registers its own at priority 2, above the SunPKCS11
one's 1, and that also serves the restored classic token.

- **Watch for:** the priorities changing, or a second implementation appearing at 2 or above.

### W11. The edition stance

`ejbca.org` states that from 9.6.2 all use of HSM crypto tokens requires Enterprise Edition, and 9.6.3
enforces it with W1. The classic tokens restored under `docker/ejbca-hsm/` come from Keyfactor's own
LGPL-2.1+ history, and the jars the image is built on declare LGPL-2.1 while their source is not
published, which is why **a built image is for local use and is never published**. This is a licensing
position, not a code detail: re-read it whenever Keyfactor changes its CE licence, terms or
`README`.

**CI publishing is disabled.** `.github/workflows/ci.yml` used to build `docker/Dockerfile` and, on a
push to `main`, push it to `ghcr.io/thpham/kimbo11ng-ejbca` (the repository is public; the image was
called `ghcr.io/thpham/ejbca-ce` until 2026-09-18, renamed because EJBCA is Keyfactor's trademark and
that name read as an official image). That was already a
redistribution of Keyfactor's image with the kimbo11ng jar added; with the overlay it would be a
redistribution of a *modified* Keyfactor jar plus the restored LGPL classes. The `push` and `merge`
jobs are therefore set to `if: false` on this branch, with a comment saying why. The `test` job still
builds the image locally on the runner and runs the suite against it; only publishing is off. The
toolchain image (`toolchain.yml`: OpenSSL and SoftHSMv3, nothing of Keyfactor's) is unaffected.
Re-enabling publishing is the repository owner's decision, and should follow a decision on the licensing
position above.

## On each EJBCA bump

1. **Get the new lib directory.** Either `git clone --depth 1 --branch r<version>
   https://github.com/Keyfactor/ejbca-ce.git` and use its `lib/`, or `docker run --rm
   --entrypoint sh keyfactor/ejbca-ce:<version> -c 'cd /opt/keyfactor/ejbca/dist/ejbca.ear/lib && tar c .' | tar x -C <dir>`.
2. **Diff the surface.** `scripts/api-diff.sh <old-lib> <new-lib>`. Exit 1 means something kimbo11ng
   uses changed; a member *added* to an inherited type is compatible, a member *removed* or
   re-typed is a fix. Read the `CryptoTokenFactory` registrations it prints against W2.
3. **Re-measure the runtime.** `java -version` in the image → the compile-target table and `pom.xml`.
4. **Check each watch item above** against the new source: W1 above all, then W3 and W5.
5. **Compare bytes** for `jacknji11` and `jna` (W7).
6. **Bump the pins** together: `justfile` (`ejbca_version`, `ejbca_digest`, `ejbca_deps`),
   `docker/Dockerfile` `FROM`, `pom.xml` versions, `.github/workflows/ci.yml`.
7. **Run** `just extract-jars-fresh setup docker-build`, then `mvn verify -Pit`.
8. **Swap the image under a live deployment.** Build the old release's image from a checkout of its
   tag, then `scripts/upgrade-swap.sh OLD_IMAGE NEW_IMAGE`. The integration suite always starts from an
   empty database; this starts the new image on the old one's database and token, so EJBCA's own
   upgrade runs, and passes only if the CA signs again with the same keys. Run for 9.3.7 → 9.6.3 on
   2026-09-18: EJBCA upgraded the database, the token stayed `Pkcs11NgCryptoToken`, and the ML-DSA-65
   CA signed CRL 3 on 9.6.3 after signing CRL 2 on 9.3.7, with identical key fingerprints.
9. **Record** what changed in the baseline and the compile-target tables, add a watch item for any
   new behaviour, and update the README version matrix.

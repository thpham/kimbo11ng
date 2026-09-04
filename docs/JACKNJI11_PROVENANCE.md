# jacknji11: where it comes from, and what happens if EJBCA stops shipping it

kimbo11ng talks to PKCS#11 through [jacknji11](https://github.com/joelhockey/jacknji11), JNA
bindings by Joel Hockey, inception year 2010, **MIT licence**. This records where the jar on the
classpath actually comes from, and the result of testing the build against upstream instead.

## Chain of custody

| Coordinates | Licence | Where it lives |
| --- | --- | --- |
| `org.pkcs11:jacknji11:1.3-SNAPSHOT` | MIT | upstream HEAD, [joelhockey/jacknji11](https://github.com/joelhockey/jacknji11) — **no release tags**, so no published jar |
| `org.signserver.jacknji11:jacknji11:1.2-pk3` | MIT | the PrimeKey/SignServer fork — the only jacknji11 on Maven Central |
| `com.keyfactor:jacknji11:1.3.1` | MIT | **what we actually use** — not on Maven Central (`numFound 0`), ships only inside `ejbca.ear/lib/` |

`org.pkcs11` is upstream's own groupId. Keyfactor's fork rebrands itself to `com.keyfactor` in its
embedded pom, but `just install-deps` extracts it from the EJBCA container image and installs it
under the **upstream** coordinate at version `1.3.1` — a version upstream never released. So
`org.pkcs11:jacknji11:1.3.1` in [pom.xml](../pom.xml) is upstream's coordinate carrying Keyfactor's
build. That conflation is deliberate and harmless in practice, but it is why the local repository
ends up with both `1.3-SNAPSHOT` and `1.3.1` under `org/pkcs11/jacknji11/` once you have built
upstream.

## Why this matters

[ejbca.org](https://www.ejbca.org/) states: *"As of EJBCA 9.6.2, all use of HSM Crypto Tokens
requires EJBCA Enterprise Edition."* No CE 9.6.2 exists — Docker Hub and the GitHub source releases
both stop at 9.3.7 (2025-12-16), and CE has had no release in the nine months since — but the
direction of travel is clear. If a future CE drops HSM support, jacknji11 may stop shipping in the
EAR, and `provided` scope stops being tenable.

## The rehearsal, and its result

```bash
just jacknji11-upstream                              # clone + build upstream, install locally
mvn verify -Djacknji11.version=1.3-SNAPSHOT          # build kimbo11ng against it
mvn verify -Pit -Djacknji11.version=1.3-SNAPSHOT     # and run the integration suite
```

Verified 2026-09-05 against upstream HEAD `82f0bac` (2026-04-14):

- **Compiles unchanged.** No source edits were needed. Upstream has the whole seam kimbo11ng
  depends on — `Cryptoki`, `CryptokiE`, `NativeProvider` — so the injection point the fake token
  uses is upstream's design, not Keyfactor's addition.
- **583 unit tests green**, which exercises the binding thoroughly: `FakeToken` implements
  `NativeProvider`, so every PKCS#11 call in the project goes through jacknji11's marshalling.
- **23 integration tests green** — and this is the important one. Our classes were *compiled*
  against upstream `1.3-SNAPSHOT` and *ran* against Keyfactor's `1.3.1` jar in the EAR. They are
  binary-compatible, so kimbo11ng is **not API-locked to Keyfactor's fork**.

### The one difference found

Upstream HEAD knows the PKCS#11 v3.2 post-quantum mechanism names; Keyfactor's 1.3.1 predates v3.2
and does not. So `TokenCapabilities.name(0x1D)` renders `CKM_ML_DSA (0x0000001d)` against upstream
and bare `0x0000001d` against 1.3.1.

The production code was already correct — it falls back to hex whenever the bindings cannot name a
mechanism, because their placeholder reads as an error. The *test* was wrong: it pinned the exact
1.3.1 rendering, making it a statement about the dependency rather than the code. It now asserts the
contract (the hex is always present) and uses a vendor-defined mechanism for the unnamed case, which
no build of jacknji11 can name.

### Independent confirmation of the profile constants

[Pkcs11v32Profile](../src/main/java/ch/ithings/kimbo11ng/profile/Pkcs11v32Profile.java) documents its
constants as "assumptions until a token confirms them". Upstream defines six of them, and **all six
match exactly**:

| | ours | upstream |
| --- | --- | --- |
| `CKM_ML_KEM_KEY_PAIR_GEN` | `0x0F` | `0x0000000f` |
| `CKM_ML_KEM` | `0x17` | `0x00000017` |
| `CKM_ML_DSA_KEY_PAIR_GEN` | `0x1C` | `0x0000001c` |
| `CKM_ML_DSA` | `0x1D` | `0x0000001d` |
| `CKM_SLH_DSA_KEY_PAIR_GEN` | `0x2D` | `0x0000002d` |
| `CKM_SLH_DSA` | `0x2E` | `0x0000002e` |
| `CKA_PARAMETER_SET` | `0x61D` | `0x0000061d` |

Upstream defines **no** post-quantum `CKK_*` values, so those three had to be checked elsewhere.
[jacknji11 PR #65](https://github.com/joelhockey/jacknji11/pull/65) ("syn parameters with p11v3.2",
merged) names its source: the OASIS working header at
[oasis-tcs/pkcs11](https://github.com/oasis-tcs/pkcs11/blob/master/working/headers/pkcs11t.h).
Checking the profile against that header directly closes the gap — `CKK_ML_KEM` `0x49`,
`CKK_ML_DSA` `0x4A`, `CKK_SLH_DSA` `0x4B`, all matching.

The same PR added `CKP.java`, which carries all eighteen parameter sets. Those match the profile
too, including the part that is easy to get wrong: `CKP` interleaves SHA2 and SHAKE within each
security level (`SHA2_128S`=1, `SHAKE_128S`=2, `SHA2_128F`=3 …) while the NIST OID arc groups all
SHA2 before all SHAKE. Deriving one ordering from the other by arithmetic would mislabel keys, which
is why both live in the table and why `Pkcs11v32ProfileTest.ckpAndOidOrdersDiffer` guards it.

**Tally, verified 2026-09-05: 28 constants, zero divergences** — 3 `CKK_*`, 6 `CKM_*`,
`CKA_PARAMETER_SET` and 18 `CKP_*`, against two sources that agree because one derives from the
other. What remains unverifiable from a spec is whether a given token implements any of it; that is
the capability probe's job, not the table's.

## If EJBCA stops shipping jacknji11

The move is small, and MIT imposes no copyleft obligation:

1. `just jacknji11-upstream` (or vendor a built jar), and set `jacknji11.version` accordingly.
2. Change the dependency scope from `provided` to `compile` so the ~142 KB jar is bundled.
3. Update [ArtifactContentsIT](../src/test/java/ch/ithings/kimbo11ng/ArtifactContentsIT.java): it
   asserts a thin artifact, and jacknji11 would legitimately appear in it.
4. Check whether JNA still ships in `ejbca.ear/lib/`. If it does, **do not bundle it** — two copies
   in one classloader fail with "native library already loaded in another classloader". If it does
   not, bundle it too.

Step 4 is the only one with a trap in it. Steps 1–3 are mechanical, and the rehearsal above shows
they are all that is needed.

## How EJBCA resolves a crypto-token type, and what that pins

Everything below was measured on 2026-09-04 against `keyfactor/ejbca-ce:9.3.7` bytecode and a
running stack, while testing whether kimbo11ng could stop using Keyfactor's class name. It could
not — but the mechanics are worth writing down, because they decide what a future CE can break and
what the response would be.

### The registry gates both paths, and the load path fails silently

`CryptoTokenSessionBean.getCryptoToken` does **not** hand the stored `tokenType` straight to
`Class.forName`. It resolves it first:

```java
String found = null;
for (AvailableCryptoToken act : CryptoTokenFactory.instance().getAvailableCryptoTokens()) {
    if (act.getClassPath().endsWith(type)) { found = act.getClassPath(); }   // no break
}
return found;                                                                // null if nothing
```

`createCryptoToken(null, …)` then takes its `ifnull` branch and returns a **`NullCryptoToken`**,
logging "This must be an imported CA that is being upgraded". So an unregistered type does not
raise `ClassNotFoundException` — it silently produces a CA that cannot sign. Two consequences: the
`endsWith` match is why a row may store either the simple name or the FQN, and no two registered
class paths may be suffixes of one another or resolution becomes iteration-order dependent.

### Registration is reachable, and refuses what it cannot load

`CryptoTokenFactory.addAvailableCryptoToken(classPath, name, translateable, use)` is
**package-private**, so it can only be called from `org.cesecore.keys.token`. That is legal from
this project: no EJBCA jar is sealed (no `Sealed` attribute in any manifest under `deps/ejbca/`) and
every jar in `ejbca.ear/lib/` shares one module classloader, so a class of ours in that package is
the same runtime package. It guards on `containsKey` (idempotent, never throws) and calls a private
`loadClass` first, refusing to register a name whose class is absent.

That last detail explains the registry size. EJBCA attempts nine registrations in `instance()`;
this image holds **six**, because `PrimeCAToken`, `FortanixCryptoToken`, `AWSKMSCryptoToken` and
`SecurosysCryptoToken` are EE-only classes CE does not ship — EJBCA logs "Can not register …. This
is normally not an error." It also means **the "PKCS#11 NG" entry exists only because kimbo11ng
supplies the class Keyfactor names.** Remove
[Pkcs11NgCryptoToken](../src/main/java/org/cesecore/keys/token/p11ng/cryptotoken/Pkcs11NgCryptoToken.java)
and the entry disappears by itself, through EJBCA's own designed path.

Registrations happen inside the `instance == null` branch, so anything added later survives for the
life of the JVM.

### The admin UI hardcodes two class names

This is why the squatted name cannot be given up. `CryptoTokenMBean` in `adminweb.war` tests a
fixed pair in two places:

| Method | What it decides |
| --- | --- |
| `getAvailableCryptoTokenTypes()` | which entries get the PKCS#11 treatment — compares `classPath` to `PKCS11CryptoToken.class.getName()` and to the literal `"org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken"` |
| `saveCurrentCryptoToken(boolean)` | which types read library / slot / slot-label-type from the form — compares the **simple** names `"PKCS11CryptoToken"` and `"Pkcs11NgCryptoToken"`, then writes the FQN it hardcoded |

A token type outside that pair still appears in the type dropdown, but renders **no** PKCS#11
fields, and saving it stores neither `sharedLibrary` nor `slotLabelValue`. Verified by registering
`ch.ithings.kimbo11ng.Kimbo11ngCryptoToken` under its own display name: the type resolved, keys
generated fine from the CLI, and the admin UI offered no way to configure a slot. Nothing in our
jar can change that — the condition lives in the WAR.

So `org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken` is not merely a name we borrow.
It is the key by which the admin UI recognises a token as PKCS#11 at all. The
[implementation](../src/main/java/ch/ithings/kimbo11ng/Kimbo11ngCryptoToken.java) therefore lives in
our own package, and that class stays as a thin subclass answering to the name the UI knows.

### If a future CE stops registering the type

The fallback is a class of ours in `org.cesecore.keys.token` calling the package-private
`addAvailableCryptoToken`, carried into the JVM by a `ServiceLoader` service. Both halves were
tested end to end and then removed, since with the entry present today the call is a no-op:

- **Carrier that works:** `META-INF/services/com.keyfactor.util.crypto.provider.CryptoProvider`.
  It fires during startup, before any crypto token resolves, and the interface pairs
  `getProvider()` with `getErrorMessage()` precisely so an implementation may decline. Return an
  **empty `Provider`**, not `null`: `CryptoProviderTools` catches the NPE and logs the error message
  on every provider-installation pass, which put eight NPE stacks in the startup log.
- **Carrier that does not work:** `org.cesecore.authorization.rules.AccessRulePlugin`. Never fired —
  not at startup, not after a restart, not during a server-side `ejbca.sh cryptotoken list` that
  demonstrably ran authorization. Whatever enumerates access-rule plugins runs later than anything
  that matters.
- ServiceLoader from `ejbca.ear/lib` is already proven in this project by
  `META-INF/services/…PKCS11SlotListWrapperFactory`, which `ArtifactContentsIT` guards.

Note what this fallback does and does not buy. It restores type *resolution*, so tokens provisioned
by SQL insert or CLI work again. It cannot restore the admin UI's PKCS#11 form, and it cannot help
if a future CE ships its own stub under that name — then the classloader picks a winner between two
identical names, and the answer is to move the stored `tokenType` to a name we own and accept
CLI-only provisioning.

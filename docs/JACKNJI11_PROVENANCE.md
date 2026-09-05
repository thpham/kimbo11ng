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

Upstream defines **no** post-quantum `CKK_*` values, so our `CKK_ML_DSA` (`0x4A`), `CKK_ML_KEM`
(`0x49`) and `CKK_SLH_DSA` (`0x4B`) remain confirmed only empirically — enumeration round-trips
correctly against SoftHSMv3, which is evidence but not a second source.

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

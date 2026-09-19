# kimbo11ng

Open-source PKCS#11 NG CryptoToken for [EJBCA CE](https://www.ejbca.org/) with post-quantum cryptography support.

Backed by [JackNJI11](https://github.com/joelhockey/jacknji11) (MIT-licensed JNA PKCS#11 bindings —
see [provenance](docs/JACKNJI11_PROVENANCE.md)) and tested against
[softhsmv3](https://github.com/pqctoday/softhsmv3) with OpenSSL 3.6+.

## Features

- Drop-in `Pkcs11NgCryptoToken` for EJBCA CE 9.6.3 (9.3.7 on `main`; 9.6.3 needs the [HSM overlay](#ejbca-ce-96-and-the-hsm-overlay))
- RSA and EC key generation and signing via PKCS#11
- **Post-quantum cryptography**: ML-DSA (FIPS 204), ML-KEM (FIPS 203), and SLH-DSA (FIPS 205)
- Vendor-agnostic `PqcMechanismProfile` abstraction for HSM-specific PQC constants, selected
  automatically by probing the token's mechanism list — adding an HSM is a table of constants plus
  a conformance test, see [docs/VENDOR_PROFILE_CHECKLIST.md](docs/VENDOR_PROFILE_CHECKLIST.md)
- Bounded session pool, durable key identity by `CKA_ID`, and two-tier recovery from a dropped
  HSM connection
- No SunPKCS11 dependency — pure JNA bindings, supports multiple HSM libraries simultaneously

## Supported Algorithms

Every row below is covered by a test that generates the key on a token, reads it back through a
fresh enumeration, and checks the OID that would land in a certificate. See
[Test coverage](#test-coverage).

| Algorithm | Key specs                                    | Operations             | Standard        |
| --------- | -------------------------------------------- | ---------------------- | --------------- |
| RSA       | 2048, 3072, 4096                             | generate, sign         | PKCS#1 v1.5     |
| RSA-PSS   | 2048, 3072, 4096                             | generate, sign         | PKCS#1 v2.1     |
| EC        | P-256/384/521, secp256k1, brainpoolP256/384/512r1 | generate, sign    | NIST / RFC 5639 |
| EdDSA     | Ed25519, Ed448                               | generate, sign         | RFC 8032        |
| ML-DSA    | ML-DSA-44, ML-DSA-65, ML-DSA-87              | generate, sign         | FIPS 204        |
| ML-KEM    | ML-KEM-512, ML-KEM-768, ML-KEM-1024          | generate, enumerate    | FIPS 203        |
| SLH-DSA   | SHA2/SHAKE x 128/192/256 x S/F (12 variants) | generate, sign         | FIPS 205        |
| Hybrid    | RSA/EC primary + ML-DSA/SLH-DSA alternative  | issue certificates     | X.509 Sec. 9.8  |

### Signature algorithms registered by the JCA provider

`SHA{1,256,384,512}withRSA`, `SHA3-{256,384,512}withRSA`, `SHA{256,384,512}withRSAandMGF1`,
`SHA{1,224,256,384,512}withECDSA`, `SHA3-{256,384,512}withECDSA`, `Ed25519`, `Ed448`, and one
service per signing algorithm in the active profile (`ML-DSA-44` … `SLH-DSA-SHAKE-256F`). A service
is registered only if the token advertises its mechanism with the matching `CKF_*` flag.

The set is chosen to match what EJBCA offers, not what is convenient: `AlgorithmTools`
`.getSignatureAlgorithms` returns the SHA-3 and `SHA224withECDSA` spellings for every RSA and EC
key, so an administrator can pick one when creating a CA. Each is registered under its OID as well
as its name — BouncyCastle's operator layer resolves a signer from an `AlgorithmIdentifier` and asks
the provider for the OID as the algorithm name, so a name-only registration is invisible to the
path EJBCA signs certificates through.

### Symmetric keys

`generateKey` creates a `CKO_SECRET_KEY` on the token — `HmacSHA256`, `HmacSHA384` or `HmacSHA512`,
generated `CKA_SENSITIVE` and not `CKA_EXTRACTABLE` — and the provider registers a matching `Mac`
service so the key can be used without leaving the HSM. This is the key EJBCA's database protection
signs rows with; nothing in Community Edition calls it, since the only call site in the deployed EAR
is a pass-through in `org.cesecore.dbprotection.CachedCryptoToken` that CE never constructs.

`AES` is refused with an explanation rather than generated: the provider registers no `Cipher`, so
an AES key on the token would be one nothing could use.

### What is not supported

- **ML-KEM is generation and enumeration only.** It has no signature or KEM operation here: EJBCA
  CE has no key-encapsulation path, and `cryptotoken testkey` on an ML-KEM alias fails rather than
  passing an RSA-style encryption test it cannot run. On 9.3.7 the failure carried kimbo11ng's
  explanation; on 9.6.3 EJBCA wraps every token in a wrapper that skips the token's own test, so the
  message is EJBCA's (see [docs/EJBCA_UPSTREAM_WATCH.md](docs/EJBCA_UPSTREAM_WATCH.md), W3).
- **Verification.** The provider signs; it does not verify. EJBCA verifies with BouncyCastle from
  the public key, so `Signature.initVerify` through this provider is refused by name.
- **Symmetric encryption.** There is no `Cipher` service, so the token's AES mechanisms are not
  reachable from here. Only the HMAC key types above are offered.
- **Certificates on the token.** `KeyStore.getCertificate` returns null, deliberately and without
  asking the token: EJBCA keeps issued certificates in its database, a PKCS#11 chain could not be
  reconstructed from unordered objects anyway, and answering from memory keeps EJBCA's
  per-key-generation cache rebuild free. This is a design decision, not a gap.

## Command-line tool

EJBCA Community ships one PKCS#11 key tool, `clientToolBox PKCS11HSMKeyTool`, and it goes through
SunPKCS11 — its key specifications are RSA, an EC curve, or `DSAnnnn`. Install kimbo11ng for
post-quantum keys and you have a key-management CLI that cannot see the keys you installed it for.
`kimbo11ng-cli` closes that gap. Keyfactor closed the same one in Enterprise with `p11ng-cli`;
[docs/P11NG_CLI_SURFACE.md](docs/P11NG_CLI_SURFACE.md) records the published evidence behind every
command name and option spelling here.

Every command that touches a key drives the same `CryptoTokenImpl` EJBCA loads, so what the tool
reports is what the CA will see — it does not model the crypto token, it runs it.

The tool lives inside the image, on `PATH`. That is not a convenience: the PKCS#11 module, its
OpenSSL, `LD_LIBRARY_PATH` and the token state exist only in the container. It picks its module the
way the server does, by sourcing `docker/environment-hsm`, so it follows a side-mounted Thales Luna
client automatically and needs no `--lib-file` in the common case.

```bash
docker compose exec ejbca kimbo11ng-cli                 # the command list
docker compose exec ejbca kimbo11ng-cli listslots       # no PIN, no slot, no library needed
just cli-token capabilities --slot-ref SLOT_LABEL --slot TestToken
```

| Command | What it answers |
| --- | --- |
| `listslots`, `showinfo`, `showslotinfo`, `showtokeninfo` | does the library load, does the slot exist, is the PIN locked — none of which needs a credential |
| `capabilities` | which algorithms this token can actually do, and the profile kimbo11ng resolves for it |
| `listkeypairs` | the alias list EJBCA will show, built by the key store the CA reads |
| `listobjects`, `showobjectattributes` | the raw PKCS#11 objects behind those aliases, with `CKA_SENSITIVE` and `CKA_EXTRACTABLE` |
| `generatekeypair`, `generatekey`, `deleteobject` | the key lifecycle, post-quantum included |
| `testkeypair` | sign and verify once, the check `HsmKeepAliveWorker` runs on a schedule |
| `signperformancetest` | throughput and per-signature latency |

`capabilities` is the one with no Enterprise counterpart. The verdict it prints — *"Effective
algorithms for profile 'pkcs11v32' (18/18 usable)"* — is today only readable in the WildFly log,
after the crypto token has been created and EJBCA has already tried to use it. As a command it is a
pre-flight check that needs no PIN.

`signperformancetest` earns its place on SLH-DSA, where the figure is not published by anyone and
is what decides whether an HSM can serve a CA at a given issuance rate. Measured on the SoftHSMv3 in
this image, single-threaded:

| Algorithm | Signings/s | Per signature |
| --- | --- | --- |
| ML-DSA-65 | 3001 (2 threads) | 0.67 ms |
| SLH-DSA-SHA2-128S | 7.25 | 140 ms |

`kimbo11ng-cli <command> --help` is the option reference, and it is generated from the same
declaration list the parser validates against, so the two cannot drift. Four options are common to
every command that opens a slot — `--lib-file`, `--slot-ref`, `--slot`, `--property` — and
`--password` is added by the ones that log in. A PIN given as `--password` is visible in `ps`; omit
it and the tool prompts.

The launcher reads four variables, none of them required inside the image:

| Variable | Effect |
| --- | --- |
| `KIMBO11NG_LIB_FILE` | Supplies `--lib-file` when the command line omits it. Set by `environment-hsm` in the image, so `--lib-file` is only ever typed on a host or to override the discovered module. |
| `KIMBO11NG_CLASSPATH` | Names the classpath outright; nothing else is guessed. |
| `EJBCA_HOME` | An EJBCA install elsewhere on the machine, whose jars the CLI then runs against — so the tool and the CA cannot disagree about what the token supports. |
| `LUNA_CRYPTOKI` | Read from `environment-hsm`: when a Thales Luna client is side-mounted its module wins over SoftHSMv3, the same order `init-hsm.sh` applies. |

Failing all of those, `cli/kimbo11ng-cli.sh` falls back to a checkout's `target/`. `just cli` runs it
from the build tree, `just cli-token` inside the running container.

Not implemented: the Utimaco CP5 key-authorisation commands (`initializekey`, `authorizekey`,
`unblockkey`, `backupobject`, `restoreobject`) — vendor extensions with no hardware here to develop
or verify against.

## EJBCA CE 9.6 and the HSM overlay

EJBCA Community Edition 9.6 refuses to start when its database holds a crypto token that is not Soft
or Null, and that includes `Pkcs11NgCryptoToken`. `docker/Dockerfile` therefore builds an overlay
into the image ([docker/ejbca-hsm/](docker/ejbca-hsm/README.md)):

- the one method that enforces the check is emptied in Keyfactor's own `ejbca-ejb.jar`, by a
  bytecode patch that fails the build if the method is not where it expects it. Measured on 9.6.3:
  with the patch the CA starts with a `Pkcs11NgCryptoToken` in the database; with the stock jar, the
  same image and database refuse with *"EJBCA Community Edition does not support HSM crypto tokens"*;
- the classic `PKCS11CryptoToken` and `AzureCryptoToken`, which 9.6 removed, are restored from their
  last Community Edition sources (adapted by [ejbca-custom](https://github.com/3keyroman/ejbca-custom)).
  kimbo11ng does not need them; they are there so existing SunPKCS11 tokens keep working. Checked
  on 9.6.3 against SoftHSMv3: create, generate an RSA key and test it.

**The image is for local use and must not be published**: it contains a modified Keyfactor jar and
LGPL code, on top of base jars whose source Keyfactor does not publish. See
[docker/ejbca-hsm/NOTICE](docker/ejbca-hsm/NOTICE).

## Prerequisites

- Docker
- [just](https://github.com/casey/just) command runner
- Maven 3.8+ and JDK 21+ to build. The artifact targets Java 21, which is the runtime of the pinned
  EJBCA image (`keyfactor/ejbca-ce:9.6.3` runs OpenJDK 21; the 9.3.7 line ran 17). The target moves with
  the image — see [docs/EJBCA_UPSTREAM_WATCH.md](docs/EJBCA_UPSTREAM_WATCH.md#compile-target)

## Quick Start

```bash
# Full pipeline: setup + build Docker image + start + provision token + integration tests
just ci

# Or step by step:
just setup          # extract JARs from EJBCA image + install + build
just docker-build   # build Docker image (EJBCA + softhsmv3 + kimbo11ng)
just up             # start EJBCA + PostgreSQL (host ports 8080/8443/9443)
just create-token   # provision TestHSM as Pkcs11NgCryptoToken (restarts EJBCA, waits until it is back)

# Admin UI: https://localhost:8443/ejbca/adminweb/  — HTTPS, and accept the self-signed certificate.
# The plain-HTTP port (8080) answers "Authorization Denied": the UI needs the TLS session. This dev
# stack sets EJBCA_ADMIN_ALLOW_ANY_IP, so anyone who reaches the HTTPS port is a super administrator.
# Do not expose it beyond your own machine.

# Port 8080, 8443 or 9443 already taken? Move the host side; the container is unchanged.
# Shell variables work, and so does a git-ignored `.env` next to docker-compose.yml:
echo 'EJBCA_HTTP_PORT=18080
EJBCA_HTTPS_PORT=18443
EJBCA_RA_PORT=19443' > .env

# Run integration tests (Testcontainers — starts a fresh stack automatically)
mvn verify -Pit
```

## Version Matrix

All versions are centralized in the `justfile`. Run `just versions` to display:

OpenSSL and SoftHSMv3 are compiled from source, but not on every image build — they live in
`ghcr.io/thpham/ejbca-ce-toolchain`, built by `docker/Dockerfile.toolchain` and consumed by
`docker/Dockerfile`. Bumping either version means republishing that image
(`gh workflow run toolchain.yml`, or `just toolchain-build` locally) and then pointing the
`TOOLCHAIN` argument at the new digest. `just docker-build` prefers a local image of the
matching tag, so `just toolchain-build` is also how to build with no access to GHCR.

```
EJBCA:     9.6.3 (keyfactor/ejbca-ce:9.6.3@sha256:ef574ed81c1e2bb335902f1097b09f9408fe32f2c3abbccfe80999d1c9b50164)
OpenSSL:   3.6.0
SoftHSMv3: v0.28.1 (pqctoday-org/pqctoday-hsm)
Toolchain: ghcr.io/thpham/ejbca-ce-toolchain:openssl3.6.0-softhsmv0.28.1
Artifact:  kimbo11ng-jar-with-dependencies.jar

Dependencies:
  com.keyfactor:cryptotokens-api:4.1.0
  com.keyfactor:cryptotokens-impl:4.1.0
  org.pkcs11:jacknji11:1.3.1
  org.cesecore:cesecore-common:9.6.3
  com.keyfactor:x509-common-util:5.11.1
```

To upgrade EJBCA, update `ejbca_version`, `ejbca_digest` and `ejbca_deps` in the justfile and the
matching `FROM` in `docker/Dockerfile` — the base image is pinned by digest in both places so that
the JARs extracted for the build and the image they run in are the same bytes — and move
`maven.compiler.release` to the new image's Java version. What to check first, and what has broken
before, is in [docs/EJBCA_UPSTREAM_WATCH.md](docs/EJBCA_UPSTREAM_WATCH.md);
`scripts/api-diff.sh OLD_LIB NEW_LIB` compares the EJBCA API surface between two releases. Then:

```bash
just extract-jars-fresh setup docker-build
mvn verify -Pit
```

## Build Recipes

| Recipe                    | Description                                                                 |
| ------------------------- | --------------------------------------------------------------------------- |
| `just setup`              | Extract EJBCA JARs + install to Maven + build                               |
| `just build`              | Build the fat JAR, gates included (`mvn clean verify`)                      |
| `just build-quick`        | Package with no clean, tests or gates — for `just deploy` iteration only    |
| `just test`               | Unit tests + every build gate, no Docker needed                             |
| `just mutation`           | Mutation testing (PIT): which deliberate bugs the unit tests miss, ~8 min   |
| `just it`                 | The above plus the integration suite — run `just docker-build` first        |
| `just it-only`            | Integration tests alone, skipping the unit suite and the gates              |
| `just cli`                | Run the command-line tool from the build tree                               |
| `just cli-token`          | Run it inside the container, against the SoftHSMv3 slot                     |
| `just deploy`             | Hot-reload JAR into running EJBCA container                                 |
| `just docker-build`       | Build Docker image (EJBCA + softhsmv3 + kimbo11ng)                          |
| `just toolchain-build`    | Compile the OpenSSL + SoftHSMv3 base image locally (minutes; offline path)  |
| `just up` / `just down`   | Start / stop services                                                       |
| `just create-token`       | Provision TestHSM as Pkcs11NgCryptoToken (idempotent)                       |
| `just luna-up`            | Start the stack with a side-mounted Thales Luna client (optional)           |
| `just luna-status`        | Report what the container makes of the mounted Luna client                  |
| `just create-luna-token`  | Provision a Pkcs11NgCryptoToken bound to a Luna partition                   |
| `just ci`                 | Full pipeline: setup + docker-build + up + create-token + integration tests |
| `just extract-jars-fresh` | Force re-extract JARs (after EJBCA version bump)                            |
| `just versions`           | Show version matrix                                                         |
| `just status`             | Show versions, git log, Docker, and artifact status                         |
| `just clean-all`          | Remove build artifacts and extracted deps                                   |

## Test coverage

**Unit tests** (`mvn verify`, no Docker) run against `FakeToken`, an in-memory PKCS#11 v3.2 token at
the JNA `NativeProvider` seam. It enforces per-session operation state as a real token does, and can
misbehave on demand — drop sessions mid-operation, report `CKA_EC_POINT` raw instead of DER-wrapped,
hide or under-report a mechanism, refuse an attribute write.

- The full algorithm matrix above, each generated, re-enumerated, and accepted by EJBCA's own
  `AlgorithmTools.getSignatureAlgorithms`
- Every registered signature algorithm signed on the token and verified with BouncyCastle,
  including through `JcaContentSignerBuilder` — the path EJBCA uses to sign a certificate
- 32-thread sign/enumerate/generate/delete mix under injected session death
- Every `PqcMechanismProfile` against `ProfileConformanceKit`, including one whose key types and
  mechanisms disagree with the standard entirely — the fake is rebuilt from the profile's own
  constants, so a vendor table is proved end to end and not merely for self-consistency
- Build gates: enforcer, duplicate-finder, SpotBugs + findsecbugs, JaCoCo floor, `-Werror`

**Mutation testing** (`just mutation`, PIT) asks the question coverage cannot: would a test fail if
this line were wrong? It is deliberately outside `verify` and has no threshold yet. The first run
(1506 mutants, 68% killed) found real gaps, several now closed: a leaked session-pool permit, a
`Signature` that carried the previous message into the next signature, and EC point prefixes that
nothing checked. Read survivors before acting on them. Some are equivalent mutants, and some mean
`FakeToken` is more forgiving than a real HSM — in that case fix the fake and add the case to
`HsmContract`, which also runs against SoftHSMv3. The report is `target/pit-reports/index.html`.

**Fuzz and refusal tests.** `EcPointFuzzTest` throws bent and arbitrary bytes at the two
`EcPointCodec` entry points and holds them to a total contract: every input yields either a point on
the curve or an `InvalidKeyException`, never an unchecked one. Seeds are fixed, so a failure is
reproducible and PIT sees a stable suite. It found one: a constructed BIT STRING with an out-of-range
pad-bit count makes BouncyCastle throw `ASN1ParsingException`, which extends `IllegalStateException`
and so escaped a catch of `IOException | IllegalArgumentException` — out through
`PublicKeyReader.readEcPublicKey`, where it would have aborted enumeration of every alias on the slot
over one malformed key. `just patcher-test` does the same for the image build's bytecode patcher:
synthetic classes with the start-up check renamed, gutted or duplicated, each of which it must refuse
by name.

**Integration tests** (`EjbcaContainerIT`) run against a full EJBCA CE stack managed by
Testcontainers:

- PKCS#11 key generation: RSA, EC, ML-DSA, ML-KEM, SLH-DSA
- Root CAs at ML-DSA-44, ML-DSA-65, ML-DSA-87, SLH-DSA-SHA2-128F, EC P-384, RSA-PSS and Hybrid
  (RSA + ML-DSA alternative), each issuing a certificate whose signature algorithm OID is checked
- `cryptotoken testkey` for each signing algorithm, and its refusal for ML-KEM
- A token created through EJBCA's own CLI is stored as `Pkcs11NgCryptoToken`, and the restored classic
  `PKCS11CryptoToken` creates, generates and tests a key (the HSM overlay, on 9.6)

`scripts/upgrade-swap.sh OLD_IMAGE NEW_IMAGE` covers what none of these can, because they all start
from an empty database: it starts the new image on an old deployment's database and token, and passes
only if the CA signs again with the same keys.

**CLI integration tests** (`CliContainerIT`) run the tool from `PATH` inside the same image, against
real SoftHSMv3 — RSA, RSA-PSS, EC, ML-DSA and a symmetric key, each generated, signed with,
inspected and deleted. The container is started with `sleep infinity` and no application server ever
boots, which is the assertion rather than an optimisation: the tool's claim is that it answers
"does this HSM work" before EJBCA is in the picture. It costs seconds rather than the minutes a full
stack takes, and it is the only place three things are covered — the launcher finding its classpath,
module discovery through `environment-hsm`, and the crypto provider being installed, without which
every post-quantum algorithm reports as excluded.

```bash
mvn verify               # 813 unit tests + 5 artifact tests, no Docker (~2 min)
mvn verify -Pit          # + 26 EJBCA + 23 CLI integration tests (~5 min)

# The concurrency soak: 100 consecutive fault-injection runs
mvn test -Dtest='ConcurrentTokenAccessTest#survivesInjectedFaults' -Dkimbo11ng.soak.runs=100

# Against real hardware: the same contract HsmContractFakeTest runs on every build.
# Skipped when kimbo11ng.it.lib is absent. Adding kimbo11ng.it.luna.jsp additionally runs the
# cross-check — both stacks on one partition, each reading the other's keys, which is the only
# test here that can falsify a vendor profile table.
mvn verify -Pit -Dkimbo11ng.it.lib=/usr/local/luna/libs/64/libCryptoki2.so \
                -Dkimbo11ng.it.slotType=SLOT_LABEL -Dkimbo11ng.it.slot=my-partition \
                -Dkimbo11ng.it.pin=userpin \
                -Dkimbo11ng.it.luna.jsp=/usr/local/luna/jsp/LunaProvider.jar
```

Integration tests require Docker. The test image is built by `just docker-build`; a hot-reloaded
JAR (`just deploy`) only patches the dev stack, not the image the ITs start from.

## Configuration

Beyond the standard EJBCA token properties (`sharedLibrary`, `slotLabelValue`, `slotLabelType`,
`doNotAddP11Provider`, `tokenFriendlyName`):

| Property                               | Default | Effect                                                             |
| -------------------------------------- | ------- | ------------------------------------------------------------------ |
| `kimbo11ng.sessions.max`               | 8       | Session pool ceiling                                                |
| `kimbo11ng.sessions.borrowTimeoutSeconds` | 30   | Wait before a borrow reports the token offline                      |
| `kimbo11ng.pqc.profile`                | (auto)  | Force a `PqcMechanismProfile` by name instead of probing            |
| `kimbo11ng.probe.failFast`             | true    | Refuse an algorithm whose mechanism the token does not advertise    |
| `kimbo11ng.keyid.backfill`             | true    | Write a `CKA_ID` onto legacy keys that have none                    |
| `kimbo11ng.strict.publickey`           | false   | Make an OID disagreement fatal when enumerating existing keys       |
| `kimbo11ng.pqc.kemUsage`               | both    | ML-KEM usage attributes: `both`, `v32` only, or `legacy` only        |

`kimbo11ng.pqc.kemUsage` is worth a word, because the default sends two pairs and that looks like
indecision until you see who reads them.

`CKA_ENCAPSULATE` (0x633) and `CKA_DECAPSULATE` (0x634) are what PKCS#11 v3.2 defines for a
key-encapsulation key, and what a v3.2 token gates `C_EncapsulateKey` and `C_DecapsulateKey` on.
Until 2026-09-05 this project asked only for `CKA_ENCRYPT` and `CKA_DECRYPT` — a different and
untrue claim, since ML-KEM has no `C_Encrypt`. It went unnoticed because SoftHSMv3 accepts the wrong
pair and then quietly sets the right one itself.

But `CKA_DECRYPT` cannot simply be dropped: **EJBCA reads it by number**. `BaseCryptoToken.testKeyPair`
branches on `contains(261) && !contains(264)`, and `getKeyUsageStringForKeyPairInfo` compares the
usage set for equality against `{261}` to decide the admin UI shows ENCRYPT. Neither knows 0x634, so
a spec-correct key with no `CKA_DECRYPT` shows no usage in the UI and gets routed to the signing
test. Hence `both`.

Set `v32` for a token strict enough to refuse `CKA_ENCRYPT` on a KEM key — defensible of it, at the
cost of the EJBCA reporting above. Set `legacy` for one that refuses the attributes it has never
heard of. Both branches are covered by `CliContainerIT` against real SoftHSMv3.

## Project Structure

```
kimbo11ng/
  src/
    main/java/
      ch/ithings/kimbo11ng/          # Core implementation
        p11/                         # Module lifecycle, session pool, capability probe
        provider/                    # JCA provider, KeyStore, Signature, KeyPairGenerator SPIs
        profile/                     # PQC mechanism profiles (v3.2, Thales, ...)
        slot/                        # PKCS#11 slot enumeration
      org/cesecore/.../              # EJBCA entry point (thin delegate)
      com/keyfactor/.../             # EJBCA SPI factory (thin delegate)
    test/java/
      ch/ithings/kimbo11ng/          # Unit tests
        fake/                        # FakeToken: in-memory PKCS#11 v3.2 token with fault knobs
    it/java/
      ch/ithings/kimbo11ng/it/       # Integration tests (EjbcaContainerIT — 26 tests,
                                     #   HsmConformanceIT — real-hardware contract)
    it/openapi/
      ejbca-api.json                 # EJBCA CE REST API spec (OpenAPI)
  docker/                            # Dockerfile, softhsmv3 config, optional Luna discovery
  docker/ejbca-hsm/                  # EJBCA 9.6 overlay: start-up check patcher + restored classic tokens (LGPL, see NOTICE)
  scripts/api-diff.sh                # EJBCA API-surface diff between two releases, run on a version bump
  docs/                              # Design notes; EJBCA_UPSTREAM_WATCH.md tracks upstream behaviour
  docker-compose.luna.yml            # Overlay for a side-mounted Thales Luna client (optional)
  deps/ejbca/                        # Extracted EJBCA JARs (gitignored)
  pom.xml                            # Maven build (ch.ithings:kimbo11ng)
  justfile                           # Build automation recipes
  docker-compose.yml                 # EJBCA + PostgreSQL stack
```

## License

[Apache License 2.0](LICENSE) — Copyright (c) 2026 Thomas Pham.

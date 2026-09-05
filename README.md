# kimbo11ng

Open-source PKCS#11 NG CryptoToken for [EJBCA CE](https://www.ejbca.org/) with post-quantum cryptography support.

Backed by [JackNJI11](https://github.com/joelhockey/jacknji11) (MIT-licensed JNA PKCS#11 bindings —
see [provenance](docs/JACKNJI11_PROVENANCE.md)) and tested against
[softhsmv3](https://github.com/pqctoday/softhsmv3) with OpenSSL 3.6+.

## Features

- Drop-in `Pkcs11NgCryptoToken` for EJBCA CE 9.3.7
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
| ML-DSA    | ML-DSA-44, ML-DSA-65, ML-DSA-87              | generate, sign         | FIPS 204        |
| ML-KEM    | ML-KEM-512, ML-KEM-768, ML-KEM-1024          | generate, enumerate    | FIPS 203        |
| SLH-DSA   | SHA2/SHAKE x 128/192/256 x S/F (12 variants) | generate, sign         | FIPS 205        |
| Hybrid    | RSA/EC primary + ML-DSA/SLH-DSA alternative  | issue certificates     | X.509 Sec. 9.8  |

### Signature algorithms registered by the JCA provider

`SHA{1,256,384,512}withRSA`, `SHA{256,384,512}withRSAandMGF1`, `SHA{1,256,384,512}withECDSA`, and
one service per signing algorithm in the active profile (`ML-DSA-44` … `SLH-DSA-SHAKE-256F`). A
service is registered only if the token advertises its mechanism with the matching `CKF_*` flag.

### What is not supported

- **ML-KEM is generation and enumeration only.** It has no signature or KEM operation here: EJBCA
  CE has no key-encapsulation path, and `cryptotoken testkey` on an ML-KEM alias is refused with an
  explanation rather than being run through an RSA-style encryption test that cannot succeed.
- **Verification.** The provider signs; it does not verify. EJBCA verifies with BouncyCastle from
  the public key, so `Signature.initVerify` through this provider is refused by name.
- **Symmetric keys.** `generateKey` throws.
- **Certificates on the token.** `KeyStore.getCertificate` returns null without a round trip;
  EJBCA keeps issued certificates in its database.

## Prerequisites

- Docker
- [just](https://github.com/casey/just) command runner
- Maven 3.8+ and JDK 21+ to build (the artifact targets Java 17, which is what EJBCA 9.3.7 runs;
  the compiler has to be 21 or newer for the `this-escape` lint category the warning gate excludes)

## Quick Start

```bash
# Full pipeline: setup + build Docker image + start + provision token + integration tests
just ci

# Or step by step:
just setup          # extract JARs from EJBCA image + install + build
just docker-build   # build Docker image (EJBCA + softhsmv3 + kimbo11ng)
just up             # start EJBCA + PostgreSQL
just create-token   # provision TestHSM as Pkcs11NgCryptoToken

# Run integration tests (Testcontainers — starts a fresh stack automatically)
mvn verify -Pit
```

## Version Matrix

All versions are centralized in the `justfile`. Run `just versions` to display:

```
EJBCA:     9.3.7 (keyfactor/ejbca-ce:9.3.7)
OpenSSL:   3.6.0
SoftHSMv3: v0.28.1 (pqctoday-org/pqctoday-hsm)
Artifact:  kimbo11ng-jar-with-dependencies.jar

Dependencies:
  com.keyfactor:cryptotokens-api:3.0.0
  com.keyfactor:cryptotokens-impl:3.0.0
  org.pkcs11:jacknji11:1.3.1
  org.cesecore:cesecore-common:9.3.7
  com.keyfactor:x509-common-util:5.3.5
```

To upgrade EJBCA, update `ejbca_version` and `ejbca_deps` in the justfile, then:

```bash
just extract-jars-fresh setup docker-build
mvn verify -Pit
```

## Build Recipes

| Recipe                    | Description                                                                 |
| ------------------------- | --------------------------------------------------------------------------- |
| `just setup`              | Extract EJBCA JARs + install to Maven + build                               |
| `just build`              | Build the fat JAR                                                           |
| `just deploy`             | Hot-reload JAR into running EJBCA container                                 |
| `just docker-build`       | Build Docker image (EJBCA + softhsmv3 + kimbo11ng)                          |
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

**Integration tests** (`EjbcaContainerIT`) run against a full EJBCA CE stack managed by
Testcontainers:

- PKCS#11 key generation: RSA, EC, ML-DSA, ML-KEM, SLH-DSA
- Root CAs at ML-DSA-44, ML-DSA-65, ML-DSA-87, SLH-DSA-SHA2-128F, EC P-384, RSA-PSS and Hybrid
  (RSA + ML-DSA alternative), each issuing a certificate whose signature algorithm OID is checked
- `cryptotoken testkey` for each signing algorithm, and its refusal for ML-KEM

```bash
mvn verify               # 583 unit tests + 4 artifact tests, no Docker (~2 min)
mvn verify -Pit          # + 24 integration tests (~4 min)

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
      ch/ithings/kimbo11ng/it/       # Integration tests (EjbcaContainerIT — 24 tests,
                                     #   HsmConformanceIT — real-hardware contract)
    it/openapi/
      ejbca-api.json                 # EJBCA CE REST API spec (OpenAPI)
  docker/                            # Dockerfile, softhsmv3 config, optional Luna discovery
  docker-compose.luna.yml            # Overlay for a side-mounted Thales Luna client (optional)
  deps/ejbca/                        # Extracted EJBCA JARs (gitignored)
  pom.xml                            # Maven build (ch.ithings:kimbo11ng)
  justfile                           # Build automation recipes
  docker-compose.yml                 # EJBCA + PostgreSQL stack
```

## License

[Apache License 2.0](LICENSE) — Copyright (c) 2026 Thomas Pham.

# The P11NG CLI surface, reconstructed from public sources

**Purpose.** kimbo11ng reimplements, in the open, the crypto token Keyfactor ships closed as
"PKCS#11 NG". That product also ships a command-line tool. This document reconstructs that tool's
surface from public evidence, so a kimbo11ng CLI can be specified against something real rather
than invented. It is a research record, not a design: the design decisions it enables are listed at
the end, none of them taken.

Everything here was retrieved on **2026-09-05**. Where a command line or an option list is quoted,
it is verbatim from the cited source; where it is not quoted, it is inference and is marked as such.

## 1. What is public, and what is not

P11NG is proprietary. The finding that shapes this whole document is *how completely* proprietary:

| Artefact | Public? | Evidence |
| --- | --- | --- |
| P11NG implementation source | **No** | `Keyfactor/signserver-ce` (LGPL-2.1) has `org/cesecore/keys/token/` with `PKCS11CryptoToken`, `LegacyPKCS11CryptoToken`, `AzureCryptoToken`, `p11/Pkcs11Wrapper` — and no `p11ng` package. `Keyfactor/ejbca-ce` likewise. |
| The `p11ng` jar | **No** | `signserver/lib/jars-list.txt` line 138 lists `./ext/p11ng-0.25.7.jar` attributed to "Keyfactor Commons", with a SHA-256 — but the file is absent from the repo tree and from the CE binary distribution. Not on Maven Central (`q=p11ng` → 0 hits; group `com.keyfactor` → 0 hits). |
| The CLI binary | **No** | `signserver-ce-7.3.2-bin.zip` (119 MB, from the GitHub release) contains `bin/{ant,randomtest,setstatusinsync.sh,signclient,signserver,stresstest}` and their `.cmd` twins. There is no `bin/p11ng-tool`. |
| P11NG **documentation** | **Yes** | Five HTML pages ship inside SignServer CE itself: `P11NG_CLI.html`, `P11NGCryptoToken.html`, `P11NGKeyWrappingCryptoToken.html`, `P11NGKeyWrappingCryptoWorker.html`, `Migrate_from_SunPKCS11_to_P11NG.html`. Plus the EJBCA docs site. |
| Any open reimplementation | **No** | GitHub repository search for `p11ng` returns 0 results. |

`signserver/res/default_build.properties` states it plainly, in a comment next to
`cryptotoken.p11.usep11ngasp11=false`:

> P11NG is a proprietary enterprise implementation.

So the documentation is the only channel. It turns out to be a generous one: Keyfactor publishes
both CLIs' full option lists and a large number of real invocations in its per-vendor integration
guides.

### Provenance and licence discipline

kimbo11ng is Apache-2.0. Every source used here is either documentation or LGPL-2.1 code
(`ejbca-ce`, `signserver-ce`). Neither may be copied into this project. The rules applied, in the
spirit of [JACKNJI11_PROVENANCE.md](JACKNJI11_PROVENANCE.md):

- **Behaviour and interface** are read and recorded. An option name like `--key-spec` is the
  vocabulary an operator already has in their fingers; matching it is interoperability, and there
  is no other way to be compatible with a documented interface than to implement it.
- **No code and no documentation text** is carried across. Where this document quotes, it quotes as
  evidence and attributes the quote.
- Nothing proprietary was decompiled. The `p11ng` jar was never obtained, which as it turns out was
  not a choice — it is not publicly available.

## 2. There are two different tools

The single most useful finding, and the one a casual search gets wrong: **EJBCA and SignServer ship
different CLIs over the same P11NG library**, with different names, different command grammars and
different feature sets. kimbo11ng targets EJBCA, so the EJBCA one is authoritative here; the
SignServer one is a second data point on what the underlying library can do.

| | EJBCA | SignServer |
| --- | --- | --- |
| Name | `p11ng-cli.sh` | `p11ng-tool` |
| Location | `$EJBCA_HOME/dist/p11ng-cli/`, built with `ant`; "built as a standalone JAR, which can be placed on any machine" | `$SIGNSERVER_HOME/bin/` |
| Grammar | subcommand + GNU long options: `p11ng-cli.sh <command> --lib-file … --slot-ref … --slot …` | single command, action as a value: `p11ng-tool -action <name> -libfile … -slot …` |
| Commands | 16 | 12 actions |
| Focus | key lifecycle, HSM introspection, vendor key-authorisation (Utimaco CP5) | key wrapping, performance testing |
| Availability | Enterprise only | Enterprise only |

Both are **standalone**: they talk to the PKCS#11 library directly and need no running server. That
property, not the command list, is what makes such a tool worth having — it is the only way to
answer "does this HSM work at all" before EJBCA is in the picture.

## 3. EJBCA `p11ng-cli` — the reconstructed surface

### 3.1 The command list

From [P11Ng CLI](https://docs.keyfactor.com/ejbca/latest/p11ng-cli) (page reflects EJBCA 9.6.2; the
9.0 page carries the same list). The tool prints this when run with no arguments; each command
accepts `--help`.

| Command | Documented description |
| --- | --- |
| `listslots` | "Lists slots available on the HSM" |
| `showinfo` | "Shows information about HSM." |
| `showslotinfo` | "Prints information about the slot." |
| `showtokeninfo` | "Prints information about token." |
| `listobjects` | "List objects available on the slot." |
| `showobjectattributes` | lists object attributes — ID, token, sensitive, private, extractable, and the cryptographic-operation flags |
| `generatekeypair` | "Generates a key pair" |
| `generatekey` | "Generates symmetric key on the HSM" |
| `deleteobject` | "Deletes objects." |
| `signperformancetest` | "Runs a signing performance test. Without the `--verify` flag, the test only calls 'initSign, update, sign' using the private key" |
| `onetimeperformancetest` | "Runs a one time performance test generating an RSA key and signing with it." |
| `initializekey` | "Initializes a key prior to authorization. CP5 specific operation." |
| `authorizekey` | "Authorizes a key before it can be used. CP5 specific operation." |
| `unblockkey` | "Unblocks a key previously blocked. CP5 specific operation." |
| `backupobject` | "Backs up a key from the HSM on the backup file. CP5 specific operation." |
| `restoreobject` | "Restores a backed up key from file into the HSM. CP5 specific operation." |

**A seventeenth command exists and is missing from that list: `listkeypairs`.** It appears in three
separate vendor guides as a working invocation (Thales Luna, Crypto4A, the SoftHSM2 container
guide). The reference page is therefore incomplete, which is worth remembering before treating any
absence in it as proof.

### 3.2 Options, as evidenced by real invocations

No page publishes a consolidated option table for `p11ng-cli` — only `--help` does, and `--help`
needs the Enterprise binary. The options below are recovered from invocations Keyfactor publishes.
Every line in this section is verbatim from the cited page.

**Common to nearly every command** — `--lib-file`, `--slot-ref` (`SLOT_NUMBER` | `SLOT_INDEX` |
`SLOT_LABEL`), `--slot`, `--password`. Omitting `--password` makes the tool prompt:
`Enter slot login password:`.

[Thales Luna](https://docs.keyfactor.com/ejbca/latest/thales-luna-hsm):

```
./p11ng-cli.sh listslots --lib-file /usr/safenet/lunaclient/lib/libCryptoki2_64.so
./p11ng-cli.sh listkeypairs --lib-file /usr/safenet/lunaclient/lib/libCryptoki2_64.so --slot-ref SLOT_NUMBER --slot 1 --password btqx-EFGH-3456-7/K9
./p11ng-cli.sh generatekeypair --lib-file /usr/safenet/lunaclient/lib/libCryptoki2_64.so --slot-ref SLOT_NUMBER --slot 1 --alias ecp256 --key-spec P-256
./p11ng-cli.sh generatekeypair --lib-file /usr/safenet/lunaclient/lib/libCryptoki2_64.so --slot-ref SLOT_NUMBER --slot 1 --alias mldsa44 --key-spec ML-DSA-44
./p11ng-cli.sh signperformancetest --lib-file /usr/safenet/lunaclient/lib/libCryptoki2_64.so --slot 1 --alias ecp256 --signature-algorithm SHA256WithECDSA --time-limit 5000
```

[IBM HPCS](https://docs.keyfactor.com/ejbca/latest/ibm-hpcs) — note `--slot-ref SLOT_LABEL` with a
quoted label, `--key-usage`, and the only published sample outputs:

```
./p11ng-cli.sh listslots --lib-file /opt/grep11/pkcs11-grep11-amd64.so
All slots:        [0]
Slots with token: [0]
ID: 0, Label: GREP11 Token

./p11ng-cli.sh generatekeypair --lib-file /opt/grep11/pkcs11-grep11-amd64.so --slot-ref SLOT_LABEL --slot "GREP11 Token" --alias ecp256nr1 --key-spec prime256v1 --key-usage SIGN
Enter slot login password:
Generated key pair with alias ecp256nr1

./p11ng-cli.sh signperformancetest --lib-file /opt/grep11/pkcs11-grep11-amd64.so --slot 0 --alias ecp256nr1 --signature-algorithm SHA256WithECDSA --time-limit 5000
Enter slot login password:
Running signing test with 1 threads using signature algorithm SHA256WithECDSA.
Using cache for reading keys.
Starting thread 0
Number of operations for thread 0: 20
Total number of signings: 20
Signings per second: 2.907399331298154
```

[Crypto4A QxHSM](https://docs.keyfactor.com/ejbca/latest/crypto4a-qxhsm) — the only page exercising
the four introspection commands, and the only one running a performance test against a PQC
algorithm:

```
./p11ng-cli.sh showinfo --lib-file /usr/local/share/lib/c4a-pkcs11/libpkcs11.so
./p11ng-cli.sh showslotinfo --lib-file /usr/local/share/lib/c4a-pkcs11/libpkcs11.so --slot 5
./p11ng-cli.sh showtokeninfo --lib-file /usr/local/share/lib/c4a-pkcs11/libpkcs11.so --slot 5
./p11ng-cli.sh listobjects --lib-file /usr/local/share/lib/c4a-pkcs11/libpkcs11.so --slot-ref SLOT_NUMBER --slot 5
./p11ng-cli.sh listkeypairs --lib-file /usr/local/share/lib/c4a-pkcs11/libpkcs11.so --slot-ref SLOT_NUMBER --slot 5
./p11ng-cli.sh generatekeypair --lib-file /usr/local/share/lib/c4a-pkcs11/libpkcs11.so --slot-ref SLOT_NUMBER --slot 5 --alias mldsa44_1 --key-spec ML-DSA-44
./p11ng-cli.sh signperformancetest --lib-file /usr/local/share/lib/c4a-pkcs11/libpkcs11.so --slot 5 --alias mldsa44_1 --signature-algorithm ML-DSA-44 --time-limit 5000
```

[Utimaco CryptoServer CP5](https://docs.keyfactor.com/ejbca-software/latest/utimaco-cryptoserver-cp5)
— the CP5 key-authorisation options, which exist nowhere else:

```
$EJBCA_HOME/dist/p11ng-cli/p11ng-cli.sh generatekeypair --lib-file ./libcs_pkcs11_R2.so --slot-ref SLOT_INDEX --slot 0 --alias signKey --key-spec RSA2048 --key-usage SIGN
$EJBCA_HOME/dist/p11ng-cli/p11ng-cli.sh initializekey --lib-file ./libcs_pkcs11_R2.so --slot-ref SLOT_INDEX --slot 0 --alias signKey --user USR_0000 --padding-scheme PKCS1 --kak-size 2048 --kak-file-path ~/kak
$EJBCA_HOME/dist/p11ng-cli/p11ng-cli.sh authorizekey --lib-file ./libcs_pkcs11_R2.so --slot-ref SLOT_INDEX --slot 0 --alias signKey --user USR_0000 --padding-scheme PKCS1 --kak-file-path ~/kak
$EJBCA_HOME/dist/p11ng-cli/p11ng-cli.sh listobjects --lib-file ./libcs_pkcs11_R2.so --slot-ref SLOT_INDEX --slot 0
```

[SoftHSM2 container automation](https://docs.keyfactor.com/container/latest/ejbca/deploy-ejbca-as-ca-with-automation-with-softhsm2)
— the tool used as intended, in an init script, with an idempotency check:

```
common_args="--password $CONFIGDUMP_CA_TOKEN_PASSWORD --lib-file /opt/keyfactor/p11proxy-client/p11proxy-client.so --slot-ref SLOT_LABEL --slot Token-1"
p11ng-cli.sh listkeypairs $common_args
p11ng-cli.sh generatekeypair $common_args --key-spec RSA2048 --alias signkey001
p11ng-cli.sh generatekeypair $common_args --key-spec RSA2048 --alias defaultkey001 --key-usage SIGN_ENCRYPT
```

Consolidated:

| Option | Values seen | Commands |
| --- | --- | --- |
| `--lib-file <path>` | absolute or relative `.so` | all |
| `--slot-ref <type>` | `SLOT_NUMBER`, `SLOT_INDEX`, `SLOT_LABEL` | all but `listslots`, `showinfo` |
| `--slot <value>` | number, index, or quoted label | all but `listslots`, `showinfo` |
| `--password <pin>` | literal; prompts when omitted | all that log in |
| `--alias <name>` | | `generatekeypair`, `generatekey`, `signperformancetest`, CP5 commands |
| `--key-spec <spec>` | `RSA2048`, `P-256`, `prime256v1`, `ML-DSA-44` | `generatekeypair` |
| `--key-usage <usage>` | `SIGN`, `SIGN_ENCRYPT` | `generatekeypair` |
| `--signature-algorithm <alg>` | `SHA256WithECDSA`, `ML-DSA-44` | `signperformancetest` |
| `--time-limit <ms>` | `5000` | `signperformancetest` |
| `--verify` | flag | `signperformancetest` |
| `--user`, `--padding-scheme`, `--kak-size`, `--kak-file-path` | `USR_0000`, `PKCS1`, `2048`, path | CP5 only |

**Options not evidenced, and therefore unknown**: everything for `generatekey`, `deleteobject`,
`showobjectattributes` and `onetimeperformancetest`. No page shows an invocation of any of them.
The thread-count option that the SignServer tool spells `-threads` almost certainly exists here too
— the sample output says "Running signing test with 1 threads" — but its spelling is not
published. Marked as inference.

### 3.3 Semantics recorded along the way

Three conventions matter more than the option names, because they determine whether keys created by
one tool are visible to another.

**The alias is `CKA_ID`, and labels are prefixed.** From
[Generic PKCS#11 Provider](https://docs.keyfactor.com/ejbca/latest/generic-pkcs-11-provider): P11NG
"prefers private/public key objects"; `CKA_ID` "must match in the private and public key objects —
this binds them together, and is used as the alias in the crypto token's key list"; `CKA_LABEL` is
"not strictly required, but set to `pub-<alias>` and `priv-<alias>` when generating keys with EJBCA
or p11ng-cli".

**Certificate objects are how SunPKCS11 sees keys, and P11NG can omit them.** SignServer's
`GENERATE_CERTIFICATE_OBJECT` (default `true`) creates "a certificate object with a self-signed
dummy certificate", which is "the same as when generating a key pair with … any other Java
application using the SunPKCS11 provider". The migration guide states the consequence: "If keys have
been generated with `GENERATE_CERTIFICATE_OBJECT=false` … these keys will not be visible if
reverting back to SunP11." The SignServer CLI exposes this as `-nocertificateobject` / `-selfcert` /
`-selfsigneddn`.

*This applies to us today.* [KeyTemplates](../src/main/java/ch/ithings/kimbo11ng/provider/KeyTemplates.java)
creates `CKO_PUBLIC_KEY`, `CKO_PRIVATE_KEY` and `CKO_SECRET_KEY` objects and never a
`CKO_CERTIFICATE`. kimbo11ng keys are therefore invisible to SunPKCS11 — a one-way door that is
correct for our design and undocumented in our README.

**Key-generation attributes are configurable, per object class and key type.** P11NGCryptoToken's
`ATTRIBUTE.x.y.z` property, where `x` ∈ {`PUBLIC`, `PRIVATE`}, `y` is the key type (`RSA`, `ECDSA`,
`EdDSA`, …) and `z` is an attribute name, a decimal ID, or a `0x`-prefixed hex ID:

```
ATTRIBUTE.PRIVATE.RSA.CKA_SENSITIVE = true
ATTRIBUTE.PRIVATE.RSA.CKA_EXTRACTABLE = false
ATTRIBUTE.PRIVATE.RSA.0X0000010C=FALSE
ATTRIBUTE.PRIVATE.RSA.CKA_ALLOWED_MECHANISMS=CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS, 0x00000043, CKM_RSA_PKCS_PSS
```

`CKA_ALLOWED_MECHANISMS` is called out as the exception that "currently cannot be specified in
decimal or hexadecimal form". This is the format behind SignServer's `-attributes_file`; whether
EJBCA's `p11ng-cli` accepts an equivalent is **not documented**.

**Symmetric key algorithms have an escape hatch.** P11NGCryptoToken accepts a standard Java name
(`AES`, `DES`), a `SEC:`-prefixed unknown name (`SEC:Blowfish`), or a `SEC:`-prefixed mechanism
number in decimal or hex (`SEC:4224`, `SEC:0x00001080`, both being `CKM_AES_KEY_GEN`). Our
[SecretKeyType](../src/main/java/ch/ithings/kimbo11ng/provider/SecretKeyType.java) table is closed
by design; this is the shape an escape hatch would take if we ever wanted one.

**Vendor quirks worth carrying into [VENDOR_PROFILE_CHECKLIST.md](VENDOR_PROFILE_CHECKLIST.md).**
AWS CloudHSM needs `GENERATE_CERTIFICATE_OBJECT=false`. GCP KMS supports neither key generation nor
wrapping nor certificate-chain import. Thales TCT requires `CKA_VERIFY=true` on RSA public keys,
"the reason behind this is currently unknown". Utimaco SecurityServer V4.10.0 in FIPS mode requires
`CKA_ALLOWED_MECHANISMS` to name the PSS mechanisms explicitly. IBM HPCS rejects sign-only RSA with
`TEMPLATE_INCONSISTENT`. And P11NG's own known limitation: sessions are reused and never closed, so
`CKA_TOKEN=false` objects accumulate until `CKR_DEVICE_MEMORY`.

## 4. SignServer `p11ng-tool` — the second data point

Full option list, verbatim from `P11NG_CLI.html` as shipped inside SignServer CE 7.3.2. The page
opens with a caveat worth keeping: "The tool is provided for troubleshooting purposes and the API is
likely to change in future versions."

```
-action <arg>               Operation to perform. Any of: [listSlots, showInfo, listObjects,
                            listKeyStoreEntries, generateKey, generateAndWrapKeyPair,
                            unwrapAndSign, deleteKeyStoreEntryByAlias, deleteObjects,
                            generateKeyPair, signPerformanceTest, unwrapPerformanceTest]
-alias <arg>                Key alias
-attributes_file <arg>      Path of file containing attributes to be used while generating key pair
-libfile <arg>              Shared library path
-method <arg>               Method to use, either pkcs11 (default) or provider
-nocertificateobject        Don't create a certificate object when generating a key.
-object <arg>               Object ID (decimal)
-pin <arg>                  User PIN
-plaintext <arg>            text string to sign
-privatekey <arg>           base64 encoded encrypted (wrapped) private key
-publickey <arg>            base64 encoded public key
-selfcert                   Generate a self-signed certificate for the new key-pair
-selfsigneddn <arg>         DN to use as issuer and subject DN in the self-signed certificate
-signaturealgorithm <arg>   default: SHA256withRSA
-slot <arg>                 Slot ID to operate on
-threads <arg>              default: 1
-timelimit <arg>            Only run for the specified time (in milliseconds)
-unwrapkey <arg>            Label of key to unwrap with
-use_cache <arg>            Whether key objects are fetched from cache instead of HSM token (default: true)
-warmuptime <arg>           Don't count signings until after this time (ms). Default=0
-wrapkey <arg>              Label of key to wrap with
```

Three things it has that EJBCA's tool does not:

- **`-method pkcs11|provider`** — run the same operation through raw PKCS#11 or through the JCA
  provider. This is the single most interesting idea in either tool for us, because kimbo11ng has
  exactly that duality ([P11Slot](../src/main/java/ch/ithings/kimbo11ng/p11/P11Slot.java) /
  `CryptokiE` underneath, [Kimbo11ngProvider](../src/main/java/ch/ithings/kimbo11ng/provider/Kimbo11ngProvider.java)
  on top) and no way to test one against the other from outside the JVM.
- **`listKeyStoreEntries` alongside `listObjects`** — the alias view versus the raw-object view,
  which is precisely the distinction that makes PKCS#11 debugging hard. EJBCA's `listkeypairs` is
  the same idea.
- **The wrapping actions** — `generateAndWrapKeyPair`, `unwrapAndSign`, `unwrapPerformanceTest`, and
  `generateKey` whose documented purpose is producing a wrap key (`-alias wrapkey1`).

That last group is out of scope for kimbo11ng and was already settled: EJBCA never calls
`C_WrapKey`/`C_UnwrapKey`, and every kimbo11ng key is `CKA_EXTRACTABLE=false`, which answers
`CKR_KEY_UNEXTRACTABLE`. Key wrapping is a SignServer worker model, not an EJBCA one.

## 5. The CE baseline: what EJBCA users already have

`keyfactor/ejbca-ce:9.3.7` ships `dist/clientToolBox/clientToolBox.jar` containing
`org.ejbca.ui.cli.HSMKeyTool`, whose source is public in `Keyfactor/ejbca-ce` at
`modules/clientToolBox/src/org/ejbca/ui/cli/HSMKeyTool.java`. Invoked as
`ejbcaClientToolBox.sh PKCS11HSMKeyTool <command>`, it prints:

```
generate  batchgenerate  certreq  installcert  delete  test  rename
encrypt  decrypt  sign  verify  move  linkcert
```

(plus `installtrusted`, which the source defines and dispatches but the usage text never advertises
— the same kind of omission as `p11ng-cli`'s missing `listkeypairs`.) It is a richer *PKI* tool than
`p11ng-cli` — it does CSRs, certificate installation, link certificates, key migration between
tokens — and a poorer *PKCS#11* tool: no slot listing, no token info, no object inspection.

**It goes through SunPKCS11.** Its key-spec help string is
`"all decimal digits RSA key with specified length, otherwise name of ECC curve or DSA key using
syntax DSAnnnn"` — RSA, ECC, DSA. There is no path through `com.keyfactor.util.keys.KeyStoreTools`
to ML-DSA, ML-KEM or SLH-DSA.

This is the gap. An EJBCA CE operator installing kimbo11ng for post-quantum keys has, today, a
key-management CLI that cannot see the keys they installed it for. Keyfactor's answer to the same
gap was `p11ng-cli`, and they are deprecating the old path outright: the HSM overview page states
Java PKCS#11 is "Deprecated as of EJBCA 9.4", with P11NG "the primary implementation of PKCS#11
integration in EJBCA Enterprise", offering "greater control and early support for quantum-safe
algorithms".

## 6. Mapping to kimbo11ng

Every row is a `p11ng-cli` command. "Brick" names what already exists in this repository; in most
cases the work is exposure, not implementation.

| Command | CE `PKCS11HSMKeyTool` | kimbo11ng brick | Verdict |
| --- | --- | --- | --- |
| `listslots` | absent | `Pkcs11Module.slotList()`, `tokenLabel(slotId)` | **implement** — needs no PIN, so it is the first thing that ever works |
| `showinfo` | absent | `C_GetInfo` unwrapped; `Pkcs11Module.ce()` reaches it | **implement** — small addition |
| `showslotinfo` | absent | `C_GetSlotInfo` unwrapped | **implement** |
| `showtokeninfo` | absent | `Pkcs11Module.tokenLabel` already calls `C_GetTokenInfo`; expose the rest of the struct | **implement** |
| `listobjects` | absent | `C_FindObjects` via `P11KeyRef.resolve`, `Kimbo11ngKeyStoreSpi.enumerateSecretKeys` | **implement** |
| `listkeypairs` | absent | `Kimbo11ngKeyStoreSpi.engineAliases()` | **implement** — highest diagnostic value: it is literally the list EJBCA will show |
| `showobjectattributes` | absent | `C_GetAttributeValue` | **implement** — the only way to check `CKA_SENSITIVE`/`CKA_EXTRACTABLE` from outside |
| `generatekeypair` | `generate` (RSA/EC/DSA only) | `Kimbo11ngKeyPairGeneratorSpi`, `KeyTemplates` | **implement** — this is the differentiator; `--key-spec ML-DSA-44` works in their tool and must in ours |
| `generatekey` | absent | `Kimbo11ngKeyGeneratorSpi`, `SecretKeyType` (merged in #6) | **implement** — and note this would be the *only* consumer that exists, since nothing in EJBCA CE calls `CryptoToken.generateKey` |
| `deleteobject` | `delete` | `Kimbo11ngKeyStoreSpi.engineDeleteEntry`, `deleteSecretEntry` | **implement** |
| `signperformancetest` | absent | `Kimbo11ngSignatureSpi` | **implement** — see §7 |
| `onetimeperformancetest` | absent | keypair generation + sign loop | defer — RSA-specific, low value here |
| `initializekey`, `authorizekey`, `unblockkey`, `backupobject`, `restoreobject` | absent | none | **out of scope** — Utimaco CP5 vendor extensions, no hardware to develop or verify against |
| — | `certreq`, `installcert`, `linkcert`, `move`, `encrypt`/`decrypt`/`verify` | none | **out of scope** — PKI operations, not token operations; EJBCA's own CLI and the CE toolbox cover them |

## 7. What kimbo11ng could do that P11NG does not

Four things, each of which exists because of a problem this project actually hit.

**Capability and profile dump.** `TokenCapabilities.probe` reads every mechanism with its
`CKF_SIGN`/`CKF_GENERATE`/`CKF_GENERATE_KEY_PAIR` flags, and `ProfileResolver` decides which PQC
profile the token matches. Today that verdict — *"18 of its 18 algorithms are advertised"* — is
only readable in the WildFly log, after deployment, once EJBCA has already tried to use the token.
Nothing in `p11ng-cli` reports it, because P11NG has no equivalent notion. Exposed as a pre-flight
command it answers, before anything is configured, whether this HSM can host a PQC CA at all.

**Provider-versus-PKCS#11 execution.** The SignServer tool's `-method` proves Keyfactor found this
worth having. For us it is worth more: our JCA layer is where the interesting bugs live (stale
handles, `CKR_OPERATION_ACTIVE` on a pooled session, the `getPrivateKey` guard added in #6), and it
is currently only reachable by starting EJBCA.

**PQC signing benchmarks.** `signperformancetest --signature-algorithm ML-DSA-44` exists upstream,
so the idea is not novel — but SLH-DSA is where it earns its keep. SLH-DSA signatures cost orders
of magnitude more than ECDSA, and the per-HSM number is not published by anyone. It is also the
figure that decides whether a given HSM can serve a CA at a given issuance rate.

**A diagnosis command.** Every failure in this project's history has been one of three things: an
`LD_LIBRARY_PATH` that does not resolve the module's own dependencies, a slot reference of the wrong
type, or a PIN. A command that reports which of the three it is would have saved more time than
every other item on this list combined.

## 8. What remains unknown

Recorded so a future reader knows these are unanswered, not unasked.

1. **Exact option spellings for `generatekey`, `deleteobject`, `showobjectattributes`,
   `onetimeperformancetest`.** Never published in any invocation. `--help` needs the EE binary.
2. **Whether `p11ng-cli` accepts an attributes file.** SignServer's tool does
   (`-attributes_file`, `ATTRIBUTE.x.y.z` format). EJBCA's documented crypto token accepts
   `attributesFile`. Nothing links the two for the CLI.
3. **The full `--key-spec` vocabulary.** Four values are evidenced: `RSA2048`, `P-256`,
   `prime256v1`, `ML-DSA-44`. Crypto4A's page says P11NG supports "ML-DSA and LMS"; SLH-DSA is
   never named in any p11ng-cli context. Whether `ML-KEM` is a valid spec is unknown.
4. **`--key-usage` beyond `SIGN` and `SIGN_ENCRYPT`.**
5. **Output formats.** Only `listslots` and `signperformancetest` have published sample output. If
   compatibility with someone's existing scripts ever matters, the rest is guesswork — which argues
   for making our own output explicitly ours rather than imitating an unseen format.
6. **`p11ng-0.25.7.jar` versioning.** A 0.x version number on a component this central is
   surprising and might mean the CLI's surface moves between releases. The SignServer page's own
   warning that "the API is likely to change" points the same way.

None of these is resolvable without an Enterprise licence. All of them are avoidable: they only bind
if the goal is byte-compatibility with `p11ng-cli`, and it need not be.

## 9. Sources

| Source | Retrieved | What it gave |
| --- | --- | --- |
| [P11Ng CLI (EJBCA 9.6.2)](https://docs.keyfactor.com/ejbca/latest/p11ng-cli) · [(9.0)](https://docs.keyfactor.com/ejbca/9.0/p11ng-cli) | 2026-09-05 | the 16-command list with descriptions |
| [Generic PKCS#11 Provider](https://docs.keyfactor.com/ejbca/latest/generic-pkcs-11-provider) | 2026-09-05 | `CKA_ID`/`CKA_LABEL` conventions, `pub-`/`priv-` prefixes, `PKCS11HSMKeyTool` examples |
| [Hardware Security Modules (HSM)](https://docs.keyfactor.com/ejbca/latest/hardware-security-modules-hsm) | 2026-09-05 | SunPKCS11 deprecated as of EJBCA 9.4; which CLI pairs with which provider |
| [Thales Luna HSM](https://docs.keyfactor.com/ejbca/latest/thales-luna-hsm) | 2026-09-05 | `listslots`, `listkeypairs`, `generatekeypair --key-spec ML-DSA-44`, `signperformancetest` |
| [IBM HPCS](https://docs.keyfactor.com/ejbca/latest/ibm-hpcs) | 2026-09-05 | `--key-usage`, `SLOT_LABEL` quoting, the only sample outputs |
| [Crypto4A QxHSM](https://docs.keyfactor.com/ejbca/latest/crypto4a-qxhsm) | 2026-09-05 | `showinfo`/`showslotinfo`/`showtokeninfo`/`listobjects`/`listkeypairs`, PQC benchmark |
| [Utimaco CryptoServer CP5](https://docs.keyfactor.com/ejbca-software/latest/utimaco-cryptoserver-cp5) | 2026-09-05 | `initializekey`/`authorizekey` and their CP5 options |
| [Deploy EJBCA as CA with SoftHSM2](https://docs.keyfactor.com/container/latest/ejbca/deploy-ejbca-as-ca-with-automation-with-softhsm2) | 2026-09-05 | the `common_args` init-script pattern |
| [SignServer P11NG CLI](https://docs.keyfactor.com/signserver/latest/p11ng-cli) — also shipped as `doc/htdocs/P11NG_CLI.html` in `signserver-ce-7.3.2-bin.zip` | 2026-09-05 | the complete `p11ng-tool` option list and 13 examples |
| `P11NGCryptoToken.html`, `Migrate_from_SunPKCS11_to_P11NG.html` (same zip) | 2026-09-05 | `ATTRIBUTE.x.y.z`, `GENERATE_CERTIFICATE_OBJECT`, `USE_CACHE`, `SEC:` prefix, vendor quirks |
| [`Keyfactor/signserver-ce`](https://github.com/Keyfactor/signserver-ce) (LGPL-2.1) | 2026-09-05 | absence of any `p11ng` package; `jars-list.txt`; `default_build.properties` |
| [`Keyfactor/ejbca-ce`](https://github.com/Keyfactor/ejbca-ce) (LGPL-2.1) | 2026-09-05 | `HSMKeyTool.java`, the CE baseline command list |
| `keyfactor/ejbca-ce:9.3.7` image | 2026-09-05 | `dist/clientToolBox` contents as actually shipped |

## 10. Decisions this document does not take

Deliberately left open, for the design phase:

- Whether the CLI is a second entry point on the existing fat JAR or its own artefact.
- Whether to match `p11ng-cli`'s grammar (`<command> --long-option`) for muscle-memory
  compatibility, or SignServer's, or neither.
- Whether `--key-spec` uses Keyfactor's vocabulary (`RSA2048`, `P-256`, `ML-DSA-44`) or the JCA
  names our provider already registers.
- Whether to open `SecretKeyType` with a `SEC:`-style escape hatch.
- Whether to emit a certificate object behind a flag, which is the only thing that would make
  kimbo11ng keys visible to SunPKCS11.

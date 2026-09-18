# ejbca-hsm

What EJBCA Community Edition 9.6 needs on top of the official image before a crypto token other than
Soft or Null will run. `build.sh` produces both artefacts, `docker/Dockerfile` copies them in, and
[NOTICE](NOTICE) says where each file came from and why it is licensed differently from the rest of the
repository.

| Artefact | What it is | Why |
| --- | --- | --- |
| `ejbca-ejb.jar` | the official jar, with `StartupSingletonBean.checkHsmTokensNotUsedInCommunityEdition()` replaced by a bare `return` | EJBCA 9.6 aborts start-up when the database holds any other token type, including `Pkcs11NgCryptoToken`. See `docs/EJBCA_UPSTREAM_WATCH.md`, W1. |
| `ejbca-hsm-tokens.jar` | `PKCS11CryptoToken`, `AzureCryptoToken`, `AzureProvider`, compiled | 9.6 removed them from `cryptotokens-impl`; `CryptoTokenFactory` still registers them by name, so supplying the classes is enough. Not needed by kimbo11ng's own token. |

## How it is built

`build.sh` runs inside the pinned EJBCA image and uses the JDK in it, so no second toolchain image is
pinned and the class files are the version of the JVM that loads them. It:

1. downloads ASM and checks its SHA-256;
2. rewrites the one method (`StartupCheckPatcher.java`), then confirms with `javap`, independently,
   that the body is a single `return`;
3. has the JVM itself load and initialise the patched class with the bytecode verifier forced on
   (`LinkCheck.java`), with the patched jar first on the class path and a failure if the class came from
   anywhere else. A rewrite that is still a bare `return` but is malformed passes step 2 and fails here;
4. refuses to continue if any jar on the EAR classpath already contains one of the three classes, since
   two of one name load in an unspecified order;
5. compiles the three classes against the EAR's own jars, and link-checks them the same way.

The patcher **fails the build** when the method is missing, when it no longer calls
`hasNonCeSupportedTokenTypes`, or when something else in the class does. A release that moves the check
therefore stops the image build, not the CA at 3 a.m.

Try it without Docker Compose:

```bash
docker run --rm --user root --entrypoint bash \
  -v "$PWD/docker/ejbca-hsm":/ejbca-hsm:ro -v /tmp/out:/out \
  keyfactor/ejbca-ce:9.6.3 -c 'OUT=/out /ejbca-hsm/build.sh'
```

## On an EJBCA bump

`docs/EJBCA_UPSTREAM_WATCH.md` lists what to re-check. For this directory: re-run the build (step 2 is
the canary), re-diff the three classes against the upstream commits in NOTICE, and re-read W1 and W2.

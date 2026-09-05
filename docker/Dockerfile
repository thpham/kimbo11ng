# ─────────────────────────────────────────────────────────────────────────────
# Prebuilt OpenSSL + SoftHSMv3, from docker/Dockerfile.toolchain.
#
# Compiling those two from source takes 446s on amd64 and 329s on arm64, both native, and
# it does not change between releases — so it lives in its own image, rebuilt only when
# OPENSSL_VERSION or SOFTHSM_VERSION moves. See docker/Dockerfile.toolchain.
#
# Pinned by digest, like every other external reference here (GitHub Actions, jacknji11,
# the EJBCA base image). It is not only hygiene: toolchain.yml and ci.yml both trigger on a
# push to main, so a tag that changes with a version bump can be referenced by a CI run
# before it exists — which is exactly what happened on the first run. A digest can only
# ever name something already published.
#
# To bump: change the versions in docker/Dockerfile.toolchain and the justfile, run
# `gh workflow run toolchain.yml`, take the digest from its job summary, and change the
# line below in a separate commit. The order matters, for the reason above.
#
# `just docker-build` overrides this with the version-derived tag instead, so that
# `just toolchain-build` works offline and without GHCR credentials.
# ─────────────────────────────────────────────────────────────────────────────
ARG TOOLCHAIN=ghcr.io/thpham/ejbca-ce-toolchain@sha256:29360d98d2c42547f3da2390c08c16c6ebaf29be88a82bb0d055340e6361ea44
FROM ${TOOLCHAIN} AS toolchain

# ─────────────────────────────────────────────────────────────────────────────
# Final EJBCA image
#
# Digest-pinned, as the block above claims for every external reference here. The tag is kept
# alongside it only so the version is readable; the digest is what resolves. `keyfactor/ejbca-ce`
# publishes a multi-arch index and this is the index digest, so amd64 and arm64 both build from
# it. Bumping EJBCA means changing `ejbca_version` and `ejbca_digest` in the justfile and this
# line together — the JARs kimbo11ng compiles against are extracted from this exact image.
# ─────────────────────────────────────────────────────────────────────────────
FROM keyfactor/ejbca-ce:9.3.7@sha256:183b86af44b9b13e7cc8912c868f635aeb8dba6bf056ccbd4683b17626964d0a

USER root

# OpenSSL shared libs (softhsmv3 runtime dependency), the PKCS#11 module and softhsm2-util
COPY --from=toolchain /opt/openssl/lib       /opt/openssl/lib
COPY --from=toolchain /usr/local/lib/softhsm /usr/local/lib/softhsm
COPY --from=toolchain /usr/local/bin         /usr/local/bin

# SoftHSM config + environment hook for EJBCA start.sh
COPY docker/softhsmv3.conf    /etc/softhsmv3.conf
COPY docker/environment-hsm   /opt/softhsm/environment-hsm

# Register the PKCS#11 libraries offered in the EJBCA Admin UI. The Luna entry is deliberately
# dangling in this image: nothing Thales-owned ships here, and the file appears only when a client
# tree is mounted at /usr/local/luna. Stock EJBCA does the same for index 255 (P11 Proxy).
RUN echo '' >> /opt/keyfactor/ejbca/conf/web.properties && \
    echo '# SoftHSMv3 (PQC-enabled)' >> /opt/keyfactor/ejbca/conf/web.properties && \
    echo 'cryptotoken.p11.lib.10.name=SoftHSMv3' >> /opt/keyfactor/ejbca/conf/web.properties && \
    echo 'cryptotoken.p11.lib.10.file=/usr/local/lib/softhsm/libsofthsmv3.so' >> /opt/keyfactor/ejbca/conf/web.properties && \
    echo '# Thales Luna — present only when a client is side-mounted (see docs/VENDOR_PROFILE_CHECKLIST.md)' >> /opt/keyfactor/ejbca/conf/web.properties && \
    echo 'cryptotoken.p11.lib.20.name=Thales Luna' >> /opt/keyfactor/ejbca/conf/web.properties && \
    echo 'cryptotoken.p11.lib.20.file=/usr/local/luna/libs/64/libCryptoki2.so' >> /opt/keyfactor/ejbca/conf/web.properties

# Mount point for an optional Thales Luna client. Empty in the image, and outside the /opt/* tree
# that start.sh scans for environment-hsm — a mount at /opt/luna would sort ahead of /opt/softhsm.
RUN mkdir -p /usr/local/luna
ENV LUNA_CLIENT_DIR=/usr/local/luna

# HSM init wrapper — runs before EJBCA start.sh
COPY docker/init-hsm.sh       /opt/keyfactor/bin/init-hsm.sh
COPY docker/luna-discover.sh  /opt/keyfactor/bin/luna-discover.sh
RUN chmod +x /opt/keyfactor/bin/init-hsm.sh

RUN mkdir -p /var/lib/softhsmv3/tokens && \
    chown -R 10001:0 /var/lib/softhsmv3

# Install gosu for privilege drop in init-hsm.sh (root → 10001).
#
# The checksum is not ceremony: GitHub release assets are mutable, so GOSU_VERSION alone names a
# URL and not a set of bytes, and this binary is exec'd as root as the last step of container
# startup. Everything else external here is pinned to immutable content — Actions by commit SHA,
# the toolchain by digest, SoftHSMv3 by tag — and this was the one hole.
#
# Digests are per architecture because the release ships one asset per arch and both are built.
# They were taken from the published assets and cross-checked against tianon's detached OpenPGP
# signatures (gosu-<arch>.asc, key B42F6819007F00F88E364FD4036A9C25BF357DD4). Verification
# happens before chmod, so a mismatched download never becomes executable, and an architecture
# with no pinned digest fails the build rather than silently skipping the check.
ARG GOSU_VERSION=1.17
ARG TARGETARCH
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) gosu_sha256='bbc4136d03ab138b1ad66fa4fc051bafc6cc7ffae632b069a53657279a450de3' ;; \
      arm64) gosu_sha256='c3805a85d17f4454c23d7059bcb97e1ec1af272b90126e79ed002342de08389b' ;; \
      *) echo "no gosu SHA-256 pinned for TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/gosu \
      "https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${TARGETARCH}"; \
    printf '%s  %s\n' "${gosu_sha256}" /usr/local/bin/gosu | sha256sum -c -; \
    chmod +x /usr/local/bin/gosu

ENV SOFTHSM2_CONF=/etc/softhsmv3.conf
ENV LD_LIBRARY_PATH=/opt/openssl/lib

# kimbo11ng fat JAR — single COPY + symlink to avoid duplicating the layer
COPY target/kimbo11ng-jar-with-dependencies.jar \
     /opt/keyfactor/ejbca/dist/ejbca.ear/lib/
RUN ln -s /opt/keyfactor/ejbca/dist/ejbca.ear/lib/kimbo11ng-jar-with-dependencies.jar \
          /opt/keyfactor/ejbca/dist/clientToolBox/lib/

# init-hsm.sh runs as root to fix volume permissions, link an optional Luna client and init the
# SoftHSM token, then drops to user 10001 via gosu before exec'ing start.sh
CMD ["/opt/keyfactor/bin/init-hsm.sh"]

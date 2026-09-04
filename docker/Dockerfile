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
# ─────────────────────────────────────────────────────────────────────────────
FROM keyfactor/ejbca-ce:9.3.7

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

# Install gosu for privilege drop in init-hsm.sh (root → 10001)
ARG GOSU_VERSION=1.17
ARG TARGETARCH
RUN curl -fsSL "https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${TARGETARCH}" \
    -o /usr/local/bin/gosu && chmod +x /usr/local/bin/gosu

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

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Build OpenSSL 3.6 from source (AlmaLinux 9 ships 3.0.x)
# ─────────────────────────────────────────────────────────────────────────────
FROM almalinux:9 AS openssl-builder

ARG OPENSSL_VERSION=3.6.0

RUN dnf install -y gcc gcc-c++ make perl wget tar xz findutils zlib-devel && dnf clean all

WORKDIR /build
RUN wget -q https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz && \
    tar xf openssl-${OPENSSL_VERSION}.tar.gz && \
    cd openssl-${OPENSSL_VERSION} && \
    ./config \
        --prefix=/opt/openssl \
        --openssldir=/opt/openssl/ssl \
        --libdir=lib \
        shared \
        zlib-dynamic \
        no-tests && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Build SoftHSMv3 against our OpenSSL
# ─────────────────────────────────────────────────────────────────────────────
FROM almalinux:9 AS softhsm-builder

COPY --from=openssl-builder /opt/openssl /opt/openssl

RUN dnf install -y gcc gcc-c++ cmake make git pkg-config && dnf clean all

ENV PKG_CONFIG_PATH=/opt/openssl/lib/pkgconfig
ENV LD_LIBRARY_PATH=/opt/openssl/lib

WORKDIR /build
# Canonical URL: pqctoday/softhsmv3 was renamed to pqctoday-org/pqctoday-hsm. Cloning the old
# name still works through GitHub's redirect, but a redirect can disappear the moment anyone
# re-creates that name, so depend on the real one. Cloned into softhsmv3/ explicitly so the
# repository rename does not change the build directory.
#
# Pinned to a release tag: an unpinned HEAD makes this image unreproducible, and upstream
# has moved past the layout these cmake flags expect.
#
# Choosing the tag is not free — upstream has three eras:
#   v0.4.4 and earlier  no stateful/ sources; builds from a plain clone.   <- pinned here
#   v0.4.7, v0.4.8      reference stateful/hash-sigs/*.c, but those are gitlinks with NO
#                       .gitmodules, so neither a plain clone nor --recurse-submodules can
#                       populate them. Unbuildable; cmake fails with
#                       "Cannot find source file: stateful/hash-sigs/endian.c".
#   v0.5.0 and later    same sources, but .gitmodules is present, so moving up to one of
#                       these requires adding --recurse-submodules to the clone below.
ARG SOFTHSM_VERSION=v0.4.4
RUN git clone --depth 1 --branch ${SOFTHSM_VERSION} \
        https://github.com/pqctoday-org/pqctoday-hsm.git softhsmv3

RUN cd softhsmv3 && \
    mkdir build && cd build && \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DWITH_CRYPTO_BACKEND=openssl \
        -DOPENSSL_ROOT_DIR=/opt/openssl \
        -DOPENSSL_INCLUDE_DIR=/opt/openssl/include \
        -DOPENSSL_CRYPTO_LIBRARY=/opt/openssl/lib/libcrypto.so \
        -DOPENSSL_SSL_LIBRARY=/opt/openssl/lib/libssl.so \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DBUILD_TESTS=OFF \
        -DENABLE_MLKEM=ON \
        -DENABLE_MLDSA=ON && \
    make -j$(nproc) && \
    make install

# ─────────────────────────────────────────────────────────────────────────────
# Stage 3: Final EJBCA image
# ─────────────────────────────────────────────────────────────────────────────
FROM keyfactor/ejbca-ce:9.3.7

USER root

# OpenSSL shared libs (softhsmv3 runtime dependency)
COPY --from=openssl-builder /opt/openssl/lib    /opt/openssl/lib

# SoftHSMv3 PKCS#11 library + management utility
COPY --from=softhsm-builder /usr/local/lib/softhsm  /usr/local/lib/softhsm
COPY --from=softhsm-builder /usr/local/bin           /usr/local/bin

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

# Install gosu for privilege drop in init-softhsm.sh (root → 10001)
ARG GOSU_VERSION=1.17
ARG TARGETARCH
RUN curl -fsSL "https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${TARGETARCH}" \
    -o /usr/local/bin/gosu && chmod +x /usr/local/bin/gosu

ENV SOFTHSM2_CONF=/etc/softhsmv3.conf
ENV LD_LIBRARY_PATH=/opt/openssl/lib

# kimbo11ng fat JAR — single COPY + symlink to avoid duplicating the layer
COPY target/kimbo11ng-1.0.0-SNAPSHOT-jar-with-dependencies.jar \
     /opt/keyfactor/ejbca/dist/ejbca.ear/lib/
RUN ln -s /opt/keyfactor/ejbca/dist/ejbca.ear/lib/kimbo11ng-1.0.0-SNAPSHOT-jar-with-dependencies.jar \
          /opt/keyfactor/ejbca/dist/clientToolBox/lib/

# init-hsm.sh runs as root to fix volume permissions, link an optional Luna client and init the
# SoftHSM token, then drops to user 10001 via gosu before exec'ing start.sh
CMD ["/opt/keyfactor/bin/init-hsm.sh"]

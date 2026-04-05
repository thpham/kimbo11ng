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
RUN git clone --depth 1 https://github.com/pqctoday/softhsmv3.git

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

# OpenSSL shared libs + CLI (softhsmv3 runtime dependency + cert tooling)
COPY --from=openssl-builder /opt/openssl/lib    /opt/openssl/lib
COPY --from=openssl-builder /opt/openssl/bin    /opt/openssl/bin

# SoftHSMv3 PKCS#11 library + management utility
COPY --from=softhsm-builder /usr/local/lib/softhsm  /usr/local/lib/softhsm
COPY --from=softhsm-builder /usr/local/bin           /usr/local/bin

# SoftHSM config + environment hook for EJBCA start.sh
COPY docker/softhsmv3.conf    /etc/softhsmv3.conf
COPY docker/environment-hsm   /opt/softhsm/environment-hsm

# Register SoftHSMv3 as a PKCS#11 library in EJBCA Admin UI
RUN echo '' >> /opt/keyfactor/ejbca/conf/web.properties && \
    echo '# SoftHSMv3 (PQC-enabled)' >> /opt/keyfactor/ejbca/conf/web.properties && \
    echo 'cryptotoken.p11.lib.10.name=SoftHSMv3' >> /opt/keyfactor/ejbca/conf/web.properties && \
    echo 'cryptotoken.p11.lib.10.file=/usr/local/lib/softhsm/libsofthsmv3.so' >> /opt/keyfactor/ejbca/conf/web.properties

# Token init wrapper — runs before EJBCA start.sh
COPY docker/init-softhsm.sh   /opt/keyfactor/bin/init-softhsm.sh
RUN chmod +x /opt/keyfactor/bin/init-softhsm.sh

RUN mkdir -p /var/lib/softhsmv3/tokens && \
    chown -R 10001:0 /var/lib/softhsmv3

# Install gosu for privilege drop in init-softhsm.sh (root → 10001)
ARG GOSU_VERSION=1.19
ARG TARGETARCH
RUN curl -fsSL "https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${TARGETARCH}" \
    -o /usr/local/bin/gosu && chmod +x /usr/local/bin/gosu

ENV SOFTHSM2_CONF=/etc/softhsmv3.conf
ENV LD_LIBRARY_PATH=/opt/openssl/lib
ENV PATH="/opt/openssl/bin:${PATH}"

# kimbo11ng fat JAR — single COPY + symlink to avoid duplicating the layer
COPY target/kimbo11ng-1.0.0-SNAPSHOT-jar-with-dependencies.jar \
     /opt/keyfactor/ejbca/dist/ejbca.ear/lib/
RUN ln -s /opt/keyfactor/ejbca/dist/ejbca.ear/lib/kimbo11ng-1.0.0-SNAPSHOT-jar-with-dependencies.jar \
          /opt/keyfactor/ejbca/dist/clientToolBox/lib/

# init-softhsm.sh runs as root to fix volume permissions and init token,
# then drops to user 10001 via gosu before exec'ing start.sh
CMD ["/opt/keyfactor/bin/init-softhsm.sh"]

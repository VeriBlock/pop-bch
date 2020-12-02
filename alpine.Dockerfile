# Build stage for Bitcoin ABC
FROM alpine as bitcoin-abc

#COPY --from=berkeleydb /opt /opt

RUN apk --no-cache add autoconf
RUN apk --no-cache add automake
RUN apk --no-cache add boost-dev
RUN apk --no-cache add build-base
RUN apk --no-cache add chrpath
RUN apk --no-cache add file
RUN apk --no-cache add gnupg
RUN apk --no-cache add libevent-dev
RUN apk --no-cache add libressl
RUN apk --no-cache add libressl-dev
RUN apk --no-cache add libtool
RUN apk --no-cache add linux-headers
RUN apk --no-cache add protobuf-dev
RUN apk --no-cache add zeromq-dev
RUN apk --no-cache add cmake
RUN apk --no-cache add git
RUN apk --no-cache add miniupnpc
RUN apk --no-cache add miniupnpc-dev
RUN apk --no-cache add db
RUN apk --no-cache add db-dev

ENV VBCH_PREFIX=/opt/vbch

COPY . /vbch

WORKDIR /vbch

# Install alt-integration-cpp
RUN export VERIBLOCK_POP_CPP_VERSION=$(awk -F '=' '/\$\(package\)_version/{print $NF}' $PWD/depends/packages/veriblock-pop-cpp.mk | head -n1); \
    (\
     cd /opt; \
     wget https://github.com/VeriBlock/alt-integration-cpp/archive/${VERIBLOCK_POP_CPP_VERSION}.tar.gz; \
     tar -xf ${VERIBLOCK_POP_CPP_VERSION}.tar.gz; \
     cd alt-integration-cpp-${VERIBLOCK_POP_CPP_VERSION}; \
     mkdir build; \
     cd build; \
     cmake .. -DCMAKE_BUILD_TYPE=Release -DTESTING=OFF; \
     make -j$(nproc) install \
    )

RUN (\
     cd /opt; \
     git clone -b 5.2.1 https://github.com/jemalloc/jemalloc.git; \
     cd jemalloc; \
     ./autogen.sh; \
     make -j$(nproc); \
     make install; \
    )

RUN cmake -H. -Bbuild -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DCMAKE_INSTALL_PREFIX=${VBCH_PREFIX} -DBUILD_BITCOIN_QT=OFF
RUN cmake --build build -- -j2 install

RUN strip ${VBCH_PREFIX}/bin/bitcoin-cli
RUN strip ${VBCH_PREFIX}/bin/bitcoin-tx
RUN strip ${VBCH_PREFIX}/bin/bitcoin-wallet
RUN strip ${VBCH_PREFIX}/bin/bitcoin-seeder
RUN strip ${VBCH_PREFIX}/bin/bitcoind
RUN strip ${VBCH_PREFIX}/lib64/libbitcoinconsensus.so.0.0.0


# Build stage for compiled artifacts
FROM alpine

RUN apk --no-cache add \
  boost \
  boost-program_options \
  curl \
  libevent \
  libressl \
  libzmq \
  su-exec

ENV DATA_DIR=/home/bitcoin/.bitcoin
ENV VBCH_PREFIX=/opt/bitcoin
ENV PATH=${VBCH_PREFIX}/bin:$PATH

COPY --from=bitcoin-abc /opt /opt

RUN mkdir -p ${DATA_DIR}
RUN set -x \
    && addgroup -g 1001 -S bitcoin \
    && adduser -u 1001 -D -S -G bitcoin bitcoin
RUN chown -R 1001:1001 ${DATA_DIR}
USER bitcoin
WORKDIR $DATA_DIR

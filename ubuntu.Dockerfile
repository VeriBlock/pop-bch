FROM ubuntu

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
  autoconf \
  automake \
  bsdmainutils \
  libevent-dev \
  ninja-build \
  libzmq3-dev \
  libjemalloc-dev \
  libboost-all-dev \
  build-essential \
  libdb-dev libdb++-dev \
  cmake \
  wget \
  git \
  python3 python3-pip python3-dev \
  curl \
  libssl-dev \
  pkg-config \
  miniupnpc \
  libminiupnpc-dev \
  && cd /usr/local/bin \
  && ln -s /usr/bin/python3 python \
  && pip3 --no-cache-dir install --upgrade pip \
  && rm -rf /var/lib/apt/lists/*

# Upgrade pip to latest version
RUN curl -s https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python get-pip.py --force-reinstall && \
    rm get-pip.py

ADD . /vbch
WORKDIR /vbch
ARG BUILD_TYPE=Release

ENV BUILD=${BUILD_TYPE}
ENV VBCH_PREFIX=/opt/vbch

RUN export VERIBLOCK_POP_CPP_VERSION=$(awk -F '=' '/\$\(package\)_version/{print $NF}' $PWD/depends/packages/veriblock-pop-cpp.mk | head -n1); \
    (\
     cd /opt; \
     wget https://github.com/VeriBlock/alt-integration-cpp/archive/${VERIBLOCK_POP_CPP_VERSION}.tar.gz; \
     tar -xf ${VERIBLOCK_POP_CPP_VERSION}.tar.gz; \
     cd alt-integration-cpp-${VERIBLOCK_POP_CPP_VERSION}; \
     mkdir build; \
     cd build; \
     cmake .. -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DTESTING=OFF; \
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
RUN cmake --build build -- -j$(nproc) install

RUN strip ${VBCH_PREFIX}/bin/bitcoin-cli
RUN strip ${VBCH_PREFIX}/bin/bitcoin-tx
RUN strip ${VBCH_PREFIX}/bin/bitcoin-wallet
RUN strip ${VBCH_PREFIX}/bin/bitcoin-seeder
RUN strip ${VBCH_PREFIX}/bin/bitcoind
RUN strip ${VBCH_PREFIX}/lib64/libbitcoinconsensus.so.0.0.0

ENV DATA_DIR=/home/bitcoin/.bitcoin
ENV VBCH_PREFIX=/opt/bitcoin
ENV PATH=${VBCH_PREFIX}/bin:$PATH

COPY --from=ubuntu /opt /opt

RUN mkdir -p ${DATA_DIR}
RUN set -x \
    && addgroup -g 1001 -S bitcoin \
    && adduser -u 1001 -D -S -G bitcoin bitcoin
RUN chown -R 1001:1001 ${DATA_DIR}
USER bitcoin
WORKDIR $DATA_DIR

# remove source files to decrease image size
#RUN rm -rf /app
#ENV DATA_DIR=/home/vbitcoin/.vbitcoin
#RUN groupadd -r --gid 1001 vbitcoin
#RUN useradd --no-log-init -r --uid 1001 --gid 1001 --create-home --shell /bin/bash vbitcoin
#RUN mkdir -p ${DATA_DIR}
#RUN chown -R 1001:1001 ${DATA_DIR}
#USER vbitcoin

#WORKDIR $DATA_DIR
FROM ubuntu

<<<<<<< HEAD
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
=======
# Key imports:
# gosu pubkey
# jasonbcox, bitcoin-abc dev pubkey
RUN useradd -r bitcoin \
  && apt-get update -y \
  && apt-get install -y curl gnupg \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
  && set -ex \
  && for key in \
    B42F6819007F00F88E364FD4036A9C25BF357DD4 \
    3BB16D00D9A6D281591BDC76E4486356E7A81D2C \
  ; do \
    gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$key"; \
  done
>>>>>>> 9181bb404 (fix syntax)

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

ENV DATA_DIR=/home/bitcoin/.bitcoin
ENV VBCH_PREFIX=/opt/bitcoin
ENV PATH=${VBCH_PREFIX}/bin:$PATH

COPY --from=ubuntu /opt /opt

RUN mkdir -p ${DATA_DIR}
RUN groupadd -r --gid 1001 bitcoin
RUN useradd --no-log-init -r --uid 1001 --gid 1001 --create-home --shell /bin/bash bitcoin
RUN chown -R 1001:1001 ${DATA_DIR}
USER bitcoin
WORKDIR $DATA_DIR

#WORKDIR $DATA_DIR

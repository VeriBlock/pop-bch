FROM veriblock/prerelease-btc

ADD . /app
WORKDIR /app
ARG BUILD_TYPE=Release

RUN apt-get update && apt-get install -y \
  libdb-dev libdb++-dev

RUN pip3 install cmake

ENV BUILD=${BUILD_TYPE}
RUN export VERIBLOCK_POP_CPP_VERSION=$(awk -F '=' '/\$\(package\)_version/{print $NF}' $PWD/depends/packages/veriblock-pop-cpp.mk | head -n1); \
    (\
     cd /opt; \
     wget https://github.com/VeriBlock/alt-integration-cpp/archive/${VERIBLOCK_POP_CPP_VERSION}.tar.gz; \
     tar -xf ${VERIBLOCK_POP_CPP_VERSION}.tar.gz; \
     cd alt-integration-cpp-${VERIBLOCK_POP_CPP_VERSION}; \
     mkdir build; \
     cd build; \
     cmake .. -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DTESTING=OFF; \
     make -j2 install \
    )

RUN (\
     cd /opt; \
     git clone -b 5.2.1 https://github.com/jemalloc/jemalloc.git; \
     cd jemalloc; \
     ./autogen.sh; \
     make -j$(nproc); \
     make install; \
    )

RUN cmake -H. -Bbuild -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DBUILD_BITCOIN_QT=OFF
RUN cmake --build build -- -j$(nproc) install

# remove source files to decrease image size
RUN rm -rf /app
ENV DATA_DIR=/home/bitcoin/.bitcoin/poptestnet
RUN groupadd -r --gid 1001 bitcoin
RUN useradd --no-log-init -r --uid 1001 --gid 1001 --create-home --shell /bin/bash bitcoin
RUN mkdir -p ${DATA_DIR}
RUN chown -R 1001:1001 ${DATA_DIR}
USER bitcoin

WORKDIR $DATA_DIR
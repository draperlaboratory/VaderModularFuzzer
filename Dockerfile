FROM ubuntu:20.04

RUN  apt-get update \
     && DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends --fix-missing \
       ca-certificates \
       curl \
       gdb \
       git \
       gnupg \
       lsb-core \
       lsb-release

RUN lsb_release -a | grep -q "18.04" && ( \
      echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-12 main" >> /etc/apt/sources.list && \
      curl -L https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
    ) || \
    (lsb_release -a | grep -q "20.04") || \
    (lsb_release -a | grep -q "22.04") || (echo "Ubuntu 18.04, 20.04, or 22.04 required!!!" >&2; exit 1)

RUN  apt-get update \
     && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --fix-missing \
       afl++ \
       afl++-clang \
       afl++-doc \
       graphviz \
       clang-12 \
       doxygen \
       libcurl4-openssl-dev \
       llvm-12 \
       python3-dev \
       python3-pip \
       python3-setuptools \
       build-essential \
       cmake \
     && pip3 install lief

ENV  LLVM_CONFIG=llvm-config-12



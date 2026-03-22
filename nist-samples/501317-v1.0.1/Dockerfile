FROM ubuntu:xenial

# INSTALL DEPENDENCIES
RUN apt-get update -yq
RUN apt-get -yq install automake byacc flex libpcap-dev libgtk2.0-dev libtool coreutils wget

# RETRIEVE AND EXTRACT THE SOURCE CODE
WORKDIR /
RUN wget https://samate.nist.gov/SATE6/wireshark-1.2-sate6.tar.xz
RUN tar --no-same-owner -Jxf wireshark-1.2-sate6.tar.xz
RUN ln -s wireshark-1.2-buggy sources_buggy
RUN ln -s wireshark-1.2-fixed sources_fixed

# COMPILE THE SOURCE CODE
WORKDIR /sources_buggy
RUN ./configure --disable-wireshark --disable-glibtest --disable-dftest CC=gcc CFLAGS="-Og"
RUN make -j$(nproc)

WORKDIR /sources_fixed
RUN ./configure --disable-wireshark --disable-glibtest --disable-dftest CC=gcc CFLAGS="-Og"
RUN make -j$(nproc)

WORKDIR /


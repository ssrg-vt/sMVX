#! /bin/sh
CC=musl-gcc ./configure --prefix=/opt/lighttpd --enable-static --disable-lfs --disable-ipv6 --without-valgrind --without-openssl --without-pcre --without-zlib --without-bzip2 --without-lua

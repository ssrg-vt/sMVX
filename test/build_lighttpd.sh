#!/bin/bash

tar xvf lighttpd-1.4.59.tar.gz
pushd lighttpd-1.4.59
CFLAGS='-fPIC -g' LDFLAGS="-pie" CC=gcc ./configure --without-pcre --without-bzip2 --without-zlib
make -j4
popd

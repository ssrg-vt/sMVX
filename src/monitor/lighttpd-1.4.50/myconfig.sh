CC=/usr/local/musl/bin/musl-gcc CFLAGS="-fPIC -O0 -I/usr/local/dec/inc" LDFLAGS="-pie -L/usr/local/lib -llmvx" ./configure --without-zlib --without-bzip2 --without-pcre

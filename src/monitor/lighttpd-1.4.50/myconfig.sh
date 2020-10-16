CCLD=/usr/local/musl/bin/musl-gcc CC=/usr/local/musl/bin/musl-clang-esjeon CFLAGS="-g -fPIC -O0 -I/usr/local/dec/inc" LDFLAGS="-pie -L/usr/local/lib -llmvx -z now" ./configure --without-zlib --without-bzip2 --without-pcre
#CC=/usr/local/musl/bin/musl-gcc CFLAGS="-fPIC -O0 -I/usr/local/dec/inc" LDFLAGS="-pie -L/usr/local/lib -llmvx" ./configure --without-zlib --without-bzip2 --without-pcre

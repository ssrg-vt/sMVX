## Description
A simple ELF loader to load a variant binary's .text section into the target's memory (the vanilla binary).

## How to use?
```
$ make
$ ls
loader.so   test.bin   liblmvx.a ...
$ BIN=test3 LD_PRELOAD=./loader.so ./test.bin
```

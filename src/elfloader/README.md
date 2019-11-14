## Description
A simple ELF loader to load a variant binary's .text section into the target's memory (the vanilla binary).

## How to use?
```
$ make
$ ls
loader.so   test.bin   liblmvx.a ...
```
Manually write the configuration file of the sensitive function (with offset) list. Examples are in conf. Run `test.bin`:
```
$ BIN=test.bin CONF=conf/func.conf LD_PRELOAD=./loader.so ./test.bin
```

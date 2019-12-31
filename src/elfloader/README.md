## Description
A simple ELF loader to load a variant binary's .text section into the target's memory (the vanilla binary).
In the master branch version, the elfloader duplicates the binary's *.text* section and starts a new thread
to execute the selected code (duplicated execution).

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

### Running Nginx w/ elfloader
To run Nginx w/ elfloader is easy. Specify the binary name and a configuration file (using env BIN=xxx 
and CONF=xxx respectively):
```
$ cd deC/src/elfloader/nginx.dec
$ BIN=nginx CONF=func.conf LD_PRELOAD=../loader.so ./objs/nginx
argc 0x3319b1b0. (null)
INFO  src/loader.c:87: LD_PRELOAD Binary: nginx. CONF: func.conf.
WARN  src/loader.h:83: mem space has gap
```

The configuration file specifies the function name and offset in the ELF. Those function names will be parsed
by the elfloader and will be passed to the liblmvx library. The *lmvx_start* has to know the sensitive function
addresses.
```
$ cat func.conf
ngx_http_handler 329e7
ngx_http_process_request_line 38ee8
ngx_http_parse_request_line 39b82

$ objdump -S objs/nginx | grep ngx_http_handler\>:
00000000000329e7 <ngx_http_handler>:
```

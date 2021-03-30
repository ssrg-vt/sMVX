# deC
The duplicated execution context project. Duplicate the execution for selected code area (A lightweight [MVX](https://en.wikipedia.org/wiki/N-version_programming) approach). It aims to *Selective Program Duplication and Differential Execution*.

## Run simple test cases
```
$ make
$ make -C test run_global_pointer
[14991] fun
my_struct_t.a 1, b 20, c 0x7fff105af3cc
[14991] main
INFO  update_pointers_self: # of old data pointers on *data+bss* 1   at update_pointers_self (loader.c:400) 
[14991] fun
my_struct_t.a 2, b 20, c 0x7fff105af3cc
INFO  update_heap_pointers_self: # of code pointers on *heap* 2   at update_heap_pointers_self (loader.c:410) 
[14992] fun
my_struct_t.a 2, b 20, c 0x7fff105af3cc
INFO  lmvx_end: finish lmvx region. status 0   at lmvx_end (lmvx.c:263) 
[14991] fun
my_struct_t.a 3, b 20, c 0x7fff105af3cc
```

## Taint analysis

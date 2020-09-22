The taint analysis engine (TAE) is used for dumping out the functions that access the "tainted memory" (memory from the network or local files).
The TAE is mostly from the [libdft project](https://www.cs.columbia.edu/~vpk/research/libdft/). Unfortunately, the libdft only supports 32 bit applications with PIN 2.x (Linux Kernel 3.x or below).
So it is best to run the TAE on a 32 bit ubuntu 14.04 VM.

### Preparation
```
$ export PIN_HOME=<path to deC>/deC/src/taint_analysis/pin-2.12
$ git submodule update 
Submodule path '../pin-2.12': checked out '8825e53d85a11d0c5b932b62e291d6e785c65761'
$ cd deC/src/taint_analysis/libdft-i386; make
```

### Running and profiling the Nginx web server
```
$ /home/xiaoguang/works/pintools/pin -follow_execv -t \
/home/xiaoguang/works/deC/src/libdft-i386/tools/libdft-dta.so -s 0 -f 0 -n 1 -- \
/home/xiaoguang/works/binaries/nginx-1.3.9/objs/nginx -c \
/home/xiaoguang/works/binaries/nginx-1.3.9/xiaoguang.conf -p \
/home/xiaoguang/works/binaries/root-nginx/ 

$ ls -lth    
-rw-rw-r--  1 xiaoguang xiaoguang  50K Sep 14 10:21 dft.out

$ ./py_dft_getaddr.py /home/xiaoguang/works/binaries/nginx-1.3.9/objs/nginx dft.out nginx-1.3.9/cscope.out 
Finish processing the large [dft log] file ...
Total lines of app instr from the log file: 2054
29 addresses found in the taint trace!
The function names + offsets are:

==== Results ====
2054 application instrs access tainted memory. Including libc, total of 2196 instrs.
17 tainted functions. Without function deduplication the number is 29

=== Functions ===
nginx-1.3.9/cscope.out
ngx_strstrn --> nginx-1.3.9/src/core/ngx_string.c
ngx_http_parse_request_line --> nginx-1.3.9/src/http/ngx_http_parse.c
ngx_http_validate_host --> nginx-1.3.9/src/http/ngx_http_request.c
ngx_http_range_header_filter --> nginx-1.3.9/src/http/modules/ngx_http_range_filter_module.c
ngx_http_process_request_line --> nginx-1.3.9/src/http/ngx_http_request.c
ngx_http_autoindex_handler --> nginx-1.3.9/src/http/modules/ngx_http_autoindex_module.c
ngx_http_send_special_response --> nginx-1.3.9/src/http/ngx_http_special_response.c
ngx_strncasecmp --> nginx-1.3.9/src/core/ngx_string.c
ngx_http_process_request_headers --> nginx-1.3.9/src/http/ngx_http_request.c
ngx_http_header_filter --> nginx-1.3.9/src/http/ngx_http_header_filter_module.c
ngx_http_log_variable_getlen --> nginx-1.3.9/src/http/modules/ngx_http_log_module.c
ngx_http_parse_header_line --> nginx-1.3.9/src/http/ngx_http_parse.c
ngx_http_static_handler --> nginx-1.3.9/src/http/modules/ngx_http_static_module.c
ngx_http_index_handler --> nginx-1.3.9/src/http/modules/ngx_http_index_module.c
ngx_strcasestrn --> nginx-1.3.9/src/core/ngx_string.c
ngx_vslprintf --> nginx-1.3.9/src/core/ngx_string.c
ngx_cpystrn --> nginx-1.3.9/src/core/ngx_string.c
```

CC          := /usr/local/musl/bin/musl-gcc
CFLAGS		:= -Wall -fPIC -pie -O0
PRELOAD		:= LD_PRELOAD=$(shell pwd)/../libmonitor.so
LMVX.SO		:= $(shell pwd)/../liblmvx.so
CHECKER		:= ../tools/checker.sh

ifneq ($(VERBOSE),YES)
HUSH_CC		= @echo ' [CC]\t\t'$@;
HUSH_CC_LD	= @echo ' [CC+LD]\t'$@;
HUSH_LD		= @echo ' [LD]\t\t'$@;
HUSH_AR		= @echo ' [AR]\t\t'$@;
endif

BIN			:= stack_pointer heap_pointer global_pointer tiny

all: $(BIN)

clean:
	rm -rf $(BIN)

## Pointers on the stack
stack_pointer: stack_pointer.c $(LMVX.SO)
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) $(CFLAGS) $^ -o $@

run_stack_pointer: stack_pointer
	$(CHECKER) $<
	BIN=$< $(PRELOAD) ./$<

## Pointers on the heap
heap_pointer: heap_pointer.c $(LMVX.SO)
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) $(CFLAGS) $^ -o $@

run_heap_pointer: heap_pointer
	$(CHECKER) $<
	BIN=$< $(PRELOAD) ./$<

## Global pointers 
global_pointer: global_pointer.c $(LMVX.SO)
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) $(CFLAGS) $^ -o $@

run_global_pointer: global_pointer
	$(CHECKER) $<
	BIN=$< $(PRELOAD) ./$<

## The tiny web server
tiny: tiny.c $(LMVX.SO)
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) $(CFLAGS) $^ -o $@

run_tiny: tiny
	$(CHECKER) $<
	BIN=$< $(PRELOAD) ./$<

## Two binaries, from (mostly) same source code
test.bin: test.c $(LMVX.SO)
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -Wall -fPIC -pie -g $^ -O0 -o $@

run_test.bin: test.bin
	$(CHECKER) $<
	BIN=$< $(PRELOAD) ./$<

## Pointer test case --> pointer.bin
pointer.bin: pointer.c $(LMVX.SO)
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -Wall -fPIC -pie -g $^ -O0 -o $@

run_pointer.bin: pointer.bin
	$(CHECKER) $<
	BIN=$< $(PRELOAD) ./$<

## TODO:
## Larger applications
nginx_run:
	LOG_LEVEL=ERROR BIN=nginx LD_PRELOAD=libmonitor.so ./nginx-1.3.9/objs/nginx

lighttpd_run: lighttpd_checker
	LOG_LEVEL=TRACE PATCH_LIBS=mod_indexfile,mod_dirlisting,mod_staticfile BIN=lighttpd LD_PRELOAD=libmonitor.so ./lighttpd-1.4.50/src/lighttpd -f ./lighttpd-1.4.50/lighttpdconfig.conf -D
	#LOG_LEVEL=TRACE BIN=lighttpd LD_PRELOAD=libmonitor.so ./lighttpd-1.4.50/src/lighttpd -f ./lighttpd-1.4.50/lighttpdconfig.conf -D

nbench_run: nbench_checker
	cd nbench; LOG_LEVEL=TRACE BIN=nbench LD_PRELOAD=../libmonitor.so ./nbench
	#LOG_LEVEL=TRACE BIN=nbench LD_PRELOAD=libmonitor.so ./nbench/nbench

debug:
	gdb test.bin -ex "set exec-wrapper env 'LD_PRELOAD=libmonitor.so'" -ex "set environment BIN=test.bin"

nginx_debug:
	gdb nginx-1.3.9/objs/nginx -ex "set environment LOG_LEVEL=TRACE" -ex "set exec-wrapper env 'LD_PRELOAD=libmonitor.so'" -ex "set environment BIN=nginx"

redis_debug:
	gdb redis/src/redis-server -ex "set environment LOG_LEVEL=TRACE" -ex "set exec-wrapper env 'LD_PRELOAD=libmonitor.so'" -ex "set environment BIN=redis-server"

lighttpd_checker:
	./checker.sh ./lighttpd-1.4.50/src/lighttpd /usr/local/lib/mod_staticfile.so /usr/local/lib/mod_dirlisting.so /usr/local/lib/mod_indexfile.so

lighttpd_debug:
	gdb ./lighttpd-1.4.50/src/lighttpd -ex "set environment LOG_LEVEL=TRACE" -ex "set environment BIN=lighttpd" -ex "set environment PATCH_LIBS=mod_indexfile,mod_dirlisting,mod_staticfile" -ex "set exec-wrapper env 'LD_PRELOAD=libmonitor.so'"

nbench_checker:
	./checker.sh ./nbench/nbench

nbench_debug: nbench_checker
	cd nbench; gdb nbench -ex "set environment LOG_LEVEL=TRACE" -ex "set environment BIN=nbench" -ex "set exec-wrapper env 'LD_PRELOAD=../libmonitor.so'"

spec_gcc_checker:
	./checker.sh ./spec2006/benchspec/CPU2006/403.gcc/run/run_base_ref_amd64-m64-gcc42-nn.0000/gcc

gcc_debug: spec_gcc_checker
	cd ./spec2006/benchspec/CPU2006/403.gcc/run/run_base_ref_amd64-m64-gcc42-nn.0000/ ; gdb gcc -ex "set environment LOG_LEVEL=TRACE" -ex "set environment BIN=gcc" -ex "set exec-wrapper env 'LD_PRELOAD=/usr/local/lib/libmonitor.so'"

nginx_rebuild:
	make clean; make nginx
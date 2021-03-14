CC          := /usr/local/musl/bin/musl-gcc
#CC          := gcc
SRC_DIR     := src
LIB_DIR     := lib
INC_DIR     := inc
TEST_DIR    := test
OBJ_DIR     := obj
COMMON_DIR  := common
LIB_OBJ_FILES	:= $(patsubst $(LIB_DIR)/%.c,$(OBJ_DIR)/$(LIB_DIR)/%.o,$(wildcard $(LIB_DIR)/*.c))

DIRS	    := $(SRC_DIR) $(LIB_DIR)

OPT_LEVEL   := -O0
INC         := -I$(INC_DIR) -I$(COMMON_DIR)
SRC         := $(shell find $(SRC_DIR) -name '*.c')
OBJ         := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o, $(SRC))
CFLAGS      := $(OPT_LEVEL) -fPIC -c -g $(INC) -DINTEL_MPK
LDFLAGS     := -L/usr/local/lib  #-lseccomp #Uncomment after fixing issue #13 in github
MKDIR       = mkdir

ifneq ($(VERBOSE),YES)
HUSH_CC		= @echo ' [CC]\t\t'$@;
HUSH_CC_LD	= @echo ' [CC+LD]\t'$@;
HUSH_LD		= @echo ' [LD]\t\t'$@;
HUSH_AR		= @echo ' [AR]\t\t'$@;
endif

BIN := test.bin

all: pre monitor liblmvx.so test.bin

nginx: pre monitor liblmvx.so

pre: clean
	@echo $(SRC)
	@echo $(LIB_OBJ_FILES)
	@echo $(LIB_DIR)/%.c
	$(MKDIR) -p $(OBJ_DIR)
	$(MKDIR) $(OBJ_DIR)/$(LIB_DIR)

monitor: $(OBJ) $(OBJ_DIR)/trampoline.o
	@echo $(OBJ)
	$(HUSH_CC_LD) $(CC) -shared $^ $(LDFLAGS) -o libmonitor.so #-ldl

#install: libmonitor.so liblmvx.so
#	install -C libmonitor.so /usr/local/lib/
#	install -C libmonitor.so /usr/lib/x86_64-linux-gnu/
#	install -C liblmvx.so /usr/local/lib/
#	install -C liblmvx.so /usr/lib/x86_64-linux-gnu/
#	install -D $(INC_DIR)/libmonitor.h /usr/local/dec/inc
#	install -D $(INC_DIR)/lmvx.h /usr/local/dec/inc

### liblmvx.so
liblmvx.so: $(LIB_OBJ_FILES)
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -shared $^ $(LDFLAGS) -o liblmvx.so

## Two binaries, from (mostly) same source code
test.bin: $(TEST_DIR)/test.c liblmvx.so
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -Wall -fPIC -pie -g $^ -O0 -o $@

test_run:
	LOG_LEVEL=TRACE BIN=test.bin LD_PRELOAD=./libmonitor.so ./test.bin

## Pointer test case --> pointer.bin
pointer.bin: $(TEST_DIR)/pointer.c liblmvx.so
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -Wall -fPIC -pie -g $^ -O0 -o $@

pointer_test:
	LOG_LEVEL=TRACE BIN=pointer LD_PRELOAD=./libmonitor.so ./pointer.bin

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

clean:
	rm -rf $(OBJ_DIR) libmonitor.so liblmvx.so test.bin

rebuild:
	make clean; make all

nginx_rebuild:
	make clean; make nginx

$(OBJ_DIR)/$(LIB_DIR)/%.o: $(LIB_DIR)/%.c
	$(HUSH_CC) $(CC) $(CFLAGS) $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(HUSH_CC) $(CC) $(CFLAGS) $< -o $@

$(OBJ_DIR)/trampoline.o: $(SRC_DIR)/trampoline.s
	$(HUSH_CC) $(CC) $(CFLAGS) $< -o $@

.PHONY: all clean install monitor_trampoline pre test_run debug rebuild

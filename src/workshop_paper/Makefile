CC          := /usr/local/musl/bin/musl-gcc
#CC          := gcc
#SRC_DIR     := ./src
#LIB_DIR     := ./lib
#INC_DIR     := ./inc
#TEST_DIR    := ./test
#OBJ_DIR     := ./obj
#COMMON_DIR  := ./common
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

all: pre monitor libthreadtest.so test.bin thread_test.bin


pre: clean
	@echo $(SRC)
	@echo $(LIB_OBJ_FILES)
	@echo $(LIB_DIR)/%.c
	$(MKDIR) -p $(OBJ_DIR)
	$(MKDIR) $(OBJ_DIR)/$(LIB_DIR)

monitor: $(OBJ) $(OBJ_DIR)/trampoline.o
	@echo $(OBJ)
	$(HUSH_CC_LD) $(CC) -shared $^ $(LDFLAGS) -o libmonitor.so #-ldl

install: libmonitor.so
	install -C libmonitor.so /usr/local/lib/
	install -C libmonitor.so /usr/lib/x86_64-linux-gnu/
	install -D $(INC_DIR)/libmonitor.h /usr/local/dec/inc

## For multithreaded testing, library, binary build targets and run/debug targets
libthreadtest.so: $(LIB_OBJ_FILES)
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -shared $^ $(LDFLAGS) -o libthreadtest.so

thread_test.bin: $(TEST_DIR)/thread_test.c libthreadtest.so
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -Wall -fPIC -pie -g $^ -O0 -o $@

thread_test_run: check_thread
	LD_LIBRARY_PATH=. LOG_LEVEL=ERROR BIN=thread_test.bin LD_PRELOAD=libmonitor.so ./thread_test.bin

thread_test_debug: check_thread
	gdb thread_test.bin -ex "set environment LD_LIBRARY_PATH=." -ex "set environment LOG_LEVEL=TRACE" -ex "set exec-wrapper env 'LD_PRELOAD=libmonitor.so'" -ex "set environment BIN=thread_test.bin"

check_thread:
	./checker.sh thread_test.bin

## Test binary build, run and debug targets
test.bin: $(TEST_DIR)/test.c
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -Wall -fPIC -pie -g $^ -O0 -o $@

test_run: check_test
	LOG_LEVEL=TRACE BIN=test.bin LD_PRELOAD=libmonitor.so ./test.bin

test_debug: check_test
	gdb test.bin -ex "set environment LOG_LEVEL=ERROR" -ex "set exec-wrapper env 'LD_PRELOAD=libmonitor.so'" -ex "set environment BIN=test.bin"

check_test:
	./checker.sh test.bin

# Loop getpid test case
getpid_loop.bin: $(TEST_DIR)/getpid.c
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -Wall -fPIC -pie -g $^ -O0 -o $@

getpid_loop_test: check_getpid
	LOG_LEVEL=ERROR BIN=getpid_loop.bin LD_PRELOAD=libmonitor.so ./getpid_loop.bin

getpid_debug: check_getpid
	gdb getpid_loop.bin -ex "set environment LOG_LEVEL=TRACE" -ex "set exec-wrapper env 'LD_PRELOAD=libmonitor.so'" -ex "set environment BIN=getpid_loop.bin"

check_getpid:
	./checker.sh getpid_loop.bin

# Nginx run and debug targets
nginx:
	$(MAKE) -C nginx-1.3.9

nginx_run: nginx check_nginx
	LOG_LEVEL=ERROR BIN=nginx LD_PRELOAD=libmonitor.so ./nginx-1.3.9/objs/nginx

check_nginx:
	./checker.sh nginx-1.3.9/objs/nginx

nginx_debug: nginx check_nginx
	gdb nginx-1.3.9/objs/nginx -ex "set environment LOG_LEVEL=TRACE" -ex "set exec-wrapper env 'LD_PRELOAD=libmonitor.so'" -ex "set environment BIN=nginx"

# Redis run and debug targets
redis: 
	$(MAKE) -C redis

redis_run: redis check_redis
	LOG_LEVEL=ERROR BIN=redis-server LD_PRELOAD=libmonitor.so ./redis/src/redis-server

redis_debug: redis check_redis
	gdb ./redis/src/redis-server -ex "set environment LOG_LEVEL=TRACE" -ex "set exec-wrapper env 'LD_PRELOAD=libmonitor.so'" -ex "set environment BIN=redis-server"

check_redis:
	./checker.sh redis/src/redis-server

clean:
	rm -rf $(OBJ_DIR) libmonitor.so libthreadtest.so test.bin getpid_loop.bin thread_test.bin

rebuild:
	make clean; make all

$(OBJ_DIR)/$(LIB_DIR)/%.o: $(LIB_DIR)/%.c
	$(HUSH_CC) $(CC) $(CFLAGS) -I$(LIB_DIR) $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(HUSH_CC) $(CC) $(CFLAGS) $< -o $@

$(OBJ_DIR)/trampoline.o: $(SRC_DIR)/trampoline.s
	$(HUSH_CC) $(CC) $(CFLAGS) $< -o $@

.PHONY: all clean install monitor_trampoline pre test_run debug rebuild

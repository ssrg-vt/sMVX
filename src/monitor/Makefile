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
CFLAGS      := $(OPT_LEVEL) -fPIC -c $(INC)
LDFLAGS     := -L/usr/local/lib  #-lseccomp #Uncomment after fixing issue #13 in github
MKDIR       = mkdir

ifneq ($(VERBOSE),YES)
HUSH_CC		= @echo ' [CC]\t\t'$@;
HUSH_CC_LD	= @echo ' [CC+LD]\t'$@;
HUSH_LD		= @echo ' [LD]\t\t'$@;
HUSH_AR		= @echo ' [AR]\t\t'$@;
endif

BIN := test.bin

all: pre monitor liblmvx.so test.bin post

pre:
	@echo $(SRC)
	@echo $(LIB_OBJ_FILES)
	@echo $(LIB_DIR)/%.c
	$(MKDIR) -p $(OBJ_DIR)
	$(MKDIR) $(OBJ_DIR)/$(LIB_DIR)

post: test.bin
	@echo "=== dump sensitive functions ==="
	@objdump -S test.bin | grep "recursive_func>:"
	@objdump -S test.bin | grep "simple_func>:"
	@cat conf/func.conf

monitor: $(OBJ)
	@echo $(OBJ)
	$(HUSH_CC_LD) $(CC) -shared $^ $(LDFLAGS) -o libmonitor.so #-ldl

install: libmonitor.so liblmvx.so
	install -C libmonitor.so /usr/local/lib/
	install -C libmonitor.so /usr/lib/x86_64-linux-gnu/
	install -C liblmvx.so /usr/local/lib/
	install -C liblmvx.so /usr/lib/x86_64-linux-gnu/
	install -D $(INC_DIR)/libmonitor.h /usr/local/dec/inc
	install -D $(INC_DIR)/lmvx.h /usr/local/dec/inc

### liblmvx.so
liblmvx.so: $(LIB_OBJ_FILES)
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -shared $^ $(OBJ_DIR)/log.o $(OBJ_DIR)/env.o $(LDFLAGS) -o liblmvx.so

## Two binaries, from (mostly) same source code
test.bin: $(TEST_DIR)/test.c liblmvx.so
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -Wall -fPIC -pie -g $^ -O0 -o $@

test_run:
	LOG_LEVEL=TRACE BIN=test.bin CONF=conf/func.conf LD_PRELOAD=libmonitor.so ./test.bin

debug:
	gdb test.bin -ex "set environment CONF=conf/func.conf" -ex "set exec-wrapper env 'LD_PRELOAD=libmonitor.so'" -ex "set environment BIN=test.bin"

clean:
	rm -rf $(OBJ_DIR) libmonitor.so liblmvx.so test.bin

rebuild:
	make clean; make

$(OBJ_DIR)/$(LIB_DIR)/%.o: $(LIB_DIR)/%.c
	$(HUSH_CC) $(CC) $(CFLAGS) $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(HUSH_CC) $(CC) $(CFLAGS) $< -o $@

.PHONY: all clean install monitor_trampoline pre post test_run debug rebuild

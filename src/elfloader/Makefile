.PHONY: all clean test

SRC_DIR := ./src
LIB_DIR := ./lib
DIRS	:= $(SRC_DIR) $(LIB_DIR)
INC_DIR := ./inc
TEST_DIR := ./test
OBJ_DIR := ./obj
CONF_TAB_ADDR := conf/tab_addr.conf

SRC_FILES		:= $(SRC_DIR)/loader.c $(LIB_DIR)/log.c $(LIB_DIR)/env.c
#LIB_FILES		:= $(wildcard $(LIB_DIR)/*.c)
#FILES			:= $(foreach dir,$(DIRS),$(wildcard $(dir)/*.c))
LIB_OBJ_FILES	:= $(patsubst $(LIB_DIR)/%.c,$(OBJ_DIR)/%.o,$(wildcard $(LIB_DIR)/*.c))

ifneq ($(VERBOSE),YES)
HUSH_CC		= @echo ' [CC]\t\t'$@;
HUSH_CC_LD	= @echo ' [CC+LD]\t'$@;
HUSH_LD		= @echo ' [LD]\t\t'$@;
HUSH_AR		= @echo ' [AR]\t\t'$@;
endif

CC = /usr/local/musl/bin/musl-gcc	#CC = gcc
CPP = g++
CFLAGS := -Wall -g -fPIC
LDFLAGS := -pie
MKDIR = mkdir
DEPS = ./inc/lmvx.h

BIN := liblmvx.a test.bin

all: pre $(BIN) post
	@echo "BIN:" $(BIN)

pre:
	@echo $(SRC_FILES)
	@echo $(LIB_OBJ_FILES)
	@echo $(LIB_DIR)/%.c
	$(MKDIR) -p $(OBJ_DIR)

post: test.bin
	@echo "=== dump sensitive functions ==="
	@objdump -S test.bin | grep "recursive_func>:"
	@objdump -S test.bin | grep "simple_func>:"
	@cat conf/func.conf

test_run:
	BIN=test.bin CONF=conf/func.conf LD_PRELOAD=./loader.so ./test.bin

### loader.so
loader.so: $(SRC_FILES)
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -I$(INC_DIR) -Wall -fPIC -shared -g $^ -o $@ -ldl

### liblmvx.a
liblmvx.a: $(LIB_OBJ_FILES)
	@echo "Generate "$@":"
	$(HUSH_AR) $(AR) -cq $@ $^

### Two binaries, from (mostly) same source code
test.bin: $(TEST_DIR)/test.c $(DEPS) liblmvx.a
	@echo "Generate "$@":"
	$(HUSH_CC) $(CC) $(CFLAGS) $^ -O0 -o $@

$(OBJ_DIR)/%.o: $(LIB_DIR)/%.c
	$(HUSH_CC) $(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

clean:
	rm -rf *.o $(BIN) $(OBJ_DIR) $(CONF_TAB_ADDR)

rebuild:
	make clean; make

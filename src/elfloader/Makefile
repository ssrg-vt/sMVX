.PHONY: all clean test

SRC_DIR := ./src
LOADER_SRC_DIR := ./src/loader
INC_DIR := ./inc
TEST_DIR := ./test
OBJ_DIR := ./obj
CONF_TAB_ADDR := conf/tab_addr.conf

SRC_FILES	:= $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES	:= $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC_FILES))

ifneq ($(VERBOSE),YES)
HUSH_CC		= @echo ' [CC]\t'$@;
HUSH_LD		= @echo ' [LD]\t'$@;
HUSH_AR		= @echo ' [AR]\t'$@;
endif

CC = gcc
AR = ar
CFLAGS := -Wall
LDFLAGS := -pie
MKDIR = mkdir
DEPS = ./inc/lmvx.h

BIN := liblmvx.a test.bin loader.so

all: pre $(BIN)
	@echo "BIN:" $(BIN)

pre:
	$(MKDIR) -p $(OBJ_DIR)

### loader.so
loader.so: $(LOADER_SRC_DIR)/loader.c $(SRC_DIR)/log.c $(SRC_DIR)/env.c
	$(HUSH_CC) $(CC) -I$(INC_DIR) -Wall -fPIC -shared $^ -o $@ -ldl

### liblmvx.a
liblmvx.a: $(OBJ_FILES)
	$(HUSH_AR) $(AR) -cq $@ $^

### Two binaries, from (mostly) same source code
test.bin: $(TEST_DIR)/test.c $(DEPS) liblmvx.a
	$(HUSH_CC) $(CC) $(CFLAGS) $^ -O0 -o $@

### I need to manually modify test.c (exclude lib) to generate test3
### TODO
test3: $(TEST_DIR)/test.c $(DEPS)
	$(HUSH_CC) $(CC) $(CFLAGS) $< -O3 -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(HUSH_CC) $(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

clean:
	rm -rf *.o $(BIN) $(OBJ_DIR) $(CONF_TAB_ADDR)

rebuild:
	make clean; make

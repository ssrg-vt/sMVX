# C Compiler
CC          := /usr/local/musl/bin/musl-gcc

# Dirs and files
SRC_DIR     := src
LIB_DIR     := lib
INC_DIR     := inc
TEST_DIR    := test
OBJ_DIR     := obj

# Compilation flags
OPT_LEVEL   := -O0
CFLAGS      := $(OPT_LEVEL) -fPIC -c -g -I$(INC_DIR) -DINTEL_MPK
LDFLAGS     := #-L/usr/local/lib  #-lseccomp #Uncomment after fixing issue #13 in github

# Src and Obj files
SRC         := $(shell find $(SRC_DIR) -name '*.c')
OBJ         := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o, $(SRC))
LIB_OBJ_FILES	:= $(patsubst $(LIB_DIR)/%.c,$(OBJ_DIR)/$(LIB_DIR)/%.o,$(wildcard $(LIB_DIR)/*.c))

# Building commands
MKDIR       = mkdir

ifneq ($(VERBOSE),YES)
HUSH_CC		= @echo ' [CC]\t\t'$@;
HUSH_CC_LD	= @echo ' [CC+LD]\t'$@;
HUSH_LD		= @echo ' [LD]\t\t'$@;
HUSH_AR		= @echo ' [AR]\t\t'$@;
endif


# Recipes
all: prebuild libmonitor.so liblmvx.so

# Build object files
$(OBJ_DIR)/$(LIB_DIR)/%.o: $(LIB_DIR)/%.c
	$(HUSH_CC) $(CC) $(CFLAGS) $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(HUSH_CC) $(CC) $(CFLAGS) $< -o $@

$(OBJ_DIR)/trampoline.o: $(SRC_DIR)/trampoline.s
	$(HUSH_CC) $(CC) $(CFLAGS) $< -o $@

prebuild: clean
	$(MKDIR) -p $(OBJ_DIR)/$(LIB_DIR)

## libmonitor.so
libmonitor.so: $(OBJ) $(OBJ_DIR)/trampoline.o
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -shared $^ $(LDFLAGS) -o libmonitor.so #-ldl
	@echo

## liblmvx.so (this is just a placeholder library that links to the appliation)
liblmvx.so: $(LIB_OBJ_FILES)
	@echo "Generate "$@":"
	$(HUSH_CC_LD) $(CC) -shared $^ $(LDFLAGS) -o liblmvx.so

# Call Makefile in test/ directory
test: libmonitor.so liblmvx.so
	make -C test

clean:
	rm -rf $(OBJ_DIR) libmonitor.so liblmvx.so

.PHONY: all clean test prebuild liblmvx.so libmonitor.so
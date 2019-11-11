CC          := /usr/local/musl/bin/musl-gcc
#CC          := gcc
OPT_LEVEL   := -O0
INC         := /usr/local/dec/inc/
SRC         := $(wildcard *.c)
OBJ         := $(SRC:.c=.o)
CFLAGS      := $(OPT_LEVEL) -c -I$(INC)
#LDFLAGS     := -L/usr/local/lib -llightweight_mvx
LDFLAGS     := -L/usr/local/lib
LD          := /usr/bin/ld

all: target_app

target_app : $(OBJ)
	$(CC) $^ $(LDFLAGS) -o target_app

clean :
	rm $(OBJ) target_app
%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: all clean

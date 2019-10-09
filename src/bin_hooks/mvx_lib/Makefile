CC          := gcc
OPT_LEVEL   := -O0
INC         := header
SRC         := $(wildcard *.c)
OBJ         := $(SRC:.c=.o)
CFLAGS      := $(OPT_LEVEL) -c -I$(INC)
LDFLAGS     := 

all: lightweight_mvx

lightweight_mvx : $(OBJ)
	$(CC) -shared $^ $(LDFLAGS) -o liblightweight_mvx.so

install: liblightweight_mvx.so
	cp liblightweight_mvx.so /usr/local/lib/

clean :
	rm $(OBJ) liblightweight_mvx.so

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: all clean install lightweight_mvx

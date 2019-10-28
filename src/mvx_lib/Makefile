CC          := gcc
OPT_LEVEL   := -O0
INC         := -Iheader -Icommon
SRC         := $(wildcard *.c)
OBJ         := $(SRC:.c=.o)
CFLAGS      := $(OPT_LEVEL) -c $(INC) -fPIC
LDFLAGS     := 

all: liblightweight_mvx 

liblightweight_mvx : $(OBJ)
	$(CC) -shared $^ $(LDFLAGS) -o liblightweight_mvx.so

install: liblightweight_mvx.so
	install -C liblightweight_mvx.so /usr/local/lib/
	install -C liblightweight_mvx.so /usr/lib/x86_64-linux-gnu/
	install -D header/lightweight_mvx.h /usr/local/dec/inc

clean :
	rm $(OBJ) liblightweight_mvx.so

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: all clean install lightweight_mvx

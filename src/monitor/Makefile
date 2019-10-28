CC          := gcc
OPT_LEVEL   := -O0
INC         := -Iheader -Icommon
SRC         := $(wildcard *.c)
OBJ         := $(SRC:.c=.o)
CFLAGS      := $(OPT_LEVEL) -c $(INC) -fPIC
LDFLAGS     := -L/usr/local/lib -lseccomp

all: monitor_trampoline

monitor_trampoline : $(OBJ)
	$(CC) -shared $^ $(LDFLAGS) -o libmonitor_trampoline.so -ldl

install: libmonitor_trampoline.so
	install -C libmonitor_trampoline.so /usr/local/lib/
	install -C libmonitor_trampoline.so /usr/lib/x86_64-linux-gnu/
	#install -D header/monitor_trampoline.h /usr/local/dec/inc

clean :
	rm $(OBJ) libmonitor_trampoline.so

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: all clean install monitor_trampoline

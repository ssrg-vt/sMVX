.POSIX:
CC     = cc
LD	   = ld
CP	   = cp
SRC	   = main.c monitor.c ptrace.c
OBJ	   = $(SRC:.c=.o)

CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200112L -Wall -g3 -g -funwind-tables -I ../inc \
		-Wno-missing-field-initializers -Wno-missing-braces -Wno-unused-parameter \
		-Wno-unused-variable -Wextra
		
LDFLAGS= -lpthread

all: mvx_monitor 
	@$(CP) $< ../

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

mvx_monitor: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	@rm -f mvx_monitor *.o

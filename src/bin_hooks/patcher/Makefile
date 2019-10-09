CC          := gcc
OPT_LEVEL   := -O0
INC         := lib/h
SRC         := $(wildcard *.cpp)
OBJ         := $(SRC:.cpp=.o)
CFLAGS      := $(OPT_LEVEL) -c -I$(INC)
LDFLAGS     := -L/usr/local/lib -lstdc++ -lboost_system -ldyninstAPI
LD          := /usr/bin/ld

all: mvx_patcher

mvx_patcher : $(OBJ)
	$(CC) $^ $(LDFLAGS) -o mvx_patcher -std=c++11

clean :
	rm $(OBJ) mvx_patcher
%.o: %.c
	$(CC) $(CFLAGS) $< -o $@ -std=c++11

.PHONY: all clean

CC = gcc

#SRC := $(wildcard *.c)
#BIN := $(SRC:%.c=%)
BIN := test

all: $(BIN) loader.so
	@echo "BIN:" $(BIN)
#	@echo "SRC:" $(SRC)

loader.so: loader.c
	$(CC) -Wall -fPIC -shared $< -o $@ -ldl

%: %.o
	$(CC) $< -o $@

%.o: %.c
	$(CC) -c $<

clean:
	rm -rfv *.o $(BIN) loader.so

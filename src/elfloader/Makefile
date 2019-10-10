CC = gcc
CFLAGS := -I. -I./inc

BIN := test test3

all: $(BIN) loader.so
	@echo "BIN:" $(BIN)

loader.so: loader.c
	$(CC) -Wall -fPIC -shared $< -o $@ -ldl

test: test.c
	$(CC) $(CFLAGS) $< -O0 -o $@

test3: test.c
	$(CC) $(CFLAGS) $< -O3 -o $@

clean:
	rm -rf *.o $(BIN) loader.so

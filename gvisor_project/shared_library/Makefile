all:
	#gcc -Wall -g -o elfloader elf_loader.c main.c wheelc/list.c -ldl -lpthread
	gcc -Wall -o aegis.so -Wl,--whole-archive libcapstone.a -Wl,--no-whole-archive -shared -fPIC prototype_runc.c elf_loader.c wheelc/list.c  -ldl

clean:
	rm -rf *.o wheelc/*.o elfloader

#all: clean main testall 
all: main testall 

main:
	@echo "[Make] src/"
	@$(MAKE) -C src 

testall:
	@echo "[Make] test/"
	@$(MAKE) -C test

curllighttpd:
	$(MAKE) -C test curl

ablighttpd:
	$(MAKE) -C test ab

clean:
	@echo "[Clean] src/ test/"
	@$(MAKE) -C src clean
	@$(MAKE) -C test clean

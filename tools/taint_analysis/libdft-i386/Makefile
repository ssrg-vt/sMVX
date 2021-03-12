SHELL := /bin/bash

all:
	pushd .; \
	cd src; make; \
	popd; \
	cd tools; make clean; make

clean:
	pushd .; \
	cd src; make clean; \
	popd; \
	cd tools; make clean


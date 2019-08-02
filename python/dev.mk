include ../src/Makefile

.PHONY: prepack
prepack:
	rm -rf .build
	mkdir .build
	cp -R ../data ../src py_saml.c Makefile .build
	rm -f .build/src/saml.o

.PHONY: build
build: prepack
	make -C .build build

.PHONY: test
test: build
	PYTHONPATH=`pwd`/.build/ python -m unittest discover -s t

.PHONY: gdb
gdb: build
	gdb -ex "set environment PYTHONPATH=`pwd`/.build/" -ex 'run -m unittest discover -s t' python

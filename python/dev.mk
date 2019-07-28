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

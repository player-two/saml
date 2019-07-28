include src/Makefile

PYTHON_INCDIR=/usr/include/python3.7m

.DEFAULT_GOAL: build

.PHONY: build
build: saml.so

py_saml.o: py_saml.c
	$(CC) -c $(CFLAGS_ALL) -I$(PYTHON_INCDIR) -Isrc/ -o $@ $<
	#python setup.py build

saml.so: py_saml.o src/saml.o
	$(CC) $(LDFLAGS_ALL) -o $@ $^

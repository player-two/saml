# Default locations
LIBXML2_INCDIR=/usr/include/libxml2
XMLSEC1_INCDIR=/usr/local/include/xmlsec1
XMLSEC1_LIBDIR=/usr/local/lib

CC=gcc
CFLAGS=-g -fPIC
XMLSEC1_CFLAGS=$(shell xmlsec1-config --cflags)
CFLAGS_ALL=$(CFLAGS) -Wall -std=c99 -I$(LIBXML2_INCDIR) -I$(XMLSEC1_INCDIR) $(XMLSEC1_CFLAGS)
LIBFLAG=-shared
LDFLAGS=-g
XMLSEC1_LDFLAGS=$(shell xmlsec1-config --libs)
LDFLAGS_ALL=$(LIBFLAG) $(LDFLAGS) -L$(LIBXML2_LIBDIR) -L$(XMLSEC1_LIBDIR) $(XMLSEC1_LDFLAGS)

.DEFAULT_GOAL: build

.PHONY: build
build: saml.so

saml.o: saml.c
	$(CC) -c $(CFLAGS_ALL) -o $@ $<

lua_saml.o: lua_saml.c
	$(CC) -c $(CFLAGS_ALL) -I$(LUA_INCDIR) -o $@ $<

saml.so: lua_saml.o saml.o
	$(CC) $(LDFLAGS_ALL) -o $@ $^

.PHONY: install
install: build
	cp saml.so $(INST_LIBDIR)
	mkdir -p $(INST_LUADIR)/resty/saml
	cp lib/resty/saml/*.lua $(INST_LUADIR)/resty/saml
	cp -R data $(INST_CONFDIR)

bin/saml.o: bin/saml.c
	$(CC) -c -o bin/saml.o $<

bin/saml: bin/saml.c saml.o
	$(CC) -I$(shell pwd) -g -Wall -Werror -std=c99 -I$(LIBXML2_INCDIR) -I$(XMLSEC1_INCDIR) $(XMLSEC1_CFLAGS) -L$(LIBXML2_LIBDIR) -L$(XMLSEC1_LIBDIR) $(XMLSEC1_LDFLAGS) -lcurl -o bin/saml $^

.PHONY: cli
cli: bin/saml

.PHONY: install-cli
install-cli: cli
	mv bin/saml $(HOME)/.local/bin/

CC=gcc
CFLAGS=-g -fPIC
XMLSEC1_CFLAGS=$(shell xmlsec1-config --cflags)
CFLAGS_ALL=$(CFLAGS) -Wall -std=c99 -I$(LIBXML2_INCDIR) -I$(XMLSEC1_INCDIR) $(XMLSEC1_CFLAGS)
LIBFLAG=-shared
LDFLAGS=-g
XMLSEC1_LDFLAGS=$(shell xmlsec1-config --libs)
LDFLAGS_ALL=$(LIBFLAG) $(LDFLAGS) -L$(LIBXML_LIBDIR) -L$(XMLSEC1_LIBDIR) $(XMLSEC1_LDFLAGS)

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

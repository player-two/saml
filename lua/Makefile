include src/Makefile

LUA_INCDIR=/usr/include

.DEFAULT_GOAL: build

.PHONY: build
build: saml.so

lua_saml.o: lua_saml.c
	$(CC) -c $(CFLAGS_ALL) -I$(LUA_INCDIR) -Isrc/ -o $@ $<

saml.so: lua_saml.o src/saml.o
	$(CC) $(LDFLAGS_ALL) -o $@ $^

.PHONY: install
install: build
	cp saml.so $(INST_LIBDIR)
	mkdir -p $(INST_LUADIR)/resty/saml
	cp -R resty $(INST_LUADIR)
	cp -R data $(INST_CONFDIR)

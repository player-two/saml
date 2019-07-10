-include common.mk # only the build and install targets require this

TEST_ARGS?=.

.DEFAULT_GOAL: build

.PHONY: prepack
prepack:
	rm -rf .build
	mkdir .build
	cp -R resty ../data ../saml.h ../*.c lua_saml.c ../common.mk Makefile saml-dev-1.rockspec .build

.PHONY: test
test: prepack
	docker run --rm -it \
		-v `pwd`/.build:/tmp/.build \
		-v `pwd`/t:/t \
		-w /t \
		-e ROCK_DIR=/usr/local/openresty/luajit/lib/luarocks/rocks/saml/dev-1/ \
		resty-saml-test:latest \
		bash -c "cd /tmp/.build && luarocks make && cd /t && busted --lua=/usr/local/openresty/bin/resty -lpath /usr/local/openresty/lualib/?.lua -cpath /usr/local/openresty/lualib/?.so $(TEST_ARGS)"

.PHONY: example
example: prepack
	docker run --rm -it --name resty-saml-example \
		-v `pwd`/.build:/tmp/.build \
		-v `pwd`/t/data:/ssl \
		-v `pwd`/example:/example \
		-p 8088:8088 \
		-p 8089:8089 \
		resty-saml:latest \
		bash -c "cd /tmp/.build && luarocks make && cd /example && openresty -c /example/nginx.conf -g 'daemon off;'"

.PHONY: build
build: saml.so

lua_saml.o: lua_saml.c
	$(CC) -c $(CFLAGS_ALL) -I$(LUA_INCDIR) -o $@ $<

saml.so: lua_saml.o saml.o
	$(CC) $(LDFLAGS_ALL) -o $@ $^

.PHONY: install
install: build
	cp saml.so $(INST_LIBDIR)
	mkdir -p $(INST_LUADIR)/resty/saml
	cp -R resty $(INST_LUADIR)
	cp -R data $(INST_CONFDIR)

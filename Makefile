include src/Makefile

.PHONY: setup
setup:
	docker build -t resty-saml lua
	docker build -t resty-saml-docs docs
	docker build -t resty-saml-test lua/t

.PHONY: docs
docs:
	docker run --rm -it \
		-v `pwd`/docs:/build/docs \
		-v `pwd`/out:/build/out \
		-v `pwd`/lua:/build/lua \
		-w /build/docs \
		resty-saml-docs:latest \
		ldoc .

.PHONY: test
test:
	$(MAKE) -C lua -f dev.mk test
	$(MAKE) -C python -f dev.mk test

.PHONY: release
release:
	$(MAKE) -C lua -f dev.mk release
	./scripts/release.sh v$(VERSION) lua/lua.tar.gz
	luarocks upload lua/saml-$(VERSION)-1.rockspec

bin/saml.o: bin/saml.c
	$(CC) -c -o bin/saml.o $<

bin/saml: bin/saml.c src/saml.o
	$(CC) -I$(shell pwd) -g -Wall -Werror -std=c99 -Isrc -I$(LIBXML2_INCDIR) -I$(XMLSEC1_INCDIR) $(XMLSEC1_CFLAGS) -L$(LIBXML2_LIBDIR) -L$(XMLSEC1_LIBDIR) $(XMLSEC1_LDFLAGS) -lcurl -o bin/saml $^

.PHONY: cli
cli: bin/saml

.PHONY: install-cli
install-cli: cli
	mv bin/saml $(HOME)/.local/bin/

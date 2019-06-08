CC = gcc
CFLAGS += -g $(shell xmlsec1-config --cflags) -I/usr/local/openresty/luajit/include/luajit-2.1/ -DUNIX_SOCKETS -Wall -fPIC -std=c99
LDFLAGS += -g $(shell xmlsec1-config --libs) -L/usr/local/openresty/luajit/lib/ -lluajit-5.1 -shared

.PHONY: build
build: saml.so

saml.o: saml.c
	$(CC) -c $(CFLAGS) $(BUILD_CFLAGS) -o $@ $<

saml.so: saml.o
	$(CC) $(LDFLAGS) -o $@ $^

local:
	$(CC) -c -g -D__XMLSEC_FUNCTION__=__func__ -DXMLSEC_NO_SIZE_T -DXMLSEC_NO_GOST=1 -DXMLSEC_NO_GOST2012=1 -DXMLSEC_DL_LIBLTDL=1 -I/home/jord7580/dev/xmlsec1-1.2.28/include -I/usr/include/libxml2 -DXMLSEC_CRYPTO_OPENSSL=1 -DUNIX_SOCKETS -Wall -fPIC -o saml.o saml.c
	$(CC) -g -L/home/jord7580/dev/xmlsec1-1.2.28 -L/usr/lib -lltdl -lxmlsec1-openssl -lxmlsec1 -lz -llzma -licui18n -licuuc -licudata -ldl -lxslt -lxml2 -lm -lssl -lcrypto -lluajit-5.1 -shared -o saml.so -Wl,-rpath=/home/jord7580/dev/xmlsec1-1.2.28 saml.o

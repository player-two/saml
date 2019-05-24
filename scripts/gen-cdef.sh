#!/bin/bash -e

DEST=/usr/local/openresty/luajit/share/lua/5.1/resty/saml/xmlsec-cdef.lua
cat <<EOF > $DEST
--[[
Warning: this file is auto-generated; do not modify it by hand.
--]]
return [[
typedef long int __time_t;
typedef __time_t time_t;
struct _IO_FILE;
typedef struct _IO_FILE FILE;
typedef unsigned int xmlSecSize;
typedef unsigned char xmlSecByte;
EOF
gcc /scripts/include-xmlsec.c -D__XMLSEC_FUNCTION__=__func__ -DXMLSEC_NO_SIZE_T -DXMLSEC_NO_XSLT=1 -DXMLSEC_NO_GOST=1 -DXMLSEC_NO_GOST2012=1 -DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1 -I/usr/local/include/xmlsec1 -I/usr/include/libxml2 -DXMLSEC_CRYPTO_OPENSSL=1 -E | lua /scripts/gen.lua >> $DEST
echo ']]' >> $DEST

# Installation

## Dependencies

* [libxml2](http://www.xmlsoft.org/html/index.html)
* [xmlsec1](https://www.aleksey.com/xmlsec/), plus a supported crypto library like openssl
* [zlib](https://www.zlib.net/)

At run time:

* [lua-nginx-module](https://github.com/openresty/lua-nginx-module/) (optional, only required for `resty.saml`)

The version of xmlsec1 that is packaged in the Centos repo is quite old, hence why the development container compiles it from source.

The compiler flags, notably which crypto backend is used by xmlsec1, are generated via the `xmlsec1-config` binary, which is usually installed as part of the linux package for the library.  If you are having issues with any crypto-related functions, such as loading a key, it may be because xmlsec1 cannot determine the correct options based on your file system layout.


## Download

### LuaRocks

[Install LuaRocks](https://github.com/luarocks/luarocks/wiki/Download), then

```bash
luarocks install saml
```

### Make

```bash
git clone https://github.com/megalord/saml && cd saml
make install INST_LIBDIR=<lua cpath> INST_LUADIR=<lua path> INST_CONFDIR=<data_dir>
```

The `path` and `cpath` can be found via
```bash
lua -e 'print("path: " .. package.path); print("cpath: " .. package.cpath)'
```

The `data_dir` can be anything, and whatever it is should be passed to `saml.init`.

## Initialization

The `saml.init` function initializes the libxml2 and xmlsec1 libraries as well as some static data defined by this library.  It should be called before any other functions and only once per process, i.e. in the `init_by_lua` phase for OpenResty (not `init_worker_by_lua`).

It takes a mandatory table with a few key/value pairs:

### debug

Optional boolean, defaults to false

Set this to true for extra debugging information to be sent to stderr.  This information can come from libxml2, xmlsec1, and this library, so it can get a bit noisy.  It is often most helpful when troubleshooting signature or document parsing errors.

### data_dir

Required string

Indicates the path to the installed Lua rock.  It is necessary because this library bundles the SAML XSD schemas internally (to prevent them being fetched over the network at runtime).  If using OpenResty, this is likely `/usr/local/openresty/luajit/lib/luarocks/rocks/saml/<version>/`.


## Shutdown

There is a `saml.shutdown` function, but you won't need it in the context of OpenResty because the OS will clean up when the nginx process finishes.

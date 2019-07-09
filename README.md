# saml

Provides [SAML](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language) support for [OpenResty](https://openresty.org/).

Documentation is hosted at [https://megalord.github.io/saml](https://megalord.github.io/saml).


### Setup

The test suite and example server run using docker.
```sh
make setup
```

After that, try out the example OpenResty server:
```sh
make -C lua example
# go to localhost:8088
```

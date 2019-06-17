# Organization

There are two modules in this library - the core C code and the integration with the [Lua Nginx API](https://github.com/openresty/lua-nginx-module/#nginx-api-for-lua)., depending on your preference and need for detail.  The C code is designed to work on its own without the presence of OpenResty.  In order of lowest to highest-level interfaces:


## Saml

The functions here fit into the following categories:

* Working with keys
* Working with documents
* Signing or verifying content

Providing a Lua interface for the entire surface area of [libxml2](http://www.xmlsoft.org/html/index.html) or [xmlsec](https://www.aleksey.com/xmlsec/api/xmlsec-reference.html) is an explicit non-goal of this library, though any function deemed critical to performing SAML operations may be added.  Further, the Lua user data (e.g. a `xmlDoc*` or `xmlSecKey*`) returned by these functions can be used with the [LuaJIT FFI](http://luajit.org/ext_ffi.html) that is included in OpenResty builds.

There are four basic functions here for working with signatures, each of which is a composition of calls to libxml2 and xmlsec:

```
|         | Document    | Binary        |
| ------- | ----------- | ------------- |
| Sign    | sign_doc    | sign_binary   |
| Verify  | verify_doc  | verify_binary |
```


## Binding

This module builds on top of plain signatures with SAML-specific concepts.  Similarly, there are four main functions:

```
|           | Create          | Parse           |
| --------- | --------------- | --------------- |
| Redirect  | create_redirect | parse_redirect  |
| Post      | create_post     | parse_post      |
```

One notable aspect of the `*_parse` functions is the `cert_from_doc` or `key_mngr_from_doc` argument.  Between parsing and validating the xml and verifying the signature, you may need to determine which certificate to use based on some content in the document, such as the `Issuer`.  This is common when a single IdP communicates with multiple SPs or vice versa.

When using the parse functions, the absence of an error should guarantee the following:

1. The HTTP method and request data (either query string or body) is correct
2. The XML document matches the XSD schema
3. The XML document is correctly signed with a key for the known cert

Notably, this does not include any checks of the document's contents itself, such as the `IssueInstant` or any `Conditions`.  Any additional processing is the responsibility of the user.

SAML implementations come in all shapes and sizes with varying adherance to the spec.  If you are working with an implementation that is not standard, you may have to fall back to the core interfaces, hopefully deriving your code from the functions in this module.


## IdP/SP

At some point, there may be a module added for defining an Identity Provider or Service Provider in a more configuration-driven way, as is common in other SAML libraries such as [python3-saml](https://github.com/onelogin/python3-saml#how-it-works).  For now, refer to the example code for a basic implementation of each.

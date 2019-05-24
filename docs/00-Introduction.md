# Introduction

[SAML](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language) is a protocol for single sign-on.  It defines how two parties, an Identity Provider (IdP) and a Service Provider (SP), can send messages to exchange authenication information.

[OpenResty](https://openresty.org/) is a web framework for adding custom functionality to [Nginx](https://nginx.org/) via [Lua](http://www.lua.org/).


### Digital Signatures

Because this information is sensitive, these parties need to form trust when sending messages over the internet, and the xmlsec spec can ensure the integrity of a message by embedding a cryptographic signature.  This library relies on the implementation of that spec in the [xmlsec](https://www.aleksey.com/xmlsec/) C library.


### Specifications

* [xmldsig](https://www.w3.org/TR/xmldsig-core/)
* [SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
* [SAML 2.0 Bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)


### Organization

There are a few different levels to use this library, depending on your preference and need for detail.  In order of lowest to highest-level interfaces:


##### Internal

The `resty.saml.internal.*` modules are the [FFI](http://luajit.org/ext_ffi.html) bindings for xmlsec and [libxml2](http://xmlsoft.org/html/index.html).  It is not advised to import them directly, as they are not intended to bind the full API surface of those libraries, rather only what is needed for the higher-level interfaces here.  These modules are purposefully not documented.


##### Sig

This module has the lowest-level that you could work at. There are four basic methods here for working with signatures, each of which is a composition of FFI calls to libxml2 and xmlsec.

```
|         | Document    | Binary        |
| ------- | ----------- | ------------- |
| Sign    | sign_doc    | sign_binary   |
| Verify  | verify_doc  | verify_binary |
```


##### Bindings

This module builds on top of plain signatures with SAML-specific concepts.  Similarly, there are four main methods:

```
|           | Create          | Parse           |
| --------- | --------------- | --------------- |
| Redirect  | create_redirect | parse_redirect  |
| Post      | create_post     | parse_post      |
```

One notable aspect of the `*_parse` methods is the `cert_from_doc` argument.  Between parsing and validating the xml and verifying the signature, you may need to determine which certificate to use based on some content in the document, such as the `Issuer`.  This is comment when a single IdP communicates with multiple SPs or vice versa.


##### IdP/SP

TODO: currently this code is in the examples


### Tooling

[SAMLTool](https://www.samltool.com/online_tools.php) has a suite of online tools that facilitate getting started with SAML.

The [xmlsec1](https://www.aleksey.com/xmlsec/download.html) binary ships with the library.  It can be used to sign and verify documents.

Not only are both tools helpful for working with documents, but they serve as third parties that can validate the functionality of this library.  As such, a few integration tests are written to ensure this tool generates and verifies signatures that independent code can validate.  If this library does not verify a signature from some other library or signs a document that another library claims is invalid, please use them as neutral authorities.

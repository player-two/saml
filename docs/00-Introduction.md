# Introduction

[SAML](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language) is a protocol for single sign-on.  It defines how two parties, an Identity Provider (IdP) and a Service Provider (SP), can send messages to exchange authenication information.

[OpenResty](https://openresty.org/) is a web framework for adding custom functionality to [Nginx](https://nginx.org/) via [Lua](http://www.lua.org/).

This project enables you to build a SAML IdP or SP using OpenResty, which is especially useful if you're using OpenResty to host a UI that requires authentication and perhaps as an API gateway too.


## Digital Signatures

Because this information is sensitive, these parties need to form trust when sending messages over the internet, and the xmlsec spec can ensure the integrity of a message by embedding a cryptographic signature.  This library relies on the implementation of that spec in the [xmlsec](https://www.aleksey.com/xmlsec/) C library.


## Specifications

* [xmldsig](https://www.w3.org/TR/xmldsig-core/)
* [SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
* [SAML 2.0 Bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)

These are important!  Using this library does not obviate the need to understand the SAML protocol;


## Tooling

[SAMLTool](https://www.samltool.com/online_tools.php) has a suite of online tools that facilitate getting started with SAML.

The [xmlsec1](https://www.aleksey.com/xmlsec/download.html) binary ships with the library.  It can be used to sign and verify documents.

Not only are both tools helpful for working with documents, but they serve as third parties that can validate the functionality of this library.  As such, a few integration tests are written to ensure this tool generates and verifies signatures that independent code can validate.  If this library does not verify a signature from some other library or signs a document that another library claims is invalid, please use them as neutral authorities.

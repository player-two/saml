/// Functions for working with XML documents and signatures
// @module saml
#include <string.h>

#include <libxml/xmlmemory.h>
#include <libxml/xmlerror.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/valid.h>
#include <libxml/xmlstring.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/xmlschemas.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
#include <xmlsec/errors.h>

#include <lua.h>
#include <lauxlib.h>

static const char* XSD_MAIN = "data/xsd/saml-schema-protocol-2.0.xsd";
static xmlXPathCompExpr *XPATH_ATTRIBUTES, *XPATH_SESSION_INDEX;
static xmlSchemaValidCtxt* XML_SCHEMA_VALIDATE_CTX;

static const xmlChar* XMLNS_ASSERTION = (xmlChar*)"urn:oasis:names:tc:SAML:2.0:assertion";
static const xmlChar* XMLNS_PROTOCOL = (xmlChar*)"urn:oasis:names:tc:SAML:2.0:protocol";

static void ingoreGenericError(void* ctx, const char* msg, ...) {};
static void ingoreStructuredError(void* userData, xmlError* error) {};

/***
Initialize the libxml2 parser and xmlsec
@function init
@tparam[opt={}] table options
@treturn ?string
@usage local err = saml.init({ debug = true })
*/
static int saml_init(lua_State* L) {
  lua_settop(L, 1);
  luaL_checktype(L, 1, LUA_TTABLE);
  lua_getfield(L, 1, "debug");
  lua_getfield(L, 1, "rock_dir");

  int debug = lua_toboolean(L, 2);
  const char* rock_dir = luaL_checklstring(L, 3, NULL);
  lua_pop(L, 2);

  xmlInitParser();

  XPATH_ATTRIBUTES = xmlXPathCompile((const xmlChar*)"//samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute");
  XPATH_SESSION_INDEX = xmlXPathCompile((const xmlChar*)"//samlp:Response/saml:Assertion/saml:AuthnStatement/@SessionIndex");

  // https://www.aleksey.com/xmlsec/api/xmlsec-notes-init-shutdown.html
  if (xmlSecInit() < 0) {
    lua_pushstring(L, "xmlsec initialization failed");
    return 1;
  }

  char data_dir[256];
  int rock_dir_len = strlen(rock_dir);
  int xsd_main_len = strlen(XSD_MAIN);
  if (rock_dir_len > sizeof(data_dir) - xsd_main_len - 1) {
    lua_pushstring(L, "rock_dir path is too long");
    return 1;
  }
  memcpy(data_dir, rock_dir, rock_dir_len);
  memcpy(data_dir + rock_dir_len, XSD_MAIN, xsd_main_len);
  data_dir[rock_dir_len + xsd_main_len + 1] = '\0';

  xmlSchemaParserCtxt* parser_ctx = xmlSchemaNewParserCtxt(data_dir);
  if (parser_ctx == NULL) {
    lua_pushstring(L, "could not create XSD schema parsing context");
    return 1;
  }

  xmlSchema* schema = xmlSchemaParse(parser_ctx);
  if (schema == NULL) {
    lua_pushstring(L, "could not parse XSD schema");
    return 1;
  }

  XML_SCHEMA_VALIDATE_CTX = xmlSchemaNewValidCtxt(schema);
  if (XML_SCHEMA_VALIDATE_CTX == NULL) {
    lua_pushstring(L, "could not create XSD schema validation context");
    return 1;
  }

  if (xmlSecCheckVersionExt(1, 1, 28, xmlSecCheckVersionABICompatible) != 1) {
    lua_pushstring(L, "loaded xmlsec library version is not compatible");
    return 1;
  }

  if (xmlSecCryptoAppInit(NULL) < 0) {
    lua_pushstring(L, "xmlsec crypto app initialization failed");
    return 1;
  }

  if (xmlSecCryptoInit() < 0) {
    lua_pushstring(L, "xmlsec crypto initialization failed");
    return 1;
  }

  if (!debug) {
    xmlSetGenericErrorFunc(NULL, ingoreGenericError);
    xmlSetStructuredErrorFunc(NULL, ingoreStructuredError);
    xmlSecErrorsSetCallback(NULL);
  }

  lua_pushnil(L);
  return 1;
}

/***
Deinitialize libxml2 and xmlsec
@function shutdown
*/
static int saml_shutdown(lua_State* L) {
  // https://www.aleksey.com/xmlsec/api/xmlsec-notes-init-shutdown.html
  xmlSecCryptoShutdown();
  xmlSecCryptoAppShutdown();
  xmlSecShutdown();

  xmlXPathFreeCompExpr(XPATH_ATTRIBUTES);
  xmlXPathFreeCompExpr(XPATH_SESSION_INDEX);
  xmlCleanupParser();
  return 1;
}

/***
Parse xml text into a libxml2 document
@function parse
@tparam string str
@treturn ?xmlDocPtr doc
*/
static int parse(lua_State* L) {
  lua_settop(L, 1);
  size_t buf_len;
  const char* buf = luaL_checklstring(L, 1, &buf_len);
  lua_pop(L, 1);

  xmlDoc* doc = xmlReadMemory(buf, buf_len, "tmp.xml", NULL, 0);
  if (doc == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushlightuserdata(L, (void*)doc);
  }
  return 1;
}

/***
Read a file with xml text and parse its contents into a libxml2 document
@function parse_file
@tparam string name
@treturn ?xmlDocPtr doc
*/
static int parse_file(lua_State* L) {
  lua_settop(L, 1);
  const char* filename = luaL_checklstring(L, 1, NULL);
  lua_pop(L, 1);

  xmlDoc* doc = xmlReadFile(filename, NULL, 0);
  if (doc == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushlightuserdata(L, (void*)doc);
  }
  return 1;
}

/***
Convert a libxml2 document into a string
@function serialize
@tparam xmlDocPtr doc
@treturn string name
*/
static int serialize(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 1);
  luaL_argcheck(L, doc != NULL, 1, "`xmlDoc*' expected");
  lua_pop(L, 1);

  int buf_len;
  xmlChar* buf;
  xmlDocDumpMemory(doc, &buf, &buf_len);
  lua_pushlstring(L, (char*)buf, buf_len);
  xmlFree(buf);
  return 1;
}

/***
Free the memory of a libxml2 document
The return value of `parse` and `parse_file` should be freed
@function free_doc
@tparam xmlDocPtr doc
*/
static int free_doc(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 1);
  luaL_argcheck(L, doc != NULL, 1, "`xmlDoc*' expected");
  lua_pop(L, 1);
  xmlFreeDoc(doc);
  lua_pop(L, 1);
  return 0;
}

/***
Determine if the libxml2 document is valid according to the SAML XSD
@function validate_doc
@tparam xmlDocPtr doc
@treturn ?string error
*/
static int validate_doc(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 1);
  luaL_argcheck(L, doc != NULL, 1, "`xmlDoc*' expected");
  lua_pop(L, 1);
  lua_pushboolean(L, xmlSchemaValidateDoc(XML_SCHEMA_VALIDATE_CTX, doc) == 0 ? 1 : 0);
  return 1;
}

xmlXPathObject* eval_xpath(xmlDoc* doc, xmlXPathCompExpr* xpath) {
  xmlXPathContext* ctx = xmlXPathNewContext(doc);
  if (ctx == NULL) {
    return NULL;
  }

  if (xmlXPathRegisterNs(ctx, (xmlChar*)"saml", XMLNS_ASSERTION) < 0) {
    xmlXPathFreeContext(ctx);
    return NULL;
  }

  if (xmlXPathRegisterNs(ctx, (xmlChar*)"samlp", XMLNS_PROTOCOL) < 0) {
    xmlXPathFreeContext(ctx);
    return NULL;
  }

  xmlXPathObject* obj = xmlXPathCompiledEval(xpath, ctx);
  xmlXPathFreeContext(ctx);
  return obj;
}

/***
Get the text of the issuer node
@function issuer
@tparam xmlDocPtr doc
@treturn ?string issuer
*/
static int saml_issuer(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 1);
  luaL_argcheck(L, doc != NULL, 1, "`xmlDoc*' expected");
  lua_pop(L, 1);

  xmlNode* node = xmlDocGetRootElement(doc);
  if (node == NULL) {
    goto err;
  }

  node = node->children;
  while (node != NULL) {
    if (xmlStrEqual(node->name, (xmlChar*)"Issuer") == 1) {
      xmlChar* content = xmlNodeListGetString(doc, node->children, 1);
      if (content == NULL) {
        goto err;
      } else {
        lua_pushstring(L, (char*)content);
        xmlFree(content);
        return 1;
      }
    }
    node = node->next;
  }

err:
  lua_pushnil(L);
  return 1;
}

/***
Get the value of the AuthnStatement[SessionIndex] attribute in the document
@function session_index
@tparam xmlDocPtr doc
@treturn ?string session_index
*/
static int saml_session_index(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 1);
  luaL_argcheck(L, doc != NULL, 1, "`xmlDoc*' expected");
  lua_pop(L, 1);

  xmlXPathObject* obj = eval_xpath(doc, XPATH_SESSION_INDEX);
  if (obj == NULL || xmlXPathNodeSetIsEmpty(obj->nodesetval)) {
    goto err;
  }

  xmlNode* node = obj->nodesetval->nodeTab[0];
  if (node->type != XML_ATTRIBUTE_NODE) {
    goto err;
  }

  xmlChar* content = xmlNodeListGetString(doc, node->children, 1);
  if (content == NULL) {
    goto err;
  }

  xmlXPathFreeObject(obj);
  lua_pushstring(L, (char*)content);
  xmlFree(content);
  return 1;

err:
  xmlXPathFreeObject(obj);
  lua_pushnil(L);
  return 1;
}

/***
Get the map of attributes in the document's assertion
@function attrs
@tparam xmlDocPtr doc
@treturn table attributes
*/
static int saml_attrs(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 1);
  luaL_argcheck(L, doc != NULL, 1, "`xmlDoc*' expected");
  lua_pop(L, 1);

  lua_newtable(L);

  xmlXPathObject* obj = eval_xpath(doc, XPATH_ATTRIBUTES);
  if (obj == NULL || xmlXPathNodeSetIsEmpty(obj->nodesetval)) {
    xmlXPathFreeObject(obj);
    return 1;
  }

  xmlNode *node, *child;
  xmlChar *name, *content;
  for (int i = 0; i < obj->nodesetval->nodeNr; i++) {
    node = obj->nodesetval->nodeTab[i];
    name = xmlGetProp(node, (xmlChar*)"Name");
    if (name == NULL) {
      continue;
    }

    lua_pushstring(L, (char *)name);
    xmlFree(name);

    switch (xmlChildElementCount(node)) {
      case 0:
        lua_pushnil(L);
        break;
      case 1:
        child = xmlFirstElementChild(node);
        if (child == NULL) {
          // this should never happen based on element count
          lua_pushnil(L);
        } else {
          content = xmlNodeListGetString(doc, child->children, 1);
          if (content == NULL) {
            lua_pushnil(L);
          } else {
            lua_pushstring(L, (char *)content);
            xmlFree(content);
          }
        }
        break;
      default: // Create a list of the values
        lua_newtable(L);
        int j = 1;
        child = node->children;
        while (child != NULL) {
          if (child->type != XML_ELEMENT_NODE) {
            child = child->next;
            continue;
          }
          lua_pushinteger(L, j);
          j++;
          content = xmlNodeListGetString(doc, child->children, 1);
          if (content == NULL) {
            lua_pushnil(L);
          } else {
            lua_pushstring(L, (char *)content);
            xmlFree(content);
          }
          lua_settable(L, -3);
          child = child->next;
        }
        break;
    }
    lua_settable(L, -3);
  }
  xmlXPathFreeObject(obj);
  return 1;
}

void add_id(xmlDoc* doc, xmlNode* node, const xmlChar* name) {
  xmlAttr* attr = node->properties;
  while (attr != NULL) {
    if (xmlStrEqual(attr->name, name) == 1) {
      xmlChar* value = xmlNodeListGetString(doc, attr->children, 1);
      if (value != NULL) {
        xmlAddID(NULL, doc, value, attr);
      }
      return;
    }
    attr = attr->next;
  }
}

/***
Load a private key from memory
@function load_key
@string data private key data
@treturn xmlSecKeyPtr
*/
static int saml_load_key(lua_State* L) {
  lua_settop(L, 1);
  size_t key_len;
  const xmlSecByte* key_data = (xmlSecByte*)luaL_checklstring(L, 1, &key_len);
  lua_pop(L, 1);

  xmlSecKey* key = xmlSecCryptoAppKeyLoadMemory(key_data, key_len, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
  if (key == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushlightuserdata(L, (void*)key);
  }
  return 1;
}

/***
Load a private key from a file
@function load_key_file
@string file path to private key file
@treturn xmlSecKeyPtr
*/
static int saml_load_key_file(lua_State* L) {
  lua_settop(L, 1);
  const char* key_file = luaL_checklstring(L, 1, NULL);
  lua_pop(L, 1);

  xmlSecKey* key = xmlSecCryptoAppKeyLoad(key_file, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
  if (key == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushlightuserdata(L, (void*)key);
  }
  return 1;
}

/***
Add a public key from memory to a private key
@function key_load_cert
@tparam xmlSecKeyPtr key
@tparam string data public key data
@treturn bool success
*/
static int saml_key_load_cert(lua_State* L) {
  lua_settop(L, 2);
  xmlSecKey* key = (xmlSecKey*)lua_touserdata(L, 1);
  luaL_argcheck(L, key != NULL, 1, "`xmlSecKey*' expected");

  size_t cert_len;
  const unsigned char* cert = (unsigned char*)luaL_checklstring(L, 2, &cert_len);
  lua_pop(L, 2);

  if (xmlSecCryptoAppKeyCertLoadMemory(key, cert, cert_len, xmlSecKeyDataFormatPem) < 0) {
    lua_pushboolean(L, 0);
  } else {
    lua_pushboolean(L, 1);
  }
  return 1;
}

/***
Add a public key from a file to a private key
@function key_load_cert_file
@tparam xmlSecKeyPtr key
@tparam string file path to public key data
@treturn bool success
*/
static int saml_key_load_cert_file(lua_State* L) {
  lua_settop(L, 2);
  xmlSecKey* key = (xmlSecKey*)lua_touserdata(L, 1);
  luaL_argcheck(L, key != NULL, 1, "`xmlSecKey*' expected");

  const char* cert_file = luaL_checklstring(L, 2, NULL);
  lua_pop(L, 2);

  if (xmlSecCryptoAppKeyCertLoad(key, cert_file, xmlSecKeyDataFormatPem) < 0) {
    lua_pushboolean(L, 0);
  } else {
    lua_pushboolean(L, 1);
  }
  return 1;
}

/***
Load a public key from memory
@function load_cert
@string data public key data
@treturn xmlSecKeyPtr
*/
static int saml_load_cert(lua_State* L) {
  lua_settop(L, 1);
  size_t cert_len;
  const xmlSecByte* cert_data = (xmlSecByte*)luaL_checklstring(L, 1, &cert_len);
  lua_pop(L, 1);

  xmlSecKey* cert = xmlSecCryptoAppKeyLoadMemory(cert_data, cert_len, xmlSecKeyDataFormatCertPem, NULL, NULL, NULL);
  lua_pushlightuserdata(L, (void*)cert);
  return 1;
}

/***
Load a public key from a file
@function load_cert_file
@string file path to public key file
@treturn xmlSecKeyPtr
*/
static int saml_load_cert_file(lua_State* L) {
  lua_settop(L, 1);
  const char* cert_file = luaL_checklstring(L, 1, NULL);
  lua_pop(L, 1);

  xmlSecKey* cert = xmlSecCryptoAppKeyLoad(cert_file, xmlSecKeyDataFormatCertPem, NULL, NULL, NULL);
  if (cert == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushlightuserdata(L, (void*)cert);
  }
  return 1;
}

/***
Create a keys manager with zero or more keys
@function create_keys_manager
@tparam {xmlSecKeyPtr,...} keys
@treturn ?xmlSecKeysMngrPtr
@treturn ?string error
@usage
local cert = saml.load_cert_file("/path/to/cert.pem")
local mngr, err = saml.create_keys_manager({ cert })
*/
static int saml_create_keys_mngr(lua_State* L) {
  lua_settop(L, 1);
  luaL_checktype(L, 1, LUA_TTABLE);
  size_t len = lua_objlen(L, 1);

  xmlSecKeysMngr* mngr = xmlSecKeysMngrCreate();
  if (mngr == NULL) {
    lua_pop(L, 1);
    lua_pushnil(L);
    lua_pushstring(L, "create keys manager failed");
    return 2;
  }

  if (xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
    xmlSecKeysMngrDestroy(mngr);
    lua_pop(L, 1);
    lua_pushnil(L);
    lua_pushstring(L, "initialize keys manager failed");
    return 2;
  }

  xmlSecKey* key = NULL;
  for (int i = 1; i < len + 1; i++) {
    lua_rawgeti(L, 1, i);
    key = (xmlSecKey*)lua_touserdata(L, 2);
    luaL_argcheck(L, key != NULL, 2, "`xmlSecKey*' expected");
    if (xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key)) {
      xmlSecKeysMngrDestroy(mngr);
      lua_pop(L, 2);
      lua_pushnil(L);
      lua_pushstring(L, "adopt key failed");
      return 2;
    }
    lua_pop(L, 1); // xmlSecKey*
  }
  lua_pop(L, 1); // arg 1 (table of xmlSecKey*)

  lua_pushlightuserdata(L, mngr);
  lua_pushnil(L);
  return 2;
}

/***
Calculate a signature for a string
@function sign_binary
@tparam xmlSecKeyPtr key
@tparam string sig_alg
@tparam string data
@treturn ?string signature
@treturn ?string error
@see resty.saml.constants:SIGNATURE_ALGORITHMS
*/
static int saml_sign_binary(lua_State* L) {
  lua_settop(L, 3);

  xmlSecKey* key = (xmlSecKey*)lua_touserdata(L, 1);
  luaL_argcheck(L, key != NULL, 1, "`xmlSecKey*' expected");

  const xmlChar* sig_alg = (xmlChar*)luaL_checklstring(L, 2, NULL);

  size_t data_len;
  const unsigned char* data = (unsigned char*)luaL_checklstring(L, 3, &data_len);

  lua_pop(L, 3);

  xmlSecTransformCtx* ctx = xmlSecTransformCtxCreate();
  if (ctx == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "transform ctx create failed");
    return 2;
  }

  if (xmlSecTransformCtxInitialize(ctx) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "transform ctx create failed");
    return 2;
  }

  xmlSecTransformId transform_id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), sig_alg, xmlSecTransformUriTypeAny);
  if (transform_id == NULL) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "transform not found");
    return 2;
  }

  if (xmlSecPtrListAdd(&ctx->enabledTransforms, (void*)transform_id) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "transform enable failed");
    return 2;
  }

  xmlSecTransform* transform = xmlSecTransformCtxCreateAndAppend(ctx, transform_id);
  if (transform == NULL) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "transform add to context failed");
    return 2;
  }

  transform->operation = xmlSecTransformOperationSign;

  if (xmlSecTransformSetKey(transform, key) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "set key failed");
    return 2;
  }

  if (xmlSecTransformCtxBinaryExecute(ctx, data, data_len) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "signature execution failed");
    return 2;
  }

  if (ctx->status != xmlSecTransformStatusFinished) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushnil(L);
    lua_pushstring(L, "signature status unknown");
    return 2;
  }

  lua_pushlstring(L, (char*)xmlSecBufferGetData(ctx->result), xmlSecBufferGetSize(ctx->result));
  xmlSecTransformCtxDestroy(ctx);
  lua_pushnil(L);
  return 2;
}

static int saml_sign_doc_impl(lua_State* L, xmlSecKey* key, const xmlChar* sig_alg, xmlDoc* doc, const xmlChar* id_attr, const xmlChar* insert_after_ns, const xmlChar* insert_after_el) {
  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    lua_pushstring(L, "no root node");
    return 1;
  }

  const xmlChar uri[80] = "#\0";
  if (id_attr != NULL) {
    add_id(doc, root, id_attr);
    xmlChar* id = xmlGetProp(root, id_attr);
    if (id == NULL) {
      lua_pushstring(L, "no ID property on document root");
      return 1;
    }
    strncat((char*)uri, (char*)id, sizeof(uri) - 2);
    xmlFree(id);
  }

  xmlSecTransformId transform_id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), sig_alg, 0xFFFF);
  if (transform_id == NULL) {
    lua_pushstring(L, "transform not found");
    return 1;
  }

  // <dsig:Signature/>
  xmlNode* sig = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId, transform_id, NULL);
  if (sig == NULL) {
    lua_pushstring(L, "create signature template failed");
    return 1;
  }

  if (insert_after_ns != NULL && insert_after_el != NULL) {
    xmlNode* target = xmlSecFindNode(root, insert_after_el, insert_after_ns);
    if (target == NULL) {
      lua_pushfstring(L, "%s:%s node not found", insert_after_ns, insert_after_el);
      return 1;
    }

    if (xmlAddNextSibling(target, sig) == NULL) {
      lua_pushstring(L, "adding signature node failed");
      return 1;
    }
  } else {
    xmlAddChild(root, sig);
  }

  // <dsig:Reference/>
  xmlNode* ref = xmlSecTmplSignatureAddReference(sig, xmlSecTransformSha1Id, NULL, (id_attr == NULL) ? NULL : uri, NULL);
  if (ref == NULL) {
    lua_pushstring(L, "add reference to signature template failed");
    return 1;
  }

  if (xmlSecTmplReferenceAddTransform(ref, xmlSecTransformEnvelopedId) == NULL) {
    lua_pushstring(L, "add enveloped transform to reference failed");
    return 1;
  }

  if (xmlSecTmplReferenceAddTransform(ref, xmlSecTransformExclC14NId) == NULL) {
    lua_pushstring(L, "add c14n transform to reference failed");
    return 1;
  }

  // <dsig:KeyInfo/>
  xmlNode* key_info = xmlSecTmplSignatureEnsureKeyInfo(sig, NULL);
  if (key_info == NULL) {
    lua_pushstring(L, "add key info to sign node failed");
    return 1;
  }
 
  // <dsig:X509Data/>
  xmlNode* x509_data = xmlSecTmplKeyInfoAddX509Data(key_info);
  if (x509_data == NULL) {
    lua_pushstring(L, "add x509 data to node failed");
    return 1;
  }

  if (xmlSecTmplX509DataAddCertificate(x509_data) == NULL) {
    lua_pushstring(L, "add x509 cert to node failed");
    return 1;
  }

  xmlSecDSigCtx* ctx = xmlSecDSigCtxCreate(NULL);
  if (ctx == NULL) {
    lua_pushstring(L, "create signature context failed");
    return 1;
  }

  ctx->signKey = key;
  int res = xmlSecDSigCtxSign(ctx, sig);
  ctx->signKey = NULL; // The signKey is lua userdata, so xmlsec should not manage it

  if (res < 0) {
    xmlSecDSigCtxDestroy(ctx);
    lua_pushstring(L, "sign failed");
    return 1;
  }

  if (ctx->status == xmlSecDSigStatusSucceeded) {
    lua_pushnil(L);
  } else {
    lua_pushstring(L, "invalid signature");
  }
  xmlSecDSigCtxDestroy(ctx);
  return 1;
}

int sign_get_opts(lua_State* L, int i, const xmlChar** id_attr, const xmlChar** namespace, const xmlChar** element) {
  if (lua_isnil(L, i)) {
    return i;
  }

  luaL_checktype(L, i, LUA_TTABLE);
  lua_getfield(L, i, "id_attr");
  lua_getfield(L, i, "insert_after");

  if (!lua_isnil(L, i + 1)) {
    *id_attr = (xmlChar*)luaL_checklstring(L, i + 1, NULL);
  }

  if (lua_isnil(L, i + 2)) {
    return i + 2;
  } else {
    luaL_checktype(L, i + 2, LUA_TTABLE);
    size_t len = lua_objlen(L, i + 2);
    if (len != 2) {
      //lua_pop(L, 6);
      luaL_argerror(L, i, "insert_after must be a table of form {namespace, element}");
    }
    lua_rawgeti(L, i + 2, 1);
    lua_rawgeti(L, i + 2, 2);
    *namespace = (xmlChar*)luaL_checklstring(L, i + 3, NULL);
    *element = (xmlChar*)luaL_checklstring(L, i + 4, NULL);
    return i + 4;
  }
}

/***
Sign an XML document (mutates the input)
@function sign_doc
@tparam xmlSecKeyPtr key
@tparam string sig_alg
@tparam xmlDocPtr doc
@tparam[opt={}] table options
@treturn ?string error
@see resty.saml.constants:SIGNATURE_ALGORITHMS
*/
static int saml_sign_doc(lua_State* L) {
  lua_settop(L, 4);

  xmlSecKey* key = (xmlSecKey*)lua_touserdata(L, 1);
  luaL_argcheck(L, key != NULL, 1, "`xmlSecKey*' expected");

  const xmlChar* sig_alg = (xmlChar*)luaL_checklstring(L, 2, NULL);

  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 3);
  luaL_argcheck(L, key != NULL, 3, "`xmlDoc*' expected");

  const xmlChar* id_attr = NULL;
  const xmlChar* namespace = NULL;
  const xmlChar* element = NULL;
  lua_pop(L, sign_get_opts(L, 4, &id_attr, &namespace, &element));

  return saml_sign_doc_impl(L, key, sig_alg, doc, id_attr, namespace, element);
}

/***
Sign an XML string
@function sign_xml
@tparam xmlSecKeyPtr key
@tparam string sig_alg
@tparam string str
@tparam[opt={}] table options
@treturn ?string signed xml
@treturn ?string error
@see sign_doc
@see resty.saml.constants:SIGNATURE_ALGORITHMS
*/
static int saml_sign_xml(lua_State* L) {
  lua_settop(L, 4);

  xmlSecKey* key = (xmlSecKey*)lua_touserdata(L, 1);
  luaL_argcheck(L, key != NULL, 1, "`xmlSecKey*' expected");

  const xmlChar* sig_alg = (xmlChar*)luaL_checklstring(L, 2, NULL);

  size_t data_len;
  const char* data = luaL_checklstring(L, 3, &data_len);

  xmlDoc* doc = xmlReadMemory(data, data_len, "tmp.xml", NULL, 0);
  if (doc == NULL) {
    lua_settop(L, 0);
    lua_pushnil(L);
    lua_pushstring(L, "unable to parse xml string");
    return 2;
  }

  const xmlChar* id_attr = NULL;
  const xmlChar* namespace = NULL;
  const xmlChar* element = NULL;
  lua_pop(L, sign_get_opts(L, 4, &id_attr, &namespace, &element));

  int res = saml_sign_doc_impl(L, key, sig_alg, doc, id_attr, namespace, element);

  if (lua_isnil(L, res)) {
    lua_pop(L, res);
    xmlChar* buf;
    int buf_len;
    xmlDocDumpMemory(doc, &buf, &buf_len);
    xmlFreeDoc(doc);
    lua_pushstring(L, (char*)buf);
    xmlFree(buf);
    lua_pushnil(L);
  } else {
    xmlFreeDoc(doc);
    const char* err = luaL_checklstring(L, res, NULL);
    lua_pop(L, res);
    lua_pushnil(L);
    lua_pushstring(L, err);
  }
  return res + 1;
}

/***
Verify a signature for a string
@function verify_binary
@tparam xmlSecKeyPtr cert
@tparam string sig_alg
@tparam string data
@tparam string signature
@treturn bool valid
@treturn ?string error
@see resty.saml.constants:SIGNATURE_ALGORITHMS
*/
static int saml_verify_binary(lua_State* L) {
  lua_settop(L, 4);

  xmlSecKey* cert = (xmlSecKey*)lua_touserdata(L, 1);
  luaL_argcheck(L, cert != NULL, 1, "`xmlSecKey*' expected");

  const xmlChar* sig_alg = (xmlChar*)luaL_checklstring(L, 2, NULL);

  size_t data_len;
  const unsigned char* data = (unsigned char*)luaL_checklstring(L, 3, &data_len);

  size_t sig_len;
  const unsigned char* sig = (unsigned char*)luaL_checklstring(L, 4, &sig_len);

  lua_pop(L, 4);

  xmlSecTransformCtx* ctx = xmlSecTransformCtxCreate();
  if (ctx == NULL) {
    lua_pushboolean(L, 0);
    lua_pushstring(L, "transform ctx create failed");
    return 2;
  }

  if (xmlSecTransformCtxInitialize(ctx) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushboolean(L, 0);
    lua_pushstring(L, "transform ctx create failed");
    return 2;
  }

  xmlSecTransformId transform_id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), sig_alg, xmlSecTransformUriTypeAny);
  if (transform_id == NULL) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushboolean(L, 0);
    lua_pushstring(L, "transform not found");
    return 2;
  }

  if (xmlSecPtrListAdd(&ctx->enabledTransforms, (void*)transform_id) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushboolean(L, 0);
    lua_pushstring(L, "transform enable failed");
    return 2;
  }

  xmlSecTransform* transform = xmlSecTransformCtxCreateAndAppend(ctx, transform_id);
  if (transform == NULL) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushboolean(L, 0);
    lua_pushstring(L, "transform add to context failed");
    return 2;
  }

  transform->operation = xmlSecTransformOperationVerify;

  if (xmlSecTransformSetKey(transform, cert) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushboolean(L, 0);
    lua_pushstring(L, "set key failed");
    return 2;
  }

  if (xmlSecTransformCtxBinaryExecute(ctx, data, data_len) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushboolean(L, 0);
    lua_pushstring(L, "binary execution failed");
    return 2;
  }

  if (ctx->status != xmlSecTransformStatusFinished) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushboolean(L, 0);
    lua_pushstring(L, "transform context status unknown");
    return 2;
  }

  if (xmlSecTransformVerify(transform, sig, sig_len, ctx) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    lua_pushboolean(L, 0);
    lua_pushstring(L, "transform verify failed");
    return 2;
  }

  lua_pushboolean(L, transform->status == xmlSecTransformStatusOk);
  xmlSecTransformCtxDestroy(ctx);
  lua_pushnil(L);
  return 2;
}

/***
Verify that a XML document has been signed with the key corresponding to a cert
@function verify_doc
@tparam xmlSecKeysMngrPtr mngr
@tparam xmlDocPtr doc
@tparam[opt={}] table options
@treturn bool valid
@treturn ?string error
*/
static int saml_verify_doc(lua_State* L) {
  lua_settop(L, 3);

  xmlSecKeysMngr* mngr = (xmlSecKeysMngr*)lua_touserdata(L, 1);
  luaL_argcheck(L, mngr != NULL, 1, "`xmlSecKeysMngr*' expected");

  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 2);
  luaL_argcheck(L, doc != NULL, 2, "`xmlDoc*' expected");

  const xmlChar* id_attr;
  if (lua_isnoneornil(L, 3)) {
    id_attr = NULL;
    lua_pop(L, lua_isnone(L, 3) ? 2 : 3);
  } else {
    luaL_checktype(L, 3, LUA_TTABLE);
    lua_getfield(L, 3, "id_attr");

    id_attr = (xmlChar*)luaL_checklstring(L, 4, NULL); // TODO: can be null
    lua_pop(L, 4);
  }

  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    lua_pushboolean(L, 0);
    lua_pushnil(L);
    return 2;
  }

  if (id_attr != NULL) {
    add_id(doc, root, id_attr);
  }

  xmlNode* sig = xmlSecFindNode(root, xmlSecNodeSignature, xmlSecDSigNs);
  if (sig == NULL) {
    lua_pushboolean(L, 0);
    lua_pushnil(L);
    return 2;
  }

  xmlSecDSigCtx* ctx = xmlSecDSigCtxCreate(mngr);
  if (ctx == NULL) {
    xmlSecDSigCtxDestroy(ctx);
    lua_pushboolean(L, 0);
    lua_pushstring(L, "create signature context failed");
    return 2;
  }

  //ctx->enabledReferenceUris = xmlSecTransformUriTypeNone & xmlSecTransformUriTypeEmpty & xmlSecTransformUriTypeSameDocument;
  ctx->enabledReferenceUris = 0x0003;
  if (xmlSecDSigCtxVerify(ctx, sig) < 0) {
    xmlSecDSigCtxDebugDump(ctx, stderr);
    xmlSecDSigCtxDestroy(ctx);
    lua_pushboolean(L, 0);
    lua_pushstring(L, "signature verify failed");
    return 2;
  }

  lua_pushboolean(L, ctx->status == xmlSecDSigStatusSucceeded);
  xmlSecDSigCtxDestroy(ctx);
  lua_pushnil(L);
  return 2;
}

static const struct luaL_Reg saml_funcs[] = {
  {"init", saml_init},
  {"shutdown", saml_shutdown},

  {"parse", parse},
  {"parse_file", parse_file},
  {"serialize", serialize},
  {"free_doc", free_doc},
  {"validate_doc", validate_doc},

  {"issuer", saml_issuer},
  {"session_index", saml_session_index},
  {"attrs", saml_attrs},

  {"sign_binary", saml_sign_binary},
  {"sign_doc", saml_sign_doc},
  {"sign_xml", saml_sign_xml},
  {"verify_binary", saml_verify_binary},
  {"verify_doc", saml_verify_doc},
  {"load_key", saml_load_key},
  {"load_key_file", saml_load_key_file},
  {"load_cert", saml_load_cert},
  {"load_cert_file", saml_load_cert_file},
  {"key_load_cert", saml_key_load_cert},
  {"key_load_cert_file", saml_key_load_cert_file},
  {"create_keys_manager", saml_create_keys_mngr},
  {NULL, NULL}
};

int luaopen_saml(lua_State* L) {
  //luaL_setfuncs(L, saml_funcs, 0);
  luaL_newlib(L, saml_funcs);
  return 1;
}

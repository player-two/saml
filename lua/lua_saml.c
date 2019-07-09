/// Functions for working with XML documents and signatures
// @module saml
#include <lua.h>
#include <lauxlib.h>

#include <libxml/xmlmemory.h>
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/crypto.h>

#include "saml.h"


/***
Initialize the libxml2 parser and xmlsec; see @{01-Installation.md}
@function init
@tparam table options
@treturn ?string
*/
static int init(lua_State* L) {
  lua_settop(L, 1);
  luaL_checktype(L, 1, LUA_TTABLE);
  lua_getfield(L, 1, "debug");
  lua_getfield(L, 1, "rock_dir");

  saml_init_opts_t opts;
  luaL_argcheck(L, lua_isboolean(L, 2) || lua_isnil(L, 2), 2, "debug must be a boolean");
  opts.debug = lua_toboolean(L, 2);
  opts.rock_dir = luaL_checklstring(L, 3, NULL);
  lua_pop(L, 2);

  if (saml_init(&opts) < 0) {
    lua_pushstring(L, "saml initialization failed");
  } else {
    lua_pushnil(L);
  }
  return 1;
}


/***
Deinitialize libxml2 and xmlsec; see @{01-Installation.md}
@function shutdown
*/
static int shutdown(lua_State* L) {
  saml_shutdown();
  return 0;
}


/***
Parse xml text into a libxml2 document
@function doc_read_memory
@tparam string str
@treturn ?xmlDoc* doc
*/
static int doc_read_memory(lua_State* L) {
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
@function doc_read_file
@tparam string name
@treturn ?xmlDoc* doc
*/
static int doc_read_file(lua_State* L) {
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
@function doc_serialize
@tparam xmlDoc* doc
@treturn string name
*/
static int doc_serialize(lua_State* L) {
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
The return value of `doc_read_memory` and `doc_read_file` should be freed
@function doc_free
@tparam xmlDoc* doc
*/
static int doc_free(lua_State* L) {
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
@function doc_validate
@tparam xmlDoc* doc
@treturn ?string error
*/
static int doc_validate(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 1);
  luaL_argcheck(L, doc != NULL, 1, "`xmlDoc*' expected");
  lua_pop(L, 1);
  lua_pushboolean(L, saml_doc_validate(doc));
  return 1;
}


/***
Get the ID of the root element in the document
@function doc_validate
@tparam xmlDoc* doc
@treturn ?string error
*/
static int doc_id(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 1);
  luaL_argcheck(L, doc != NULL, 1, "`xmlDoc*' expected");
  lua_pop(L, 1);

  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    lua_pushnil(L);
    return 1;
  }

  xmlChar* id = xmlGetProp(root, (xmlChar*)"ID");
  if (id == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushstring(L, (char*)id);
    xmlFree(id);
  }
  return 1;
}


/***
Get the text of the issuer node
@function doc_issuer
@tparam xmlDoc* doc
@treturn ?string issuer
*/
static int doc_issuer(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 1);
  luaL_argcheck(L, doc != NULL, 1, "`xmlDoc*' expected");
  lua_pop(L, 1);

  xmlChar* issuer = saml_doc_issuer(doc);
  if (issuer == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushstring(L, (char*)issuer);
    xmlFree(issuer);
  }
  return 1;
}


/***
Get the value of the AuthnStatement[SessionIndex] attribute in the document
@function doc_session_index
@tparam xmlDoc* doc
@treturn ?string session_index
*/
static int doc_session_index(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 1);
  luaL_argcheck(L, doc != NULL, 1, "`xmlDoc*' expected");
  lua_pop(L, 1);

  xmlChar* session_index = saml_doc_session_index(doc);
  if (session_index == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushstring(L, (char*)session_index);
    xmlFree(session_index);
  }
  return 1;
}


/***
Get the map of attributes in the document's assertion
@function doc_attrs
@tparam xmlDoc* doc
@treturn table attributes
*/
static int doc_attrs(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 1);
  luaL_argcheck(L, doc != NULL, 1, "`xmlDoc*' expected");
  lua_pop(L, 1);

  saml_attr_t* attrs;
  size_t attrs_len;
  if (saml_doc_attrs(doc, &attrs, &attrs_len) < 0) {
    lua_pushnil(L);
    return 1;
  }

  lua_newtable(L);
  for (int i = 0; i < attrs_len; i++) {
    if (attrs[i].name != NULL) {
      lua_pushstring(L, (char*)attrs[i].name);
      switch (attrs[i].num_values) {
        case 0:
          lua_pushnil(L);
          break;
        case 1:
          if (attrs[i].values[0] == NULL) {
            lua_pushnil(L);
          } else {
            lua_pushstring(L, (char*)attrs[i].values[0]);
          }
          break;
        default: // Create a list of the values
          lua_newtable(L);
          for (int j = 0; j < attrs[i].num_values; j++) {
            lua_pushinteger(L, j + 1);
            if (attrs[i].values[j] == NULL) {
              lua_pushnil(L);
            } else {
              lua_pushstring(L, (char*)attrs[i].values[j]);
            }
            lua_settable(L, -3);
          }
          break;
      }
      lua_settable(L, -3);
    }
  }
  saml_attrs_free(attrs, attrs_len);
  return 1;
}


static int get_key_format(lua_State* L, int narg) {
  int format = luaL_checkint(L, narg);
  luaL_argcheck(L, (xmlSecKeyDataFormatUnknown <= format && format <= xmlSecKeyDataFormatCertDer), narg, \
                "format is not valid");
  return format;
}

/***
Load a private key from memory
@function key_read_memory
@string data private key data
@tparam xmlSecKeyDataFormat key format
@treturn xmlSecKey*
*/
static int key_read_memory(lua_State* L) {
  lua_settop(L, 2);
  size_t key_len;
  const xmlSecByte* key_data = (xmlSecByte*)luaL_checklstring(L, 1, &key_len);

  int format = get_key_format(L, 2);
  lua_pop(L, 2);

  xmlSecKey* key = xmlSecCryptoAppKeyLoadMemory(key_data, key_len, format, NULL, NULL, NULL);
  if (key == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushlightuserdata(L, (void*)key);
  }
  return 1;
}


/***
Load a private key from a file
@function key_read_file
@string file path to private key file
@tparam xmlSecKeyDataFormat key format
@treturn xmlSecKey*
*/
static int key_read_file(lua_State* L) {
  lua_settop(L, 2);
  const char* key_file = luaL_checklstring(L, 1, NULL);

  int format = get_key_format(L, 2);
  lua_pop(L, 2);

  xmlSecKey* key = xmlSecCryptoAppKeyLoad(key_file, format, NULL, NULL, NULL);
  if (key == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushlightuserdata(L, (void*)key);
  }
  return 1;
}


/***
Add a public key from memory to a private key
@function key_add_cert_memory
@tparam xmlSecKey* key
@tparam string data public key data
@tparam xmlSecKeyDataFormat key format
@treturn bool success
*/
static int key_add_cert_memory(lua_State* L) {
  lua_settop(L, 3);
  xmlSecKey* key = (xmlSecKey*)lua_touserdata(L, 1);
  luaL_argcheck(L, key != NULL, 1, "`xmlSecKey*' expected");

  size_t cert_len;
  const unsigned char* cert = (unsigned char*)luaL_checklstring(L, 2, &cert_len);

  int format = get_key_format(L, 3);
  lua_pop(L, 3);

  if (xmlSecCryptoAppKeyCertLoadMemory(key, cert, cert_len, format) < 0) {
    lua_pushboolean(L, 0);
  } else {
    lua_pushboolean(L, 1);
  }
  return 1;
}


/***
Add a public key from a file to a private key
@function key_add_cert_file
@tparam xmlSecKey* key
@tparam string file path to public key data
@tparam xmlSecKeyDataFormat key format
@treturn bool success
*/
static int key_add_cert_file(lua_State* L) {
  lua_settop(L, 3);
  xmlSecKey* key = (xmlSecKey*)lua_touserdata(L, 1);
  luaL_argcheck(L, key != NULL, 1, "`xmlSecKey*' expected");

  const char* cert_file = luaL_checklstring(L, 2, NULL);

  int format = get_key_format(L, 3);
  lua_pop(L, 3);

  if (xmlSecCryptoAppKeyCertLoad(key, cert_file, format) < 0) {
    lua_pushboolean(L, 0);
  } else {
    lua_pushboolean(L, 1);
  }
  return 1;
}


/***
Create a keys manager with zero or more keys
@function create_keys_manager
@tparam {xmlSecKey*,...} keys
@treturn ?xmlSecKeysMngr*
@treturn ?string error
@usage
local cert = saml.cert_read_file("/path/to/cert.pem")
local mngr, err = saml.create_keys_manager({ cert })
*/
static int create_keys_mngr(lua_State* L) {
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
Find a transform by href
@function find_transform_by_href
@tparam string href
@treturn ?xmlSecTransformId
*/
static int find_transform_by_href(lua_State* L) {
  lua_settop(L, 1);

  const xmlChar* href = (xmlChar*)luaL_checklstring(L, 1, NULL);
  lua_pop(L, 1);

  xmlSecTransformId transform_id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), href, xmlSecTransformUriTypeAny);
  if (transform_id == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushlightuserdata(L, (void*)transform_id);
  }
  return 1;
}


/***
Calculate a signature for a string
@function sign_binary
@tparam xmlSecKey* key
@tparam xmlSecTransformId transform_id
@tparam string data
@treturn ?string signature
@treturn ?string error
*/
static int sign_binary(lua_State* L) {
  lua_settop(L, 3);

  xmlSecKey* key = (xmlSecKey*)lua_touserdata(L, 1);
  luaL_argcheck(L, key != NULL, 1, "`xmlSecKey*' expected");

  xmlSecTransformId transform_id = (xmlSecTransformId)lua_touserdata(L, 2);
  luaL_argcheck(L, transform_id != NULL, 2, "`xmlSecTransformId` expected");

  size_t data_len;
  unsigned char* data = (unsigned char*)luaL_checklstring(L, 3, &data_len);

  lua_pop(L, 3);

  xmlSecTransformCtx* ctx = saml_sign_binary(key, transform_id, data, data_len);
  if (ctx == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "saml sign failed");
  } else {
    lua_pushlstring(L, (char*)xmlSecBufferGetData(ctx->result), xmlSecBufferGetSize(ctx->result));
    xmlSecTransformCtxDestroy(ctx);
    lua_pushnil(L);
  }
  return 2;
}


int sign_get_opts(lua_State* L, int i, saml_doc_opts_t* opts) {
  opts->id_attr = NULL;
  opts->insert_after_ns = NULL;
  opts->insert_after_el = NULL;

  if (lua_isnil(L, i)) {
    return i;
  }

  luaL_checktype(L, i, LUA_TTABLE);
  lua_getfield(L, i, "id_attr");
  lua_getfield(L, i, "insert_after");

  if (!lua_isnil(L, i + 1)) {
    opts->id_attr = (xmlChar*)luaL_checklstring(L, i + 1, NULL);
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
    opts->insert_after_ns = (xmlChar*)luaL_checklstring(L, i + 3, NULL);
    opts->insert_after_el = (xmlChar*)luaL_checklstring(L, i + 4, NULL);
    return i + 4;
  }
}


/***
Sign an XML document (mutates the input)
@function sign_doc
@tparam xmlSecKey* key
@tparam string xmlSecTransformId transform_id
@tparam xmlDoc* doc
@tparam[opt={}] table options
@treturn ?string error
*/
static int sign_doc(lua_State* L) {
  lua_settop(L, 4);


  xmlSecKey* key = (xmlSecKey*)lua_touserdata(L, 1);
  luaL_argcheck(L, key != NULL, 1, "`xmlSecKey*' expected");

  xmlSecTransformId transform_id = (xmlSecTransformId)lua_touserdata(L, 2);
  luaL_argcheck(L, transform_id != NULL, 2, "`xmlSecTransformId` expected");

  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 3);
  luaL_argcheck(L, key != NULL, 3, "`xmlDoc*' expected");

  saml_doc_opts_t opts;
  lua_pop(L, sign_get_opts(L, 4, &opts));

  int res = saml_sign_doc(key, transform_id, doc, &opts);
  if (res == 0) {
    lua_pushnil(L);
  } else {
    lua_pushstring(L, "saml sign failed");
  }
  return 1;
}


/***
Sign an XML string
@function sign_xml
@tparam xmlSecKey* key
@tparam string xmlSecTransformId transform_id
@tparam string str
@tparam[opt={}] table options
@treturn ?string signed xml
@see sign_doc
*/
static int sign_xml(lua_State* L) {
  lua_settop(L, 4);

  xmlSecKey* key = (xmlSecKey*)lua_touserdata(L, 1);
  luaL_argcheck(L, key != NULL, 1, "`xmlSecKey*' expected");

  xmlSecTransformId transform_id = (xmlSecTransformId)lua_touserdata(L, 2);
  luaL_argcheck(L, transform_id != NULL, 2, "`xmlSecTransformId` expected");

  size_t data_len;
  const char* data = luaL_checklstring(L, 3, &data_len);

  xmlDoc* doc = xmlReadMemory(data, data_len, "tmp.xml", NULL, 0);
  if (doc == NULL) {
    lua_settop(L, 0);
    lua_pushnil(L);
    lua_pushstring(L, "unable to parse xml string");
    return 2;
  }

  saml_doc_opts_t opts;
  lua_pop(L, sign_get_opts(L, 4, &opts));

  int res = saml_sign_doc(key, transform_id, doc, &opts);
  if (res == 0) {
    xmlChar* buf;
    int buf_len;
    xmlDocDumpMemory(doc, &buf, &buf_len);
    lua_pushlstring(L, (char*)buf, buf_len);
    xmlFree(buf);
    lua_pushnil(L);
  } else {
    lua_pushnil(L);
    lua_pushstring(L, "saml sign failed");
  }
  xmlFreeDoc(doc);
  return 2;
}


/***
Verify a signature for a string
@function verify_binary
@tparam xmlSecKey* cert
@tparam string xmlSecTransformId transform_id
@tparam string data
@tparam string signature
@treturn bool valid
@treturn ?string error
*/
static int verify_binary(lua_State* L) {
  lua_settop(L, 4);

  xmlSecKey* cert = (xmlSecKey*)lua_touserdata(L, 1);
  luaL_argcheck(L, cert != NULL, 1, "`xmlSecKey*' expected");

  xmlSecTransformId transform_id = (xmlSecTransformId)lua_touserdata(L, 2);
  luaL_argcheck(L, transform_id != NULL, 2, "`xmlSecTransformId` expected");

  size_t data_len;
  unsigned char* data = (unsigned char*)luaL_checklstring(L, 3, &data_len);

  size_t sig_len;
  unsigned char* sig = (unsigned char*)luaL_checklstring(L, 4, &sig_len);

  lua_pop(L, 4);

  int res = saml_verify_binary(cert, transform_id, data, data_len, sig, sig_len);
  if (res < 0) {
    lua_pushnil(L);
    lua_pushstring(L, "saml verify failed");
  } else {
    lua_pushboolean(L, 1 - res);
    lua_pushnil(L);
  }
  return 2;
}


/***
Verify that a XML document has been signed with the key corresponding to a cert
@function verify_doc
@tparam xmlSecKeysMngr* mngr
@tparam xmlDoc* doc
@tparam[opt={}] table options
@treturn bool valid
@treturn ?string error
*/
static int verify_doc(lua_State* L) {
  lua_settop(L, 3);

  xmlSecKeysMngr* mngr = (xmlSecKeysMngr*)lua_touserdata(L, 1);
  luaL_argcheck(L, mngr != NULL, 1, "`xmlSecKeysMngr*' expected");

  xmlDoc* doc = (xmlDoc*)lua_touserdata(L, 2);
  luaL_argcheck(L, doc != NULL, 2, "`xmlDoc*' expected");

  saml_doc_opts_t opts;
  if (lua_isnoneornil(L, 3)) {
    opts.id_attr = NULL;
    lua_pop(L, lua_isnone(L, 3) ? 2 : 3);
  } else {
    luaL_checktype(L, 3, LUA_TTABLE);
    lua_getfield(L, 3, "id_attr");

    opts.id_attr = (xmlChar*)luaL_checklstring(L, 4, NULL); // TODO: can be null
    lua_pop(L, 4);
  }

  int res = saml_verify_doc(mngr, doc, &opts);
  if (res < 0) {
    lua_pushnil(L);
    lua_pushstring(L, "saml verify failed");
  } else {
    lua_pushboolean(L, 1 - res);
    lua_pushnil(L);
  }
  return 2;
}


static const struct luaL_Reg saml_funcs[] = {
  {"init", init},
  {"shutdown", shutdown},

  {"doc_read_memory", doc_read_memory},
  {"doc_read_file", doc_read_file},
  {"doc_serialize", doc_serialize},
  {"doc_free", doc_free},
  {"doc_validate", doc_validate},

  {"doc_id", doc_id},
  {"doc_issuer", doc_issuer},
  {"doc_session_index", doc_session_index},
  {"doc_attrs", doc_attrs},

  {"key_read_memory", key_read_memory},
  {"key_read_file", key_read_file},
  {"key_add_cert_memory", key_add_cert_memory},
  {"key_add_cert_file", key_add_cert_file},
  {"create_keys_manager", create_keys_mngr},

  {"find_transform_by_href", find_transform_by_href},
  {"sign_binary", sign_binary},
  {"sign_doc", sign_doc},
  {"sign_xml", sign_xml},
  {"verify_binary", verify_binary},
  {"verify_doc", verify_doc},
  {NULL, NULL}
};


#define SETCONST(n, v) (lua_pushliteral(L, n), lua_pushstring(L, v), lua_settable(L, -3))
#define SETENUM(n, v)  (lua_pushliteral(L, n), lua_pushnumber(L, v), lua_settable(L, -3))


int luaopen_saml(lua_State* L) {
#if (LUA_VERSION_NUM >= 502)
  luaL_newlib(L, saml_funcs);
#else
  luaL_register(L, "saml", saml_funcs);
#endif
  SETCONST("XMLNS_ASSERTION", SAML_XMLNS_ASSERTION);
  SETCONST("XMLNS_PROTOCOL", SAML_XMLNS_PROTOCOL);

  SETCONST("BINDING_HTTP_POST", SAML_BINDING_HTTP_POST);
  SETCONST("BINDING_HTTP_REDIRECT", SAML_BINDING_HTTP_REDIRECT);

  SETCONST("STATUS_SUCCESS", SAML_STATUS_SUCCESS);
  SETCONST("STATUS_REQUESTER", SAML_STATUS_REQUESTER);
  SETCONST("STATUS_RESPONDER", SAML_STATUS_RESPONDER);
  SETCONST("STATUS_VERSION_MISMATCH", SAML_STATUS_VERSION_MISMATCH);

  // export of keysdata.h:xmlSecKeyDataFormat
  SETENUM("KeyDataFormatUnknown", xmlSecKeyDataFormatUnknown);
  SETENUM("KeyDataFormatBinary", xmlSecKeyDataFormatBinary);
  SETENUM("KeyDataFormatPem", xmlSecKeyDataFormatPem);
  SETENUM("KeyDataFormatDer", xmlSecKeyDataFormatDer);
  SETENUM("KeyDataFormatPkcs8Pem", xmlSecKeyDataFormatPkcs8Pem);
  SETENUM("KeyDataFormatPkcs8Der", xmlSecKeyDataFormatPkcs8Der);
  SETENUM("KeyDataFormatPkcs12", xmlSecKeyDataFormatPkcs12);
  SETENUM("KeyDataFormatCertPem", xmlSecKeyDataFormatCertPem);
  SETENUM("KeyDataFormatCertDer", xmlSecKeyDataFormatCertDer);
  return 1;
}

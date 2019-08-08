/// Functions for working with XML documents and signatures
// @module saml
#include <lua.h>
#include <lauxlib.h>

#include <libxml/xmlmemory.h>
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/crypto.h>

#include "saml.h"

#if (LUA_VERSION_NUM <= 502)
// Always cast the result
#define luaL_len(L, i) lua_objlen(L, i)
#endif


static int doc_gc(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc** doc_ref = (xmlDoc**)luaL_checkudata(L, 1, "xmlDoc*");
  luaL_argcheck(L, *doc_ref != NULL, 1, "`xmlDoc*' expected");
  lua_pop(L, 1);
  xmlFreeDoc(*doc_ref);
  *doc_ref = NULL;
  return 0;
}


static const luaL_Reg doc_mt[] = {
  {"__gc", doc_gc},
  {NULL, NULL}
};


static void doc_new(lua_State* L, xmlDoc* doc) {
  xmlDoc** doc_ref = (xmlDoc**)lua_newuserdata(L, sizeof(xmlDoc*));
  *doc_ref = doc;
  luaL_getmetatable(L, "xmlDoc*");
  lua_setmetatable(L, -2);
}


static xmlDoc* doc_check(lua_State* L, int i) {
  xmlDoc** doc_ref = (xmlDoc**)luaL_checkudata(L, i, "xmlDoc*");
  luaL_argcheck(L, *doc_ref != NULL, i, "`xmlDoc*' expected");
  return *doc_ref;
}


static int key_gc(lua_State* L) {
  lua_settop(L, 1);
  xmlSecKey** key_ref = (xmlSecKey**)luaL_checkudata(L, 1, "xmlSecKey*");
  luaL_argcheck(L, *key_ref != NULL, 1, "`xmlSecKey*' expected");
  lua_pop(L, 1);
  xmlSecKeyDestroy(*key_ref);
  *key_ref = NULL;
  return 0;
}


static const luaL_Reg key_mt[] = {
  {"__gc", key_gc},
  {NULL, NULL}
};


static void key_new(lua_State* L, xmlSecKey* key) {
  xmlSecKey** key_ref = (xmlSecKey**)lua_newuserdata(L, sizeof(xmlSecKey*));
  *key_ref = key;
  luaL_getmetatable(L, "xmlSecKey*");
  lua_setmetatable(L, -2);
}


static xmlSecKey* key_check(lua_State* L, int i) {
  xmlSecKey** key_ref = (xmlSecKey**)luaL_checkudata(L, i, "xmlSecKey*");
  luaL_argcheck(L, *key_ref != NULL, i, "`xmlSecKey*' expected");
  return *key_ref;
}


static int keys_mngr_gc(lua_State* L) {
  lua_settop(L, 1);
  xmlSecKeysMngr** keys_mngr_ref = (xmlSecKeysMngr**)luaL_checkudata(L, 1, "xmlSecKeysMngr*");
  luaL_argcheck(L, *keys_mngr_ref != NULL, 1, "`xmlSecKeysMngr*' expected");
  lua_pop(L, 1);
  xmlSecKeysMngrDestroy(*keys_mngr_ref);
  *keys_mngr_ref = NULL;
  return 0;
}


static const luaL_Reg keys_mngr_mt[] = {
  {"__gc", keys_mngr_gc},
  {NULL, NULL}
};


static void keys_mngr_new(lua_State* L, xmlSecKeysMngr* keys_mngr) {
  xmlSecKeysMngr** keys_mngr_ref = (xmlSecKeysMngr**)lua_newuserdata(L, sizeof(xmlSecKeysMngr*));
  *keys_mngr_ref = keys_mngr;
  luaL_getmetatable(L, "xmlSecKeysMngr*");
  lua_setmetatable(L, -2);
}


static xmlSecKeysMngr* keys_mngr_check(lua_State* L, int i) {
  xmlSecKeysMngr** keys_mngr_ref = (xmlSecKeysMngr**)luaL_checkudata(L, i, "xmlSecKeysMngr*");
  luaL_argcheck(L, *keys_mngr_ref != NULL, i, "`xmlSecKeysMngr*' expected");
  return *keys_mngr_ref;
}


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
  lua_getfield(L, 1, "data_dir");

  saml_init_opts_t opts;
  luaL_argcheck(L, lua_isboolean(L, 2) || lua_isnil(L, 2), 2, "debug must be a boolean");
  opts.debug = lua_toboolean(L, 2);
  opts.data_dir = luaL_checklstring(L, 3, NULL);
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


static int base64_encode(lua_State* L) {
  lua_settop(L, 1);

  size_t in_len;
  const char* in = luaL_checklstring(L, 1, &in_len);
  lua_pop(L, 1);

  char* out = saml_base64_encode((byte*)in, in_len);
  lua_pushstring(L, out);
  free(out);
  return 1;
}


static int base64_decode(lua_State* L) {
  lua_settop(L, 1);

  size_t in_len;
  const char* in = luaL_checklstring(L, 1, &in_len);
  lua_pop(L, 1);

  byte* out;
  int out_len;
  if (saml_base64_decode(in, in_len, &out, &out_len) < 0) {
    lua_pushnil(L);
  } else {
    lua_pushlstring(L, (char*)out, out_len);
  }
  if (out != NULL) {
    free(out);
  }
  return 1;
}


static int uri_encode(lua_State* L) {
  lua_settop(L, 1);

  const char* in = luaL_checklstring(L, 1, NULL);
  lua_pop(L, 1);

  char* out = saml_uri_encode(in);
  lua_pushstring(L, out);
  free(out);
  return 1;
}


static int uri_decode(lua_State* L) {
  lua_settop(L, 1);

  const char* in = luaL_checklstring(L, 1, NULL);
  lua_pop(L, 1);

  char* out;
  if (saml_uri_decode(in, &out) < 0) {
    lua_pushnil(L);
  } else {
    lua_pushstring(L, out);
  }
  if (out != NULL) {
    free(out);
  }
  return 1;
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
    doc_new(L, doc);
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
    doc_new(L, doc);
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
  xmlDoc* doc = doc_check(L, 1);
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
DEPRECATED - documents are garbage-collected and this function is a no-op
@function doc_free
@tparam xmlDoc* doc
*/
static int doc_free(lua_State* L) {
  lua_settop(L, 1);
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
  xmlDoc* doc = doc_check(L, 1);
  lua_pop(L, 1);
  lua_pushboolean(L, saml_doc_validate(doc));
  return 1;
}


/***
Get the name of the root element in the document
@function doc_root_name
@tparam xmlDoc* doc
@treturn ?string name
*/
static int doc_root_name(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = doc_check(L, 1);
  lua_pop(L, 1);

  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    lua_pushnil(L);
    return 1;
  }

  if (root->name == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushstring(L, (char*)root->name);
  }
  return 1;
}


/***
Get the ID of the root element in the document
@function doc_id
@tparam xmlDoc* doc
@treturn ?string id
*/
static int doc_id(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = doc_check(L, 1);
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
Get the text of the NameID node
@function doc_name_id
@tparam xmlDoc* doc
@treturn ?string name_id
*/
static int doc_name_id(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = doc_check(L, 1);
  lua_pop(L, 1);

  xmlChar* name_id = saml_doc_name_id(doc);
  if (name_id == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushstring(L, (char*)name_id);
    xmlFree(name_id);
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
  xmlDoc* doc = doc_check(L, 1);
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
Get the value of the StatusCode[Value] attribute in the document
@function doc_status_code
@tparam xmlDoc* doc
@treturn ?string status_code
*/
static int doc_status_code(lua_State* L) {
  lua_settop(L, 1);
  xmlDoc* doc = doc_check(L, 1);
  lua_pop(L, 1);

  xmlChar* status_code = saml_doc_status_code(doc);
  if (status_code == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushstring(L, (char*)status_code);
    xmlFree(status_code);
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
  xmlDoc* doc = doc_check(L, 1);
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
  xmlDoc* doc = doc_check(L, 1);
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
#if (LUA_VERSION_NUM > 502)
  int format = (int)luaL_checkinteger(L, narg);
#else
  int format = luaL_checkint(L, narg);
#endif
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
    key_new(L, key);
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
    key_new(L, key);
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
  xmlSecKey* key = key_check(L, 1);
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
  xmlSecKey* key = key_check(L, 1);
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
  size_t len = (size_t)luaL_len(L, 1);

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
  xmlSecKey* copy = NULL;
  for (int i = 1; i < len + 1; i++) {
    lua_rawgeti(L, 1, i);
    key = key_check(L, 2);
    luaL_argcheck(L, key != NULL, 2, "`xmlSecKey*' expected");
    copy = xmlSecKeyDuplicate(key); // Copy needed because manager owns key memory
    if (copy == NULL) {
      xmlSecKeysMngrDestroy(mngr);
      lua_pop(L, 2);
      lua_pushnil(L);
      lua_pushstring(L, "copy key failed");
    }

    if (xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, copy)) {
      xmlSecKeyDestroy(copy);
      xmlSecKeysMngrDestroy(mngr);
      lua_pop(L, 2);
      lua_pushnil(L);
      lua_pushstring(L, "adopt key failed");
      return 2;
    }
    lua_pop(L, 1); // xmlSecKey*
  }
  lua_pop(L, 1); // arg 1 (table of xmlSecKey*)

  keys_mngr_new(L, mngr);
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

  xmlSecKey* key = key_check(L, 1);

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
    size_t len = (size_t)luaL_len(L, i + 2);
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
@tparam xmlSecTransformId transform_id
@tparam xmlDoc* doc
@tparam[opt={}] table options
@treturn ?string error
*/
static int sign_doc(lua_State* L) {
  lua_settop(L, 4);

  xmlSecKey* key = key_check(L, 1);

  xmlSecTransformId transform_id = (xmlSecTransformId)lua_touserdata(L, 2);
  luaL_argcheck(L, transform_id != NULL, 2, "`xmlSecTransformId` expected");

  xmlDoc* doc = doc_check(L, 3);

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
@tparam xmlSecTransformId transform_id
@tparam string str
@tparam[opt={}] table options
@treturn ?string signed xml
@see sign_doc
*/
static int sign_xml(lua_State* L) {
  lua_settop(L, 4);

  xmlSecKey* key = key_check(L, 1);

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
@tparam xmlSecTransformId transform_id
@tparam string data
@tparam string signature
@treturn bool valid
@treturn ?string error
*/
static int verify_binary(lua_State* L) {
  lua_settop(L, 4);

  xmlSecKey* cert = key_check(L, 1);

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

  xmlSecKeysMngr* mngr = keys_mngr_check(L, 1);
  luaL_argcheck(L, mngr != NULL, 1, "`xmlSecKeysMngr*' expected");

  xmlDoc* doc = doc_check(L, 2);

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


static int binding_redirect_create(lua_State* L) {
  lua_settop(L, 5);

  xmlSecKey* key = key_check(L, 1);
  luaL_argcheck(L, key != NULL, 1, "`xmlSecKey*' expected");

  char* saml_type = (char*)luaL_checklstring(L, 2, NULL);
  char* content = (char*)luaL_checklstring(L, 3, NULL);
  char* sig_alg = (char*)luaL_checklstring(L, 4, NULL);
  char* relay_state = (char*)luaL_checklstring(L, 5, NULL);
  lua_pop(L, 5);

  str_t query;
  saml_binding_status_t res = saml_binding_redirect_create(key, saml_type, content, sig_alg, relay_state, &query);
  if (res != SAML_OK) {
    lua_pushnil(L);
    lua_pushstring(L, saml_binding_error_msg(res));
  } else {
    lua_pushlstring(L, query.data, query.len);
    lua_pushnil(L);
    str_free(&query);
  }
  return 2;
}


static int binding_redirect_parse(lua_State* L) {
  lua_settop(L, 3);

  char* saml_type = (char*)luaL_checklstring(L, 1, NULL);

  luaL_checktype(L, 2, LUA_TTABLE);
  luaL_checktype(L, 3, LUA_TFUNCTION);

  lua_getfield(L, 2, saml_type);
  char* content = (char*)luaL_checkstring(L, 4);

  lua_getfield(L, 2, "SigAlg");
  char* sig_alg = (char*)lua_tostring(L, 5);

  lua_getfield(L, 2, "Signature");
  char* signature = (char*)lua_tostring(L, 6);

  lua_getfield(L, 2, "RelayState");
  char* relay_state = NULL;
  if (!lua_isnil(L, 6)) {
    relay_state = (char*)lua_tostring(L, 7);
  }

  // leave only the cert_from_doc function on the stack
  lua_pop(L, 4);
  lua_remove(L, 1);
  lua_remove(L, 1);

  xmlDoc* doc = NULL;
  saml_binding_status_t res = saml_binding_redirect_parse(content, sig_alg, &doc);
  if (res != SAML_OK) {
    lua_pop(L, 1);
    if (doc != NULL) {
      doc_new(L, doc);
    } else {
      lua_pushnil(L);
    }
    lua_pushstring(L, saml_binding_error_msg(res));
    return 2;
  }

  doc_new(L, doc);
  // copy the doc userdata and put it on the bottom of the stack so it remains after lua_call
  lua_pushvalue(L, 2);
  lua_insert(L, 1);
  lua_call(L, 1, 1);
  if (lua_isnil(L, 2)) {
    lua_pop(L, 1);
    lua_pushstring(L, "no cert");
    return 2;
  }
  xmlSecKey* cert = key_check(L, 2);
  lua_pop(L, 1);

  res = saml_binding_redirect_verify(cert, saml_type, content, sig_alg, relay_state, signature);
  if (res != SAML_OK) {
    lua_pushstring(L, saml_binding_error_msg(res));
  } else {
    lua_pushnil(L);
  }

  return 2;
}


static int binding_post_create(lua_State* L) {
  lua_settop(L, 6);

  xmlSecKey* key = key_check(L, 1);
  luaL_argcheck(L, key != NULL, 1, "`xmlSecKey*' expected");

  char* saml_type = (char*)luaL_checklstring(L, 2, NULL);
  char* content = (char*)luaL_checklstring(L, 3, NULL);
  char* sig_alg = (char*)luaL_checklstring(L, 4, NULL);
  char* relay_state = NULL;
  if (!lua_isnil(L, 5)) {
    relay_state = (char*)luaL_checklstring(L, 5, NULL);
  }
  char* destination = (char*)luaL_checklstring(L, 6, NULL);
  lua_pop(L, 6);

  str_t html;
  saml_binding_status_t res = saml_binding_post_create(key, saml_type, content, sig_alg, relay_state, destination, &html);
  if (res != SAML_OK) {
    lua_pushnil(L);
    lua_pushstring(L, saml_binding_error_msg(res));
  } else {
    lua_pushlstring(L, html.data, html.len);
    lua_pushnil(L);
    str_free(&html);
  }
  return 2;
}


static int binding_post_parse(lua_State* L) {
  lua_settop(L, 2);

  char* content = (char*)luaL_checklstring(L, 1, NULL);
  luaL_checktype(L, 2, LUA_TFUNCTION);

  lua_remove(L, 1);

  xmlDoc* doc = NULL;
  saml_binding_status_t res = saml_binding_post_parse(content, &doc);
  if (res != SAML_OK) {
    lua_pop(L, 1);
    if (doc != NULL) {
      doc_new(L, doc);
    } else {
      lua_pushnil(L);
    }
    lua_pushstring(L, saml_binding_error_msg(res));
    return 2;
  }

  doc_new(L, doc);
  // copy the doc userdata and put it on the bottom of the stack so it remains after lua_call
  lua_pushvalue(L, 2);
  lua_insert(L, 1);
  lua_call(L, 1, 1);
  if (lua_isnil(L, 2)) {
    lua_pop(L, 1);
    lua_pushstring(L, "no cert");
    return 2;
  }
  xmlSecKeysMngr* mngr = keys_mngr_check(L, 2);
  lua_pop(L, 1);

  res = saml_binding_post_verify(mngr, doc);

  if (res != SAML_OK) {
    lua_pushstring(L, saml_binding_error_msg(res));
  } else {
    lua_pushnil(L);
  }

  return 2;
}


static const struct luaL_Reg saml_funcs[] = {
  {"init", init},
  {"shutdown", shutdown},

  {"base64_encode", base64_encode},
  {"base64_decode", base64_decode},
  {"uri_encode", uri_encode},
  {"uri_decode", uri_decode},

  {"doc_read_memory", doc_read_memory},
  {"doc_read_file", doc_read_file},
  {"doc_serialize", doc_serialize},
  {"doc_free", doc_free},
  {"doc_validate", doc_validate},

  {"doc_root_name", doc_root_name},
  {"doc_id", doc_id},
  {"doc_issuer", doc_issuer},
  {"doc_name_id", doc_name_id},
  {"doc_status_code", doc_status_code},
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

  {"binding_redirect_create", binding_redirect_create},
  {"binding_redirect_parse", binding_redirect_parse},
  {"binding_post_create", binding_post_create},
  {"binding_post_parse", binding_post_parse},
  {NULL, NULL}
};


#define SETCONST(n, v) (lua_pushliteral(L, n), lua_pushstring(L, v), lua_settable(L, -3))
#define SETENUM(n, v)  (lua_pushliteral(L, n), lua_pushnumber(L, v), lua_settable(L, -3))


static void create_mt(lua_State* L, const char* name, const luaL_Reg fns[]) {
  luaL_newmetatable(L, name);
#if (LUA_VERSION_NUM >= 502)
  luaL_setfuncs(L, fns, 0);
#else
  luaL_register(L, NULL, fns);
#endif
  lua_pop(L, 1);
}


int luaopen_saml(lua_State* L) {
  create_mt(L, "xmlDoc*", doc_mt);
  create_mt(L, "xmlSecKey*", key_mt);
  create_mt(L, "xmlSecKeysMngr*", keys_mngr_mt);

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

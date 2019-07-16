#ifndef _SAML_H
#define _SAML_H

#include <libxml/xmlstring.h>
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>

const char* SAML_XMLNS_ASSERTION;
const char* SAML_XMLNS_PROTOCOL;

const char* SAML_BINDING_HTTP_POST;
const char* SAML_BINDING_HTTP_REDIRECT;

const char* SAML_STATUS_SUCCESS;
const char* SAML_STATUS_REQUESTER;
const char* SAML_STATUS_RESPONDER;
const char* SAML_STATUS_VERSION_MISMATCH;

typedef unsigned char byte;

typedef struct {
  int len, total;
  char* data;
} str_t;

typedef struct {
  int debug;
  const char* data_dir;
} saml_init_opts_t;

typedef struct {
  xmlChar* id_attr;
  xmlChar* insert_after_ns;
  xmlChar* insert_after_el;
} saml_doc_opts_t;

typedef struct {
  xmlChar* name;
  xmlChar** values;
  int num_values;
} saml_attr_t;

typedef enum {
  SAML_ZLIB_ERROR = -2,
  SAML_XMLSEC_ERROR,

  SAML_OK,

  SAML_NO_CONTENT,
  SAML_NO_SIG_ALG,
  SAML_NO_SIGNATURE,
  SAML_BASE64,
  SAML_INVALID_COMPRESSION,
  SAML_INVALID_XML,
  SAML_INVALID_DOC,
  SAML_INVALID_SIG_ALG,
  SAML_INVALID_SIGNATURE,
} saml_binding_status_t;

char* saml_binding_error_msg(saml_binding_status_t status);

void str_init(str_t* str, int total);
void str_free(str_t* str);
void str_grow(str_t* str);
void str_cat(str_t* str, const char* data, int len);
void str_append(str_t* str, char c);
void str_print(str_t* str, FILE* f);

char* saml_base64_encode(const byte* c, int len);
int saml_base64_decode(const char* in, int in_len, byte** out, int* out_len);
char* saml_uri_encode(const char* in);
int saml_uri_decode(const char* in, char** out);

int saml_init(saml_init_opts_t*);
void saml_shutdown();

int saml_doc_validate(xmlDoc* doc);
xmlChar* saml_doc_issuer(xmlDoc* doc);
xmlChar* saml_doc_session_index(xmlDoc* doc);
int saml_doc_attrs(xmlDoc* doc, saml_attr_t** attrs, size_t* attrs_len);
void saml_attrs_free(saml_attr_t* attrs, size_t attrs_len);

xmlSecTransformCtx* saml_sign_binary(xmlSecKey* key, xmlSecTransformId transform_id, unsigned char* data, size_t data_len);
int saml_verify_binary(xmlSecKey* cert, xmlSecTransformId transform_id, unsigned char* data, size_t data_len, unsigned char* sig, size_t sig_len);
int saml_sign_doc(xmlSecKey* key, xmlSecTransformId transform_id, xmlDoc* doc, saml_doc_opts_t* opts);
int saml_verify_doc(xmlSecKeysMngr* mngr, xmlDoc* doc, saml_doc_opts_t* opts);

saml_binding_status_t saml_binding_redirect_create(xmlSecKey* key, char* saml_type, char* content, char* sig_alg, char* relay_state, str_t* query);
saml_binding_status_t saml_binding_redirect_parse(char* content, char* sig_alg, xmlDoc** doc);
saml_binding_status_t saml_binding_redirect_verify(xmlSecKey* cert, char* saml_type, char* content, char* sig_alg, char* relay_state, char* signature);
saml_binding_status_t saml_binding_post_create(xmlSecKey* key, char* saml_type, char* content, char* sig_alg, char* relay_state, char* destination, str_t* html);
saml_binding_status_t saml_binding_post_parse(char* content, xmlDoc** doc);
saml_binding_status_t saml_binding_post_verify(xmlSecKeysMngr* mngr, xmlDoc* doc);
#endif

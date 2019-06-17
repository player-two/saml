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

typedef struct {
  int debug;
  const char* rock_dir;
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

#endif

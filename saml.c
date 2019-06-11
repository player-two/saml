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
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
#include <xmlsec/errors.h>

#include "saml.h"


static const char* XSD_MAIN = "data/xsd/saml-schema-protocol-2.0.xsd";
static xmlXPathCompExpr *XPATH_ATTRIBUTES, *XPATH_SESSION_INDEX;
static xmlSchemaValidCtxt* XML_SCHEMA_VALIDATE_CTX;

const xmlChar* XMLNS_ASSERTION = (xmlChar*)"urn:oasis:names:tc:SAML:2.0:assertion";
const xmlChar* XMLNS_PROTOCOL = (xmlChar*)"urn:oasis:names:tc:SAML:2.0:protocol";

static int DEBUG_ENABLED = 1;
static void ingoreGenericError(void* ctx, const char* msg, ...) {};
static void ingoreStructuredError(void* userData, xmlError* error) {};


static void saml_log(char* msg) {
  if (DEBUG_ENABLED) {
    fprintf(stderr, "%s\n", msg);
  }
}


int saml_init(saml_init_opts_t* opts) {
  xmlInitParser();

  XPATH_ATTRIBUTES = xmlXPathCompile((const xmlChar*)"//samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute");
  XPATH_SESSION_INDEX = xmlXPathCompile((const xmlChar*)"//samlp:Response/saml:Assertion/saml:AuthnStatement/@SessionIndex");

  // https://www.aleksey.com/xmlsec/api/xmlsec-notes-init-shutdown.html
  if (xmlSecInit() < 0) {
    saml_log("xmlsec initialization failed");
    return -1;
  }

  char data_dir[256];
  int rock_dir_len = strlen(opts->rock_dir);
  int xsd_main_len = strlen(XSD_MAIN);
  if (rock_dir_len > sizeof(data_dir) - xsd_main_len - 1) {
    saml_log("rock_dir path is too long");
    return -1;
  }
  memcpy(data_dir, opts->rock_dir, rock_dir_len);
  memcpy(data_dir + rock_dir_len, XSD_MAIN, xsd_main_len);
  data_dir[rock_dir_len + xsd_main_len + 1] = '\0';

  xmlSchemaParserCtxt* parser_ctx = xmlSchemaNewParserCtxt(data_dir);
  if (parser_ctx == NULL) {
    saml_log("could not create XSD schema parsing context");
    return -1;
  }

  xmlSchema* schema = xmlSchemaParse(parser_ctx);
  if (schema == NULL) {
    saml_log("could not parse XSD schema");
    return -1;
  }

  XML_SCHEMA_VALIDATE_CTX = xmlSchemaNewValidCtxt(schema);
  if (XML_SCHEMA_VALIDATE_CTX == NULL) {
    saml_log("could not create XSD schema validation context");
    return -1;
  }

  if (xmlSecCheckVersionExt(1, 1, 28, xmlSecCheckVersionABICompatible) != 1) {
    saml_log("loaded xmlsec library version is not compatible");
    return -1;
  }

  if (xmlSecCryptoAppInit(NULL) < 0) {
    saml_log("xmlsec crypto app initialization failed");
    return -1;
  }

  if (xmlSecCryptoInit() < 0) {
    saml_log("xmlsec crypto initialization failed");
    return -1;
  }

  if (!opts->debug) {
    DEBUG_ENABLED = 0;
    xmlSetGenericErrorFunc(NULL, ingoreGenericError);
    xmlSetStructuredErrorFunc(NULL, ingoreStructuredError);
    xmlSecErrorsSetCallback(NULL);
  }

  return 0;
}


void saml_shutdown() {
  // https://www.aleksey.com/xmlsec/api/xmlsec-notes-init-shutdown.html
  xmlSecCryptoShutdown();
  xmlSecCryptoAppShutdown();
  xmlSecShutdown();

  xmlSchemaFreeValidCtxt(XML_SCHEMA_VALIDATE_CTX);
  xmlXPathFreeCompExpr(XPATH_ATTRIBUTES);
  xmlXPathFreeCompExpr(XPATH_SESSION_INDEX);
  xmlCleanupParser();
}


int saml_doc_validate(xmlDoc* doc) {
  return xmlSchemaValidateDoc(XML_SCHEMA_VALIDATE_CTX, doc) == 0 ? 1 : 0;
}


static xmlXPathObject* eval_xpath(xmlDoc* doc, xmlXPathCompExpr* xpath) {
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


xmlChar* saml_doc_issuer(xmlDoc* doc) {
  xmlNode* node = xmlDocGetRootElement(doc);
  if (node == NULL) {
    return NULL;
  }

  node = node->children;
  while (node != NULL) {
    if (xmlStrEqual(node->name, (xmlChar*)"Issuer") == 1) {
      return xmlNodeListGetString(doc, node->children, 1);
    }
    node = node->next;
  }
  return NULL;
}


xmlChar* saml_doc_session_index(xmlDoc* doc) {
  xmlXPathObject* obj = eval_xpath(doc, XPATH_SESSION_INDEX);
  if (obj == NULL || xmlXPathNodeSetIsEmpty(obj->nodesetval)) {
    xmlXPathFreeObject(obj);
    return NULL;
  }

  xmlNode* node = obj->nodesetval->nodeTab[0];
  if (node->type != XML_ATTRIBUTE_NODE) {
    xmlXPathFreeObject(obj);
    return NULL;
  }

  xmlChar* content = xmlNodeListGetString(doc, node->children, 1);
  xmlXPathFreeObject(obj);
  return content;
}


int saml_doc_attrs(xmlDoc* doc, saml_attr_t** attrs, size_t* attrs_len) {
  xmlXPathObject* obj = eval_xpath(doc, XPATH_ATTRIBUTES);
  if (obj == NULL) {
    return -1;
  }

  if (xmlXPathNodeSetIsEmpty(obj->nodesetval)) {
    xmlXPathFreeObject(obj);
    *attrs_len = 0;
    *attrs = NULL;
    return 0;
  }

  *attrs_len = obj->nodesetval->nodeNr;
  *attrs = malloc(*attrs_len * sizeof(saml_attr_t));

  saml_attr_t* attr;
  xmlNode *node, *child;
  for (int i = 0; i < obj->nodesetval->nodeNr; i++) {
    attr = *attrs + i;
    node = obj->nodesetval->nodeTab[i];
    attr->name = xmlGetProp(node, (xmlChar*)"Name");
    if (attr->name == NULL) {
      continue;
    }

    attr->num_values = xmlChildElementCount(node);

    switch (attr->num_values) {
      case 0:
        attr->values = NULL;
        break;
      case 1:
        child = xmlFirstElementChild(node);
        if (child == NULL) {
          // this should never happen based on element count
          attr->values = NULL;
        } else {
          attr->values = malloc(attr->num_values * sizeof(xmlChar*));
          attr->values[0] = xmlNodeListGetString(doc, child->children, 1);
        }
        break;
      default: // Create a list of the values
        attr->values = malloc(attr->num_values * sizeof(xmlChar*));
        child = xmlFirstElementChild(node);
        for (int j = 0; j < attr->num_values; j++) {
          attr->values[j] = child->type == XML_ELEMENT_NODE ? xmlNodeListGetString(doc, child->children, 1) : NULL;
          child = xmlNextElementSibling(child);
        }
        break;
    }
  }
  xmlXPathFreeObject(obj);
  return 0;
}


void saml_free_attrs(saml_attr_t* attrs, size_t attrs_len) {
  for (int i = 0; i < attrs_len; i++) {
    if (attrs[i].name != NULL) {
      xmlFree(attrs[i].name);
      for (int j = 0; j < attrs[i].num_values; j++) {
        if (attrs[i].values[j] != NULL) {
          xmlFree(attrs[i].values[j]);
        }
      }
    }
  }
  free(attrs);
}


xmlSecTransformCtx* saml_sign_binary(xmlSecKey* key, xmlSecTransformId transform_id, unsigned char* data, size_t data_len) {
  xmlSecTransformCtx* ctx = xmlSecTransformCtxCreate();
  if (ctx == NULL) {
    saml_log("transform ctx create failed");
    return NULL;
  }

  if (xmlSecTransformCtxInitialize(ctx) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform ctx create failed");
    return NULL;
  }

  if (xmlSecPtrListAdd(&ctx->enabledTransforms, (void*)transform_id) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform enable failed");
    return NULL;
  }

  xmlSecTransform* transform = xmlSecTransformCtxCreateAndAppend(ctx, transform_id);
  if (transform == NULL) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform add to context failed");
    return NULL;
  }

  transform->operation = xmlSecTransformOperationSign;

  if (xmlSecTransformSetKey(transform, key) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("set key failed");
    return NULL;
  }

  if (xmlSecTransformCtxBinaryExecute(ctx, data, data_len) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("signature execution failed");
    return NULL;
  }

  if (ctx->status != xmlSecTransformStatusFinished) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("signature status unknown");
    return NULL;
  }

  return ctx;
}


int saml_verify_binary(xmlSecKey* cert, xmlSecTransformId transform_id, unsigned char* data, size_t data_len, unsigned char* sig, size_t sig_len) {
  xmlSecTransformCtx* ctx = xmlSecTransformCtxCreate();
  if (ctx == NULL) {
    saml_log("transform ctx create failed");
    return -1;
  }

  if (xmlSecTransformCtxInitialize(ctx) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform ctx create failed");
    return -1;
  }

  if (xmlSecPtrListAdd(&ctx->enabledTransforms, (void*)transform_id) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform enable failed");
    return -1;
  }

  xmlSecTransform* transform = xmlSecTransformCtxCreateAndAppend(ctx, transform_id);
  if (transform == NULL) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform add to context failed");
    return -1;
  }

  transform->operation = xmlSecTransformOperationVerify;

  if (xmlSecTransformSetKey(transform, cert) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("set key failed");
    return -1;
  }

  if (xmlSecTransformCtxBinaryExecute(ctx, data, data_len) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("binary execution failed");
    return -1;
  }

  if (ctx->status != xmlSecTransformStatusFinished) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform context status unknown");
    return -1;
  }

  if (xmlSecTransformVerify(transform, sig, sig_len, ctx) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform verify failed");
    return -1;
  }

  int status = transform->status == xmlSecTransformStatusOk ? 0 : 1;
  xmlSecTransformCtxDestroy(ctx);
  return status;
}


static void add_id(xmlDoc* doc, xmlNode* node, const xmlChar* name) {
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


int saml_sign_doc(xmlSecKey* key, xmlSecTransformId transform_id, xmlDoc* doc, saml_doc_opts_t* opts) {
  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    saml_log("no root node");
    return -1;
  }

  const xmlChar uri[80] = "#\0";
  if (opts->id_attr != NULL) {
    xmlChar* id = xmlGetProp(root, opts->id_attr);
    if (id == NULL) {
      saml_log("no ID property on document root");
      return -1;
    }
    strncat((char*)uri, (char*)id, sizeof(uri) - 2);
    xmlFree(id);
    add_id(doc, root, opts->id_attr);
  }

  // <dsig:Signature/>
  xmlNode* sig = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId, transform_id, NULL);
  if (sig == NULL) {
    saml_log("create signature template failed");
    return -1;
  }

  if (opts->insert_after_ns != NULL && opts->insert_after_el != NULL) {
    xmlNode* target = xmlSecFindNode(root, opts->insert_after_el, opts->insert_after_ns);
    if (target == NULL) {
      saml_log("insertion point node not found");
      return -1;
    }

    if (xmlAddNextSibling(target, sig) == NULL) {
      saml_log("adding signature node failed");
      return -1;
    }
  } else {
    xmlAddChild(root, sig);
  }

  // <dsig:Reference/>
  xmlNode* ref = xmlSecTmplSignatureAddReference(sig, xmlSecTransformSha1Id, NULL, (opts->id_attr == NULL) ? NULL : uri, NULL);
  if (ref == NULL) {
    saml_log("add reference to signature template failed");
    return -1;
  }

  if (xmlSecTmplReferenceAddTransform(ref, xmlSecTransformEnvelopedId) == NULL) {
    saml_log("add enveloped transform to reference failed");
    return -1;
  }

  if (xmlSecTmplReferenceAddTransform(ref, xmlSecTransformExclC14NId) == NULL) {
    saml_log("add c14n transform to reference failed");
    return -1;
  }

  // <dsig:KeyInfo/>
  xmlNode* key_info = xmlSecTmplSignatureEnsureKeyInfo(sig, NULL);
  if (key_info == NULL) {
    saml_log("add key info to sign node failed");
    return -1;
  }
 
  // <dsig:X509Data/>
  xmlNode* x509_data = xmlSecTmplKeyInfoAddX509Data(key_info);
  if (x509_data == NULL) {
    saml_log("add x509 data to node failed");
    return -1;
  }

  if (xmlSecTmplX509DataAddCertificate(x509_data) == NULL) {
    saml_log("add x509 cert to node failed");
    return -1;
  }

  xmlSecDSigCtx* ctx = xmlSecDSigCtxCreate(NULL);
  if (ctx == NULL) {
    saml_log("create signature context failed");
    return -1;
  }

  ctx->signKey = key;
  int res = xmlSecDSigCtxSign(ctx, sig);
  ctx->signKey = NULL; // The signKey is lua userdata, so xmlsec should not manage it

  if (res < 0) {
    xmlSecDSigCtxDestroy(ctx);
    saml_log("sign failed");
    return -1;
  }

  int status = ctx->status == xmlSecDSigStatusSucceeded ? 0 : 1;
  xmlSecDSigCtxDestroy(ctx);
  return status;
}


int saml_verify_doc(xmlSecKeysMngr* mngr, xmlDoc* doc, saml_doc_opts_t* opts) {
  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    return 1;
  }

  if (opts->id_attr != NULL) {
    add_id(doc, root, opts->id_attr);
  }

  xmlNode* sig = xmlSecFindNode(root, xmlSecNodeSignature, xmlSecDSigNs);
  if (sig == NULL) {
    return 1;
  }

  xmlSecDSigCtx* ctx = xmlSecDSigCtxCreate(mngr);
  if (ctx == NULL) {
    xmlSecDSigCtxDestroy(ctx);
    saml_log("create signature context failed");
    return -1;
  }

  //ctx->enabledReferenceUris = xmlSecTransformUriTypeNone & xmlSecTransformUriTypeEmpty & xmlSecTransformUriTypeSameDocument;
  ctx->enabledReferenceUris = 0x0003;
  if (xmlSecDSigCtxVerify(ctx, sig) < 0) {
    xmlSecDSigCtxDestroy(ctx);
    saml_log("signature verify failed");
    return -1;
  }

  int status = ctx->status == xmlSecDSigStatusSucceeded ? 0 : 1;
  xmlSecDSigCtxDestroy(ctx);
  return status;
}

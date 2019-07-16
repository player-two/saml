#include <assert.h>
#include <math.h>
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

#include <zlib.h>

#include "saml.h"

static const char* XSD_MAIN = "/xsd/saml-schema-protocol-2.0.xsd";
static xmlXPathCompExpr *XPATH_ATTRIBUTES, *XPATH_SESSION_INDEX;
static xmlSchemaValidCtxt* XML_SCHEMA_VALIDATE_CTX;

const char* SAML_XMLNS_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
const char* SAML_XMLNS_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";

const char* SAML_BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const char* SAML_BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

const char* SAML_STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
const char* SAML_STATUS_REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester";
const char* SAML_STATUS_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder";
const char* SAML_STATUS_VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";

static int DEBUG_ENABLED = 1;
static void ingoreGenericError(void* ctx, const char* msg, ...) {};
static void ingoreStructuredError(void* userData, xmlError* error) {};


static void saml_log(char* msg) {
  if (DEBUG_ENABLED) {
    fprintf(stderr, "%s\n", msg);
  }
}


#include "str.c"
#include "codecs.c"
#include "xml.c"
#include "sig.c"
#include "binding.c"


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
  int data_dir_len = strlen(opts->data_dir);
  int xsd_main_len = strlen(XSD_MAIN);
  if (data_dir_len > sizeof(data_dir) - xsd_main_len - 1) {
    saml_log("data_dir path is too long");
    return -1;
  }
  memcpy(data_dir, opts->data_dir, data_dir_len);
  memcpy(data_dir + data_dir_len, XSD_MAIN, xsd_main_len);
  data_dir[data_dir_len + xsd_main_len] = '\0';

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

  if (xmlSecCheckVersion() != 1) {
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

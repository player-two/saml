local ffi = require "ffi"

ffi.cdef([[
// libxml/xmlmemory.h
typedef void (*xmlFreeFunc)(void *mem);
xmlFreeFunc *__xmlFree(void);
xmlFreeFunc xmlFree;

// libxml/xmlerror.h
struct _xmlError;
typedef struct xmlError *xmlErrorPtr;
typedef void (*xmlGenericErrorFunc)(void * ctx, const char * msg);
typedef void (*xmlStructuredErrorFunc)(void * userData, xmlErrorPtr error);
void xmlSetGenericErrorFunc(void * ctx, xmlGenericErrorFunc handler);
void xmlSetStructuredErrorFunc(void * ctx, xmlStructuredErrorFunc handler);

// libxml/parser.h
struct xmlDoc;
typedef struct xmlDoc *xmlDocPtr;
void xmlInitParser();
xmlDocPtr xmlParseFile(const char* filename);
void xmlFreeDoc(xmlDocPtr);
xmlDocPtr xmlReadMemory(const char * buffer, int size, const char * URL, const char * encoding, int options);
typedef void* (*xmlExternalEntityLoader) (const char *URL, const char *ID, void* context);

// libxml/tree.h
struct _xmlOutputBuffer;
typedef struct _xmlOutputBuffer *xmlOutputBufferPtr;
struct _xmlParserInputBuffer;
typedef struct _xmlParserInputBuffer *xmlParserInputBufferPtr;
typedef enum {
  XML_ELEMENT_NODE = 1,
  XML_ATTRIBUTE_NODE = 2
} xmlElementType;

struct xmlAttr;
struct xmlNode {
  void* _private;
  xmlElementType type;
  char* name;
  struct xmlNode* children;
  struct xmlNode* last;
  struct xmlNode* parent;
  struct xmlNode* next;
  struct xmlNode* prev;
  xmlDocPtr doc;
  void* ns;
  char* content;
  struct xmlAttr* properties;
  void* nsDef;
  void* psvi;
  unsigned short line;
  unsigned short extra;
};
typedef struct xmlNode *xmlNodePtr;
xmlNodePtr xmlDocGetRootElement(xmlDocPtr doc);
xmlNodePtr xmlAddChild(xmlNodePtr parent, xmlNodePtr cur);
xmlNodePtr xmlAddNextSibling(xmlNodePtr cur, xmlNodePtr elem);
char* xmlGetProp(xmlNodePtr, const char*);

typedef enum {
  XML_ATTRIBUTE_CDATA = 1,
  XML_ATTRIBUTE_ID = 2,
  XML_ATTRIBUTE_IDREF = 3,
  XML_ATTRIBUTE_IDREFS = 4,
  XML_ATTRIBUTE_ENTITY = 5,
  XML_ATTRIBUTE_ENTITIES = 6,
  XML_ATTRIBUTE_NMTOKEN = 7,
  XML_ATTRIBUTE_NMTOKENS = 8,
  XML_ATTRIBUTE_ENUMERATION = 9,
  XML_ATTRIBUTE_NOTATION = 10
} xmlAttributeType;

struct xmlAttr {
  void * _private;
  xmlElementType type;
  char* name;
  struct xmlNode* children;
  struct xmlNode* last;
  struct xmlNode* parent;
  struct xmlAttr* next;
  struct xmlAttr* prev;
  struct xmlDoc* doc;
  char* ns;
  xmlAttributeType atype;
  void* psvi;
};
typedef struct xmlAttr *xmlAttrPtr;

char* xmlNodeListGetString(xmlDocPtr, xmlNodePtr, int);

void xmlDocDumpMemory(xmlDocPtr cur, char ** mem, int * size);


// libxml/valid.h
void xmlAddID(void *, xmlDocPtr, const char *value, xmlAttrPtr);

// libxml/xmlstring.h
typedef unsigned char xmlChar;
int xmlStrEqual(const char*, const char*);

// libxml/xpath.h
struct _xmlNodeSet;
typedef struct _xmlNodeSet *xmlNodeSetPtr;

// libxml/xmlschemas.h
struct _xmlSchema;
typedef struct _xmlSchema *xmlSchemaPtr;
struct _xmlSchemaParserCtxt;
typedef struct _xmlSchemaParserCtxt *xmlSchemaParserCtxtPtr;
struct _xmlSchemaValidCtxt;
typedef struct _xmlSchemaValidCtxt *xmlSchemaValidCtxtPtr;
xmlSchemaParserCtxtPtr xmlSchemaNewParserCtxt(const char * URL);
xmlSchemaValidCtxtPtr xmlSchemaNewValidCtxt(xmlSchemaPtr schema);
xmlSchemaPtr xmlSchemaParse(xmlSchemaParserCtxtPtr ctxt);
int xmlSchemaValidateDoc(xmlSchemaValidCtxtPtr ctxt, xmlDocPtr doc);
]])

return ffi.load("libxml2")

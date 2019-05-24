--[[
Warning: this file is auto-generated; do not modify it by hand.
--]]
return [[
typedef long int __time_t;
typedef __time_t time_t;
struct _IO_FILE;
typedef struct _IO_FILE FILE;
typedef unsigned int xmlSecSize;
typedef unsigned char xmlSecByte;
// 1 "/scripts/include-xmlsec.c"
// 1 "/scripts/include-xmlsec.c"
// 1 "/usr/local/include/xmlsec1/xmlsec/errors.h" 1
// 395 "/usr/local/include/xmlsec1/xmlsec/errors.h"
typedef void (*xmlSecErrorsCallback) (const char* file,
                                                                 int line,
                                                                 const char* func,
                                                                 const char* errorObject,
                                                                 const char* errorSubject,
                                                                 int reason,
                                                                 const char* msg);
void xmlSecErrorsInit (void);
void xmlSecErrorsShutdown (void);
void xmlSecErrorsSetCallback (xmlSecErrorsCallback callback);
void xmlSecErrorsDefaultCallback (const char* file,
                                                                 int line,
                                                                 const char* func,
                                                                 const char* errorObject,
                                                                 const char* errorSubject,
                                                                 int reason,
                                                                 const char* msg);
void xmlSecErrorsDefaultCallbackEnableOutput
                                                                (int enabled);
int xmlSecErrorsGetCode (xmlSecSize pos);
const char* xmlSecErrorsGetMsg (xmlSecSize pos);
// 462 "/usr/local/include/xmlsec1/xmlsec/errors.h"
void xmlSecError (const char* file,
                                                         int line,
                                                         const char* func,
                                                         const char* errorObject,
                                                         const char* errorSubject,
                                                         int reason,
                                                         const char* msg, ...) __attribute__ ((format (printf, 7, 8)));
// 2 "/scripts/include-xmlsec.c" 2
// 1 "/usr/local/include/xmlsec1/xmlsec/buffer.h" 1
// 14 "/usr/local/include/xmlsec1/xmlsec/buffer.h"
// 15 "/usr/local/include/xmlsec1/xmlsec/buffer.h" 2
// 1 "/usr/local/include/xmlsec1/xmlsec/xmlsec.h" 1
// 16 "/usr/local/include/xmlsec1/xmlsec/xmlsec.h"
// 1 "/usr/local/include/xmlsec1/xmlsec/version.h" 1
// 17 "/usr/local/include/xmlsec1/xmlsec/xmlsec.h" 2
// 1 "/usr/local/include/xmlsec1/xmlsec/exports.h" 1
// 18 "/usr/local/include/xmlsec1/xmlsec/xmlsec.h" 2
// 1 "/usr/local/include/xmlsec1/xmlsec/strings.h" 1
// 16 "/usr/local/include/xmlsec1/xmlsec/strings.h"
// 1 "/usr/local/include/xmlsec1/xmlsec/xmlsec.h" 1
// 17 "/usr/local/include/xmlsec1/xmlsec/strings.h" 2
// 27 "/usr/local/include/xmlsec1/xmlsec/strings.h"
extern const xmlChar xmlSecNs[];
extern const xmlChar xmlSecDSigNs[];
extern const xmlChar xmlSecEncNs[];
extern const xmlChar xmlSecXPathNs[];
extern const xmlChar xmlSecXPath2Ns[];
extern const xmlChar xmlSecXPointerNs[];
extern const xmlChar xmlSecSoap11Ns[];
extern const xmlChar xmlSecSoap12Ns[];
extern const xmlChar xmlSecNodeSignature[];
extern const xmlChar xmlSecNodeSignedInfo[];
extern const xmlChar xmlSecNodeSignatureValue[];
extern const xmlChar xmlSecNodeCanonicalizationMethod[];
extern const xmlChar xmlSecNodeSignatureMethod[];
extern const xmlChar xmlSecNodeDigestMethod[];
extern const xmlChar xmlSecNodeDigestValue[];
extern const xmlChar xmlSecNodeObject[];
extern const xmlChar xmlSecNodeManifest[];
extern const xmlChar xmlSecNodeSignatureProperties[];
extern const xmlChar xmlSecNodeEncryptedData[];
extern const xmlChar xmlSecNodeEncryptionMethod[];
extern const xmlChar xmlSecNodeEncryptionProperties[];
extern const xmlChar xmlSecNodeEncryptionProperty[];
extern const xmlChar xmlSecNodeCipherData[];
extern const xmlChar xmlSecNodeCipherValue[];
extern const xmlChar xmlSecNodeCipherReference[];
extern const xmlChar xmlSecNodeReferenceList[];
extern const xmlChar xmlSecNodeDataReference[];
extern const xmlChar xmlSecNodeKeyReference[];
extern const xmlChar xmlSecNodeCarriedKeyName[];
extern const xmlChar xmlSecTypeEncContent[];
extern const xmlChar xmlSecTypeEncElement[];
extern const xmlChar xmlSecNodeKeyInfo[];
extern const xmlChar xmlSecNodeReference[];
extern const xmlChar xmlSecNodeTransforms[];
extern const xmlChar xmlSecNodeTransform[];
extern const xmlChar xmlSecAttrId[];
extern const xmlChar xmlSecAttrURI[];
extern const xmlChar xmlSecAttrType[];
extern const xmlChar xmlSecAttrMimeType[];
extern const xmlChar xmlSecAttrEncoding[];
extern const xmlChar xmlSecAttrAlgorithm[];
extern const xmlChar xmlSecAttrTarget[];
extern const xmlChar xmlSecAttrFilter[];
extern const xmlChar xmlSecAttrRecipient[];
extern const xmlChar xmlSecNameAESKeyValue[];
extern const xmlChar xmlSecNodeAESKeyValue[];
extern const xmlChar xmlSecHrefAESKeyValue[];
extern const xmlChar xmlSecNameAes128Cbc[];
extern const xmlChar xmlSecHrefAes128Cbc[];
extern const xmlChar xmlSecNameAes192Cbc[];
extern const xmlChar xmlSecHrefAes192Cbc[];
extern const xmlChar xmlSecNameAes256Cbc[];
extern const xmlChar xmlSecHrefAes256Cbc[];
extern const xmlChar xmlSecNameAes128Gcm[];
extern const xmlChar xmlSecHrefAes128Gcm[];
extern const xmlChar xmlSecNameAes192Gcm[];
extern const xmlChar xmlSecHrefAes192Gcm[];
extern const xmlChar xmlSecNameAes256Gcm[];
extern const xmlChar xmlSecHrefAes256Gcm[];
extern const xmlChar xmlSecNameKWAes128[];
extern const xmlChar xmlSecHrefKWAes128[];
extern const xmlChar xmlSecNameKWAes192[];
extern const xmlChar xmlSecHrefKWAes192[];
extern const xmlChar xmlSecNameKWAes256[];
extern const xmlChar xmlSecHrefKWAes256[];
extern const xmlChar xmlSecNameBase64[];
extern const xmlChar xmlSecHrefBase64[];
extern const xmlChar xmlSecNameC14N[];
extern const xmlChar xmlSecHrefC14N[];
extern const xmlChar xmlSecNameC14NWithComments[];
extern const xmlChar xmlSecHrefC14NWithComments[];
extern const xmlChar xmlSecNameC14N11[];
extern const xmlChar xmlSecHrefC14N11[];
extern const xmlChar xmlSecNameC14N11WithComments[];
extern const xmlChar xmlSecHrefC14N11WithComments[];
extern const xmlChar xmlSecNameExcC14N[];
extern const xmlChar xmlSecHrefExcC14N[];
extern const xmlChar xmlSecNameExcC14NWithComments[];
extern const xmlChar xmlSecHrefExcC14NWithComments[];
extern const xmlChar xmlSecNsExcC14N[];
extern const xmlChar xmlSecNsExcC14NWithComments[];
extern const xmlChar xmlSecNodeInclusiveNamespaces[];
extern const xmlChar xmlSecAttrPrefixList[];
extern const xmlChar xmlSecNameDESKeyValue[];
extern const xmlChar xmlSecNodeDESKeyValue[];
extern const xmlChar xmlSecHrefDESKeyValue[];
extern const xmlChar xmlSecNameDes3Cbc[];
extern const xmlChar xmlSecHrefDes3Cbc[];
extern const xmlChar xmlSecNameKWDes3[];
extern const xmlChar xmlSecHrefKWDes3[];
extern const xmlChar xmlSecNameDSAKeyValue[];
extern const xmlChar xmlSecNodeDSAKeyValue[];
extern const xmlChar xmlSecHrefDSAKeyValue[];
extern const xmlChar xmlSecNodeDSAP[];
extern const xmlChar xmlSecNodeDSAQ[];
extern const xmlChar xmlSecNodeDSAG[];
extern const xmlChar xmlSecNodeDSAJ[];
extern const xmlChar xmlSecNodeDSAX[];
extern const xmlChar xmlSecNodeDSAY[];
extern const xmlChar xmlSecNodeDSASeed[];
extern const xmlChar xmlSecNodeDSAPgenCounter[];
extern const xmlChar xmlSecNameDsaSha1[];
extern const xmlChar xmlSecHrefDsaSha1[];
extern const xmlChar xmlSecNameDsaSha256[];
extern const xmlChar xmlSecHrefDsaSha256[];
extern const xmlChar xmlSecNameECDSAKeyValue[];
extern const xmlChar xmlSecNodeECDSAKeyValue[];
extern const xmlChar xmlSecHrefECDSAKeyValue[];
extern const xmlChar xmlSecNodeECDSAP[];
extern const xmlChar xmlSecNodeECDSAQ[];
extern const xmlChar xmlSecNodeECDSAG[];
extern const xmlChar xmlSecNodeECDSAJ[];
extern const xmlChar xmlSecNodeECDSAX[];
extern const xmlChar xmlSecNodeECDSAY[];
extern const xmlChar xmlSecNodeECDSASeed[];
extern const xmlChar xmlSecNodeECDSAPgenCounter[];
extern const xmlChar xmlSecNameEcdsaSha1[];
extern const xmlChar xmlSecHrefEcdsaSha1[];
extern const xmlChar xmlSecNameEcdsaSha224[];
extern const xmlChar xmlSecHrefEcdsaSha224[];
extern const xmlChar xmlSecNameEcdsaSha256[];
extern const xmlChar xmlSecHrefEcdsaSha256[];
extern const xmlChar xmlSecNameEcdsaSha384[];
extern const xmlChar xmlSecHrefEcdsaSha384[];
extern const xmlChar xmlSecNameEcdsaSha512[];
extern const xmlChar xmlSecHrefEcdsaSha512[];
extern const xmlChar xmlSecNameGOST2001KeyValue[];
extern const xmlChar xmlSecNodeGOST2001KeyValue[];
extern const xmlChar xmlSecHrefGOST2001KeyValue[];
extern const xmlChar xmlSecNameGost2001GostR3411_94[];
extern const xmlChar xmlSecHrefGost2001GostR3411_94[];
extern const xmlChar xmlSecNameGostR3410_2012_256KeyValue[];
extern const xmlChar xmlSecNodeGostR3410_2012_256KeyValue[];
extern const xmlChar xmlSecHrefGostR3410_2012_256KeyValue[];
extern const xmlChar xmlSecNameGostR3410_2012_512KeyValue[];
extern const xmlChar xmlSecNodeGostR3410_2012_512KeyValue[];
extern const xmlChar xmlSecHrefGostR3410_2012_512KeyValue[];
extern const xmlChar xmlSecNameGostR3410_2012GostR3411_2012_256[];
extern const xmlChar xmlSecHrefGostR3410_2012GostR3411_2012_256[];
extern const xmlChar xmlSecNameGostR3410_2012GostR3411_2012_512[];
extern const xmlChar xmlSecHrefGostR3410_2012GostR3411_2012_512[];
extern const xmlChar xmlSecNameEncryptedKey[];
extern const xmlChar xmlSecNodeEncryptedKey[];
extern const xmlChar xmlSecHrefEncryptedKey[];
extern const xmlChar xmlSecNameEnveloped[];
extern const xmlChar xmlSecHrefEnveloped[];
extern const xmlChar xmlSecNameHMACKeyValue[];
extern const xmlChar xmlSecNodeHMACKeyValue[];
extern const xmlChar xmlSecHrefHMACKeyValue[];
extern const xmlChar xmlSecNodeHMACOutputLength[];
extern const xmlChar xmlSecNameHmacMd5[];
extern const xmlChar xmlSecHrefHmacMd5[];
extern const xmlChar xmlSecNameHmacRipemd160[];
extern const xmlChar xmlSecHrefHmacRipemd160[];
extern const xmlChar xmlSecNameHmacSha1[];
extern const xmlChar xmlSecHrefHmacSha1[];
extern const xmlChar xmlSecNameHmacSha224[];
extern const xmlChar xmlSecHrefHmacSha224[];
extern const xmlChar xmlSecNameHmacSha256[];
extern const xmlChar xmlSecHrefHmacSha256[];
extern const xmlChar xmlSecNameHmacSha384[];
extern const xmlChar xmlSecHrefHmacSha384[];
extern const xmlChar xmlSecNameHmacSha512[];
extern const xmlChar xmlSecHrefHmacSha512[];
extern const xmlChar xmlSecNameKeyName[];
extern const xmlChar xmlSecNodeKeyName[];
extern const xmlChar xmlSecNameKeyValue[];
extern const xmlChar xmlSecNodeKeyValue[];
extern const xmlChar xmlSecNameMemBuf[];
extern const xmlChar xmlSecNameMd5[];
extern const xmlChar xmlSecHrefMd5[];
extern const xmlChar xmlSecNameRetrievalMethod[];
extern const xmlChar xmlSecNodeRetrievalMethod[];
extern const xmlChar xmlSecNameRipemd160[];
extern const xmlChar xmlSecHrefRipemd160[];
extern const xmlChar xmlSecNameRSAKeyValue[];
extern const xmlChar xmlSecNodeRSAKeyValue[];
extern const xmlChar xmlSecHrefRSAKeyValue[];
extern const xmlChar xmlSecNodeRSAModulus[];
extern const xmlChar xmlSecNodeRSAExponent[];
extern const xmlChar xmlSecNodeRSAPrivateExponent[];
extern const xmlChar xmlSecNameRsaMd5[];
extern const xmlChar xmlSecHrefRsaMd5[];
extern const xmlChar xmlSecNameRsaRipemd160[];
extern const xmlChar xmlSecHrefRsaRipemd160[];
extern const xmlChar xmlSecNameRsaSha1[];
extern const xmlChar xmlSecHrefRsaSha1[];
extern const xmlChar xmlSecNameRsaSha224[];
extern const xmlChar xmlSecHrefRsaSha224[];
extern const xmlChar xmlSecNameRsaSha256[];
extern const xmlChar xmlSecHrefRsaSha256[];
extern const xmlChar xmlSecNameRsaSha384[];
extern const xmlChar xmlSecHrefRsaSha384[];
extern const xmlChar xmlSecNameRsaSha512[];
extern const xmlChar xmlSecHrefRsaSha512[];
extern const xmlChar xmlSecNameRsaPkcs1[];
extern const xmlChar xmlSecHrefRsaPkcs1[];
extern const xmlChar xmlSecNameRsaOaep[];
extern const xmlChar xmlSecHrefRsaOaep[];
extern const xmlChar xmlSecNodeRsaOAEPparams[];
extern const xmlChar xmlSecNameGostR3411_94[];
extern const xmlChar xmlSecHrefGostR3411_94[];
extern const xmlChar xmlSecNameGostR3411_2012_256[];
extern const xmlChar xmlSecHrefGostR3411_2012_256[];
extern const xmlChar xmlSecNameGostR3411_2012_512[];
extern const xmlChar xmlSecHrefGostR3411_2012_512[];
extern const xmlChar xmlSecNameSha1[];
extern const xmlChar xmlSecHrefSha1[];
extern const xmlChar xmlSecNameSha224[];
extern const xmlChar xmlSecHrefSha224[];
extern const xmlChar xmlSecNameSha256[];
extern const xmlChar xmlSecHrefSha256[];
extern const xmlChar xmlSecNameSha384[];
extern const xmlChar xmlSecHrefSha384[];
extern const xmlChar xmlSecNameSha512[];
extern const xmlChar xmlSecHrefSha512[];
extern const xmlChar xmlSecNameX509Data[];
extern const xmlChar xmlSecNodeX509Data[];
extern const xmlChar xmlSecHrefX509Data[];
extern const xmlChar xmlSecNodeX509Certificate[];
extern const xmlChar xmlSecNodeX509CRL[];
extern const xmlChar xmlSecNodeX509SubjectName[];
extern const xmlChar xmlSecNodeX509IssuerSerial[];
extern const xmlChar xmlSecNodeX509IssuerName[];
extern const xmlChar xmlSecNodeX509SerialNumber[];
extern const xmlChar xmlSecNodeX509SKI[];
extern const xmlChar xmlSecNameRawX509Cert[];
extern const xmlChar xmlSecHrefRawX509Cert[];
extern const xmlChar xmlSecNameX509Store[];
extern const xmlChar xmlSecNamePGPData[];
extern const xmlChar xmlSecNodePGPData[];
extern const xmlChar xmlSecHrefPGPData[];
extern const xmlChar xmlSecNameSPKIData[];
extern const xmlChar xmlSecNodeSPKIData[];
extern const xmlChar xmlSecHrefSPKIData[];
extern const xmlChar xmlSecNameXPath[];
extern const xmlChar xmlSecNodeXPath[];
extern const xmlChar xmlSecNameXPath2[];
extern const xmlChar xmlSecNodeXPath2[];
extern const xmlChar xmlSecXPath2FilterIntersect[];
extern const xmlChar xmlSecXPath2FilterSubtract[];
extern const xmlChar xmlSecXPath2FilterUnion[];
extern const xmlChar xmlSecNameXPointer[];
extern const xmlChar xmlSecNodeXPointer[];
extern const xmlChar xmlSecNameRelationship[];
extern const xmlChar xmlSecHrefRelationship[];
extern const xmlChar xmlSecNodeRelationship[];
extern const xmlChar xmlSecNodeRelationshipReference[];
extern const xmlChar xmlSecRelationshipsNs[];
extern const xmlChar xmlSecRelationshipReferenceNs[];
extern const xmlChar xmlSecRelationshipAttrId[];
extern const xmlChar xmlSecRelationshipAttrSourceId[];
extern const xmlChar xmlSecRelationshipAttrTargetMode[];
extern const xmlChar xmlSecNameXslt[];
extern const xmlChar xmlSecHrefXslt[];
extern const xmlChar xmlSecNodeEnvelope[];
extern const xmlChar xmlSecNodeHeader[];
extern const xmlChar xmlSecNodeBody[];
extern const xmlChar xmlSecNodeFault[];
extern const xmlChar xmlSecNodeFaultCode[];
extern const xmlChar xmlSecNodeFaultString[];
extern const xmlChar xmlSecNodeFaultActor[];
extern const xmlChar xmlSecNodeFaultDetail[];
extern const xmlChar xmlSecNodeCode[];
extern const xmlChar xmlSecNodeReason[];
extern const xmlChar xmlSecNodeNode[];
extern const xmlChar xmlSecNodeRole[];
extern const xmlChar xmlSecNodeDetail[];
extern const xmlChar xmlSecNodeValue[];
extern const xmlChar xmlSecNodeSubcode[];
extern const xmlChar xmlSecNodeText[];
extern const xmlChar xmlSecSoapFaultCodeVersionMismatch[];
extern const xmlChar xmlSecSoapFaultCodeMustUnderstand[];
extern const xmlChar xmlSecSoapFaultCodeClient[];
extern const xmlChar xmlSecSoapFaultCodeServer[];
extern const xmlChar xmlSecSoapFaultCodeReceiver[];
extern const xmlChar xmlSecSoapFaultCodeSender[];
extern const xmlChar xmlSecSoapFaultDataEncodningUnknown[];
// 571 "/usr/local/include/xmlsec1/xmlsec/strings.h"
extern const xmlChar xmlSecStringEmpty[];
extern const xmlChar xmlSecStringCR[];
// 19 "/usr/local/include/xmlsec1/xmlsec/xmlsec.h" 2
// 34 "/usr/local/include/xmlsec1/xmlsec/xmlsec.h"
typedef void* xmlSecPtr;
// 69 "/usr/local/include/xmlsec1/xmlsec/xmlsec.h"
typedef struct _xmlSecKeyData xmlSecKeyData, *xmlSecKeyDataPtr;
typedef struct _xmlSecKeyDataStore xmlSecKeyDataStore, *xmlSecKeyDataStorePtr;
typedef struct _xmlSecKeyInfoCtx xmlSecKeyInfoCtx, *xmlSecKeyInfoCtxPtr;
typedef struct _xmlSecKey xmlSecKey, *xmlSecKeyPtr;
typedef struct _xmlSecKeyStore xmlSecKeyStore, *xmlSecKeyStorePtr;
typedef struct _xmlSecKeysMngr xmlSecKeysMngr, *xmlSecKeysMngrPtr;
typedef struct _xmlSecTransform xmlSecTransform, *xmlSecTransformPtr;
typedef struct _xmlSecTransformCtx xmlSecTransformCtx, *xmlSecTransformCtxPtr;
typedef struct _xmlSecDSigCtx xmlSecDSigCtx, *xmlSecDSigCtxPtr;
typedef struct _xmlSecEncCtx xmlSecEncCtx, *xmlSecEncCtxPtr;
 int xmlSecInit (void);
 int xmlSecShutdown (void);
 const xmlChar * xmlSecGetDefaultCrypto (void);
 void xmlSecSetExternalEntityLoader (xmlExternalEntityLoader);
// 149 "/usr/local/include/xmlsec1/xmlsec/xmlsec.h"
typedef enum {
    xmlSecCheckVersionExactMatch = 0,
    xmlSecCheckVersionABICompatible
} xmlSecCheckVersionMode;
 int xmlSecCheckVersionExt (int major,
                                                 int minor,
                                                 int subminor,
                                                 xmlSecCheckVersionMode mode);
// 16 "/usr/local/include/xmlsec1/xmlsec/buffer.h" 2
typedef struct _xmlSecBuffer xmlSecBuffer,
                                                                *xmlSecBufferPtr;
// 34 "/usr/local/include/xmlsec1/xmlsec/buffer.h"
typedef enum {
    xmlSecAllocModeExact = 0,
    xmlSecAllocModeDouble
} xmlSecAllocMode;
// 54 "/usr/local/include/xmlsec1/xmlsec/buffer.h"
struct _xmlSecBuffer {
    unsigned char* data;
    unsigned int size;
    unsigned int maxSize;
    xmlSecAllocMode allocMode;
};
 void xmlSecBufferSetDefaultAllocMode (xmlSecAllocMode defAllocMode,
                                                                 unsigned int defInitialSize);
 xmlSecBufferPtr xmlSecBufferCreate (unsigned int size);
 void xmlSecBufferDestroy (xmlSecBufferPtr buf);
 int xmlSecBufferInitialize (xmlSecBufferPtr buf,
                                                                 unsigned int size);
 void xmlSecBufferFinalize (xmlSecBufferPtr buf);
 unsigned char* xmlSecBufferGetData (xmlSecBufferPtr buf);
 int xmlSecBufferSetData (xmlSecBufferPtr buf,
                                                                 const unsigned char* data,
                                                                 unsigned int size);
 unsigned int xmlSecBufferGetSize (xmlSecBufferPtr buf);
 int xmlSecBufferSetSize (xmlSecBufferPtr buf,
                                                                 unsigned int size);
 unsigned int xmlSecBufferGetMaxSize (xmlSecBufferPtr buf);
 int xmlSecBufferSetMaxSize (xmlSecBufferPtr buf,
                                                                 unsigned int size);
 void xmlSecBufferEmpty (xmlSecBufferPtr buf);
 int xmlSecBufferAppend (xmlSecBufferPtr buf,
                                                                 const unsigned char* data,
                                                                 unsigned int size);
 int xmlSecBufferPrepend (xmlSecBufferPtr buf,
                                                                 const unsigned char* data,
                                                                 unsigned int size);
 int xmlSecBufferRemoveHead (xmlSecBufferPtr buf,
                                                                 unsigned int size);
 int xmlSecBufferRemoveTail (xmlSecBufferPtr buf,
                                                                 unsigned int size);
 int xmlSecBufferReadFile (xmlSecBufferPtr buf,
                                                                 const char* filename);
 int xmlSecBufferBase64NodeContentRead(xmlSecBufferPtr buf,
                                                                 xmlNodePtr node);
 int xmlSecBufferBase64NodeContentWrite(xmlSecBufferPtr buf,
                                                                 xmlNodePtr node,
                                                                 int columns);
 xmlOutputBufferPtr xmlSecBufferCreateOutputBuffer (xmlSecBufferPtr buf);
// 3 "/scripts/include-xmlsec.c" 2
// 1 "/usr/local/include/xmlsec1/xmlsec/keys.h" 1
// 14 "/usr/local/include/xmlsec1/xmlsec/keys.h"
// 15 "/usr/local/include/xmlsec1/xmlsec/keys.h" 2
// 1 "/usr/local/include/xmlsec1/xmlsec/list.h" 1
// 21 "/usr/local/include/xmlsec1/xmlsec/list.h"
typedef const struct _xmlSecPtrListKlass xmlSecPtrListKlass,
                                                                *xmlSecPtrListId;
typedef struct _xmlSecPtrList xmlSecPtrList,
                                                                *xmlSecPtrListPtr;
// 36 "/usr/local/include/xmlsec1/xmlsec/list.h"
struct _xmlSecPtrList {
    xmlSecPtrListId id;
    xmlSecPtr* data;
    unsigned int use;
    unsigned int max;
    xmlSecAllocMode allocMode;
};
 void xmlSecPtrListSetDefaultAllocMode(xmlSecAllocMode defAllocMode,
                                                                 unsigned int defInitialSize);
 int xmlSecPtrListInitialize (xmlSecPtrListPtr list,
                                                                 xmlSecPtrListId id);
 void xmlSecPtrListFinalize (xmlSecPtrListPtr list);
 xmlSecPtrListPtr xmlSecPtrListCreate (xmlSecPtrListId id);
 void xmlSecPtrListDestroy (xmlSecPtrListPtr list);
 void xmlSecPtrListEmpty (xmlSecPtrListPtr list);
 int xmlSecPtrListCopy (xmlSecPtrListPtr dst,
                                                                 xmlSecPtrListPtr src);
 xmlSecPtrListPtr xmlSecPtrListDuplicate (xmlSecPtrListPtr list);
 unsigned int xmlSecPtrListGetSize (xmlSecPtrListPtr list);
 xmlSecPtr xmlSecPtrListGetItem (xmlSecPtrListPtr list,
                                                                 unsigned int pos);
 int xmlSecPtrListAdd (xmlSecPtrListPtr list,
                                                                 xmlSecPtr item);
 int xmlSecPtrListSet (xmlSecPtrListPtr list,
                                                                 xmlSecPtr item,
                                                                 unsigned int pos);
 int xmlSecPtrListRemove (xmlSecPtrListPtr list,
                                                                 unsigned int pos);
 xmlSecPtr xmlSecPtrListRemoveAndReturn (xmlSecPtrListPtr list,
                                                                 unsigned int pos);
 void xmlSecPtrListDebugDump (xmlSecPtrListPtr list,
                                                                 FILE* output);
 void xmlSecPtrListDebugXmlDump (xmlSecPtrListPtr list,
                                                                 FILE* output);
// 127 "/usr/local/include/xmlsec1/xmlsec/list.h"
typedef xmlSecPtr (*xmlSecPtrDuplicateItemMethod) (xmlSecPtr ptr);
typedef void (*xmlSecPtrDestroyItemMethod) (xmlSecPtr ptr);
// 144 "/usr/local/include/xmlsec1/xmlsec/list.h"
typedef void (*xmlSecPtrDebugDumpItemMethod) (xmlSecPtr ptr,
                                                                 FILE* output);
// 157 "/usr/local/include/xmlsec1/xmlsec/list.h"
struct _xmlSecPtrListKlass {
    const xmlChar* name;
    xmlSecPtrDuplicateItemMethod duplicateItem;
    xmlSecPtrDestroyItemMethod destroyItem;
    xmlSecPtrDebugDumpItemMethod debugDumpItem;
    xmlSecPtrDebugDumpItemMethod debugXmlDumpItem;
};
// 187 "/usr/local/include/xmlsec1/xmlsec/list.h"
 xmlSecPtrListId xmlSecStringListGetKlass (void);
// 18 "/usr/local/include/xmlsec1/xmlsec/keys.h" 2
// 1 "/usr/local/include/xmlsec1/xmlsec/keysdata.h" 1
// 29 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef const struct _xmlSecKeyDataKlass xmlSecKeyDataKlass,
                                                        *xmlSecKeyDataId;
typedef const struct _xmlSecKeyDataStoreKlass xmlSecKeyDataStoreKlass,
                                                        *xmlSecKeyDataStoreId;
typedef struct _xmlSecKeyDataList xmlSecKeyDataList,
                                                        *xmlSecKeyDataListPtr;
// 47 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef unsigned int xmlSecKeyDataUsage;
// 142 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef unsigned int xmlSecKeyDataType;
// 226 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef enum {
    xmlSecKeyDataFormatUnknown = 0,
    xmlSecKeyDataFormatBinary,
    xmlSecKeyDataFormatPem,
    xmlSecKeyDataFormatDer,
    xmlSecKeyDataFormatPkcs8Pem,
    xmlSecKeyDataFormatPkcs8Der,
    xmlSecKeyDataFormatPkcs12,
    xmlSecKeyDataFormatCertPem,
    xmlSecKeyDataFormatCertDer
} xmlSecKeyDataFormat;
 xmlSecPtrListPtr xmlSecKeyDataIdsGet (void);
 int xmlSecKeyDataIdsInit (void);
 void xmlSecKeyDataIdsShutdown (void);
 int xmlSecKeyDataIdsRegisterDefault (void);
 int xmlSecKeyDataIdsRegister (xmlSecKeyDataId id);
// 262 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
struct _xmlSecKeyData {
    xmlSecKeyDataId id;
    void* reserved0;
    void* reserved1;
};
 xmlSecKeyDataPtr xmlSecKeyDataCreate (xmlSecKeyDataId id);
 xmlSecKeyDataPtr xmlSecKeyDataDuplicate (xmlSecKeyDataPtr data);
 void xmlSecKeyDataDestroy (xmlSecKeyDataPtr data);
 int xmlSecKeyDataGenerate (xmlSecKeyDataPtr data,
                                                                 unsigned int sizeBits,
                                                                 xmlSecKeyDataType type);
 xmlSecKeyDataType xmlSecKeyDataGetType (xmlSecKeyDataPtr data);
 unsigned int xmlSecKeyDataGetSize (xmlSecKeyDataPtr data);
 const xmlChar* xmlSecKeyDataGetIdentifier (xmlSecKeyDataPtr data);
 void xmlSecKeyDataDebugDump (xmlSecKeyDataPtr data,
                                                                 FILE *output);
 void xmlSecKeyDataDebugXmlDump (xmlSecKeyDataPtr data,
                                                                 FILE *output);
 int xmlSecKeyDataXmlRead (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
 int xmlSecKeyDataXmlWrite (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
 int xmlSecKeyDataBinRead (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 const unsigned char* buf,
                                                                 unsigned int bufSize,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
 int xmlSecKeyDataBinWrite (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 unsigned char** buf,
                                                                 unsigned int* bufSize,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
// 376 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef int (*xmlSecKeyDataInitMethod) (xmlSecKeyDataPtr data);
// 387 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef int (*xmlSecKeyDataDuplicateMethod) (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
// 397 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef void (*xmlSecKeyDataFinalizeMethod) (xmlSecKeyDataPtr data);
// 410 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef int (*xmlSecKeyDataXmlReadMethod) (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
// 425 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef int (*xmlSecKeyDataXmlWriteMethod) (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
// 441 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef int (*xmlSecKeyDataBinReadMethod) (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 const unsigned char* buf,
                                                                 unsigned int bufSize,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
// 458 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef int (*xmlSecKeyDataBinWriteMethod) (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 unsigned char** buf,
                                                                 unsigned int* bufSize,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
// 474 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef int (*xmlSecKeyDataGenerateMethod) (xmlSecKeyDataPtr data,
                                                                 unsigned int sizeBits,
                                                                 xmlSecKeyDataType type);
// 486 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef xmlSecKeyDataType (*xmlSecKeyDataGetTypeMethod) (xmlSecKeyDataPtr data);
// 496 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef unsigned int (*xmlSecKeyDataGetSizeMethod) (xmlSecKeyDataPtr data);
// 507 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef const xmlChar* (*xmlSecKeyDataGetIdentifierMethod) (xmlSecKeyDataPtr data);
// 516 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef void (*xmlSecKeyDataDebugDumpMethod) (xmlSecKeyDataPtr data,
                                                                 FILE* output);
// 546 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
struct _xmlSecKeyDataKlass {
    unsigned int klassSize;
    unsigned int objSize;
    const xmlChar* name;
    xmlSecKeyDataUsage usage;
    const xmlChar* href;
    const xmlChar* dataNodeName;
    const xmlChar* dataNodeNs;
    xmlSecKeyDataInitMethod initialize;
    xmlSecKeyDataDuplicateMethod duplicate;
    xmlSecKeyDataFinalizeMethod finalize;
    xmlSecKeyDataGenerateMethod generate;
    xmlSecKeyDataGetTypeMethod getType;
    xmlSecKeyDataGetSizeMethod getSize;
    xmlSecKeyDataGetIdentifierMethod getIdentifier;
    xmlSecKeyDataXmlReadMethod xmlRead;
    xmlSecKeyDataXmlWriteMethod xmlWrite;
    xmlSecKeyDataBinReadMethod binRead;
    xmlSecKeyDataBinWriteMethod binWrite;
    xmlSecKeyDataDebugDumpMethod debugDump;
    xmlSecKeyDataDebugDumpMethod debugXmlDump;
    void* reserved0;
    void* reserved1;
};
// 604 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
 xmlSecPtrListId xmlSecKeyDataListGetKlass (void);
// 618 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
 xmlSecPtrListId xmlSecKeyDataIdListGetKlass (void);
 int xmlSecKeyDataIdListFind (xmlSecPtrListPtr list,
                                                                 xmlSecKeyDataId dataId);
 xmlSecKeyDataId xmlSecKeyDataIdListFindByNode (xmlSecPtrListPtr list,
                                                                 const xmlChar* nodeName,
                                                                 const xmlChar* nodeNs,
                                                                 xmlSecKeyDataUsage usage);
 xmlSecKeyDataId xmlSecKeyDataIdListFindByHref (xmlSecPtrListPtr list,
                                                                 const xmlChar* href,
                                                                 xmlSecKeyDataUsage usage);
 xmlSecKeyDataId xmlSecKeyDataIdListFindByName (xmlSecPtrListPtr list,
                                                                 const xmlChar* name,
                                                                 xmlSecKeyDataUsage usage);
 void xmlSecKeyDataIdListDebugDump (xmlSecPtrListPtr list,
                                                                 FILE* output);
 void xmlSecKeyDataIdListDebugXmlDump (xmlSecPtrListPtr list,
                                                                 FILE* output);
// 651 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
 int xmlSecKeyDataBinaryValueInitialize (xmlSecKeyDataPtr data);
 int xmlSecKeyDataBinaryValueDuplicate (xmlSecKeyDataPtr dst,
                                                                        xmlSecKeyDataPtr src);
 void xmlSecKeyDataBinaryValueFinalize (xmlSecKeyDataPtr data);
 int xmlSecKeyDataBinaryValueXmlRead (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
 int xmlSecKeyDataBinaryValueXmlWrite (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
 int xmlSecKeyDataBinaryValueBinRead (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         const unsigned char* buf,
                                                                         unsigned int bufSize,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
 int xmlSecKeyDataBinaryValueBinWrite (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         unsigned char** buf,
                                                                         unsigned int* bufSize,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
 void xmlSecKeyDataBinaryValueDebugDump (xmlSecKeyDataPtr data,
                                                                        FILE* output);
 void xmlSecKeyDataBinaryValueDebugXmlDump (xmlSecKeyDataPtr data,
                                                                         FILE* output);
 unsigned int xmlSecKeyDataBinaryValueGetSize (xmlSecKeyDataPtr data);
 xmlSecBufferPtr xmlSecKeyDataBinaryValueGetBuffer (xmlSecKeyDataPtr data);
 int xmlSecKeyDataBinaryValueSetBuffer (xmlSecKeyDataPtr data,
                                                                         const unsigned char* buf,
                                                                         unsigned int bufSize);
// 699 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
struct _xmlSecKeyDataStore {
    xmlSecKeyDataStoreId id;
    void* reserved0;
    void* reserved1;
};
 xmlSecKeyDataStorePtr xmlSecKeyDataStoreCreate (xmlSecKeyDataStoreId id);
 void xmlSecKeyDataStoreDestroy (xmlSecKeyDataStorePtr store);
// 772 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
typedef int (*xmlSecKeyDataStoreInitializeMethod) (xmlSecKeyDataStorePtr store);
typedef void (*xmlSecKeyDataStoreFinalizeMethod) (xmlSecKeyDataStorePtr store);
// 794 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
struct _xmlSecKeyDataStoreKlass {
    unsigned int klassSize;
    unsigned int objSize;
    const xmlChar* name;
    xmlSecKeyDataStoreInitializeMethod initialize;
    xmlSecKeyDataStoreFinalizeMethod finalize;
    void* reserved0;
    void* reserved1;
};
// 830 "/usr/local/include/xmlsec1/xmlsec/keysdata.h"
 xmlSecPtrListId xmlSecKeyDataStorePtrListGetKlass (void);
// 19 "/usr/local/include/xmlsec1/xmlsec/keys.h" 2
// 29 "/usr/local/include/xmlsec1/xmlsec/keys.h"
typedef unsigned int xmlSecKeyUsage;
// 79 "/usr/local/include/xmlsec1/xmlsec/keys.h"
typedef struct _xmlSecKeyUseWith xmlSecKeyUseWith, *xmlSecKeyUseWithPtr;
 int xmlSecKeyUseWithInitialize (xmlSecKeyUseWithPtr keyUseWith);
 void xmlSecKeyUseWithFinalize (xmlSecKeyUseWithPtr keyUseWith);
 void xmlSecKeyUseWithReset (xmlSecKeyUseWithPtr keyUseWith);
 int xmlSecKeyUseWithCopy (xmlSecKeyUseWithPtr dst,
                                                                 xmlSecKeyUseWithPtr src);
 xmlSecKeyUseWithPtr xmlSecKeyUseWithCreate (const xmlChar* application,
                                                                 const xmlChar* identifier);
 xmlSecKeyUseWithPtr xmlSecKeyUseWithDuplicate (xmlSecKeyUseWithPtr keyUseWith);
 void xmlSecKeyUseWithDestroy (xmlSecKeyUseWithPtr keyUseWith);
 int xmlSecKeyUseWithSet (xmlSecKeyUseWithPtr keyUseWith,
                                                                 const xmlChar* application,
                                                                 const xmlChar* identifier);
 void xmlSecKeyUseWithDebugDump (xmlSecKeyUseWithPtr keyUseWith,
                                                                 FILE* output);
 void xmlSecKeyUseWithDebugXmlDump (xmlSecKeyUseWithPtr keyUseWith,
                                                                 FILE* output);
// 106 "/usr/local/include/xmlsec1/xmlsec/keys.h"
struct _xmlSecKeyUseWith {
    xmlChar* application;
    xmlChar* identifier;
    void* reserved1;
    void* reserved2;
};
 xmlSecPtrListId xmlSecKeyUseWithPtrListGetKlass (void);
typedef struct _xmlSecKeyReq xmlSecKeyReq, *xmlSecKeyReqPtr;
// 141 "/usr/local/include/xmlsec1/xmlsec/keys.h"
struct _xmlSecKeyReq {
    xmlSecKeyDataId keyId;
    xmlSecKeyDataType keyType;
    xmlSecKeyUsage keyUsage;
    unsigned int keyBitsSize;
    xmlSecPtrList keyUseWithList;
    void* reserved1;
    void* reserved2;
};
 int xmlSecKeyReqInitialize (xmlSecKeyReqPtr keyReq);
 void xmlSecKeyReqFinalize (xmlSecKeyReqPtr keyReq);
 void xmlSecKeyReqReset (xmlSecKeyReqPtr keyReq);
 int xmlSecKeyReqCopy (xmlSecKeyReqPtr dst,
                                                                 xmlSecKeyReqPtr src);
 int xmlSecKeyReqMatchKey (xmlSecKeyReqPtr keyReq,
                                                                 xmlSecKeyPtr key);
 int xmlSecKeyReqMatchKeyValue (xmlSecKeyReqPtr keyReq,
                                                                 xmlSecKeyDataPtr value);
 void xmlSecKeyReqDebugDump (xmlSecKeyReqPtr keyReq,
                                                                 FILE* output);
 void xmlSecKeyReqDebugXmlDump (xmlSecKeyReqPtr keyReq,
                                                                 FILE* output);
// 177 "/usr/local/include/xmlsec1/xmlsec/keys.h"
struct _xmlSecKey {
    xmlChar* name;
    xmlSecKeyDataPtr value;
    xmlSecPtrListPtr dataList;
    xmlSecKeyUsage usage;
    time_t notValidBefore;
    time_t notValidAfter;
};
 xmlSecKeyPtr xmlSecKeyCreate (void);
 void xmlSecKeyDestroy (xmlSecKeyPtr key);
 void xmlSecKeyEmpty (xmlSecKeyPtr key);
 xmlSecKeyPtr xmlSecKeyDuplicate (xmlSecKeyPtr key);
 int xmlSecKeyCopy (xmlSecKeyPtr keyDst,
                                                         xmlSecKeyPtr keySrc);
 const xmlChar* xmlSecKeyGetName (xmlSecKeyPtr key);
 int xmlSecKeySetName (xmlSecKeyPtr key,
                                                         const xmlChar* name);
 xmlSecKeyDataType xmlSecKeyGetType (xmlSecKeyPtr key);
 xmlSecKeyDataPtr xmlSecKeyGetValue (xmlSecKeyPtr key);
 int xmlSecKeySetValue (xmlSecKeyPtr key,
                                                         xmlSecKeyDataPtr value);
 xmlSecKeyDataPtr xmlSecKeyGetData (xmlSecKeyPtr key,
                                                         xmlSecKeyDataId dataId);
 xmlSecKeyDataPtr xmlSecKeyEnsureData (xmlSecKeyPtr key,
                                                         xmlSecKeyDataId dataId);
 int xmlSecKeyAdoptData (xmlSecKeyPtr key,
                                                         xmlSecKeyDataPtr data);
 void xmlSecKeyDebugDump (xmlSecKeyPtr key,
                                                         FILE *output);
 void xmlSecKeyDebugXmlDump (xmlSecKeyPtr key,
                                                         FILE *output);
 xmlSecKeyPtr xmlSecKeyGenerate (xmlSecKeyDataId dataId,
                                                         unsigned int sizeBits,
                                                         xmlSecKeyDataType type);
 xmlSecKeyPtr xmlSecKeyGenerateByName (const xmlChar* name,
                                                         unsigned int sizeBits,
                                                         xmlSecKeyDataType type);
 int xmlSecKeyMatch (xmlSecKeyPtr key,
                                                         const xmlChar *name,
                                                         xmlSecKeyReqPtr keyReq);
 xmlSecKeyPtr xmlSecKeyReadBuffer (xmlSecKeyDataId dataId,
                                                         xmlSecBuffer* buffer);
 xmlSecKeyPtr xmlSecKeyReadBinaryFile (xmlSecKeyDataId dataId,
                                                         const char* filename);
 xmlSecKeyPtr xmlSecKeyReadMemory (xmlSecKeyDataId dataId,
                                                         const unsigned char* data,
                                                         unsigned int dataSize);
// 269 "/usr/local/include/xmlsec1/xmlsec/keys.h"
 xmlSecPtrListId xmlSecKeyPtrListGetKlass (void);
// 4 "/scripts/include-xmlsec.c" 2
// 1 "/usr/local/include/xmlsec1/xmlsec/xmltree.h" 1
// 17 "/usr/local/include/xmlsec1/xmlsec/xmltree.h"
// 18 "/usr/local/include/xmlsec1/xmlsec/xmltree.h" 2
// 37 "/usr/local/include/xmlsec1/xmlsec/xmltree.h"
 const xmlChar* xmlSecGetDefaultLineFeed(void);
 void xmlSecSetDefaultLineFeed(const xmlChar *linefeed);
 const xmlChar* xmlSecGetNodeNsHref (const xmlNodePtr cur);
 int xmlSecCheckNodeName (const xmlNodePtr cur,
                                                         const xmlChar *name,
                                                         const xmlChar *ns);
 xmlNodePtr xmlSecGetNextElementNode(xmlNodePtr cur);
 xmlNodePtr xmlSecFindSibling (const xmlNodePtr cur,
                                                         const xmlChar *name,
                                                         const xmlChar *ns);
 xmlNodePtr xmlSecFindChild (const xmlNodePtr parent,
                                                         const xmlChar *name,
                                                         const xmlChar *ns);
 xmlNodePtr xmlSecFindParent (const xmlNodePtr cur,
                                                         const xmlChar *name,
                                                         const xmlChar *ns);
 xmlNodePtr xmlSecFindNode (const xmlNodePtr parent,
                                                         const xmlChar *name,
                                                         const xmlChar *ns);
 xmlNodePtr xmlSecAddChild (xmlNodePtr parent,
                                                         const xmlChar *name,
                                                         const xmlChar *ns);
 xmlNodePtr xmlSecEnsureEmptyChild (xmlNodePtr parent,
                                                         const xmlChar *name,
                                                         const xmlChar *ns);
 xmlNodePtr xmlSecAddChildNode (xmlNodePtr parent,
                                                         xmlNodePtr child);
 xmlNodePtr xmlSecAddNextSibling (xmlNodePtr node,
                                                         const xmlChar *name,
                                                         const xmlChar *ns);
 xmlNodePtr xmlSecAddPrevSibling (xmlNodePtr node,
                                                         const xmlChar *name,
                                                         const xmlChar *ns);
 int xmlSecReplaceNode (xmlNodePtr node,
                                                         xmlNodePtr newNode);
 int xmlSecReplaceNodeAndReturn
                                                        (xmlNodePtr node,
                                                         xmlNodePtr newNode,
                                                         xmlNodePtr* replaced);
 int xmlSecReplaceContent (xmlNodePtr node,
                                                         xmlNodePtr newNode);
 int xmlSecReplaceContentAndReturn
                                                        (xmlNodePtr node,
                                                         xmlNodePtr newNode,
                                                         xmlNodePtr* replaced);
 int xmlSecReplaceNodeBuffer (xmlNodePtr node,
                                                         const unsigned char *buffer,
                                                         unsigned int size);
 int xmlSecReplaceNodeBufferAndReturn
                                                        (xmlNodePtr node,
                                                         const unsigned char *buffer,
                                                         unsigned int size,
                                                         xmlNodePtr* replaced);
 int xmlSecNodeEncodeAndSetContent
                                                        (xmlNodePtr node,
                                                         const xmlChar *buffer);
 void xmlSecAddIDs (xmlDocPtr doc,
                                                         xmlNodePtr cur,
                                                         const xmlChar** ids);
 xmlDocPtr xmlSecCreateTree (const xmlChar* rootNodeName,
                                                         const xmlChar* rootNodeNs);
 int xmlSecIsEmptyNode (xmlNodePtr node);
 int xmlSecIsEmptyString (const xmlChar* str);
 xmlChar* xmlSecGetQName (xmlNodePtr node,
                                                         const xmlChar* href,
                                                         const xmlChar* local);
 int xmlSecPrintXmlString (FILE * fd,
                                                         const xmlChar * str);
// 146 "/usr/local/include/xmlsec1/xmlsec/xmltree.h"
typedef struct _xmlSecQName2IntegerInfo xmlSecQName2IntegerInfo, *xmlSecQName2IntegerInfoPtr;
struct _xmlSecQName2IntegerInfo {
    const xmlChar* qnameHref;
    const xmlChar* qnameLocalPart;
    int intValue;
};
typedef const xmlSecQName2IntegerInfo * xmlSecQName2IntegerInfoConstPtr;
 xmlSecQName2IntegerInfoConstPtr xmlSecQName2IntegerGetInfo
                                                                (xmlSecQName2IntegerInfoConstPtr info,
                                                                 int intValue);
 int xmlSecQName2IntegerGetInteger (xmlSecQName2IntegerInfoConstPtr info,
                                                                 const xmlChar* qnameHref,
                                                                 const xmlChar* qnameLocalPart,
                                                                 int* intValue);
 int xmlSecQName2IntegerGetIntegerFromString
                                                                (xmlSecQName2IntegerInfoConstPtr info,
                                                                 xmlNodePtr node,
                                                                 const xmlChar* qname,
                                                                 int* intValue);
 xmlChar* xmlSecQName2IntegerGetStringFromInteger
                                                                (xmlSecQName2IntegerInfoConstPtr info,
                                                                 xmlNodePtr node,
                                                                 int intValue);
 int xmlSecQName2IntegerNodeRead (xmlSecQName2IntegerInfoConstPtr info,
                                                                 xmlNodePtr node,
                                                                 int* intValue);
 int xmlSecQName2IntegerNodeWrite (xmlSecQName2IntegerInfoConstPtr info,
                                                                 xmlNodePtr node,
                                                                 const xmlChar* nodeName,
                                                                 const xmlChar* nodeNs,
                                                                 int intValue);
 int xmlSecQName2IntegerAttributeRead(xmlSecQName2IntegerInfoConstPtr info,
                                                                 xmlNodePtr node,
                                                                 const xmlChar* attrName,
                                                                 int* intValue);
 int xmlSecQName2IntegerAttributeWrite(xmlSecQName2IntegerInfoConstPtr info,
                                                                 xmlNodePtr node,
                                                                 const xmlChar* attrName,
                                                                 int intValue);
 void xmlSecQName2IntegerDebugDump (xmlSecQName2IntegerInfoConstPtr info,
                                                                 int intValue,
                                                                 const xmlChar* name,
                                                                 FILE* output);
 void xmlSecQName2IntegerDebugXmlDump(xmlSecQName2IntegerInfoConstPtr info,
                                                                 int intValue,
                                                                 const xmlChar* name,
                                                                 FILE* output);
// 212 "/usr/local/include/xmlsec1/xmlsec/xmltree.h"
typedef unsigned int xmlSecBitMask;
// 222 "/usr/local/include/xmlsec1/xmlsec/xmltree.h"
typedef struct _xmlSecQName2BitMaskInfo xmlSecQName2BitMaskInfo, *xmlSecQName2BitMaskInfoPtr;
struct _xmlSecQName2BitMaskInfo {
    const xmlChar* qnameHref;
    const xmlChar* qnameLocalPart;
    xmlSecBitMask mask;
};
typedef const xmlSecQName2BitMaskInfo* xmlSecQName2BitMaskInfoConstPtr;
 xmlSecQName2BitMaskInfoConstPtr xmlSecQName2BitMaskGetInfo
                                                                (xmlSecQName2BitMaskInfoConstPtr info,
                                                                 xmlSecBitMask mask);
 int xmlSecQName2BitMaskGetBitMask (xmlSecQName2BitMaskInfoConstPtr info,
                                                                 const xmlChar* qnameLocalPart,
                                                                 const xmlChar* qnameHref,
                                                                 xmlSecBitMask* mask);
 int xmlSecQName2BitMaskNodesRead (xmlSecQName2BitMaskInfoConstPtr info,
                                                                 xmlNodePtr* node,
                                                                 const xmlChar* nodeName,
                                                                 const xmlChar* nodeNs,
                                                                 int stopOnUnknown,
                                                                 xmlSecBitMask* mask);
 int xmlSecQName2BitMaskGetBitMaskFromString
                                                                (xmlSecQName2BitMaskInfoConstPtr info,
                                                                 xmlNodePtr node,
                                                                 const xmlChar* qname,
                                                                 xmlSecBitMask* mask);
 xmlChar* xmlSecQName2BitMaskGetStringFromBitMask
                                                                (xmlSecQName2BitMaskInfoConstPtr info,
                                                                 xmlNodePtr node,
                                                                 xmlSecBitMask mask);
 int xmlSecQName2BitMaskNodesWrite (xmlSecQName2BitMaskInfoConstPtr info,
                                                                 xmlNodePtr node,
                                                                 const xmlChar* nodeName,
                                                                 const xmlChar* nodeNs,
                                                                 xmlSecBitMask mask);
 void xmlSecQName2BitMaskDebugDump (xmlSecQName2BitMaskInfoConstPtr info,
                                                                 xmlSecBitMask mask,
                                                                 const xmlChar* name,
                                                                 FILE* output);
 void xmlSecQName2BitMaskDebugXmlDump(xmlSecQName2BitMaskInfoConstPtr info,
                                                                 xmlSecBitMask mask,
                                                                 const xmlChar* name,
                                                                 FILE* output);
// 6 "/scripts/include-xmlsec.c" 2
// 1 "/usr/local/include/xmlsec1/xmlsec/xmldsig.h" 1
// 26 "/usr/local/include/xmlsec1/xmlsec/xmldsig.h"
// 1 "/usr/local/include/xmlsec1/xmlsec/keysmngr.h" 1
// 18 "/usr/local/include/xmlsec1/xmlsec/keysmngr.h"
// 1 "/usr/local/include/xmlsec1/xmlsec/keyinfo.h" 1
// 23 "/usr/local/include/xmlsec1/xmlsec/keyinfo.h"
// 1 "/usr/local/include/xmlsec1/xmlsec/transforms.h" 1
// 20 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
// 1 "/usr/local/include/xmlsec1/xmlsec/nodeset.h" 1
// 23 "/usr/local/include/xmlsec1/xmlsec/nodeset.h"
typedef struct _xmlSecNodeSet xmlSecNodeSet, *xmlSecNodeSetPtr;
// 41 "/usr/local/include/xmlsec1/xmlsec/nodeset.h"
typedef enum {
    xmlSecNodeSetNormal = 0,
    xmlSecNodeSetInvert,
    xmlSecNodeSetTree,
    xmlSecNodeSetTreeWithoutComments,
    xmlSecNodeSetTreeInvert,
    xmlSecNodeSetTreeWithoutCommentsInvert,
    xmlSecNodeSetList
} xmlSecNodeSetType;
// 59 "/usr/local/include/xmlsec1/xmlsec/nodeset.h"
typedef enum {
    xmlSecNodeSetIntersection = 0,
    xmlSecNodeSetSubtraction,
    xmlSecNodeSetUnion
} xmlSecNodeSetOp;
// 80 "/usr/local/include/xmlsec1/xmlsec/nodeset.h"
struct _xmlSecNodeSet {
    xmlNodeSetPtr nodes;
    xmlDocPtr doc;
    int destroyDoc;
    xmlSecNodeSetType type;
    xmlSecNodeSetOp op;
    xmlSecNodeSetPtr next;
    xmlSecNodeSetPtr prev;
    xmlSecNodeSetPtr children;
};
// 103 "/usr/local/include/xmlsec1/xmlsec/nodeset.h"
typedef int (*xmlSecNodeSetWalkCallback) (xmlSecNodeSetPtr nset,
                                                         xmlNodePtr cur,
                                                         xmlNodePtr parent,
                                                         void* data);
 xmlSecNodeSetPtr xmlSecNodeSetCreate (xmlDocPtr doc,
                                                         xmlNodeSetPtr nodes,
                                                         xmlSecNodeSetType type);
 void xmlSecNodeSetDestroy (xmlSecNodeSetPtr nset);
 void xmlSecNodeSetDocDestroy (xmlSecNodeSetPtr nset);
 int xmlSecNodeSetContains (xmlSecNodeSetPtr nset,
                                                         xmlNodePtr node,
                                                         xmlNodePtr parent);
 xmlSecNodeSetPtr xmlSecNodeSetAdd (xmlSecNodeSetPtr nset,
                                                         xmlSecNodeSetPtr newNSet,
                                                         xmlSecNodeSetOp op);
 xmlSecNodeSetPtr xmlSecNodeSetAddList (xmlSecNodeSetPtr nset,
                                                         xmlSecNodeSetPtr newNSet,
                                                         xmlSecNodeSetOp op);
 xmlSecNodeSetPtr xmlSecNodeSetGetChildren(xmlDocPtr doc,
                                                         const xmlNodePtr parent,
                                                         int withComments,
                                                         int invert);
 int xmlSecNodeSetWalk (xmlSecNodeSetPtr nset,
                                                         xmlSecNodeSetWalkCallback walkFunc,
                                                         void* data);
 int xmlSecNodeSetDumpTextNodes(xmlSecNodeSetPtr nset,
                                                        xmlOutputBufferPtr out);
 void xmlSecNodeSetDebugDump (xmlSecNodeSetPtr nset,
                                                         FILE *output);
// 21 "/usr/local/include/xmlsec1/xmlsec/transforms.h" 2
// 31 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef const struct _xmlSecTransformKlass xmlSecTransformKlass,
                                                        *xmlSecTransformId;
// 47 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecPtrListPtr xmlSecTransformIdsGet (void);
 int xmlSecTransformIdsInit (void);
 void xmlSecTransformIdsShutdown (void);
 int xmlSecTransformIdsRegisterDefault(void);
 int xmlSecTransformIdsRegister (xmlSecTransformId id);
// 63 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef enum {
    xmlSecTransformStatusNone = 0,
    xmlSecTransformStatusWorking,
    xmlSecTransformStatusFinished,
    xmlSecTransformStatusOk,
    xmlSecTransformStatusFail
} xmlSecTransformStatus;
// 79 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef enum {
    xmlSecTransformModeNone = 0,
    xmlSecTransformModePush,
    xmlSecTransformModePop
} xmlSecTransformMode;
// 97 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef enum {
    xmlSecTransformOperationNone = 0,
    xmlSecTransformOperationEncode,
    xmlSecTransformOperationDecode,
    xmlSecTransformOperationSign,
    xmlSecTransformOperationVerify,
    xmlSecTransformOperationEncrypt,
    xmlSecTransformOperationDecrypt
} xmlSecTransformOperation;
// 117 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef unsigned int xmlSecTransformUriType;
// 161 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 int xmlSecTransformUriTypeCheck (xmlSecTransformUriType type,
                                                                         const xmlChar* uri);
// 173 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef unsigned char xmlSecTransformDataType;
// 206 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef unsigned int xmlSecTransformUsage;
// 274 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef int (*xmlSecTransformCtxPreExecuteCallback) (xmlSecTransformCtxPtr transformCtx);
// 313 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
struct _xmlSecTransformCtx {
    void* userData;
    unsigned int flags;
    unsigned int flags2;
    xmlSecTransformUriType enabledUris;
    xmlSecPtrList enabledTransforms;
    xmlSecTransformCtxPreExecuteCallback preExecCallback;
    xmlSecBufferPtr result;
    xmlSecTransformStatus status;
    xmlChar* uri;
    xmlChar* xptrExpr;
    xmlSecTransformPtr first;
    xmlSecTransformPtr last;
    void* reserved0;
    void* reserved1;
};
 xmlSecTransformCtxPtr xmlSecTransformCtxCreate (void);
 void xmlSecTransformCtxDestroy (xmlSecTransformCtxPtr ctx);
 int xmlSecTransformCtxInitialize (xmlSecTransformCtxPtr ctx);
 void xmlSecTransformCtxFinalize (xmlSecTransformCtxPtr ctx);
 void xmlSecTransformCtxReset (xmlSecTransformCtxPtr ctx);
 int xmlSecTransformCtxCopyUserPref (xmlSecTransformCtxPtr dst,
                                                                         xmlSecTransformCtxPtr src);
 int xmlSecTransformCtxSetUri (xmlSecTransformCtxPtr ctx,
                                                                         const xmlChar* uri,
                                                                         xmlNodePtr hereNode);
 int xmlSecTransformCtxAppend (xmlSecTransformCtxPtr ctx,
                                                                         xmlSecTransformPtr transform);
 int xmlSecTransformCtxPrepend (xmlSecTransformCtxPtr ctx,
                                                                         xmlSecTransformPtr transform);
 xmlSecTransformPtr xmlSecTransformCtxCreateAndAppend(xmlSecTransformCtxPtr ctx,
                                                                         xmlSecTransformId id);
 xmlSecTransformPtr xmlSecTransformCtxCreateAndPrepend(xmlSecTransformCtxPtr ctx,
                                                                         xmlSecTransformId id);
 xmlSecTransformPtr xmlSecTransformCtxNodeRead (xmlSecTransformCtxPtr ctx,
                                                                         xmlNodePtr node,
                                                                         xmlSecTransformUsage usage);
 int xmlSecTransformCtxNodesListRead (xmlSecTransformCtxPtr ctx,
                                                                         xmlNodePtr node,
                                                                         xmlSecTransformUsage usage);
 int xmlSecTransformCtxPrepare (xmlSecTransformCtxPtr ctx,
                                                                         xmlSecTransformDataType inputDataType);
 int xmlSecTransformCtxBinaryExecute (xmlSecTransformCtxPtr ctx,
                                                                         const unsigned char* data,
                                                                         unsigned int dataSize);
 int xmlSecTransformCtxUriExecute (xmlSecTransformCtxPtr ctx,
                                                                         const xmlChar* uri);
 int xmlSecTransformCtxXmlExecute (xmlSecTransformCtxPtr ctx,
                                                                         xmlSecNodeSetPtr nodes);
 int xmlSecTransformCtxExecute (xmlSecTransformCtxPtr ctx,
                                                                         xmlDocPtr doc);
 void xmlSecTransformCtxDebugDump (xmlSecTransformCtxPtr ctx,
                                                                        FILE* output);
 void xmlSecTransformCtxDebugXmlDump (xmlSecTransformCtxPtr ctx,
                                                                         FILE* output);
// 397 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
struct _xmlSecTransform {
    xmlSecTransformId id;
    xmlSecTransformOperation operation;
    xmlSecTransformStatus status;
    xmlNodePtr hereNode;
    xmlSecTransformPtr next;
    xmlSecTransformPtr prev;
    xmlSecBuffer inBuf;
    xmlSecBuffer outBuf;
    xmlSecNodeSetPtr inNodes;
    xmlSecNodeSetPtr outNodes;
    void* reserved0;
    void* reserved1;
};
 xmlSecTransformPtr xmlSecTransformCreate (xmlSecTransformId id);
 void xmlSecTransformDestroy (xmlSecTransformPtr transform);
 xmlSecTransformPtr xmlSecTransformNodeRead (xmlNodePtr node,
                                                                 xmlSecTransformUsage usage,
                                                                 xmlSecTransformCtxPtr transformCtx);
 int xmlSecTransformPump (xmlSecTransformPtr left,
                                                                 xmlSecTransformPtr right,
                                                                 xmlSecTransformCtxPtr transformCtx);
 int xmlSecTransformSetKey (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
 int xmlSecTransformSetKeyReq(xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
 int xmlSecTransformVerify (xmlSecTransformPtr transform,
                                                                 const unsigned char* data,
                                                                 unsigned int dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
 int xmlSecTransformVerifyNodeContent(xmlSecTransformPtr transform,
                                                                 xmlNodePtr node,
                                                                 xmlSecTransformCtxPtr transformCtx);
 xmlSecTransformDataType xmlSecTransformGetDataType(xmlSecTransformPtr transform,
                                                                 xmlSecTransformMode mode,
                                                                 xmlSecTransformCtxPtr transformCtx);
 int xmlSecTransformPushBin (xmlSecTransformPtr transform,
                                                                 const unsigned char* data,
                                                                 unsigned int dataSize,
                                                                 int final,
                                                                 xmlSecTransformCtxPtr transformCtx);
 int xmlSecTransformPopBin (xmlSecTransformPtr transform,
                                                                 unsigned char* data,
                                                                 unsigned int maxDataSize,
                                                                 unsigned int* dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
 int xmlSecTransformPushXml (xmlSecTransformPtr transform,
                                                                 xmlSecNodeSetPtr nodes,
                                                                 xmlSecTransformCtxPtr transformCtx);
 int xmlSecTransformPopXml (xmlSecTransformPtr transform,
                                                                 xmlSecNodeSetPtr* nodes,
                                                                 xmlSecTransformCtxPtr transformCtx);
 int xmlSecTransformExecute (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
 void xmlSecTransformDebugDump(xmlSecTransformPtr transform,
                                                                 FILE* output);
 void xmlSecTransformDebugXmlDump(xmlSecTransformPtr transform,
                                                                 FILE* output);
// 518 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 int xmlSecTransformConnect (xmlSecTransformPtr left,
                                                                 xmlSecTransformPtr right,
                                                                 xmlSecTransformCtxPtr transformCtx);
 void xmlSecTransformRemove (xmlSecTransformPtr transform);
 xmlSecTransformDataType xmlSecTransformDefaultGetDataType(xmlSecTransformPtr transform,
                                                                 xmlSecTransformMode mode,
                                                                 xmlSecTransformCtxPtr transformCtx);
 int xmlSecTransformDefaultPushBin(xmlSecTransformPtr transform,
                                                                 const unsigned char* data,
                                                                 unsigned int dataSize,
                                                                 int final,
                                                                 xmlSecTransformCtxPtr transformCtx);
 int xmlSecTransformDefaultPopBin(xmlSecTransformPtr transform,
                                                                 unsigned char* data,
                                                                 unsigned int maxDataSize,
                                                                 unsigned int* dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
 int xmlSecTransformDefaultPushXml(xmlSecTransformPtr transform,
                                                                 xmlSecNodeSetPtr nodes,
                                                                 xmlSecTransformCtxPtr transformCtx);
 int xmlSecTransformDefaultPopXml(xmlSecTransformPtr transform,
                                                                 xmlSecNodeSetPtr* nodes,
                                                                 xmlSecTransformCtxPtr transformCtx);
 xmlOutputBufferPtr xmlSecTransformCreateOutputBuffer(xmlSecTransformPtr transform,
                                                                 xmlSecTransformCtxPtr transformCtx);
 xmlParserInputBufferPtr xmlSecTransformCreateInputBuffer(xmlSecTransformPtr transform,
                                                                 xmlSecTransformCtxPtr transformCtx);
// 571 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef int (*xmlSecTransformInitializeMethod) (xmlSecTransformPtr transform);
typedef void (*xmlSecTransformFinalizeMethod) (xmlSecTransformPtr transform);
// 592 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef xmlSecTransformDataType (*xmlSecTransformGetDataTypeMethod)(xmlSecTransformPtr transform,
                                                                 xmlSecTransformMode mode,
                                                                 xmlSecTransformCtxPtr transformCtx);
// 607 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef int (*xmlSecTransformNodeReadMethod) (xmlSecTransformPtr transform,
                                                                 xmlNodePtr node,
                                                                 xmlSecTransformCtxPtr transformCtx);
// 621 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef int (*xmlSecTransformNodeWriteMethod) (xmlSecTransformPtr transform,
                                                                 xmlNodePtr node,
                                                                 xmlSecTransformCtxPtr transformCtx);
// 634 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef int (*xmlSecTransformSetKeyRequirementsMethod)(xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
// 646 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef int (*xmlSecTransformSetKeyMethod) (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
// 663 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef int (*xmlSecTransformVerifyMethod) (xmlSecTransformPtr transform,
                                                                 const unsigned char* data,
                                                                 unsigned int dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
// 681 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef int (*xmlSecTransformPushBinMethod) (xmlSecTransformPtr transform,
                                                                 const unsigned char* data,
                                                                 unsigned int dataSize,
                                                                 int final,
                                                                 xmlSecTransformCtxPtr transformCtx);
// 700 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef int (*xmlSecTransformPopBinMethod) (xmlSecTransformPtr transform,
                                                                 unsigned char* data,
                                                                 unsigned int maxDataSize,
                                                                 unsigned int* dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
// 716 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef int (*xmlSecTransformPushXmlMethod) (xmlSecTransformPtr transform,
                                                                 xmlSecNodeSetPtr nodes,
                                                                 xmlSecTransformCtxPtr transformCtx);
// 730 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef int (*xmlSecTransformPopXmlMethod) (xmlSecTransformPtr transform,
                                                                 xmlSecNodeSetPtr* nodes,
                                                                 xmlSecTransformCtxPtr transformCtx);
// 743 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
typedef int (*xmlSecTransformExecuteMethod) (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
// 773 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
struct _xmlSecTransformKlass {
    unsigned int klassSize;
    unsigned int objSize;
    const xmlChar* name;
    const xmlChar* href;
    xmlSecTransformUsage usage;
    xmlSecTransformInitializeMethod initialize;
    xmlSecTransformFinalizeMethod finalize;
    xmlSecTransformNodeReadMethod readNode;
    xmlSecTransformNodeWriteMethod writeNode;
    xmlSecTransformSetKeyRequirementsMethod setKeyReq;
    xmlSecTransformSetKeyMethod setKey;
    xmlSecTransformVerifyMethod verify;
    xmlSecTransformGetDataTypeMethod getDataType;
    xmlSecTransformPushBinMethod pushBin;
    xmlSecTransformPopBinMethod popBin;
    xmlSecTransformPushXmlMethod pushXml;
    xmlSecTransformPopXmlMethod popXml;
    xmlSecTransformExecuteMethod execute;
    void* reserved0;
    void* reserved1;
};
// 826 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecPtrListId xmlSecTransformIdListGetKlass (void);
 int xmlSecTransformIdListFind (xmlSecPtrListPtr list,
                                                                 xmlSecTransformId transformId);
 xmlSecTransformId xmlSecTransformIdListFindByHref (xmlSecPtrListPtr list,
                                                                 const xmlChar* href,
                                                                 xmlSecTransformUsage usage);
 xmlSecTransformId xmlSecTransformIdListFindByName (xmlSecPtrListPtr list,
                                                                 const xmlChar* name,
                                                                 xmlSecTransformUsage usage);
 void xmlSecTransformIdListDebugDump (xmlSecPtrListPtr list,
                                                                 FILE* output);
 void xmlSecTransformIdListDebugXmlDump(xmlSecPtrListPtr list,
                                                                 FILE* output);
// 860 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecTransformId xmlSecTransformBase64GetKlass (void);
 void xmlSecTransformBase64SetLineSize (xmlSecTransformPtr transform,
                                                                         unsigned int lineSize);
 xmlSecTransformId xmlSecTransformInclC14NGetKlass (void);
// 879 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecTransformId xmlSecTransformInclC14NWithCommentsGetKlass(void);
// 888 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecTransformId xmlSecTransformInclC14N11GetKlass (void);
// 897 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecTransformId xmlSecTransformInclC14N11WithCommentsGetKlass(void);
// 906 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecTransformId xmlSecTransformExclC14NGetKlass (void);
// 915 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecTransformId xmlSecTransformExclC14NWithCommentsGetKlass(void);
// 924 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecTransformId xmlSecTransformEnvelopedGetKlass (void);
// 933 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecTransformId xmlSecTransformXPathGetKlass (void);
// 942 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecTransformId xmlSecTransformXPath2GetKlass (void);
// 951 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecTransformId xmlSecTransformXPointerGetKlass (void);
 int xmlSecTransformXPointerSetExpr (xmlSecTransformPtr transform,
                                                                         const xmlChar* expr,
                                                                         xmlSecNodeSetType nodeSetType,
                                                                         xmlNodePtr hereNode);
 xmlSecTransformId xmlSecTransformRelationshipGetKlass (void);
// 985 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecTransformId xmlSecTransformRemoveXmlTagsC14NGetKlass(void);
// 997 "/usr/local/include/xmlsec1/xmlsec/transforms.h"
 xmlSecTransformId xmlSecTransformVisa3DHackGetKlass (void);
 int xmlSecTransformVisa3DHackSetID (xmlSecTransformPtr transform,
                                                                         const xmlChar* id);
// 24 "/usr/local/include/xmlsec1/xmlsec/keyinfo.h" 2
// 34 "/usr/local/include/xmlsec1/xmlsec/keyinfo.h"
 int xmlSecKeyInfoNodeRead (xmlNodePtr keyInfoNode,
                                                                 xmlSecKeyPtr key,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
 int xmlSecKeyInfoNodeWrite (xmlNodePtr keyInfoNode,
                                                                 xmlSecKeyPtr key,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
// 48 "/usr/local/include/xmlsec1/xmlsec/keyinfo.h"
typedef enum {
    xmlSecKeyInfoModeRead = 0,
    xmlSecKeyInfoModeWrite
} xmlSecKeyInfoMode;
// 195 "/usr/local/include/xmlsec1/xmlsec/keyinfo.h"
struct _xmlSecKeyInfoCtx {
    void* userData;
    unsigned int flags;
    unsigned int flags2;
    xmlSecKeysMngrPtr keysMngr;
    xmlSecKeyInfoMode mode;
    xmlSecPtrList enabledKeyData;
    int base64LineSize;
    xmlSecTransformCtx retrievalMethodCtx;
    int maxRetrievalMethodLevel;
    xmlSecEncCtxPtr encCtx;
    int maxEncryptedKeyLevel;
    time_t certsVerificationTime;
    int certsVerificationDepth;
    void* pgpReserved;
    int curRetrievalMethodLevel;
    int curEncryptedKeyLevel;
    xmlSecKeyReq keyReq;
    void* reserved0;
    void* reserved1;
};
 xmlSecKeyInfoCtxPtr xmlSecKeyInfoCtxCreate (xmlSecKeysMngrPtr keysMngr);
 void xmlSecKeyInfoCtxDestroy (xmlSecKeyInfoCtxPtr keyInfoCtx);
 int xmlSecKeyInfoCtxInitialize (xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         xmlSecKeysMngrPtr keysMngr);
 void xmlSecKeyInfoCtxFinalize (xmlSecKeyInfoCtxPtr keyInfoCtx);
 void xmlSecKeyInfoCtxReset (xmlSecKeyInfoCtxPtr keyInfoCtx);
 int xmlSecKeyInfoCtxCopyUserPref (xmlSecKeyInfoCtxPtr dst,
                                                                         xmlSecKeyInfoCtxPtr src);
 int xmlSecKeyInfoCtxCreateEncCtx (xmlSecKeyInfoCtxPtr keyInfoCtx);
 void xmlSecKeyInfoCtxDebugDump (xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         FILE* output);
 void xmlSecKeyInfoCtxDebugXmlDump (xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         FILE* output);
 xmlSecKeyDataId xmlSecKeyDataNameGetKlass (void);
 xmlSecKeyDataId xmlSecKeyDataValueGetKlass (void);
 xmlSecKeyDataId xmlSecKeyDataRetrievalMethodGetKlass(void);
// 277 "/usr/local/include/xmlsec1/xmlsec/keyinfo.h"
 xmlSecKeyDataId xmlSecKeyDataEncryptedKeyGetKlass(void);
// 19 "/usr/local/include/xmlsec1/xmlsec/keysmngr.h" 2
typedef const struct _xmlSecKeyKlass xmlSecKeyKlass,
                                                        *xmlSecKeyId;
typedef const struct _xmlSecKeyStoreKlass xmlSecKeyStoreKlass,
                                                        *xmlSecKeyStoreId;
 xmlSecKeysMngrPtr xmlSecKeysMngrCreate (void);
 void xmlSecKeysMngrDestroy (xmlSecKeysMngrPtr mngr);
 xmlSecKeyPtr xmlSecKeysMngrFindKey (xmlSecKeysMngrPtr mngr,
                                                                         const xmlChar* name,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
 int xmlSecKeysMngrAdoptKeysStore (xmlSecKeysMngrPtr mngr,
                                                                         xmlSecKeyStorePtr store);
 xmlSecKeyStorePtr xmlSecKeysMngrGetKeysStore (xmlSecKeysMngrPtr mngr);
 int xmlSecKeysMngrAdoptDataStore (xmlSecKeysMngrPtr mngr,
                                                                         xmlSecKeyDataStorePtr store);
 xmlSecKeyDataStorePtr xmlSecKeysMngrGetDataStore (xmlSecKeysMngrPtr mngr,
                                                                         xmlSecKeyDataStoreId id);
// 61 "/usr/local/include/xmlsec1/xmlsec/keysmngr.h"
typedef xmlSecKeyPtr (*xmlSecGetKeyCallback) (xmlNodePtr keyInfoNode,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
// 72 "/usr/local/include/xmlsec1/xmlsec/keysmngr.h"
struct _xmlSecKeysMngr {
    xmlSecKeyStorePtr keysStore;
    xmlSecPtrList storesList;
    xmlSecGetKeyCallback getKey;
};
 xmlSecKeyPtr xmlSecKeysMngrGetKey (xmlNodePtr keyInfoNode,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
// 96 "/usr/local/include/xmlsec1/xmlsec/keysmngr.h"
struct _xmlSecKeyStore {
    xmlSecKeyStoreId id;
    void* reserved0;
    void* reserved1;
};
 xmlSecKeyStorePtr xmlSecKeyStoreCreate (xmlSecKeyStoreId id);
 void xmlSecKeyStoreDestroy (xmlSecKeyStorePtr store);
 xmlSecKeyPtr xmlSecKeyStoreFindKey (xmlSecKeyStorePtr store,
                                                                 const xmlChar* name,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
// 171 "/usr/local/include/xmlsec1/xmlsec/keysmngr.h"
typedef int (*xmlSecKeyStoreInitializeMethod) (xmlSecKeyStorePtr store);
typedef void (*xmlSecKeyStoreFinalizeMethod) (xmlSecKeyStorePtr store);
// 192 "/usr/local/include/xmlsec1/xmlsec/keysmngr.h"
typedef xmlSecKeyPtr (*xmlSecKeyStoreFindKeyMethod) (xmlSecKeyStorePtr store,
                                                                 const xmlChar* name,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
// 209 "/usr/local/include/xmlsec1/xmlsec/keysmngr.h"
struct _xmlSecKeyStoreKlass {
    unsigned int klassSize;
    unsigned int objSize;
    const xmlChar* name;
    xmlSecKeyStoreInitializeMethod initialize;
    xmlSecKeyStoreFinalizeMethod finalize;
    xmlSecKeyStoreFindKeyMethod findKey;
    void* reserved0;
    void* reserved1;
};
// 247 "/usr/local/include/xmlsec1/xmlsec/keysmngr.h"
 xmlSecKeyStoreId xmlSecSimpleKeysStoreGetKlass (void);
 int xmlSecSimpleKeysStoreAdoptKey (xmlSecKeyStorePtr store,
                                                                         xmlSecKeyPtr key);
 int xmlSecSimpleKeysStoreLoad (xmlSecKeyStorePtr store,
                                                                         const char *uri,
                                                                         xmlSecKeysMngrPtr keysMngr);
 int xmlSecSimpleKeysStoreSave (xmlSecKeyStorePtr store,
                                                                         const char *filename,
                                                                         xmlSecKeyDataType type);
 xmlSecPtrListPtr xmlSecSimpleKeysStoreGetKeys (xmlSecKeyStorePtr store);
// 27 "/usr/local/include/xmlsec1/xmlsec/xmldsig.h" 2
typedef struct _xmlSecDSigReferenceCtx xmlSecDSigReferenceCtx,
                                                *xmlSecDSigReferenceCtxPtr;
// 45 "/usr/local/include/xmlsec1/xmlsec/xmldsig.h"
typedef enum {
    xmlSecDSigStatusUnknown = 0,
    xmlSecDSigStatusSucceeded,
    xmlSecDSigStatusInvalid
} xmlSecDSigStatus;
// 131 "/usr/local/include/xmlsec1/xmlsec/xmldsig.h"
struct _xmlSecDSigCtx {
    void* userData;
    unsigned int flags;
    unsigned int flags2;
    xmlSecKeyInfoCtx keyInfoReadCtx;
    xmlSecKeyInfoCtx keyInfoWriteCtx;
    xmlSecTransformCtx transformCtx;
    xmlSecTransformUriType enabledReferenceUris;
    xmlSecPtrListPtr enabledReferenceTransforms;
    xmlSecTransformCtxPreExecuteCallback referencePreExecuteCallback;
    xmlSecTransformId defSignMethodId;
    xmlSecTransformId defC14NMethodId;
    xmlSecTransformId defDigestMethodId;
    xmlSecKeyPtr signKey;
    xmlSecTransformOperation operation;
    xmlSecBufferPtr result;
    xmlSecDSigStatus status;
    xmlSecTransformPtr signMethod;
    xmlSecTransformPtr c14nMethod;
    xmlSecTransformPtr preSignMemBufMethod;
    xmlNodePtr signValueNode;
    xmlChar* id;
    xmlSecPtrList signedInfoReferences;
    xmlSecPtrList manifestReferences;
    void* reserved0;
    void* reserved1;
};
 xmlSecDSigCtxPtr xmlSecDSigCtxCreate (xmlSecKeysMngrPtr keysMngr);
 void xmlSecDSigCtxDestroy (xmlSecDSigCtxPtr dsigCtx);
 int xmlSecDSigCtxInitialize (xmlSecDSigCtxPtr dsigCtx,
                                                                 xmlSecKeysMngrPtr keysMngr);
 void xmlSecDSigCtxFinalize (xmlSecDSigCtxPtr dsigCtx);
 int xmlSecDSigCtxSign (xmlSecDSigCtxPtr dsigCtx,
                                                                 xmlNodePtr tmpl);
 int xmlSecDSigCtxVerify (xmlSecDSigCtxPtr dsigCtx,
                                                                 xmlNodePtr node);
 int xmlSecDSigCtxEnableReferenceTransform(xmlSecDSigCtxPtr dsigCtx,
                                                                xmlSecTransformId transformId);
 int xmlSecDSigCtxEnableSignatureTransform(xmlSecDSigCtxPtr dsigCtx,
                                                                xmlSecTransformId transformId);
 xmlSecBufferPtr xmlSecDSigCtxGetPreSignBuffer (xmlSecDSigCtxPtr dsigCtx);
 void xmlSecDSigCtxDebugDump (xmlSecDSigCtxPtr dsigCtx,
                                                                 FILE* output);
 void xmlSecDSigCtxDebugXmlDump (xmlSecDSigCtxPtr dsigCtx,
                                                                 FILE* output);
// 198 "/usr/local/include/xmlsec1/xmlsec/xmldsig.h"
typedef enum {
    xmlSecDSigReferenceOriginSignedInfo,
    xmlSecDSigReferenceOriginManifest
} xmlSecDSigReferenceOrigin;
// 225 "/usr/local/include/xmlsec1/xmlsec/xmldsig.h"
struct _xmlSecDSigReferenceCtx {
    void* userData;
    xmlSecDSigCtxPtr dsigCtx;
    xmlSecDSigReferenceOrigin origin;
    xmlSecTransformCtx transformCtx;
    xmlSecTransformPtr digestMethod;
    xmlSecBufferPtr result;
    xmlSecDSigStatus status;
    xmlSecTransformPtr preDigestMemBufMethod;
    xmlChar* id;
    xmlChar* uri;
    xmlChar* type;
    void* reserved0;
    void* reserved1;
};
 xmlSecDSigReferenceCtxPtr xmlSecDSigReferenceCtxCreate(xmlSecDSigCtxPtr dsigCtx,
                                                                xmlSecDSigReferenceOrigin origin);
 void xmlSecDSigReferenceCtxDestroy (xmlSecDSigReferenceCtxPtr dsigRefCtx);
 int xmlSecDSigReferenceCtxInitialize(xmlSecDSigReferenceCtxPtr dsigRefCtx,
                                                                xmlSecDSigCtxPtr dsigCtx,
                                                                xmlSecDSigReferenceOrigin origin);
 void xmlSecDSigReferenceCtxFinalize (xmlSecDSigReferenceCtxPtr dsigRefCtx);
 int xmlSecDSigReferenceCtxProcessNode(xmlSecDSigReferenceCtxPtr dsigRefCtx,
                                                                  xmlNodePtr node);
 xmlSecBufferPtr xmlSecDSigReferenceCtxGetPreDigestBuffer
                                                                (xmlSecDSigReferenceCtxPtr dsigRefCtx);
 void xmlSecDSigReferenceCtxDebugDump (xmlSecDSigReferenceCtxPtr dsigRefCtx,
                                                                 FILE* output);
 void xmlSecDSigReferenceCtxDebugXmlDump(xmlSecDSigReferenceCtxPtr dsigRefCtx,
                                                                 FILE* output);
// 272 "/usr/local/include/xmlsec1/xmlsec/xmldsig.h"
 xmlSecPtrListId xmlSecDSigReferenceCtxListGetKlass(void);
// 7 "/scripts/include-xmlsec.c" 2
// 1 "/usr/local/include/xmlsec1/xmlsec/xmlenc.h" 1
// 40 "/usr/local/include/xmlsec1/xmlsec/xmlenc.h"
typedef enum {
    xmlEncCtxModeEncryptedData = 0,
    xmlEncCtxModeEncryptedKey
} xmlEncCtxMode;
// 93 "/usr/local/include/xmlsec1/xmlsec/xmlenc.h"
struct _xmlSecEncCtx {
    void* userData;
    unsigned int flags;
    unsigned int flags2;
    xmlEncCtxMode mode;
    xmlSecKeyInfoCtx keyInfoReadCtx;
    xmlSecKeyInfoCtx keyInfoWriteCtx;
    xmlSecTransformCtx transformCtx;
    xmlSecTransformId defEncMethodId;
    xmlSecKeyPtr encKey;
    xmlSecTransformOperation operation;
    xmlSecBufferPtr result;
    int resultBase64Encoded;
    int resultReplaced;
    xmlSecTransformPtr encMethod;
    xmlChar* id;
    xmlChar* type;
    xmlChar* mimeType;
    xmlChar* encoding;
    xmlChar* recipient;
    xmlChar* carriedKeyName;
    xmlNodePtr encDataNode;
    xmlNodePtr encMethodNode;
    xmlNodePtr keyInfoNode;
    xmlNodePtr cipherValueNode;
    xmlNodePtr replacedNodeList;
    void* reserved1;
};
 xmlSecEncCtxPtr xmlSecEncCtxCreate (xmlSecKeysMngrPtr keysMngr);
 void xmlSecEncCtxDestroy (xmlSecEncCtxPtr encCtx);
 int xmlSecEncCtxInitialize (xmlSecEncCtxPtr encCtx,
                                                                 xmlSecKeysMngrPtr keysMngr);
 void xmlSecEncCtxFinalize (xmlSecEncCtxPtr encCtx);
 int xmlSecEncCtxCopyUserPref (xmlSecEncCtxPtr dst,
                                                                 xmlSecEncCtxPtr src);
 void xmlSecEncCtxReset (xmlSecEncCtxPtr encCtx);
 int xmlSecEncCtxBinaryEncrypt (xmlSecEncCtxPtr encCtx,
                                                                 xmlNodePtr tmpl,
                                                                 const unsigned char* data,
                                                                 unsigned int dataSize);
 int xmlSecEncCtxXmlEncrypt (xmlSecEncCtxPtr encCtx,
                                                                 xmlNodePtr tmpl,
                                                                 xmlNodePtr node);
 int xmlSecEncCtxUriEncrypt (xmlSecEncCtxPtr encCtx,
                                                                 xmlNodePtr tmpl,
                                                                 const xmlChar *uri);
 int xmlSecEncCtxDecrypt (xmlSecEncCtxPtr encCtx,
                                                                 xmlNodePtr node);
 xmlSecBufferPtr xmlSecEncCtxDecryptToBuffer (xmlSecEncCtxPtr encCtx,
                                                                 xmlNodePtr node );
 void xmlSecEncCtxDebugDump (xmlSecEncCtxPtr encCtx,
                                                                 FILE* output);
 void xmlSecEncCtxDebugXmlDump (xmlSecEncCtxPtr encCtx,
                                                                 FILE* output);
// 8 "/scripts/include-xmlsec.c" 2
// 1 "/usr/local/include/xmlsec1/xmlsec/templates.h" 1
// 28 "/usr/local/include/xmlsec1/xmlsec/templates.h"
 xmlNodePtr xmlSecTmplSignatureCreate (xmlDocPtr doc,
                                                                 xmlSecTransformId c14nMethodId,
                                                                 xmlSecTransformId signMethodId,
                                                                 const xmlChar *id);
 xmlNodePtr xmlSecTmplSignatureCreateNsPref (xmlDocPtr doc,
                                                                xmlSecTransformId c14nMethodId,
                                                                xmlSecTransformId signMethodId,
                                                                const xmlChar *id,
                                                                const xmlChar *nsPrefix);
 xmlNodePtr xmlSecTmplSignatureEnsureKeyInfo (xmlNodePtr signNode,
                                                                 const xmlChar *id);
 xmlNodePtr xmlSecTmplSignatureAddReference (xmlNodePtr signNode,
                                                                 xmlSecTransformId digestMethodId,
                                                                 const xmlChar *id,
                                                                 const xmlChar *uri,
                                                                 const xmlChar *type);
 xmlNodePtr xmlSecTmplSignatureAddObject (xmlNodePtr signNode,
                                                                 const xmlChar *id,
                                                                 const xmlChar *mimeType,
                                                                 const xmlChar *encoding);
 xmlNodePtr xmlSecTmplSignatureGetSignMethodNode (xmlNodePtr signNode);
 xmlNodePtr xmlSecTmplSignatureGetC14NMethodNode (xmlNodePtr signNode);
 xmlNodePtr xmlSecTmplReferenceAddTransform (xmlNodePtr referenceNode,
                                                                 xmlSecTransformId transformId);
 xmlNodePtr xmlSecTmplObjectAddSignProperties (xmlNodePtr objectNode,
                                                                 const xmlChar *id,
                                                                 const xmlChar *target);
 xmlNodePtr xmlSecTmplObjectAddManifest (xmlNodePtr objectNode,
                                                                 const xmlChar *id);
 xmlNodePtr xmlSecTmplManifestAddReference (xmlNodePtr manifestNode,
                                                                 xmlSecTransformId digestMethodId,
                                                                 const xmlChar *id,
                                                                 const xmlChar *uri,
                                                                 const xmlChar *type);
 xmlNodePtr xmlSecTmplEncDataCreate (xmlDocPtr doc,
                                                                 xmlSecTransformId encMethodId,
                                                                 const xmlChar *id,
                                                                 const xmlChar *type,
                                                                 const xmlChar *mimeType,
                                                                 const xmlChar *encoding);
 xmlNodePtr xmlSecTmplEncDataEnsureKeyInfo (xmlNodePtr encNode,
                                                                 const xmlChar *id);
 xmlNodePtr xmlSecTmplEncDataEnsureEncProperties (xmlNodePtr encNode,
                                                                 const xmlChar *id);
 xmlNodePtr xmlSecTmplEncDataAddEncProperty (xmlNodePtr encNode,
                                                                 const xmlChar *id,
                                                                 const xmlChar *target);
 xmlNodePtr xmlSecTmplEncDataEnsureCipherValue (xmlNodePtr encNode);
 xmlNodePtr xmlSecTmplEncDataEnsureCipherReference (xmlNodePtr encNode,
                                                                 const xmlChar *uri);
 xmlNodePtr xmlSecTmplEncDataGetEncMethodNode (xmlNodePtr encNode);
 xmlNodePtr xmlSecTmplCipherReferenceAddTransform (xmlNodePtr cipherReferenceNode,
                                                                 xmlSecTransformId transformId);
 xmlNodePtr xmlSecTmplReferenceListAddDataReference(xmlNodePtr encNode,
                                                                 const xmlChar *uri);
 xmlNodePtr xmlSecTmplReferenceListAddKeyReference (xmlNodePtr encNode,
                                                                 const xmlChar *uri);
 xmlNodePtr xmlSecTmplKeyInfoAddKeyName (xmlNodePtr keyInfoNode,
                                                                 const xmlChar* name);
 xmlNodePtr xmlSecTmplKeyInfoAddKeyValue (xmlNodePtr keyInfoNode);
 xmlNodePtr xmlSecTmplKeyInfoAddX509Data (xmlNodePtr keyInfoNode);
 xmlNodePtr xmlSecTmplKeyInfoAddRetrievalMethod (xmlNodePtr keyInfoNode,
                                                                 const xmlChar *uri,
                                                                 const xmlChar *type);
 xmlNodePtr xmlSecTmplRetrievalMethodAddTransform (xmlNodePtr retrMethodNode,
                                                                 xmlSecTransformId transformId);
 xmlNodePtr xmlSecTmplKeyInfoAddEncryptedKey (xmlNodePtr keyInfoNode,
                                                                 xmlSecTransformId encMethodId,
                                                                 const xmlChar *id,
                                                                 const xmlChar *type,
                                                                 const xmlChar *recipient);
 xmlNodePtr xmlSecTmplX509DataAddIssuerSerial (xmlNodePtr x509DataNode);
 xmlNodePtr xmlSecTmplX509IssuerSerialAddIssuerName(xmlNodePtr x509IssuerSerialNode, const xmlChar* issuerName);
 xmlNodePtr xmlSecTmplX509IssuerSerialAddSerialNumber(xmlNodePtr x509IssuerSerialNode, const xmlChar* serial);
 xmlNodePtr xmlSecTmplX509DataAddSubjectName (xmlNodePtr x509DataNode);
 xmlNodePtr xmlSecTmplX509DataAddSKI (xmlNodePtr x509DataNode);
 xmlNodePtr xmlSecTmplX509DataAddCertificate (xmlNodePtr x509DataNode);
 xmlNodePtr xmlSecTmplX509DataAddCRL (xmlNodePtr x509DataNode);
 int xmlSecTmplTransformAddHmacOutputLength (xmlNodePtr transformNode,
                                                                 unsigned int bitsLen);
 int xmlSecTmplTransformAddRsaOaepParam (xmlNodePtr transformNode,
                                                                 const unsigned char *buf,
                                                                 unsigned int size);
 int xmlSecTmplTransformAddXsltStylesheet (xmlNodePtr transformNode,
                                                                 const xmlChar *xslt);
 int xmlSecTmplTransformAddC14NInclNamespaces(xmlNodePtr transformNode,
                                                                 const xmlChar *prefixList);
 int xmlSecTmplTransformAddXPath (xmlNodePtr transformNode,
                                                                 const xmlChar *expression,
                                                                 const xmlChar **nsList);
 int xmlSecTmplTransformAddXPath2 (xmlNodePtr transformNode,
                                                                 const xmlChar* type,
                                                                 const xmlChar *expression,
                                                                 const xmlChar **nsList);
 int xmlSecTmplTransformAddXPointer (xmlNodePtr transformNode,
                                                                 const xmlChar *expression,
                                                                 const xmlChar **nsList);
// 9 "/scripts/include-xmlsec.c" 2
// 1 "/usr/local/include/xmlsec1/xmlsec/crypto.h" 1
// 28 "/usr/local/include/xmlsec1/xmlsec/crypto.h"
// 29 "/usr/local/include/xmlsec1/xmlsec/crypto.h" 2
// 1 "/usr/local/include/xmlsec1/xmlsec/dl.h" 1
// 30 "/usr/local/include/xmlsec1/xmlsec/dl.h"
typedef struct _xmlSecCryptoDLFunctions xmlSecCryptoDLFunctions,
                                                *xmlSecCryptoDLFunctionsPtr;
 int xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms
                                                                            (xmlSecCryptoDLFunctionsPtr functions);
// 30 "/usr/local/include/xmlsec1/xmlsec/crypto.h" 2
// 31 "/usr/local/include/xmlsec1/xmlsec/crypto.h" 2
// 32 "/usr/local/include/xmlsec1/xmlsec/crypto.h" 2
// 9 "/scripts/include-xmlsec.c" 2
]]

//#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <libxml/xmlmemory.h>
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/crypto.h>

#include "saml.h"


static PyObject* SamlError;

static char* CAPSULE_XML_DOC = "xmlDoc*";
static char* CAPSULE_XML_SEC_KEY = "xmlSecKey*";
static char* CAPSULE_XML_SEC_KEYS_MNGR= "xmlSecKeysMngr*";
static char* CAPSULE_XML_SEC_TRANSFORM_ID = "xmlSecTransformId";


static void xmlDoc_destructor(PyObject* capsule) {
  xmlDoc* doc = (xmlDoc*)PyCapsule_GetPointer(capsule, CAPSULE_XML_DOC);
  if (doc != NULL) {
    xmlFreeDoc(doc);
  }
}


static void xmlSecKey_destructor(PyObject* capsule) {
  xmlSecKey* key = (xmlSecKey*)PyCapsule_GetPointer(capsule, CAPSULE_XML_SEC_KEY);
  if (key != NULL) {
    xmlSecKeyDestroy(key);
  }
}


static void xmlSecKeysMngr_destructor(PyObject* capsule) {
  xmlSecKeysMngr* mngr = (xmlSecKeysMngr*)PyCapsule_GetPointer(capsule, CAPSULE_XML_SEC_KEYS_MNGR);
  if (mngr != NULL) {
    xmlSecKeysMngrDestroy(mngr);
  }
}


static PyObject* init(PyObject* self, PyObject* args, PyObject* kwargs) {
  saml_init_opts_t opts;
  opts.debug = 0;
  char* keywords[] = { "data_dir", "debug", NULL };
  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|$p", keywords, &opts.data_dir, &opts.debug)) {
    return NULL;
  }

  if (saml_init(&opts) < 0) {
    PyErr_SetString(SamlError, "saml initialization failed");
    return NULL;
  }

  Py_RETURN_NONE;
}


static PyObject* shutdown(PyObject* self, PyObject* args) {
  if (!PyArg_ParseTuple(args, "")) {
    return NULL;
  }

  saml_shutdown();
  Py_RETURN_NONE;
}


static PyObject* doc_read_memory(PyObject* self, PyObject* args) {
  int buf_len;
  const char* buf;
  if (!PyArg_ParseTuple(args, "s#", &buf, &buf_len)) {
    return NULL;
  }

  xmlDoc* doc = xmlReadMemory(buf, buf_len, "tmp.xml", NULL, 0);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "invalid xml");
    return NULL;
  } else {
    return PyCapsule_New((void*)doc, CAPSULE_XML_DOC, &xmlDoc_destructor);
  }
}


static PyObject* doc_read_file(PyObject* self, PyObject* args) {
  const char* filename;
  if (!PyArg_ParseTuple(args, "s", &filename)) {
    return NULL;
  }

  xmlDoc* doc = xmlReadFile(filename, NULL, 0);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "file does not exist or has invalid xml");
    return NULL;
  } else {
    return PyCapsule_New((void*)doc, CAPSULE_XML_DOC, &xmlDoc_destructor);
  }
}


static PyObject* doc_serialize(PyObject* self, PyObject* args) {
  PyObject* capsule;
  if (!PyArg_ParseTuple(args, "O", &capsule)) {
    return NULL;
  }

  xmlDoc* doc = (xmlDoc*)PyCapsule_GetPointer(capsule, CAPSULE_XML_DOC);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "invalid document value");
    return NULL;
  }

  int buf_len;
  xmlChar* buf;
  xmlDocDumpMemory(doc, &buf, &buf_len);
  PyObject* ret = Py_BuildValue("s#", buf, buf_len);
  xmlFree(buf);
  return ret;
}


static PyObject* doc_validate(PyObject* self, PyObject* args) {
  PyObject* capsule;
  if (!PyArg_ParseTuple(args, "O", &capsule)) {
    return NULL;
  }

  xmlDoc* doc = (xmlDoc*)PyCapsule_GetPointer(capsule, CAPSULE_XML_DOC);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "invalid document value");
    return NULL;
  }

  return PyBool_FromLong((long)saml_doc_validate(doc));
}


static PyObject* doc_root_name(PyObject* self, PyObject* args) {
  PyObject* capsule;
  if (!PyArg_ParseTuple(args, "O", &capsule)) {
    return NULL;
  }

  xmlDoc* doc = (xmlDoc*)PyCapsule_GetPointer(capsule, CAPSULE_XML_DOC);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "invalid document value");
    return NULL;
  }

  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL || root->name == NULL) {
    Py_RETURN_NONE;
  }
  return Py_BuildValue("s", root->name);
}


static PyObject* doc_id(PyObject* self, PyObject* args) {
  PyObject* capsule;
  if (!PyArg_ParseTuple(args, "O", &capsule)) {
    return NULL;
  }

  xmlDoc* doc = (xmlDoc*)PyCapsule_GetPointer(capsule, CAPSULE_XML_DOC);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "invalid document value");
    return NULL;
  }

  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL || root->name == NULL) {
    Py_RETURN_NONE;
  }

  xmlChar* id = xmlGetProp(root, (xmlChar*)"ID");
  if (id == NULL) {
    Py_RETURN_NONE;
  }

  PyObject* ret = Py_BuildValue("s", id);
  xmlFree(id);
  return ret;
}


static PyObject* doc_name_id(PyObject* self, PyObject* args) {
  PyObject* capsule;
  if (!PyArg_ParseTuple(args, "O", &capsule)) {
    return NULL;
  }

  xmlDoc* doc = (xmlDoc*)PyCapsule_GetPointer(capsule, CAPSULE_XML_DOC);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "invalid document value");
    return NULL;
  }

  xmlChar* name_id = saml_doc_name_id(doc);
  if (name_id == NULL) {
    Py_RETURN_NONE;
  }

  PyObject* ret = Py_BuildValue("s", name_id);
  xmlFree(name_id);
  return ret;
}


static PyObject* doc_issuer(PyObject* self, PyObject* args) {
  PyObject* capsule;
  if (!PyArg_ParseTuple(args, "O", &capsule)) {
    return NULL;
  }

  xmlDoc* doc = (xmlDoc*)PyCapsule_GetPointer(capsule, CAPSULE_XML_DOC);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "invalid document value");
    return NULL;
  }

  xmlChar* issuer = saml_doc_issuer(doc);
  if (issuer == NULL) {
    Py_RETURN_NONE;
  }

  PyObject* ret = Py_BuildValue("s", issuer);
  xmlFree(issuer);
  return ret;
}


static PyObject* doc_status_code(PyObject* self, PyObject* args) {
  PyObject* capsule;
  if (!PyArg_ParseTuple(args, "O", &capsule)) {
    return NULL;
  }

  xmlDoc* doc = (xmlDoc*)PyCapsule_GetPointer(capsule, CAPSULE_XML_DOC);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "invalid document value");
    return NULL;
  }

  xmlChar* status_code = saml_doc_status_code(doc);
  if (status_code == NULL) {
    Py_RETURN_NONE;
  }

  PyObject* ret = Py_BuildValue("s", status_code);
  xmlFree(status_code);
  return ret;
}


static PyObject* doc_session_index(PyObject* self, PyObject* args) {
  PyObject* capsule;
  if (!PyArg_ParseTuple(args, "O", &capsule)) {
    return NULL;
  }

  xmlDoc* doc = (xmlDoc*)PyCapsule_GetPointer(capsule, CAPSULE_XML_DOC);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "invalid document value");
    return NULL;
  }

  xmlChar* session_index = saml_doc_session_index(doc);
  if (session_index == NULL) {
    Py_RETURN_NONE;
  } else {
    PyObject* ret = Py_BuildValue("s", session_index);
    xmlFree(session_index);
    return ret;
  }
}


static PyObject* doc_attrs(PyObject* self, PyObject* args) {
  PyObject* capsule;
  if (!PyArg_ParseTuple(args, "O", &capsule)) {
    return NULL;
  }

  xmlDoc* doc = (xmlDoc*)PyCapsule_GetPointer(capsule, CAPSULE_XML_DOC);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "invalid document value");
    return NULL;
  }

  saml_attr_t* attrs;
  size_t attrs_len;
  if (saml_doc_attrs(doc, &attrs, &attrs_len) < 0) {
    Py_RETURN_NONE;
  }

  PyObject* ret = PyDict_New();
  PyObject* val;
  for (int i = 0; i < attrs_len; i++) {
    if (attrs[i].name != NULL) {
      val = NULL;
      switch (attrs[i].num_values) {
        case 0:
          val = Py_None;
          Py_INCREF(val);
          break;
        case 1:
          if (attrs[i].values[0] == NULL) {
            val = Py_None;
            Py_INCREF(val);
          } else {
            val = Py_BuildValue("s", (char*)attrs[i].values[0]);
          }
          break;
        default: // Create a list of the values
          val = PyList_New(attrs[i].num_values);
          for (int j = 0; j < attrs[i].num_values; j++) {
            if (attrs[i].values[j] == NULL) {
              PyList_SetItem(val, j, Py_None);
              Py_INCREF(Py_None);
            } else {
              PyList_SetItem(val, j, Py_BuildValue("s", (char*)attrs[i].values[j]));
            }
          }
          break;
      }
      PyDict_SetItemString(ret, (char*)attrs[i].name, val);
    }
  }

  saml_attrs_free(attrs, attrs_len);
  return ret;
}


static int validate_key_format(int format) {
  if (xmlSecKeyDataFormatUnknown <= format && format <= xmlSecKeyDataFormatCertDer) {
    return 1;
  } else {
    PyErr_SetString(SamlError, "invalid key format");
    return 0;
  }
}


static PyObject* key_read_memory(PyObject* self, PyObject* args) {
  int key_len, format;
  const xmlSecByte* key_data;
  if (!PyArg_ParseTuple(args, "s#i", &key_data, &key_len, &format)) {
    return NULL;
  }

  if (!validate_key_format(format)) {
    return NULL;
  }

  xmlSecKey* key = xmlSecCryptoAppKeyLoadMemory(key_data, key_len, format, NULL, NULL, NULL);
  if (key == NULL) {
    Py_RETURN_NONE;
  } else {
    return PyCapsule_New((void*)key, CAPSULE_XML_SEC_KEY, &xmlSecKey_destructor);
  }
}


static PyObject* key_read_file(PyObject* self, PyObject* args) {
  int format;
  const char* key_file;
  if (!PyArg_ParseTuple(args, "si", &key_file, &format)) {
    return NULL;
  }

  if (!validate_key_format(format)) {
    return NULL;
  }

  xmlSecKey* key = xmlSecCryptoAppKeyLoad(key_file, format, NULL, NULL, NULL);
  if (key == NULL) {
    Py_RETURN_NONE;
  } else {
    return PyCapsule_New((void*)key, CAPSULE_XML_SEC_KEY, &xmlSecKey_destructor);
  }
}


static PyObject* key_add_cert_memory(PyObject* self, PyObject* args) {
  PyObject* capsule;
  const xmlSecByte* cert;
  int cert_len, format;
  if (!PyArg_ParseTuple(args, "Os#i", &capsule, &cert, &cert_len, &format)) {
    return NULL;
  }

  xmlSecKey* key = (xmlSecKey*)PyCapsule_GetPointer(capsule, CAPSULE_XML_SEC_KEY);
  if (key == NULL) {
    PyErr_SetString(SamlError, "invalid key value");
    return NULL;
  }

  if (!validate_key_format(format)) {
    return NULL;
  }

  if (xmlSecCryptoAppKeyCertLoadMemory(key, cert, cert_len, format) < 0) {
    Py_RETURN_FALSE;
  } else {
    Py_RETURN_TRUE;
  }
}


static PyObject* key_add_cert_file(PyObject* self, PyObject* args) {
  PyObject* capsule;
  const char* cert_file;
  int format;
  if (!PyArg_ParseTuple(args, "Osi", &capsule, &cert_file, &format)) {
    return NULL;
  }

  xmlSecKey* key = (xmlSecKey*)PyCapsule_GetPointer(capsule, CAPSULE_XML_SEC_KEY);
  if (key == NULL) {
    PyErr_SetString(SamlError, "invalid key value");
    return NULL;
  }

  if (!validate_key_format(format)) {
    return NULL;
  }

  if (xmlSecCryptoAppKeyCertLoad(key, cert_file, format) < 0) {
    Py_RETURN_FALSE;
  } else {
    Py_RETURN_TRUE;
  }
}


static PyObject* create_keys_mngr(PyObject* self, PyObject* args) {
  PyObject* list;
  if (!PyArg_ParseTuple(args, "O", &list)) {
    return NULL;
  }
  if (!PyList_Check(list)) {
    PyErr_SetString(PyExc_TypeError, "create_keys_mngr not called with list");
    return NULL;
  }

  xmlSecKeysMngr* mngr = xmlSecKeysMngrCreate();
  if (mngr == NULL) {
    PyErr_SetString(SamlError, "create keys manager failed");
    return NULL;
  }

  if (xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
    xmlSecKeysMngrDestroy(mngr);
    PyErr_SetString(SamlError, "initialize keys manager failed");
    return NULL;
  }

  Py_ssize_t len = PyList_Size(list);
  PyObject* capsule;
  xmlSecKey* key = NULL;
  xmlSecKey* copy = NULL;
  for (int i = 0; i < len; i++) {
    capsule = PyList_GetItem(list, 0);
    if (!PyCapsule_CheckExact(capsule)) {
      xmlSecKeysMngrDestroy(mngr);
      PyErr_Format(PyExc_TypeError, "create_keys_mngr argument keys[%i] is not xmlSecKey*", i);
      return NULL;
    }

    key = (xmlSecKey*)PyCapsule_GetPointer(capsule, CAPSULE_XML_SEC_KEY);
    if (key == NULL) {
      xmlSecKeysMngrDestroy(mngr);
      PyErr_SetString(SamlError, "invalid key value");
      return NULL;
    }
    copy = xmlSecKeyDuplicate(key); // Copy needed because manager owns key memory
    if (copy == NULL) {
      xmlSecKeysMngrDestroy(mngr);
      PyErr_SetString(SamlError, "copy key failed");
    }


    if (xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, copy)) {
      xmlSecKeyDestroy(copy);
      xmlSecKeysMngrDestroy(mngr);
      PyErr_SetString(SamlError, "adopt key failed");
      return NULL;
    }
  }

  return PyCapsule_New((void*)mngr, CAPSULE_XML_SEC_KEYS_MNGR, &xmlSecKeysMngr_destructor);
}


static PyObject* find_transform_by_href(PyObject* self, PyObject* args) {
  xmlChar* href;
  if (!PyArg_ParseTuple(args, "s", &href)) {
    return NULL;
  }

  xmlSecTransformId transform_id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), href, xmlSecTransformUriTypeAny);
  if (transform_id == NULL) {
    Py_RETURN_NONE;
  } else {
    return PyCapsule_New((void*)transform_id, CAPSULE_XML_SEC_TRANSFORM_ID, NULL);
  }
}


static PyObject* sign_binary(PyObject* self, PyObject* args) {
  PyObject *key_capsule, *transform_capsule;
  unsigned char* data;
  int data_len;
  if (!PyArg_ParseTuple(args, "OOy#", &key_capsule, &transform_capsule, &data, &data_len)) {
    return NULL;
  }

  xmlSecKey* key = (xmlSecKey*)PyCapsule_GetPointer(key_capsule, CAPSULE_XML_SEC_KEY);
  if (key == NULL) {
    PyErr_SetString(SamlError, "invalid key value");
    return NULL;
  }

  xmlSecTransformId transform_id = (xmlSecTransformId)PyCapsule_GetPointer(transform_capsule, CAPSULE_XML_SEC_TRANSFORM_ID);
  if (transform_id == NULL) {
    PyErr_SetString(SamlError, "invalid transform_id value");
    return NULL;
  }

  xmlSecTransformCtx* ctx = saml_sign_binary(key, transform_id, data, data_len);
  if (ctx == NULL) {
    PyErr_SetString(SamlError, "invalid transform_id value");
    return NULL;
  }

  PyObject* ret = Py_BuildValue("y#", (char*)xmlSecBufferGetData(ctx->result), xmlSecBufferGetSize(ctx->result));
  xmlSecTransformCtxDestroy(ctx);
  return ret;
}


static PyObject* sign_doc(PyObject* self, PyObject* args, PyObject* kwargs) {
  saml_doc_opts_t opts = { .id_attr = NULL, .insert_after_ns = NULL, .insert_after_el = NULL };
  PyObject *key_capsule, *transform_capsule, *doc_capsule;
  char* keywords[] = { "id_attr", "insert_after_ns", "insert_after_el", NULL };
  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OOO|$sss", keywords, &key_capsule, &transform_capsule, &doc_capsule, &opts.id_attr, &opts.insert_after_ns, &opts.insert_after_el)) {
    return NULL;
  }

  xmlSecKey* key = (xmlSecKey*)PyCapsule_GetPointer(key_capsule, CAPSULE_XML_SEC_KEY);
  if (key == NULL) {
    PyErr_SetString(SamlError, "invalid key value");
    return NULL;
  }

  xmlSecTransformId transform_id = (xmlSecTransformId)PyCapsule_GetPointer(transform_capsule, CAPSULE_XML_SEC_TRANSFORM_ID);
  if (transform_id == NULL) {
    PyErr_SetString(SamlError, "invalid transform_id value");
    return NULL;
  }

  xmlDoc* doc = (xmlDoc*)PyCapsule_GetPointer(doc_capsule, CAPSULE_XML_DOC);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "invalid doc value");
    return NULL;
  }

  int res = saml_sign_doc(key, transform_id, doc, &opts);
  if (res == 0) {
    Py_RETURN_NONE;
  } else {
    PyErr_SetString(SamlError, "saml sign failed");
    return NULL;
  }
}


static PyObject* sign_xml(PyObject* self, PyObject* args, PyObject* kwargs) {
  saml_doc_opts_t opts = { .id_attr = NULL, .insert_after_ns = NULL, .insert_after_el = NULL };
  PyObject *key_capsule, *transform_capsule;
  char* data;
  int data_len;
  char* keywords[] = { "key", "transform", "xml", "id_attr", "insert_after_ns", "insert_after_el", NULL };
  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OOs#|$sss", keywords, &key_capsule, &transform_capsule, &data, &data_len, &opts.id_attr, &opts.insert_after_ns, &opts.insert_after_el)) {
    return NULL;
  }

  xmlSecKey* key = (xmlSecKey*)PyCapsule_GetPointer(key_capsule, CAPSULE_XML_SEC_KEY);
  if (key == NULL) {
    PyErr_SetString(SamlError, "invalid key value");
    return NULL;
  }

  xmlSecTransformId transform_id = (xmlSecTransformId)PyCapsule_GetPointer(transform_capsule, CAPSULE_XML_SEC_TRANSFORM_ID);
  if (transform_id == NULL) {
    PyErr_SetString(SamlError, "invalid transform_id value");
    return NULL;
  }

  xmlDoc* doc = xmlReadMemory(data, data_len, "tmp.xml", NULL, 0);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "unable to parse xml string");
    return NULL;
  }

  int res = saml_sign_doc(key, transform_id, doc, &opts);
  if (res == 0) {
    xmlChar* buf;
    int buf_len;
    xmlDocDumpMemory(doc, &buf, &buf_len);
    PyObject* ret = Py_BuildValue("s#", buf, buf_len);
    xmlFree(buf);
    return ret;
  } else {
    PyErr_SetString(SamlError, "saml sign failed");
    return NULL;
  }
}


static PyObject* verify_binary(PyObject* self, PyObject* args) {
  PyObject *cert_capsule, *transform_capsule;
  unsigned char *data, *sig;
  int data_len, sig_len;
  if (!PyArg_ParseTuple(args, "OOs#s#", &cert_capsule, &transform_capsule, &data, &data_len, &sig, &sig_len)) {
    return NULL;
  }

  xmlSecKey* cert = (xmlSecKey*)PyCapsule_GetPointer(cert_capsule, CAPSULE_XML_SEC_KEY);
  if (cert == NULL) {
    PyErr_SetString(SamlError, "invalid cert value");
    return NULL;
  }

  xmlSecTransformId transform_id = (xmlSecTransformId)PyCapsule_GetPointer(transform_capsule, CAPSULE_XML_SEC_TRANSFORM_ID);
  if (transform_id == NULL) {
    PyErr_SetString(SamlError, "invalid transform_id value");
    return NULL;
  }

  int res = saml_verify_binary(cert, transform_id, data, data_len, sig, sig_len);
  if (res < 0) {
    PyErr_SetString(SamlError, "saml verify failed");
    return NULL;
  } else {
    return PyBool_FromLong(1 - res);
  }
}


static PyObject* verify_doc(PyObject* self, PyObject* args, PyObject* kwargs) {
  saml_doc_opts_t opts = { .id_attr = NULL, .insert_after_ns = NULL, .insert_after_el = NULL };
  PyObject *mngr_capsule, *doc_capsule;
  char* keywords[] = { "mngr", "doc", "id_attr", NULL };
  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|$s#", keywords, &mngr_capsule, &doc_capsule, &opts.id_attr)) {
    return NULL;
  }

  xmlSecKeysMngr* mngr = (xmlSecKeysMngr*)PyCapsule_GetPointer(mngr_capsule, CAPSULE_XML_SEC_KEYS_MNGR);
  if (mngr == NULL) {
    PyErr_SetString(SamlError, "invalid mngr value");
    return NULL;
  }

  xmlDoc* doc = (xmlDoc*)PyCapsule_GetPointer(doc_capsule, CAPSULE_XML_DOC);
  if (doc == NULL) {
    PyErr_SetString(SamlError, "invalid doc value");
    return NULL;
  }

  int res = saml_verify_doc(mngr, doc, &opts);
  if (res < 0) {
    PyErr_SetString(SamlError, "saml verify failed");
    return NULL;
  } else {
    return PyBool_FromLong(1 - res);
  }
}


static PyMethodDef saml_funcs[] = {
  {"init", (PyCFunction)init, METH_VARARGS | METH_KEYWORDS, ""},
  {"shutdown", shutdown, METH_VARARGS, ""},

  {"doc_read_memory", doc_read_memory, METH_VARARGS, ""},
  {"doc_read_file", doc_read_file, METH_VARARGS, ""},
  {"doc_serialize", doc_serialize, METH_VARARGS, ""},
  {"doc_validate", doc_validate, METH_VARARGS, ""},

  {"doc_root_name", doc_root_name, METH_VARARGS, ""},
  {"doc_id", doc_id, METH_VARARGS, ""},
  {"doc_issuer", doc_issuer, METH_VARARGS, ""},
  {"doc_name_id", doc_name_id, METH_VARARGS, ""},
  {"doc_status_code", doc_status_code, METH_VARARGS, ""},
  {"doc_session_index", doc_session_index, METH_VARARGS, ""},
  {"doc_attrs", doc_attrs, METH_VARARGS, ""},

  {"key_read_memory", key_read_memory, METH_VARARGS, ""},
  {"key_read_file", key_read_file, METH_VARARGS, ""},
  {"key_add_cert_memory", key_add_cert_memory, METH_VARARGS, ""},
  {"key_add_cert_file", key_add_cert_file, METH_VARARGS, ""},
  {"create_keys_manager", create_keys_mngr, METH_VARARGS, ""},

  {"find_transform_by_href", find_transform_by_href, METH_VARARGS, ""},
  {"sign_binary", sign_binary, METH_VARARGS, ""},
  {"sign_doc", (PyCFunction)sign_doc, METH_VARARGS | METH_KEYWORDS, ""},
  {"sign_xml", (PyCFunction)sign_xml, METH_VARARGS | METH_KEYWORDS, ""},
  {"verify_binary", verify_binary, METH_VARARGS, ""},
  {"verify_doc", (PyCFunction)verify_doc, METH_VARARGS | METH_KEYWORDS, ""},

  {NULL, NULL, 0, NULL}
};


static struct PyModuleDef saml_module = {
  PyModuleDef_HEAD_INIT,
  "saml",
  NULL,
  -1,
  saml_funcs
};


PyMODINIT_FUNC PyInit_saml(void) {
  PyObject* m;

  m = PyModule_Create(&saml_module);
  if (m == NULL) {
    return NULL;
  }

  SamlError = PyErr_NewException("saml.error", NULL, NULL);
  Py_INCREF(SamlError);
  PyModule_AddObject(m, "error", SamlError);

  PyModule_AddStringConstant(m, "XMLNS_ASSERTION", SAML_XMLNS_ASSERTION);
  PyModule_AddStringConstant(m, "XMLNS_PROTOCOL", SAML_XMLNS_PROTOCOL);

  PyModule_AddStringConstant(m, "BINDING_HTTP_POST", SAML_BINDING_HTTP_POST);
  PyModule_AddStringConstant(m, "BINDING_HTTP_REDIRECT", SAML_BINDING_HTTP_REDIRECT);

  PyModule_AddStringConstant(m, "STATUS_SUCCESS", SAML_STATUS_SUCCESS);
  PyModule_AddStringConstant(m, "STATUS_REQUESTER", SAML_STATUS_REQUESTER);
  PyModule_AddStringConstant(m, "STATUS_RESPONDER", SAML_STATUS_RESPONDER);
  PyModule_AddStringConstant(m, "STATUS_VERSION_MISMATCH", SAML_STATUS_VERSION_MISMATCH);

  // export of keysdata.h:xmlSecKeyDataFormat
  PyModule_AddIntConstant(m, "KeyDataFormatUnknown", xmlSecKeyDataFormatUnknown);
  PyModule_AddIntConstant(m, "KeyDataFormatBinary", xmlSecKeyDataFormatBinary);
  PyModule_AddIntConstant(m, "KeyDataFormatPem", xmlSecKeyDataFormatPem);
  PyModule_AddIntConstant(m, "KeyDataFormatDer", xmlSecKeyDataFormatDer);
  PyModule_AddIntConstant(m, "KeyDataFormatPkcs8Pem", xmlSecKeyDataFormatPkcs8Pem);
  PyModule_AddIntConstant(m, "KeyDataFormatPkcs8Der", xmlSecKeyDataFormatPkcs8Der);
  PyModule_AddIntConstant(m, "KeyDataFormatPkcs12", xmlSecKeyDataFormatPkcs12);
  PyModule_AddIntConstant(m, "KeyDataFormatCertPem", xmlSecKeyDataFormatCertPem);
  PyModule_AddIntConstant(m, "KeyDataFormatCertDer", xmlSecKeyDataFormatCertDer);
  return m;
}

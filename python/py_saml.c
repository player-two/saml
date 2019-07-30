//#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "saml.h"


static PyObject* SamlError;

static char* CAPSULE_XML_DOC = "xmlDoc*";


static void xmlDoc_destructor(PyObject* capsule) {
  xmlDoc* doc = (xmlDoc*)PyCapsule_GetPointer(capsule, CAPSULE_XML_DOC);
  if (doc != NULL) {
    xmlFreeDoc(doc);
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


static PyMethodDef saml_funcs[] = {
  {"init", (PyCFunction)init, METH_VARARGS | METH_KEYWORDS, ""},
  {"shutdown", shutdown, METH_VARARGS, ""},

  {"doc_read_memory", doc_read_memory, METH_VARARGS, ""},
  {"doc_read_file", doc_read_file, METH_VARARGS, ""},

  {"doc_session_index", doc_session_index, METH_VARARGS, ""},

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
  return m;
}

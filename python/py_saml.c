//#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "saml.h"


static PyObject* SamlError;


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


static PyMethodDef saml_funcs[] = {
  {"init", (PyCFunction)init, METH_VARARGS | METH_KEYWORDS, ""},
  {"shutdown", shutdown, METH_VARARGS, ""},
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

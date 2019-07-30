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

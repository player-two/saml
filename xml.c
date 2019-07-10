int saml_doc_validate(xmlDoc* doc) {
  return xmlSchemaValidateDoc(XML_SCHEMA_VALIDATE_CTX, doc) == 0 ? 1 : 0;
}


static xmlXPathObject* eval_xpath(xmlDoc* doc, xmlXPathCompExpr* xpath) {
  xmlXPathContext* ctx = xmlXPathNewContext(doc);
  if (ctx == NULL) {
    return NULL;
  }

  if (xmlXPathRegisterNs(ctx, (xmlChar*)"saml", (xmlChar*)SAML_XMLNS_ASSERTION) < 0) {
    xmlXPathFreeContext(ctx);
    return NULL;
  }

  if (xmlXPathRegisterNs(ctx, (xmlChar*)"samlp", (xmlChar*)SAML_XMLNS_PROTOCOL) < 0) {
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


void saml_attrs_free(saml_attr_t* attrs, size_t attrs_len) {
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

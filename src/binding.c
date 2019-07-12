#if MAX_MEM_LEVEL >= 8
#  define DEF_MEM_LEVEL 8
#else
#  define DEF_MEM_LEVEL  MAX_MEM_LEVEL
#endif

static char* SAML_BINDING_ERRORS[] = {
  "internal zlib error",
  "internal xmlsec error",
  "ok", // just in case it was actually a success
  "no saml content",
  "no SigAlg",
  "no Signature",
  "invalid base64 content",
  "content is not valid xml",
  "document does not validate against schema",
  "invalid signature algorithm",
  "signature does not match",
};

char* saml_binding_error_msg(saml_binding_status_t status) {
  return SAML_BINDING_ERRORS[status - SAML_ZLIB_ERROR];
}

static void redirect_concat_args(char* saml_type, char* content, char* sig_alg, char* relay_state, str_t* query) {
  char* content_uri = saml_uri_encode(content);
  char* sig_alg_uri = saml_uri_encode(sig_alg);

  str_init(query, 1024);
  str_cat(query, saml_type, strlen(saml_type));
  str_append(query, '=');
  str_cat(query, content_uri, strlen(content_uri));
  if (relay_state != NULL) {
    char* relay_state_uri = saml_uri_encode(relay_state);
    str_cat(query, "&RelayState=", sizeof("&RelayState="));
    str_cat(query, relay_state_uri, strlen(relay_state_uri));
    free(relay_state_uri);
  }
  str_cat(query, "&SigAlg=", sizeof("&SigAlg="));
  str_cat(query, sig_alg_uri, strlen(sig_alg_uri));

  free(content_uri);
  free(sig_alg_uri);
}

saml_binding_status_t saml_binding_redirect_create(xmlSecKey* key, char* saml_type, char* content, char* sig_alg, char* relay_state, str_t* query) {
  xmlSecTransformId transform_id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), (xmlChar*)sig_alg, xmlSecTransformUriTypeAny);
  if (transform_id == NULL) {
    return SAML_INVALID_SIG_ALG;
  }

  int content_len = strlen(content);
  z_stream stream = (z_stream){
    .zalloc   = Z_NULL,
    .zfree    = Z_NULL,
    .opaque   = Z_NULL,
    .next_in  = (unsigned char*)content,
    .avail_in = content_len,
  };

  if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY) != Z_OK) {
    return SAML_ZLIB_ERROR;
  }

  unsigned char* deflated = malloc(content_len);
  stream.next_out = deflated;
  stream.avail_out = content_len;

  if (deflate(&stream, Z_FINISH) == Z_STREAM_ERROR) {
    deflateEnd(&stream);
    return SAML_ZLIB_ERROR;
  }

  char* b64_encoded = saml_base64_encode(deflated, stream.total_out);
  redirect_concat_args(saml_type, b64_encoded, sig_alg, relay_state, query);
  free(b64_encoded);

  xmlSecTransformCtx* ctx = saml_sign_binary(key, transform_id, (unsigned char*)query->data, query->len);
  if (ctx == NULL) {
    str_free(query);
    return SAML_XMLSEC_ERROR;
  }

  char* sig_encoded = saml_base64_encode(xmlSecBufferGetData(ctx->result), xmlSecBufferGetSize(ctx->result));
  xmlSecTransformCtxDestroy(ctx);
  char* sig_uri = saml_uri_encode(sig_encoded);
  str_cat(query, "&Signature=", sizeof("&Signature="));
  str_cat(query, sig_uri, strlen(sig_uri));
  free(sig_uri);

  return SAML_OK;
}

saml_binding_status_t saml_binding_redirect_parse(char* content, char* sig_alg, xmlDoc** doc) {
  if (content == NULL) {
    return SAML_NO_CONTENT;
  } else if (sig_alg == NULL) {
    return SAML_NO_SIG_ALG;
  }

  xmlSecTransformId transform_id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), (xmlChar*)sig_alg, xmlSecTransformUriTypeAny);
  if (transform_id == NULL) {
    return SAML_INVALID_SIG_ALG;
  }

  byte* decoded;
  int decoded_len;
  if (saml_base64_decode(content, strlen(content), &decoded, &decoded_len) < 0) {
    if (decoded != NULL) {
      free(decoded);
    }
    return SAML_BASE64;
  }

  z_stream stream = (z_stream){
    .zalloc   = Z_NULL,
    .zfree    = Z_NULL,
    .opaque   = Z_NULL,
    .next_in  = decoded,
    .avail_in = decoded_len,
  };
  if (inflateInit2(&stream, -15) != Z_OK) {
    return SAML_ZLIB_ERROR;
  }

  str_t xml;
  str_init(&xml, decoded_len * 2);
  int zlib_res;
  do {
    stream.next_out = (unsigned char*)xml.data + xml.len;
    stream.avail_out = xml.total - xml.len;
    zlib_res = inflate(&stream, Z_NO_FLUSH);
    xml.len = stream.total_out;
    if (zlib_res == Z_BUF_ERROR && stream.avail_out == 0) {
      str_grow(&xml);
    } else if (zlib_res == Z_STREAM_ERROR || zlib_res == Z_DATA_ERROR || zlib_res == Z_MEM_ERROR || zlib_res == Z_NEED_DICT) {
      inflateEnd(&stream);
      return SAML_ZLIB_ERROR;
    }
  } while (zlib_res != Z_STREAM_END);
  inflateEnd(&stream);

  *doc = xmlReadMemory((char*)xml.data, xml.len, "tmp.xml", NULL, 0);
  if (*doc == NULL) {
    return SAML_INVALID_XML;
  }

  if (!saml_doc_validate(*doc)) {
    return SAML_INVALID_DOC;
  }

  return SAML_OK;
}

saml_binding_status_t saml_binding_redirect_verify(xmlSecKey* cert, char* saml_type, char* content, char* sig_alg, char* relay_state, char* signature) {
  if (content == NULL) {
    return SAML_NO_CONTENT;
  } else if (sig_alg == NULL) {
    return SAML_NO_SIG_ALG;
  } else if (signature == NULL) {
    return SAML_NO_SIGNATURE;
  }

  xmlSecTransformId transform_id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), (xmlChar*)sig_alg, xmlSecTransformUriTypeAny);
  if (transform_id == NULL) {
    return SAML_INVALID_SIG_ALG;
  }

  byte* sig;
  int sig_len;
  if (saml_base64_decode(signature, strlen(signature), &sig, &sig_len) < 0) {
    return SAML_BASE64;
  }

  str_t query;
  redirect_concat_args(saml_type, content, sig_alg, relay_state, &query);

  int res = saml_verify_binary(cert, transform_id, (unsigned char*)query.data, query.len, sig, sig_len);
  str_free(&query);
  return res < 0 ? SAML_INVALID_SIGNATURE : SAML_OK;
}

int saml_binding_post_create(xmlSecKey* key, char* saml_type, char* content, char* sig_alg, char* relay_state) {
  return SAML_OK;
}

int saml_binding_post_parse(char* content, xmlDoc** doc) {
  return SAML_OK;
}

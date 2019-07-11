#if MAX_MEM_LEVEL >= 8
#  define DEF_MEM_LEVEL 8
#else
#  define DEF_MEM_LEVEL  MAX_MEM_LEVEL
#endif

int saml_binding_redirect_create(xmlSecKey* key, char* saml_type, char* content, char* sig_alg, char* relay_state, str_t* query) {
  xmlSecTransformId transform_id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), (xmlChar*)sig_alg, xmlSecTransformUriTypeAny);
  if (transform_id == NULL) {
    return -1;
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
    return -1;
  }

  unsigned char* deflated = malloc(content_len);
  stream.next_out = deflated;
  stream.avail_out = content_len;

  if (deflate(&stream, Z_FINISH) == Z_STREAM_ERROR) {
    deflateEnd(&stream);
    return -1;
  }

  char* b64_encoded = saml_base64_encode(deflated, stream.total_out);
  char* uri_encoded = saml_uri_encode(b64_encoded);
  free(b64_encoded);
  char* sig_alg_uri = saml_uri_encode(sig_alg);
  char* relay_state_uri = NULL;

  str_init(query, 1024);
  str_cat(query, saml_type, strlen(saml_type));
  str_append(query, '=');
  str_cat(query, uri_encoded, strlen(uri_encoded));
  free(uri_encoded);
  if (relay_state != NULL) {
    relay_state_uri = saml_uri_encode(relay_state);
    str_cat(query, "&RelayState=", sizeof("&RelayState="));
    str_cat(query, relay_state_uri, strlen(relay_state_uri));
    free(relay_state_uri);
  }
  str_cat(query, "&SigAlg=", sizeof("&SigAlg="));
  str_cat(query, sig_alg_uri, strlen(sig_alg_uri));
  free(sig_alg_uri);

  xmlSecTransformCtx* ctx = saml_sign_binary(key, transform_id, (unsigned char*)query->data, query->len);
  if (ctx == NULL) {
    str_free(query);
    return -1;
  }

  char* sig_encoded = saml_base64_encode(xmlSecBufferGetData(ctx->result), xmlSecBufferGetSize(ctx->result));
  xmlSecTransformCtxDestroy(ctx);
  char* sig_uri = saml_uri_encode(sig_encoded);
  str_cat(query, "&Signature=", sizeof("&Signature="));
  str_cat(query, sig_uri, strlen(sig_uri));
  free(sig_uri);

  return 0;
}

int saml_binding_redirect_parse(char* content, char* sig_alg, xmlDoc** doc) {
  xmlSecTransformId transform_id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), (xmlChar*)sig_alg, xmlSecTransformUriTypeAny);
  if (transform_id == NULL) {
    return -1;
  }

  byte* decoded;
  int decoded_len;
  if (saml_base64_decode(content, strlen(content), &decoded, &decoded_len) < 0) {
    if (decoded != NULL) {
      free(decoded);
    }
    return -1;
  }

  z_stream stream = (z_stream){
    .zalloc   = Z_NULL,
    .zfree    = Z_NULL,
    .opaque   = Z_NULL,
    .next_in  = decoded,
    .avail_in = decoded_len,
  };
  if (inflateInit2(&stream, -15) != Z_OK) {
    return -1;
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
      return -1;
    }
  } while (zlib_res != Z_STREAM_END);
  inflateEnd(&stream);

  *doc = xmlReadMemory((char*)xml.data, xml.len, "tmp.xml", NULL, 0);
  if (*doc == NULL) {
    return -1;
  }

  if (!saml_doc_validate(*doc)) {
    return -1;
  }

  return 0;
}

int saml_binding_redirect_verify(xmlSecKey* cert, char* saml_type, char* content, char* sig_alg, char* relay_state, char* signature) {
  xmlSecTransformId transform_id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), (xmlChar*)sig_alg, xmlSecTransformUriTypeAny);
  if (transform_id == NULL) {
    return -1;
  }

  str_t query;
  str_init(&query, 1024);
  str_cat(&query, saml_type, strlen(saml_type));
  str_append(&query, '=');
  str_cat(&query, content, strlen(content));
  if (relay_state != NULL) {
    str_cat(&query, "&RelayState=", sizeof("&RelayState="));
    str_cat(&query, relay_state, strlen(relay_state));
  }
  str_cat(&query, "&SigAlg=", sizeof("&SigAlg="));
  str_cat(&query, sig_alg, strlen(sig_alg));

  byte* sig;
  int sig_len;
  if (saml_base64_decode(signature, strlen(signature), &sig, &sig_len) < 0) {
    return -1;
  }

  int res = saml_verify_binary(cert, transform_id, (unsigned char*)query.data, query.len, sig, sig_len);
  str_free(&query);
  return res;
}

int saml_binding_post_create(xmlSecKey* key, char* saml_type, char* content, char* sig_alg, char* relay_state) {
  return 0;
}

int saml_binding_post_parse(char* content, xmlDoc** doc) {
  return 0;
}

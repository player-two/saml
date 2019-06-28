#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <curl/urlapi.h>
#include <xmlsec/crypto.h>
#include <zlib.h>

#include "saml.h"

#define URI_MAXLEN 4096
#define INFLATED_MAXLEN 40960 // zlib compression ration is reasonable 2-5x; 10x the max uri length gives plenty of room

char* USAGE = "\
Usage: saml [command] [options]\n\
Commands:\n\
  verify-redirect cert-file\n\
    Verify a redirect binding is correctly formatted and signed\n\
\n";

struct uri_arg_t;
typedef struct uri_arg_t {
  char* name;
  char* value;
  struct uri_arg_t* next;
} uri_arg_t;

uri_arg_t* uri_arg_alloc() {
  uri_arg_t* arg = malloc(sizeof(uri_arg_t));
  arg->name = NULL;
  arg->value = NULL;
  arg->next = NULL;
  return arg;
}

void uri_arg_free(uri_arg_t* arg) {
  if (arg->name != NULL) {
    curl_free(arg->name);
  }
  if (arg->name != NULL) {
    curl_free(arg->value);
  }
  arg->next = NULL;
  free(arg);
}

void uri_args_free(uri_arg_t* arg) {
  uri_arg_t* next;
  while (arg != NULL) {
    next = arg->next;
    uri_arg_free(arg);
    arg = next;
  }
}

int uri_parse_args(char* uri, uri_arg_t** args) {
  CURLUcode cu;
  CURLU *h = curl_url();
  curl_url_set(h, CURLUPART_URL, uri, 0);
  char *query;
  cu = curl_url_get(h, CURLUPART_QUERY, &query, 0);
  if (cu != CURLUE_OK) {
    curl_url_cleanup(h);
    return -1;
  }

  int query_len = strlen(query);
  if (query_len == 0) {
    curl_free(query);
    curl_url_cleanup(h);
    return -1;
  }

  // https://url.spec.whatwg.org/#concept-urlencoded-serializer
  *args = uri_arg_alloc();
  uri_arg_t* arg = *args;

  char buf[1024];
  int i_buf = 0;
  for (int i = 0; i < query_len; i++) {
    switch (query[i]) {
      case '=':
        if (i_buf == 0) {
          fprintf(stderr, "invalid uri query: no name for value\n");
          return -1;
        }
        arg->name = curl_unescape(buf, i_buf);
        i_buf = 0;
        break;
      case '&':
        arg->value = curl_unescape(buf, i_buf);
        i_buf = 0;
        arg->next = uri_arg_alloc();
        arg = arg->next;
        break;
      default:
        buf[i_buf] = query[i];
        i_buf++;
        break;
    }
  }

  if (i_buf > 0) {
    arg->value = curl_unescape(buf, i_buf);
  }

  curl_free(query);
  curl_url_cleanup(h);
  return 0;
}

char* uri_args_serialize(uri_arg_t* arg) {
  CURL* curl = curl_easy_init();
  if (curl == NULL) {
    return NULL;
  }

  char* tmp;
  int tmp_len;
  char* out = malloc(URI_MAXLEN * sizeof(char));
  char* out_i = out;
  while (arg != NULL) {
    tmp = curl_easy_escape(curl, arg->name, 0);
    tmp_len = strlen(tmp);
    memcpy(out_i, tmp, tmp_len);
    out_i += tmp_len;
    curl_free(tmp);

    *out_i++ = '=';

    tmp = curl_easy_escape(curl, arg->value, 0);
    tmp_len = strlen(tmp);
    memcpy(out_i, tmp, tmp_len);
    out_i += tmp_len;
    curl_free(tmp);

    *out_i++ = '&';

    arg = arg->next;
  }
  *out_i = '\0';
  curl_easy_cleanup(curl);
  return out;
}

unsigned char BASE64_ENCODE_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

unsigned char* base64_encode(unsigned char* c, int len) {
  unsigned char* out = malloc(len * sizeof(unsigned char));
  int a[3];
  uint32_t sum;
  while (len-- > 0) {
    a[0] = *c++ << 16;
    a[1] = len-- > 0 ? (*c++ << 8) : 0;
    a[2] = len-- > 0 ? *c++ : 0;
    sum = a[0] & a[1] & a[2];
    *out++ = BASE64_ENCODE_TABLE[sum >> 18 & 0x3f];
    *out++ = BASE64_ENCODE_TABLE[sum >> 12 & 0x3f];
    *out++ = BASE64_ENCODE_TABLE[sum >>  6 & 0x3f];
    *out++ = BASE64_ENCODE_TABLE[sum       & 0x3f];
  }
  *out = '\0';
  return out;
}

int base64_is_valid(unsigned char c) {
  return (('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '+' || c == '/') ? 1 : 0;
}

unsigned char base64_sub(unsigned char c) {
  if (c == '+') {
    return 62;
  } else if (c == '/') {
    return 63;
  } else if ('A' <= c && c <= 'Z') {
    return c - 'A';
  } else if ('a' <= c && c <= 'z') {
    return c - 'a' + 26;
  } else {
    assert('0' <= c && c <= '9');
    return c - '0' + 52;
  }
}

int base64_decode(unsigned char* in, int in_len, unsigned char** out, int* out_len) {
  if (in_len % 4 != 0) {
    return -1; // isn't padded correctly
  }

  unsigned char* stop = in + in_len;
  *out = malloc((in_len / 4) * 3 * sizeof(unsigned char));
  unsigned char* o = *out;
  uint32_t sum;

  *out_len = 0;
  while (in < stop) {
    sum = 0;
    int i;
    for(i = 3; i >= 0; i--) {
      if (base64_is_valid(*in)) {
        sum = sum + (base64_sub(*in++) << (i * 6));
      } else if (*in == '=') {
        in++;
        break;
      } else {
        return -1;
      }
    }
    if (i == 3) break; // this should never happen because it implies an entire quadruplet of padding
    *o++ = sum >> 16 & 0xFF;
    *out_len = *out_len + 1;
    if (i == 2) break;
    *o++ = sum >>  8 & 0xFF;
    *out_len = *out_len + 1;
    if (i == 1) break;
    *o++ = sum       & 0xFF;
    *out_len = *out_len + 1;
    if (i == 0) break;
  }
  return 0;
}

int verify_redirect(char* args[], int args_len) {
  if (args_len < 1) {
    fprintf(stderr, "not enough arguments\n");
    return 1;
  } else if (args_len > 2) {
    fprintf(stderr, "too many arguments\n");
    return 1;
  }

  xmlSecKey* cert = xmlSecCryptoAppKeyLoad(args[0], xmlSecKeyDataFormatCertPem, NULL, NULL, NULL);
  if (cert == NULL) {
    fprintf(stderr, "could not load cert from %s\n", args[0]);
    return 1;
  }

  char* uri;
  if (args_len == 2) {
    uri = args[1];
  } else {
    char uri_stdin[URI_MAXLEN];
    ssize_t read_len = read(STDIN_FILENO, uri_stdin, sizeof(uri_stdin) - 1);
    if (read_len == -1) {
      fprintf(stderr, "failed to read uri from stdin\n");
      return 1;
    }
    uri_stdin[read_len] = '\0';
    uri = uri_stdin;
  }

  uri_arg_t* uri_arg;
  if (uri_parse_args(uri, &uri_arg) < 0) {
    fprintf(stderr, "uri parsing failed\n");
    if (uri_arg != NULL) {
      uri_args_free(uri_arg);
    }
    return 1;
  }

  uri_arg_t* relay_state = NULL;
  uri_arg_t* saml = NULL;
  uri_arg_t* sig_alg = NULL;
  uri_arg_t* signature = NULL;
  uri_arg_t* next;
  while(uri_arg != NULL) {
    next = uri_arg->next;
    if (strcmp(uri_arg->name, "SAMLRequest") == 0) {
      saml = uri_arg;
    } else if (strcmp(uri_arg->name, "SAMLResponse") == 0) {
      saml = uri_arg;
    } else if (strcmp(uri_arg->name, "RelayState") == 0) {
      relay_state = uri_arg;
    } else if (strcmp(uri_arg->name, "SigAlg") == 0) {
      sig_alg = uri_arg;
    } else if (strcmp(uri_arg->name, "Signature") == 0) {
      signature = uri_arg;
    } else {
      uri_arg_free(uri_arg);
    }
    uri_arg = next;
  }

  if (saml == NULL) {
    fprintf(stderr, "No SAMLRequest or SAMLResponse found in uri query\n");
    //uri_arg_free(uri_args);
    return 1;
  }

  if (sig_alg == NULL) {
    fprintf(stderr, "No SigAlg found in uri query\n");
    //uri_arg_free(uri_args);
    return 1;
  }

  if (signature == NULL) {
    fprintf(stderr, "No Signature found in uri query\n");
    //uri_arg_free(uri_args);
    return 1;
  }

  if (relay_state == NULL) {
    saml->next = sig_alg;
  } else {
    saml->next = relay_state;
    relay_state->next = sig_alg;
  }


  xmlSecTransformId transform_id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), (xmlChar*)sig_alg->value, xmlSecTransformUriTypeAny);
  if (transform_id == NULL) {
    fprintf(stderr, "No transform found for %s\n", sig_alg->value);
    //uri_arg_free(uri_arg);
    return 1;
  }

  unsigned char* decoded;
  int decoded_len;
  if (base64_decode((unsigned char*)saml->value, strlen(saml->value), &decoded, &decoded_len) < 0) {
    fprintf(stderr, "bad base64 data for %s\n", saml->name);
    if (decoded != NULL) {
      free(decoded);
    }
    return 1;
  }

  // zlib.inflate(-15, decode_base64(args.SAMLRequest || args.SAMLResponse))
  z_stream stream = (z_stream){
    .zalloc   = Z_NULL,
    .zfree    = Z_NULL,
    .opaque   = Z_NULL,
    .next_in = decoded,
    .avail_in = decoded_len,
  };
  if (inflateInit2(&stream, -15) != Z_OK) {
    fprintf(stderr, "zlib setup failed\n");
    return 1;
  }

  unsigned char out[INFLATED_MAXLEN];
  stream.next_out = out;
  stream.avail_out = sizeof(out);

  int zlib_res = inflate(&stream, Z_FINISH);
  if (!(zlib_res == Z_STREAM_END || (zlib_res == Z_BUF_ERROR && stream.avail_in == 0))) {
    fprintf(stderr, "zlib inflate failed (%d): %s\n", zlib_res, stream.msg);
    inflateEnd(&stream);
    return 1;
  }
  out[stream.total_out] = '\0';
  inflateEnd(&stream);

  xmlDoc* doc = xmlReadMemory((char*)out, stream.total_out, "tmp.xml", NULL, 0);
  inflateEnd(&stream);
  if (doc == NULL) {
    fprintf(stderr, "decompressed content is not valid xml: %s\n", out);
    return 1;
  }

  if (!saml_doc_validate(doc)) {
    fprintf(stderr, "document does not validate against schema\n");
    return 1;
  }

  char* sig_input = uri_args_serialize(saml);
  if (sig_input == NULL) {
    fprintf(stderr, "failed to serialize uri args\n");
    return 1;
  }

  unsigned char* sig;
  int sig_len;
  if (base64_decode((unsigned char*)signature->value, strlen(signature->value), &sig, &sig_len) < 0) {
    fprintf(stderr, "failed to decode signature\n");
    return 1;
  }
  int res = saml_verify_binary(cert, transform_id, (unsigned char*)sig_input, strlen(sig_input), sig, sig_len);
  if (res < 0) {
    return 1;
  }

  return 0;
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    fprintf(stderr, "%s", USAGE);
    return 1;
  }

  char rock_dir[120];
  if (getcwd(rock_dir, sizeof(rock_dir)) == NULL) {
    fprintf(stderr, "getcwd failed\n");
    return 1;
  }

  saml_init_opts_t opts = (saml_init_opts_t){ .debug = 0, .rock_dir = rock_dir };
  if (saml_init(&opts) < 0) {
    fprintf(stderr, "initialization failed\n");
    return 1;
  }

  int res;
  if (strncmp(argv[1], "verify-redirect", sizeof("verify-redirect")) == 0) {
    res = verify_redirect(argv + 2, argc - 2);
    if (res == 0) {
      puts("redirect binding is valid");
    }
    return res;
  }

  fprintf(stderr, "unknown command %s\n", argv[1]);
  fprintf(stderr, "%s", USAGE);
  return 1;
}

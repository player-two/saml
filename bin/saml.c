#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <curl/urlapi.h>
#include <xmlsec/crypto.h>
#include <zlib.h>

#include "saml.h"

#define URI_MAXLEN 4096

char* USAGE = "\
Usage: saml [command] [options]\n\
Commands:\n\
  create-post key-file sig-alg [relay-state] xml-file\n\
  create-redirect key-file sig-alg [relay-state] xml-file\n\
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


int create_post(char* args[], int args_len) {
  if (args_len < 3) {
    fprintf(stderr, "not enough arguments\n");
    return 1;
  } else if (args_len > 4) {
    fprintf(stderr, "too many arguments\n");
    return 1;
  }

  xmlSecKey* key = xmlSecCryptoAppKeyLoad(args[0], xmlSecKeyDataFormatPem, NULL, NULL, NULL);
  if (key == NULL) {
    fprintf(stderr, "could not load key from %s\n", args[0]);
    return 1;
  }

  char* relay_state = args_len == 4 ? args[2] : NULL;

  str_t content;
  str_init(&content, 2048);
  FILE* f = fopen(args_len == 4 ? args[3] : args[2], "r");
  size_t read_len = fread((void*)content.data, sizeof(char), content.total, f);
  content.len = read_len;
  while (read_len != 0) {
    str_grow(&content);
    read_len = fread((void*)content.data + content.len, sizeof(char), content.total - content.len, f);
    content.len += read_len;
  }
  fclose(f);
  str_append(&content, '\0');

  str_t html;
  saml_binding_status_t res = saml_binding_post_create(key, "SAMLRequest", content.data, args[1], relay_state, "localhost:8080/acs", &html);
  str_free(&content);
  if (res != SAML_OK) {
    fprintf(stderr, "%s\n", saml_binding_error_msg(res));
    return 1;
  } else {
    fprintf(stderr, "%*s\n", html.len, html.data);
    str_free(&html);
    return 0;
  }
}


int create_redirect(char* args[], int args_len) {
  if (args_len < 3) {
    fprintf(stderr, "not enough arguments\n");
    return 1;
  } else if (args_len > 4) {
    fprintf(stderr, "too many arguments\n");
    return 1;
  }

  xmlSecKey* key = xmlSecCryptoAppKeyLoad(args[0], xmlSecKeyDataFormatPem, NULL, NULL, NULL);
  if (key == NULL) {
    fprintf(stderr, "could not load key from %s\n", args[0]);
    return 1;
  }

  char* relay_state = args_len == 4 ? args[2] : NULL;

  str_t content;
  str_init(&content, 1024);
  FILE* f = fopen(args_len == 4 ? args[3] : args[2], "r");
  size_t read_len = fread((void*)content.data, sizeof(char), content.total, f);
  content.len = read_len;
  while (read_len != 0) {
    str_grow(&content);
    read_len = fread((void*)content.data + content.len, sizeof(char), content.total - content.len, f);
    content.len += read_len;
  }
  fclose(f);
  str_append(&content, '\0');

  str_t query;
  saml_binding_status_t res = saml_binding_redirect_create(key, "SAMLRequest", content.data, args[1], relay_state, &query);
  str_free(&content);
  if (res != SAML_OK) {
    fprintf(stderr, "%s\n", saml_binding_error_msg(res));
    str_free(&query);
    return 1;
  } else {
    fprintf(stderr, "%*s\n", query.len, query.data);
    str_free(&query);
    return 0;
  }
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

  xmlDoc* doc;
  if (saml_binding_redirect_parse(saml->value, sig_alg->value, &doc) < 0) {
    return 1;
  }

  if (saml_binding_redirect_verify(cert, saml->name, saml->value, sig_alg->value, (relay_state == NULL ? NULL : relay_state->value), signature->value) < 0) {
    return 1;
  }

  return 0;
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    fprintf(stderr, "%s", USAGE);
    return 1;
  }

  char data_dir[120];
  if (getcwd(data_dir, sizeof(data_dir)) == NULL) {
    fprintf(stderr, "getcwd failed\n");
    return 1;
  }

  saml_init_opts_t opts = (saml_init_opts_t){ .debug = 0, .data_dir = data_dir };
  if (saml_init(&opts) < 0) {
    fprintf(stderr, "initialization failed\n");
    return 1;
  }

  int res;
  if (strncmp(argv[1], "create-post", sizeof("create-post")) == 0) {
    return create_post(argv + 2, argc - 2);
  } else if (strncmp(argv[1], "create-redirect", sizeof("create-redirect")) == 0) {
    return create_redirect(argv + 2, argc - 2);
  } else if (strncmp(argv[1], "verify-redirect", sizeof("verify-redirect")) == 0) {
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

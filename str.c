void str_init(str_t* str, int total) {
  str->len = 0;
  str->total = total;
  str->data = malloc(str->total);
}


void str_free(str_t* str) {
  free(str->data);
}


void str_grow(str_t* str) {
  str->total = 2 * str->total;
  char* data = malloc(str->total);
  memcpy(data, str->data, str->len);
  free(str->data);
  str->data = data;
}


void str_cat(str_t* str, const char* data, int len) {
  if (len > str->total - str->len) {
    str_grow(str);
    str_cat(str, data, len);
  } else {
    memcpy(str->data + str->len, data, len);
    str->len += len;
  }
}


void str_append(str_t* str, char c) {
  if (str->total - str->len <= 0) {
    str_grow(str);
    str_append(str, c);
  } else {
    str->data[str->len++] = c;
  }
}

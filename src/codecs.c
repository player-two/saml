static const char BASE64_ENCODE_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* saml_base64_encode(const byte* c, int len) {
  char* out = malloc(ceil(len * 4 / 3) + 4); // up to 3 bytes in padding
  char* out_i = out;
  int a[3];
  uint32_t sum;
  int padding = 0;
  while (len-- > 0) {
    a[0] = *c++ << 16;

    if (len-- > 0) {
      a[1] = *c++ << 8;
      if (len-- > 0) {
        a[2] = *c++;
      } else {
        a[2] = 0;
        padding = 1;
      }
    } else {
      a[1] = 0;
      a[2] = 0;
      padding = 2;
    }

    sum = a[0] | a[1] | a[2];
    int i;
    for (i = 3; i >= padding; i--) {
      *out_i++ = BASE64_ENCODE_TABLE[(sum >> i * 6) & 0x3f];
    }
    for (; i >= 0; i--) {
      *out_i++ = '=';
    }
  }
  *out_i = '\0';
  return out;
}

static int base64_is_valid(byte c) {
  return (('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '+' || c == '/') ? 1 : 0;
}

static char base64_sub(byte c) {
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

int saml_base64_decode(const char* in, int in_len, byte** out, int* out_len) {
  if (in_len % 4 != 0) {
    return -1; // isn't padded correctly
  }

  const char* stop = in + in_len;
  *out = malloc((in_len / 4) * 3);
  byte* o = *out;
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
        i++;
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

static int uri_is_unreserved(char c) {
  return (('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') ? 1 : 0;
}

static int hex_is_valid(char c) {
  return (('A' <= c && c <= 'F') || ('a' <= c && c <= 'f') || ('0' <= c && c <= '9')) ? 1 : 0;
}

static char hex_from_dec(char n) {
  return n + (n < 10 ? '0' : ('A' - 10));
}

static char hex_to_dec(char c) {
  if ('A' <= c && c <= 'F') {
    return c - 'A' + 10;
  } else if ('a' <= c && c <= 'f') {
    return c - 'a' + 10;
  } else {
    assert('0' <= c && c <= '9');
    return c - '0';
  }
}

char* saml_uri_encode(const char* in) {
  int out_i = 0;
  char* out = malloc(3 * strlen(in) + 1); // worst case where every char must be encoded
  while(*in != '\0') {
    if (uri_is_unreserved(*in)) {
      out[out_i++] = *in;
    } else {
      out[out_i++] = '%';
      out[out_i++] = hex_from_dec((char)floor(*in / 16));
      out[out_i++] = hex_from_dec(*in % 16);
    }
    in++;
  }
  out[out_i] = '\0';
  return out;
}

int saml_uri_decode(const char* in, char** out) {
  *out = malloc(strlen(in) + 1); // worst case where every char is unreserved
  char* out_c = *out;
  while(*in != '\0') {
    if (*in == '%') {
      if (!hex_is_valid(in[1]) || !hex_is_valid(in[2])) {
        return -1;
      }
      *out_c = 16 * hex_to_dec(in[1]) + hex_to_dec(in[2]);
      in += 3;
      out_c++;
    } else {
      *out_c++ = *in++;
    }
  }
  *out_c = '\0';
  return 0;
}

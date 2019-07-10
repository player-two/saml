#include <assert.h>
#include <math.h>

static const char BASE64_ENCODE_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* base64_encode(char* c, int len) {
  char* out = malloc(len * sizeof(char));
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

static int base64_is_valid(char c) {
  return (('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '+' || c == '/') ? 1 : 0;
}

static char base64_sub(char c) {
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

int base64_decode(char* in, int in_len, char** out, int* out_len) {
  if (in_len % 4 != 0) {
    return -1; // isn't padded correctly
  }

  char* stop = in + in_len;
  *out = malloc((in_len / 4) * 3 * sizeof(char));
  char* o = *out;
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

static int uri_is_unreserved(char c) {
  return (('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') ? 1 : 0;
}

static int hex_is_valid(char c) {
  return (('A' <= c && c <= 'F') || ('a' <= c && c <= 'f') || ('0' <= c && c <= '9')) ? 1 : 0;
}

static char hex_from_dec(char n) {
  return n + (n < 10 ? '0' : 'a');
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

char* uri_encode(char* in) {
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

int uri_decode(char* in, char** out) {
  *out = malloc(strlen(in) + 1); // worst case where every char is unreserved
  char* out_c = *out;
  while(*in != '\0') {
    if (*in == '%') {
      if (!hex_is_valid(*in) || !hex_is_valid(*(in + 1))) {
        return -1;
      }
      in++;
      *out_c = 10 * hex_to_dec(*in++);
      *out_c += hex_to_dec(*in++);
      out_c++;
    } else {
      *out_c++ = *in++;
    }
  }
  *out_c = '\0';
  return 0;
}

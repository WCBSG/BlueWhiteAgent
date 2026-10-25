
#include "webutil.h"

#include <bcrypt.h>
#include <ctype.h>

#include "rules.h"

int sha256_hex(const char *data, size_t len, char *out, size_t cap) {
  if (!out || cap < 65) return -1;
  BCRYPT_ALG_HANDLE alg = NULL;
  BCRYPT_HASH_HANDLE hash = NULL;
  unsigned char digest[32];
  int ok = -1;
  if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0) {
    if (BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) == 0) {
      BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0);
      BCryptFinishHash(hash, digest, sizeof(digest), 0);
      BCryptDestroyHash(hash);
      ok = 0;
    }
    BCryptCloseAlgorithmProvider(alg, 0);
  }
  if (ok != 0) {

    snprintf(out, cap, "unavailable");
    return -1;
  }
  hex_encode(digest, sizeof(digest), out, cap);
  return 0;
}

static int is_space_c(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

static void web_norm_impl(buf_t *out, const char *body, int kill_digits) {
  if (!body) return;
  const char *p = body;
  int last_space = 1;
  while (*p) {
    if (p[0] == '<' && p[1] == '!' && p[2] == '-' && p[3] == '-') {
      const char *e = strstr(p + 4, "-->");
      p = e ? e + 3 : p + strlen(p);
      continue;
    }
    unsigned char c = (unsigned char)*p;
    if (is_space_c((char)c)) {
      if (!last_space) { buf_putc_(out, ' '); last_space = 1; }
      p++;
      continue;
    }
    if (kill_digits && isdigit(c)) {
      if (out->len == 0 || out->data[out->len - 1] != '#') buf_putc_(out, '#');
      last_space = 0;
      while (isdigit((unsigned char)*p)) p++;
      continue;
    }
    buf_putc_(out, (char)c);
    last_space = 0;
    p++;
  }

  while (out->len > 0 && out->data[out->len - 1] == ' ') out->data[--out->len] = 0;
}

void web_norm_text(buf_t *out, const char *body) { web_norm_impl(out, body, 0); }
void web_shape(buf_t *out, const char *body) { web_norm_impl(out, body, 1); }

int web_same_shape(const char *a, const char *b) {
  if (!a || !b) return 0;
  buf_t x, y;
  buf_init(&x);
  buf_init(&y);
  web_shape(&x, a);
  web_shape(&y, b);
  int same = (strcmp(x.data ? x.data : "", y.data ? y.data : "") == 0);
  buf_free(&x);
  buf_free(&y);
  return same;
}

int web_body_hash(const char *body, char *out, size_t cap) {
  buf_t n;
  buf_init(&n);
  web_norm_text(&n, body ? body : "");
  int rc = sha256_hex(n.data ? n.data : "", n.len, out, cap);
  buf_free(&n);
  return rc;
}

void web_title(const char *body, char *out, size_t cap) {
  if (cap) out[0] = 0;
  if (!body) return;
  const char *p = body;
  while ((p = strchr(p, '<')) != NULL) {
    if ((p[1] == 't' || p[1] == 'T') && str_icase_find(p, "<title")) {
      const char *gt = strchr(p, '>');
      if (!gt) return;
      const char *end = str_icase_find(gt, "</title>");
      const char *stop = end ? end : gt + 1 + strcspn(gt + 1, "<");
      size_t n = (size_t)(stop - (gt + 1));
      if (n > cap - 1) n = cap - 1;
      memcpy(out, gt + 1, n);
      out[n] = 0;
      char *t = str_trim(out);
      if (t != out) memmove(out, t, strlen(t) + 1);
      return;
    }
    p++;
  }
}

typedef void (*hdr_cb_t)(const char *name, size_t nlen, const char *value,
                         size_t vlen, void *ud);

static void headers_walk(const char *raw, hdr_cb_t cb, void *ud) {
  if (!raw) return;
  const char *p = raw;
  while (*p) {
    const char *eol = strchr(p, '\n');
    size_t len = eol ? (size_t)(eol - p) : strlen(p);
    if (len && p[len - 1] == '\r') len--;
    if (len > 0 && !(len >= 5 && str_icase_find(p, "HTTP/"))) {
      const char *colon = static_cast<const char *>(memchr(p, ':', len));
      if (colon) {
        const char *name = p;
        size_t nlen = (size_t)(colon - p);
        const char *val = colon + 1;
        size_t vlen = len - (size_t)(val - p);
        while (nlen > 0 && is_space_c(name[nlen - 1])) nlen--;
        while (vlen > 0 && is_space_c(*val)) { val++; vlen--; }
        while (vlen > 0 && is_space_c(val[vlen - 1])) vlen--;
        if (nlen > 0 && nlen <= 64) cb(name, nlen, val, vlen, ud);
      }
    }
    if (!eol) break;
    p = eol + 1;
  }
}

static int hdr_name_eq(const char *name, size_t nlen, const char *want) {
  size_t w = strlen(want);
  if (nlen != w) return 0;
  for (size_t i = 0; i < nlen; i++) {
    if (tolower((unsigned char)name[i]) != tolower((unsigned char)want[i])) return 0;
  }
  return 1;
}

typedef struct {
  const char *want;
  int idx;
  int count;
  int got;
  buf_t *out;
} hdr_ud_t;

static void hdr_collect(const char *name, size_t nlen, const char *value,
                        size_t vlen, void *ud) {
  hdr_ud_t *h = (hdr_ud_t *)ud;
  if (!hdr_name_eq(name, nlen, h->want)) return;
  if (h->idx >= 0) {
    if (h->count == h->idx && h->out) {
      buf_putn(h->out, value, vlen);
      h->got = 1;
    }
    h->count++;
    return;
  }
  if (h->out) {
    if (h->count > 0) buf_puts(h->out, ", ");
    buf_putn(h->out, value, vlen);
  }
  h->count++;
}

int web_header_count(const char *raw_headers, const char *name) {
  hdr_ud_t h;
  memset(&h, 0, sizeof(h));
  h.want = name;
  h.idx = -1;
  headers_walk(raw_headers, hdr_collect, &h);
  return h.count;
}

int web_header(const char *raw_headers, const char *name, buf_t *out) {
  hdr_ud_t h;
  memset(&h, 0, sizeof(h));
  h.want = name;
  h.idx = -1;
  h.out = out;
  headers_walk(raw_headers, hdr_collect, &h);
  return h.count > 0 ? 1 : 0;
}

int web_header_at(const char *raw_headers, const char *name, int idx, buf_t *out) {
  hdr_ud_t h;
  memset(&h, 0, sizeof(h));
  h.want = name;
  h.idx = idx;
  h.out = out;
  headers_walk(raw_headers, hdr_collect, &h);
  return h.got;
}

int web_headers_available(const char *raw_headers) {
  if (!raw_headers) return 0;
  static const char *PROBE[] = {"content-type", "server", "content-length",
                                "date", "set-cookie"};
  for (size_t i = 0; i < sizeof(PROBE) / sizeof(PROBE[0]); i++) {
    if (web_header_count(raw_headers, PROBE[i]) > 0) return 1;
  }
  return 0;
}

static int header_needs_mask(const char *name, size_t nlen) {
  static const char *MASK[] = {"cookie", "set-cookie", "authorization",
                               "proxy-authorization", "x-auth-token", "token"};
  for (size_t i = 0; i < sizeof(MASK) / sizeof(MASK[0]); i++) {
    if (hdr_name_eq(name, nlen, MASK[i])) return 1;
  }
  return 0;
}

static void mask_header_value(const char *name, size_t nlen, const char *val,
                              size_t vlen, buf_t *out) {
  if (!header_needs_mask(name, nlen)) {
    buf_putn(out, val, vlen);
    return;
  }

  const char *eq = static_cast<const char *>(memchr(val, '=', vlen));
  if (hdr_name_eq(name, nlen, "set-cookie") && eq) {
    buf_putn(out, val, (size_t)(eq - val));
    buf_puts(out, "=***");
    const char *semi = static_cast<const char *>(memchr(val, ';', vlen));
    if (semi) buf_putn(out, semi, vlen - (size_t)(semi - val));
    return;
  }
  buf_puts(out, "***");
  (void)nlen;
}

typedef struct { json_t *out; } hdr_json_ud_t;

static void hdr_to_json(const char *name, size_t nlen, const char *value,
                        size_t vlen, void *ud) {
  hdr_json_ud_t *h = (hdr_json_ud_t *)ud;
  char *key = xstrndup(name, nlen);
  buf_t val;
  buf_init(&val);
  mask_header_value(name, nlen, value, vlen, &val);

  json_t *exist = j_get(h->out, key);
  if (!exist) {
    j_set_str(h->out, key, val.data ? val.data : "");
  } else if (exist->type == J_STR) {
    json_t *arr = j_arr();
    j_add(arr, j_str(exist->str ? exist->str : ""));
    j_add(arr, j_str(val.data ? val.data : ""));
    j_set(h->out, key, arr);
  } else if (exist->type == J_ARR) {
    j_add(exist, j_str(val.data ? val.data : ""));
  }
  buf_free(&val);
  free(key);
}

json_t *web_headers_json(const char *raw_headers) {
  json_t *o = j_obj();
  hdr_json_ud_t ud;
  ud.out = o;
  headers_walk(raw_headers, hdr_to_json, &ud);
  return o;
}

int web_is_dir_listing(const char *body) {
  if (!body) return 0;
  int n = rules_arr_count("markers.dir_listing");
  int marker = 0;
  for (int i = 0; i < n; i++) {
    const char *m = rules_arr_str("markers.dir_listing", i, "", "");
    if (!m[0]) m = rules_arr_str("markers.dir_listing", i, "mark", "");
    if (m[0] && str_icase_find(body, m)) { marker = 1; break; }
  }
  if (!marker) return 0;

  if (!str_icase_find(body, "<a href=") && !str_icase_find(body, "href='")) return 0;
  return 1;
}

void web_dir_listing_entries(const char *body, json_t *out, int max) {
  if (!body) return;
  const char *p = body;
  while ((p = str_icase_find(p, "href=")) != NULL && j_len(out) < max) {
    p += 5;
    char quote = *p;
    if (quote != '"' && quote != '\'') continue;
    p++;
    const char *end = strchr(p, quote);
    if (!end) break;
    size_t n = (size_t)(end - p);
    if (n > 0 && n < 300) {
      char *href = xstrndup(p, n);
      int skip = strstr(href, "..") != NULL || href[0] == '?' ||
                 str_startswith(href, "http://") || str_startswith(href, "https://") ||
                 str_startswith(href, "/");
      if (!skip) j_add(out, j_str(href));
      free(href);
    }
    p = end;
  }
}

int web_has_password_form(const char *body) {
  if (!body) return 0;

  char field[64];
  snprintf(field, sizeof(field), "%s",
           rules_arr_str("markers", 0, "login_password_field", "password"));

  static const char *kNameMarkers[] = {"name=\"pass\"", "name='pass'", "name=\"pwd\"",
                                       "name='pwd'", "name=\"password\"", "name='password'"};
  for (size_t m = 0; m < sizeof(kNameMarkers) / sizeof(kNameMarkers[0]); m++) {
    if (str_icase_find(body, kNameMarkers[m])) return 1;
  }
  const char *p = body;
  while ((p = str_icase_find(p, "type=")) != NULL) {
    p += 5;
    char q = *p;
    if (q == '"' || q == '\'') {
      const char *end = strchr(p + 1, q);
      if (!end) break;
      char val[32];
      size_t n = (size_t)(end - p - 1);
      if (n >= sizeof(val)) n = sizeof(val) - 1;
      memcpy(val, p + 1, n);
      val[n] = 0;
      if (str_icase_find(val, field)) return 1;
      p = end;
      continue;
    }
    if (str_icase_find(p, field)) return 1;
  }
  return 0;
}

int web_has_mixed_content(const char *body) {
  if (!body) return 0;
  static const char *ATTRS[] = {"src=\"http://", "src='http://", "href=\"http://",
                                "href='http://", "action=\"http://", "action='http://"};
  for (size_t i = 0; i < sizeof(ATTRS) / sizeof(ATTRS[0]); i++) {
    if (str_icase_find(body, ATTRS[i])) return 1;
  }
  return 0;
}

void web_url_parts(const char *url, char *host, size_t hcap, char *path, size_t pcap) {
  if (host && hcap) host[0] = 0;
  if (path && pcap) path[0] = 0;
  if (!url) return;
  const char *p = strstr(url, "://");
  p = p ? p + 3 : url;
  const char *slash = strpbrk(p, "/?#");
  size_t hlen = slash ? (size_t)(slash - p) : strlen(p);
  if (host && hcap) {
    if (hlen >= hcap) hlen = hcap - 1;
    memcpy(host, p, hlen);
    host[hlen] = 0;
  }
  if (path && pcap && slash) snprintf(path, pcap, "%s", slash);
}

void web_url_key(const char *url, char *out, size_t cap) {
  const char *p = url ? url : "";
  const char *sep = strstr(p, "://");
  const char *h = sep ? sep + 3 : p;
  const char *slash = strchr(h, '/');
  size_t hn = slash ? (size_t)(slash - h) : strlen(h);
  char path[512];
  snprintf(path, sizeof(path), "%s", slash ? slash : "/");
  char *q = strpbrk(path, "?#");
  if (q) *q = 0;
  static const char *IDX[] = {"/index.html", "/index.htm", "/index.php", "/default.asp",
                              "/default.aspx"};
  size_t pl = strlen(path);
  for (size_t i = 0; i < sizeof(IDX) / sizeof(IDX[0]); i++) {
    size_t il = strlen(IDX[i]);
    if (pl >= il && str_ieq(path + pl - il, IDX[i])) {
      pl -= il;
      path[pl] = 0;
      break;
    }
  }
  while (pl > 1 && path[pl - 1] == '/') path[--pl] = 0;
  snprintf(out, cap, "%.*s%s", (int)hn, h, path);
}

void web_url_encode(const char *s, buf_t *out) {
  static const char *HEX = "0123456789ABCDEF";
  for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
    unsigned char c = *p;
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') buf_putc_(out, (char)c);
    else {
      buf_putc_(out, '%');
      buf_putc_(out, HEX[c >> 4]);
      buf_putc_(out, HEX[c & 0x0F]);
    }
  }
}

static void split_query(const char *url, buf_t *base, buf_t *query, buf_t *frag) {
  const char *hash = strchr(url ? url : "", '#');
  size_t end = hash ? (size_t)(hash - url) : strlen(url ? url : "");
  const char *q = static_cast<const char *>(memchr(url ? url : "", '?', end));
  if (q) {
    buf_putn(base, url, (size_t)(q - url));
    buf_putn(query, q + 1, end - (size_t)(q + 1 - url));
  } else {
    buf_putn(base, url, end);
  }
  if (hash) buf_puts(frag, hash);
}

void web_url_set_param(const char *url, const char *key, const char *value, buf_t *out) {
  buf_t base, query, frag;
  buf_init(&base);
  buf_init(&query);
  buf_init(&frag);
  split_query(url, &base, &query, &frag);

  buf_puts(out, base.data ? base.data : "");
  buf_putc_(out, '?');
  int replaced = 0, written = 0;
  const char *p = query.data ? query.data : "";
  while (*p) {
    const char *amp = strchr(p, '&');
    size_t len = amp ? (size_t)(amp - p) : strlen(p);
    if (len > 0) {
      const char *eq = static_cast<const char *>(memchr(p, '=', len));
      size_t klen = eq ? (size_t)(eq - p) : len;
      char *k = xstrndup(p, klen);
      if (str_ieq(k, key)) {
        if (written) buf_putc_(out, '&');
        buf_puts(out, key);
        buf_putc_(out, '=');
        web_url_encode(value, out);
        written = 1;
        replaced = 1;
      } else {
        if (written) buf_putc_(out, '&');
        buf_putn(out, p, len);
        written = 1;
      }
      free(k);
    }
    if (!amp) break;
    p = amp + 1;
  }
  if (!replaced) {
    if (written) buf_putc_(out, '&');
    buf_puts(out, key);
    buf_putc_(out, '=');
    web_url_encode(value, out);
  }
  if (frag.data) buf_puts(out, frag.data);
  buf_free(&base);
  buf_free(&query);
  buf_free(&frag);
}

void web_url_params(const char *url, json_t *out) {
  const char *q = strchr(url ? url : "", '?');
  if (!q) return;
  const char *p = q + 1;
  while (*p) {
    const char *amp = strchr(p, '&');
    size_t len = amp ? (size_t)(amp - p) : strlen(p);
    const char *eq = static_cast<const char *>(memchr(p, '=', len));
    size_t klen = eq ? (size_t)(eq - p) : len;
    if (klen > 0 && klen < 64) {
      char *k = xstrndup(p, klen);
      int dup = 0;
      for (int i = 0; i < j_len(out); i++) {
        if (j_at(out, i)->str && strcmp(j_at(out, i)->str, k) == 0) { dup = 1; break; }
      }
      if (!dup) j_add(out, j_str(k));
      free(k);
    }
    if (!amp) break;
    p = amp + 1;
  }
}

int web_url_get_param(const char *url, const char *key, buf_t *out) {
  const char *q = strchr(url ? url : "", '?');
  if (!q) return 0;
  const char *p = q + 1;
  while (*p) {
    const char *amp = strchr(p, '&');
    size_t len = amp ? (size_t)(amp - p) : strlen(p);
    const char *eq = static_cast<const char *>(memchr(p, '=', len));
    size_t klen = eq ? (size_t)(eq - p) : len;
    char *k = xstrndup(p, klen);
    int hit = str_ieq(k, key);
    free(k);
    if (hit) {
      if (eq) buf_putn(out, eq + 1, len - klen - 1);
      return 1;
    }
    if (!amp) break;
    p = amp + 1;
  }
  return 0;
}

void web_extract_links(const char *html, json_t *out) {
  if (!html) return;
  static const char *ATTRS[] = {"href=", "src=", "action=", "data-src=", "poster="};
  for (size_t a = 0; a < sizeof(ATTRS) / sizeof(ATTRS[0]); a++) {
    const char *p = html;
    while ((p = str_icase_find(p, ATTRS[a])) != NULL) {
      p += strlen(ATTRS[a]);
      char quote = *p;
      const char *start = p;
      const char *end = NULL;
      if (quote == '"' || quote == '\'') {
        start = p + 1;
        end = strchr(start, quote);
      } else {
        end = start + strcspn(start, " \t\r\n>");
      }
      if (!end) break;
      size_t n = (size_t)(end - start);
      if (n > 0 && n < 1024) {
        char *link = xstrndup(start, n);
        if (!str_startswith(link, "javascript:") && !str_startswith(link, "mailto:") &&
            !str_startswith(link, "tel:") && !str_startswith(link, "#") &&
            !str_startswith(link, "data:")) {
          j_add(out, j_str(link));
        }
        free(link);
      }
      p = end;
    }
  }
}

int web_count_icase(const char *hay, const char *needle) {
  if (!hay || !needle || !*needle) return 0;
  size_t nl = strlen(needle);
  int n = 0;
  const char *p = hay;
  while ((p = str_icase_find(p, needle)) != NULL) {
    n++;
    p += nl;
  }
  return n;
}

static int named_entity(const char *p, int *consumed, unsigned *cp) {
  struct { const char *name; unsigned code; } kMap[] = {
    {"amp", '&'}, {"lt", '<'}, {"gt", '>'}, {"quot", '"'}, {"apos", '\''},
    {"nbsp", ' '}, {"colon", ':'}, {"sol", '/'}, {"equals", '='}, {"period", '.'},
    {"commat", '@'}, {"plus", '+'}, {"num", '#'},
  };
  for (size_t i = 0; i < sizeof(kMap) / sizeof(kMap[0]); i++) {
    size_t n = strlen(kMap[i].name);
    if (strncmp(p, kMap[i].name, n) == 0 && p[n] == ';') {
      *cp = kMap[i].code;
      *consumed = (int)n + 1;
      return 1;
    }
  }
  return 0;
}

static void put_utf8(buf_t *out, unsigned cp) {
  if (cp < 0x80) {
    buf_putc_(out, (char)cp);
  } else if (cp < 0x800) {
    buf_putc_(out, (char)(0xC0 | (cp >> 6)));
    buf_putc_(out, (char)(0x80 | (cp & 0x3F)));
  } else if (cp < 0x10000) {
    buf_putc_(out, (char)(0xE0 | (cp >> 12)));
    buf_putc_(out, (char)(0x80 | ((cp >> 6) & 0x3F)));
    buf_putc_(out, (char)(0x80 | (cp & 0x3F)));
  } else {
    buf_putc_(out, (char)(0xF0 | (cp >> 18)));
    buf_putc_(out, (char)(0x80 | ((cp >> 12) & 0x3F)));
    buf_putc_(out, (char)(0x80 | ((cp >> 6) & 0x3F)));
    buf_putc_(out, (char)(0x80 | (cp & 0x3F)));
  }
}

void web_decode_entities(buf_t *out, const char *s) {
  if (!s) return;
  const char *p = s;
  while (*p) {
    if (*p != '&') { buf_putc_(out, *p++); continue; }

    if (p[1] == '#') {
      unsigned cp = 0;
      int ok = 0;
      const char *q = p + 2;
      if (*q == 'x' || *q == 'X') {
        q++;
        while (isxdigit((unsigned char)*q)) {
          unsigned d = (unsigned)(isdigit((unsigned char)*q) ? *q - '0'
                                                             : (tolower((unsigned char)*q) - 'a' + 10));
          cp = cp * 16 + d;
          q++;
          ok = 1;
        }
      } else {
        while (isdigit((unsigned char)*q)) {
          cp = cp * 10 + (unsigned)(*q - '0');
          q++;
          ok = 1;
        }
      }
      if (ok && *q == ';' && cp > 0 && cp <= 0x10FFFF) {
        put_utf8(out, cp);
        p = q + 1;
        continue;
      }
    } else {
      int consumed = 0;
      unsigned cp = 0;
      if (named_entity(p + 1, &consumed, &cp)) {
        put_utf8(out, cp);
        p += 1 + consumed;
        continue;
      }
    }
    buf_putc_(out, *p++);
  }
}

void web_strip_invisible(buf_t *out, const char *s) {
  if (!s) return;
  const unsigned char *p = (const unsigned char *)s;
  while (*p) {

    if (p[0] == 0xE2 && p[1] == 0x80 &&
        (p[2] == 0x8B || p[2] == 0x8C || p[2] == 0x8D || p[2] == 0x8E || p[2] == 0x8F ||
         p[2] == 0xAA || p[2] == 0xAB || p[2] == 0xAC || p[2] == 0xAD || p[2] == 0xAE ||
         p[2] == 0xAF)) {
      p += 3;
      continue;
    }
    if (p[0] == 0xE2 && p[1] == 0x81 && p[2] == 0xA0) { p += 3; continue; }
    if (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) { p += 3; continue; }
    if (p[0] == 0xC2 && p[1] == 0xAD) { p += 2; continue; }
    buf_putc_(out, (char)*p);
    p++;
  }
}

void web_merge_js_strings(buf_t *out, const char *s) {
  if (!s) return;
  const char *p = s;
  while (*p) {
    char q = *p;
    if (q != '\'' && q != '"' && q != '`') { buf_putc_(out, *p++); continue; }

    const char *start = p + 1;
    const char *e = start;
    while (*e && *e != q) {
      if (*e == '\\' && e[1]) e += 2;
      else e++;
    }
    if (*e != q) { buf_putc_(out, *p++); continue; }

    const char *after = e + 1;
    const char *t = after;
    while (*t == ' ' || *t == '\t' || *t == '\r' || *t == '\n') t++;
    int merges = 0;
    if (*t == '+') {
      const char *u = t + 1;
      while (*u == ' ' || *u == '\t' || *u == '\r' || *u == '\n') u++;
      if (*u == '\'' || *u == '"' || *u == '`') merges = 1;
    }
    if (!merges) {
      buf_putn(out, p, (size_t)(e - p + 1));
      p = after;
      continue;
    }

    buf_putn(out, start, (size_t)(e - start));

    const char *next = after;
    for (;;) {
      const char *tt = next;
      while (*tt == ' ' || *tt == '\t' || *tt == '\r' || *tt == '\n') tt++;
      if (*tt != '+') { next = tt; break; }
      tt++;
      while (*tt == ' ' || *tt == '\t' || *tt == '\r' || *tt == '\n') tt++;
      if (*tt != '\'' && *tt != '"' && *tt != '`') { next = tt; break; }
      char q2 = *tt;
      const char *s2 = tt + 1;
      const char *e2 = s2;
      while (*e2 && *e2 != q2) {
        if (*e2 == '\\' && e2[1]) e2 += 2;
        else e2++;
      }
      if (*e2 != q2) { next = tt; break; }
      buf_putn(out, s2, (size_t)(e2 - s2));
      next = e2 + 1;
    }
    p = next;
  }
}

static int printable_ratio_ok(const char *s, size_t n) {
  if (n == 0) return 0;
  size_t ok = 0;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '\t' || c == '\r' || c == '\n' || (c >= 0x20 && c != 0x7F)) ok++;
  }
  return ok * 100 >= n * 90;
}

void web_decode_b64_fragments(const char *s, int min_len, buf_t *out) {
  if (!s) return;
  if (min_len < 8) min_len = 8;
  const char *p = s;
  while (*p) {

    while (*p && !(isalnum((unsigned char)*p) || *p == '+' || *p == '/' || *p == '=' ||
                   *p == '-' || *p == '_')) p++;
    const char *start = p;
    while (*p && (isalnum((unsigned char)*p) || *p == '+' || *p == '/' || *p == '=' ||
                  *p == '-' || *p == '_')) p++;
    size_t n = (size_t)(p - start);
    if (n < (size_t)min_len) continue;

    int has_sym = 0;
    for (size_t i = 0; i < n; i++) {
      char c = start[i];
      if (!isalnum((unsigned char)c)) { has_sym = 1; break; }
    }
    if (!has_sym && n < 24) continue;
    buf_t dec;
    buf_init(&dec);
    int got = b64_decode(start, n, &dec);
    if (got > 0 && dec.data && printable_ratio_ok(dec.data, dec.len) && utf8_valid(dec.data)) {
      buf_puts(out, "\n[b64] ");
      buf_putn(out, dec.data, dec.len);
    } else if (got < 0) {

    }
    buf_free(&dec);
  }
}

void web_scan_text(buf_t *out, const char *raw) {
  if (!out || !raw) return;
  buf_t a, b, c;
  buf_init(&a);
  buf_init(&b);
  buf_init(&c);
  web_strip_invisible(&a, raw);
  web_decode_entities(&b, a.data ? a.data : "");
  web_merge_js_strings(&c, b.data ? b.data : "");
  buf_puts(out, c.data ? c.data : "");
  web_decode_b64_fragments(c.data ? c.data : "", 12, out);
  buf_free(&a);
  buf_free(&b);
  buf_free(&c);
}

static const char *attr_value(const char *tag, const char *attr, size_t *vlen) {
  size_t al = strlen(attr);
  const char *p = tag;
  while ((p = str_icase_find(p, attr)) != NULL) {

    if (p != tag && p[-1] != ' ' && p[-1] != '\t' && p[-1] != '\n' && p[-1] != '\r') {
      p += al;
      continue;
    }
    const char *q = p + al;
    while (*q == ' ') q++;
    if (*q != '=') { p = q; continue; }
    q++;
    while (*q == ' ') q++;
    if (*q == '"' || *q == '\'') {
      char quote = *q++;
      const char *e = strchr(q, quote);
      if (!e) return NULL;
      if (vlen) *vlen = (size_t)(e - q);
      return q;
    }
    const char *e = q + strcspn(q, " \t\r\n>");
    if (vlen) *vlen = (size_t)(e - q);
    return q;
  }
  return NULL;
}

void web_attr_values(const char *html, const char *attr, json_t *out, int max) {
  if (!html || !attr || !out) return;
  const char *p = html;
  while (*p && j_len(out) < max) {
    const char *lt = strchr(p, '<');
    if (!lt) break;
    const char *gt = strchr(lt, '>');
    if (!gt) break;
    const char *tag_start = lt + 1;
    while (*tag_start == '/') tag_start++;
    const char *tag_end = tag_start;
    while (*tag_end && !isspace((unsigned char)*tag_end) && *tag_end != '>' && *tag_end != '/') tag_end++;
    size_t nlen = (size_t)(tag_end - tag_start);
    size_t vlen = 0;
    const char *v = attr_value(lt, attr, &vlen);
    if (v && vlen > 0 && vlen < 2048) {
      json_t *o = j_obj();
      char name[64];
      snprintf(name, sizeof(name), "%.*s", (int)(nlen < 63 ? nlen : 63), tag_start);
      j_set_str(o, "tag", name);
      char *val = xstrndup(v, vlen);
      j_set_str(o, "value", val);
      free(val);
      j_add(out, o);
    }
    p = gt + 1;
  }
}

void web_script_refs(const char *html, json_t *out, int max) {
  if (!html || !out) return;
  json_t *srcs = j_arr();
  web_attr_values(html, "src", srcs, max * 2);
  for (int i = 0; i < j_len(srcs) && j_len(out) < max; i++) {
    if (!str_ieq(j_s(j_at(srcs, i), "tag", ""), "script")) continue;
    json_t *o = j_obj();
    j_set_str(o, "kind", "script");
    j_set_str(o, "url", j_s(j_at(srcs, i), "value", ""));
    j_add(out, o);
  }
  json_free(srcs);

  const char *p = html;
  while (*p && j_len(out) < max) {
    const char *lt = str_icase_find(p, "<link");
    if (!lt) break;
    const char *gt = strchr(lt, '>');
    if (!gt) break;
    if (str_icontains(lt, "stylesheet")) {
      size_t vlen = 0;
      const char *v = attr_value(lt, "href", &vlen);
      if (v && vlen > 0 && vlen < 2048) {
        json_t *o = j_obj();
        j_set_str(o, "kind", "style");
        char *val = xstrndup(v, vlen);
        j_set_str(o, "url", val);
        free(val);
        j_add(out, o);
      }
    }
    p = gt + 1;
  }
}

void web_regions(const char *html, json_t *out, int max) {
  if (!html || !out) return;
  const char *p = html;
  while (*p && j_len(out) < max) {
    if (p[0] == '<' && p[1] == '!' && p[2] == '-' && p[3] == '-') {
      const char *e = strstr(p + 4, "-->");
      const char *body = p + 4;
      size_t n = e ? (size_t)(e - body) : strlen(body);
      if (n > 0) {
        json_t *o = j_obj();
        j_set_str(o, "kind", "comment");
        char *txt = xstrndup(body, n > 4000 ? 4000 : n);
        j_set_str(o, "text", txt);
        free(txt);
        j_add(out, o);
      }
      p = e ? e + 3 : p + strlen(p);
      continue;
    }
    if (str_icase_find(p, "<script") == p) {
      const char *gt = strchr(p, '>');
      if (!gt) break;

      if (!attr_value(p, "src", NULL)) {
        const char *close = str_icase_find(gt, "</script");
        size_t n = close ? (size_t)(close - gt - 1) : 0;
        if (n > 0) {
          json_t *o = j_obj();
          j_set_str(o, "kind", "script");
          char *txt = xstrndup(gt + 1, n > 6000 ? 6000 : n);
          j_set_str(o, "text", txt);
          free(txt);
          j_add(out, o);
        }
        p = close ? close + 9 : gt + 1;
        continue;
      }
      p = gt + 1;
      continue;
    }
    if (str_icase_find(p, "<style") == p) {
      const char *gt = strchr(p, '>');
      const char *close = gt ? str_icase_find(gt, "</style") : NULL;
      size_t n = (gt && close) ? (size_t)(close - gt - 1) : 0;
      if (n > 0) {
        json_t *o = j_obj();
        j_set_str(o, "kind", "style");
        char *txt = xstrndup(gt + 1, n > 6000 ? 6000 : n);
        j_set_str(o, "text", txt);
        free(txt);
        j_add(out, o);
      }
      p = close ? close + 8 : (gt ? gt + 1 : p + 1);
      continue;
    }
    p++;
  }
}


#include "tool_api.h"

int do_fetch(tool_ctx_t *ctx, const char *url, const char *method,
                    int *status, char **body, char **err) {
  if (!ctx->io.fetch) {
    if (err) *err = xstrdup("取数通道未就绪");
    return -1;
  }
  size_t len = 0;
  int rc = ctx->io.fetch(ctx->io.userdata, url, method, status, body, &len, err);
  ctx->http_calls++;
  return rc;
}

int scope_ok(tool_ctx_t *ctx, const char *url) {
  if (!ctx->io.in_scope) return 1;
  return ctx->io.in_scope(ctx->io.userdata, url);
}

void value_text(buf_t *out, json_t *v) {
  if (!v) {
    buf_puts(out, "(未设置)");
    return;
  }
  if (v->type == J_STR) {
    buf_puts(out, v->str ? v->str : "");
    return;
  }
  if (v->type == J_NULL) {
    buf_puts(out, "null");
    return;
  }
  char *d = json_dump(v);
  buf_puts(out, d ? d : "");
  free(d);
}

void join_keys(buf_t *out, json_t *obj) {
  if (!obj || obj->type != J_OBJ) return;
  for (int i = 0; i < obj->count; i++) {
    if (!obj->keys[i]) continue;
    if (out->len) buf_puts(out, "、");
    buf_puts(out, obj->keys[i]);
  }
}

void settings_audit(tool_ctx_t *ctx, const char *action, const char *target,
                           const char *detail) {
  if (!ctx || !ctx->store) return;
  store_audit((store_t *)ctx->store, action, target ? target : "", 1,
              detail ? detail : "", ctx->task_id, ctx->run_id);
}

json_t *obj_arg(json_t *args, const char *key) {
  json_t *v = j_get(args, key);
  if (!v) return NULL;
  if (v->type == J_OBJ || v->type == J_ARR) {
    char *d = json_dump(v);
    json_t *cp = d ? json_parse(d) : NULL;
    free(d);
    return cp;
  }
  if (v->type == J_STR && v->str && v->str[0]) return json_parse(v->str);
  return NULL;
}

json_t *value_arg(json_t *args, const char *key) {
  json_t *v = j_get(args, key);
  if (!v) return NULL;
  if (v->type == J_STR) {
    json_t *parsed = (v->str && v->str[0]) ? json_parse(v->str) : NULL;
    return parsed ? parsed : j_str(v->str ? v->str : "");
  }
  char *d = json_dump(v);
  json_t *cp = d ? json_parse(d) : NULL;
  free(d);
  return cp;
}

int top_key_of(const char *path, char *out, size_t cap) {
  if (!path || !*path || !out || cap == 0) return 0;
  const char *dot = strchr(path, '.');
  size_t n = dot ? (size_t)(dot - path) : strlen(path);
  if (n == 0 || n >= cap) return 0;
  memcpy(out, path, n);
  out[n] = 0;
  return 1;
}

int deep_set(json_t *root, const char *path, json_t *value) {
  if (!root || root->type != J_OBJ || !path || !*path) return 0;
  const char *dot = strchr(path, '.');
  if (!dot) {
    j_set(root, path, value);
    return 1;
  }
  char head[128];
  size_t n = (size_t)(dot - path);
  if (n == 0 || n >= sizeof(head)) return 0;
  memcpy(head, path, n);
  head[n] = 0;
  json_t *child = j_get(root, head);
  if (!child || child->type != J_OBJ) {
    child = j_obj();
    j_set(root, head, child);
  }
  return deep_set(child, dot + 1, value);
}

int settings_fail(tool_result_t *out, buf_t *msg) {
  out->is_error = 1;
  out->text = buf_take(msg);
  out->say = xstrdup("这个设置我没有改动。");
  return -1;
}

void mask_into(buf_t *out, const char *s, int len) {
  if (len <= 4) { for (int i = 0; i < len; i++) buf_putc_(out, '*'); return; }
  buf_putn(out, s, 2);
  for (int i = 2; i < len - 2; i++) buf_putc_(out, '*');
  buf_putn(out, s + len - 2, 2);
}

int tools_regex_first(const char *pattern, const char *text, int *off, int *len) {
  if (!pattern || !text) return 0;
  char err[128];
  return rx_find(pattern, text, off, len, err, sizeof(err));
}

static int seen_has(json_t *seen, const char *key) {
  for (int i = 0; i < j_len(seen); i++) {
    json_t *it = j_at(seen, i);
    if (it && it->type == J_STR && it->str && strcmp(it->str, key) == 0) return 1;
  }
  return 0;
}

static int scan_pass(const char *text, const char *via, json_t *hits, json_t *seen) {
  int count = 0;
  int rules_n = rules_arr_count("patterns.sensitive");
  for (int r = 0; r < rules_n; r++) {
    const char *kind = rules_arr_str("patterns.sensitive", r, "kind", "");
    const char *pattern = rules_arr_str("patterns.sensitive", r, "pattern", "");
    const char *severity = rules_arr_str("patterns.sensitive", r, "severity", "中");
    if (!pattern[0]) continue;
    char rerr[128] = {0};
    rx_pattern *re = rx_compile(pattern, rerr, sizeof(rerr));
    if (!re) {

      log_warn("[规则] 敏感信息正则不合法,已跳过: %s(%s)", pattern, rerr);
      continue;
    }
    const char *scan = text;
    int searched = 0;
    while (searched < 200) {
      int off = 0, len = 0;
      if (!rx_search(re, scan, &off, &len)) break;
      buf_t masked;
      buf_init(&masked);
      mask_into(&masked, scan + off, len);
      const char *label = kind[0] ? kind : pattern;
      char key[512];
      snprintf(key, sizeof(key), "%s|%s", label, masked.data ? masked.data : "");
      if (!seen_has(seen, key)) {
        json_t *h = j_obj();
        j_set_str(h, "kind", label);
        j_set_str(h, "severity", severity);
        j_set_str(h, "masked", masked.data ? masked.data : "");
        j_set_str(h, "rule", pattern);
        if (via && *via) j_set_str(h, "via", via);
        j_add(hits, h);
        j_add(seen, j_str(key));
        count++;
      }
      buf_free(&masked);
      scan += off + len;
      searched++;
      if (off + len <= 0) break;
    }
    rx_free(re);
  }
  return count;
}

int scan_text_into(tool_ctx_t *ctx, const char *text, json_t *hits) {
  if (!text) return 0;
  if (rules_arr_count("patterns.sensitive") == 0) {
    log_warn("[规则] patterns.sensitive 为空:敏感信息扫描没有可用规则");
  }
  json_t *seen = j_arr();
  int count = scan_pass(text, NULL, hits, seen);

  buf_t norm;
  buf_init(&norm);
  if (strlen(text) < 8u * 1024u * 1024u) web_scan_text(&norm, text);
  const char *normText = (norm.data && strcmp(norm.data, text) != 0) ? norm.data : NULL;
  if (normText) count += scan_pass(normText, "还原", hits, seen);

  for (int pass = 0; pass < 2; pass++) {
    const char *src = pass == 0 ? text : normText;
    if (!src) continue;
    char kind[64], sev[16], masked[160];
    kind[0] = sev[0] = masked[0] = 0;
    if (!profile_scan_text(src, kind, sizeof(kind), sev, sizeof(sev), masked, sizeof(masked))) continue;
    char key[512];
    snprintf(key, sizeof(key), "%s|%s", kind, masked);
    if (seen_has(seen, key)) continue;
    json_t *h = j_obj();
    j_set_str(h, "kind", kind);
    j_set_str(h, "severity", sev);
    j_set_str(h, "masked", masked);
    j_set_str(h, "rule", "本单位敏感信息定义");
    if (pass == 1) j_set_str(h, "via", "还原");
    j_add(hits, h);
    j_add(seen, j_str(key));
    count++;
  }
  buf_free(&norm);
  json_free(seen);

  (void)ctx;
  return count;
}

int looks_like_html(const char *ct) {
  return !ct || !*ct || str_icontains(ct, "html") || str_icontains(ct, "text/plain");
}

void extract_links(const char *html, json_t *out) {
  static const char *attrs[] = {"href=\"", "src=\"", "action=\""};
  for (size_t a = 0; a < sizeof(attrs) / sizeof(attrs[0]); a++) {
    const char *p = html;
    while ((p = strstr(p, attrs[a])) != NULL) {
      p += strlen(attrs[a]);
      const char *end = strchr(p, '"');
      if (!end) break;
      size_t n = (size_t)(end - p);
      if (n > 0 && n < 1024) {
        char *link = xstrndup(p, n);
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

const char *classify_kind(const char *url) {
  const char *path = strstr(url, "://");
  path = path ? strchr(path + 3, '/') : url;
  if (!path) return "页面";
  const char *dot = strrchr(path, '.');
  const char *q = strchr(path, '?');
  if (q && (!dot || q < dot)) return "接口";
  if (!dot) return str_endswith(path, "/") ? "页面" : "其他";
  if (str_icontains(dot, ".css") || str_icontains(dot, ".js") || str_icontains(dot, ".png") ||
      str_icontains(dot, ".jpg") || str_icontains(dot, ".gif") || str_icontains(dot, ".svg") ||
      str_icontains(dot, ".ico") || str_icontains(dot, ".woff") || str_icontains(dot, ".map")) {
    return "静态资源";
  }
  if (str_icontains(path, "/api/") || str_icontains(path, "/ajax/")) return "接口";
  return "页面";
}

void url_path_query(const char *url, char *out, size_t cap) {
  const char *p = strstr(url, "://");
  p = p ? strchr(p + 3, '/') : strchr(url, '/');
  snprintf(out, cap, "%s", p && p[0] ? p : "/");
}

void url_origin(const char *url, char *out, size_t cap) {
  const char *scheme = strstr(url, "://");
  const char *hoststart = scheme ? scheme + 3 : url;
  size_t n = (size_t)(hoststart - url) + strcspn(hoststart, "/?#");
  if (n >= cap) n = cap - 1;
  memcpy(out, url, n);
  out[n] = 0;
}

void path_normalize(const char *in, char *out, size_t cap) {
  char tmp[2048];
  snprintf(tmp, sizeof(tmp), "%s", in && in[0] ? in : "/");
  char *q = strpbrk(tmp, "?#");
  if (q) *q = 0;
  int want_dir = tmp[0] && tmp[strlen(tmp) - 1] == '/';
  const char *seg[128];
  int n = 0;
  for (char *s = tmp; *s;) {
    while (*s == '/') s++;
    if (!*s) break;
    char *e = s + strcspn(s, "/");
    char save = *e;
    *e = 0;
    if (strcmp(s, ".") == 0) {

    } else if (strcmp(s, "..") == 0) {
      if (n > 0) n--;
    } else if (n < 128) {
      seg[n++] = s;
    }
    if (!save) break;
    s = e + 1;
  }
  buf_t b;
  buf_init(&b);
  for (int i = 0; i < n; i++) {
    buf_putc_(&b, '/');
    buf_puts(&b, seg[i]);
  }
  if (n == 0) buf_putc_(&b, '/');
  else if (want_dir) buf_putc_(&b, '/');
  snprintf(out, cap, "%s", b.data ? b.data : "/");
  buf_free(&b);
}

void url_resolve(const char *base_url, const char *link, char *out, size_t cap) {
  out[0] = 0;
  if (!link || !*link) return;
  char origin[512];
  url_origin(base_url, origin, sizeof(origin));
  if (str_startswith(link, "http://") || str_startswith(link, "https://")) {
    snprintf(out, cap, "%s", link);
    return;
  }
  if (str_startswith(link, "//")) {
    const char *scheme_end = strstr(base_url, "://");
    snprintf(out, cap, "%.*s%s", (int)(scheme_end ? scheme_end - base_url : 0), base_url, link);
    return;
  }
  if (link[0] == '#') {
    return;
  }
  if (link[0] == '?') {
    char bq[2048];
    url_path_query(base_url, bq, sizeof(bq));
    char *q = strpbrk(bq, "?#");
    if (q) *q = 0;
    snprintf(out, cap, "%s%s%s", origin, bq, link);
    return;
  }
  char base_path[2048];
  url_path_query(base_url, base_path, sizeof(base_path));
  char *q = strpbrk(base_path, "?#");
  if (q) *q = 0;
  char joined[2048];
  if (link[0] == '/') {
    snprintf(joined, sizeof(joined), "%s", link);
  } else {

    char *slash = strrchr(base_path, '/');
    size_t dlen = slash ? (size_t)(slash - base_path) + 1 : 1;
    if (dlen >= sizeof(joined)) dlen = sizeof(joined) - 1;
    memcpy(joined, base_path, dlen);
    joined[dlen] = 0;
    snprintf(joined + dlen, sizeof(joined) - dlen, "%s", link);
  }
  char norm[2048];
  path_normalize(joined, norm, sizeof(norm));
  snprintf(out, cap, "%s%s", origin, norm);
}

int path_in_scope(const char *path, const char *scope) {
  if (!scope || !scope[0] || strcmp(scope, "/") == 0) return 1;
  size_t pl = strlen(scope), ql = path ? strlen(path) : 0;
  if (ql < pl) return 0;
  if (strncmp(path, scope, pl) != 0) return 0;
  if (scope[pl - 1] == '/') return 1;
  return path[pl] == 0 || path[pl] == '/' || path[pl] == '?';
}

void t_fetch_m(tool_ctx_t *ctx, const char *url, const char *method, fetch_t *f) {
  memset(f, 0, sizeof(*f));
  if (ctx->io.fetch_ex) {
    ctx->io.fetch_ex(ctx->io.userdata, url, method, &f->status, &f->headers,
                     &f->body, NULL, &f->err);
  } else if (ctx->io.fetch) {
    ctx->io.fetch(ctx->io.userdata, url, method, &f->status, &f->body, NULL, &f->err);
  } else {
    f->err = xstrdup("取数通道未就绪");
  }
  ctx->http_calls++;
}

void t_fetch(tool_ctx_t *ctx, const char *url, fetch_t *f) {
  t_fetch_m(ctx, url, "GET", f);
}

void fetch_free2(fetch_t *f) {
  free(f->headers);
  free(f->body);
  free(f->err);
  f->headers = f->body = f->err = NULL;
}

void probe_root(const char *url, char *out, size_t cap) {
  const char *p = url ? url : "";
  const char *scheme = strstr(p, "://");
  const char *hoststart = scheme ? scheme + 3 : p;
  const char *end = hoststart + strcspn(hoststart, "/?#");
  size_t path_len = 0;
  if (*end == '/') {
    while (end[path_len] && end[path_len] != '?' && end[path_len] != '#') path_len++;
    while (path_len > 0 && end[path_len - 1] == '/') path_len--;
  }
  if (!scheme) {

    char h[256];
    int port = net_host_port_of(p, h, sizeof(h));
    const char *proto = (port == 443) ? "https" : (port > 0 ? "http" : "https");
    int n = snprintf(out, cap, "%s://%.*s%.*s", proto, (int)(end - p), p, (int)path_len, end);
    if (n < 0) out[0] = 0;
    return;
  }
  size_t n = (size_t)(end - p) + path_len;
  if (n >= cap) n = cap - 1;
  memcpy(out, p, n);
  out[n] = 0;
}

void normalize_target(const char *in, char *out, size_t cap) {
  const char *s = in ? in : "";
  while (*s == ' ' || *s == '"') s++;
  if (strstr(s, "://")) snprintf(out, cap, "%s", s);
  else {

    char h[256];
    int port = net_host_port_of(s, h, sizeof(h));
    snprintf(out, cap, "%s://%s", (port == 443 || port <= 0) ? "https" : "http", s);
  }
  char *e = out + strlen(out);
  while (e > out && (e[-1] == ' ' || e[-1] == '"')) *--e = 0;
}

void join_path(char *out, size_t cap, const char *root, const char *path) {
  size_t n = strlen(root);
  while (n > 0 && root[n - 1] == '/') n--;
  if (path && path[0] == '/') snprintf(out, cap, "%.*s%s", (int)n, root, path);
  else snprintf(out, cap, "%.*s/%s", (int)n, root, path ? path : "");
}

void calib_free(calib_t *c) { buf_free(&c->shape); }

void calib_run(tool_ctx_t *ctx, const char *root, calib_t *c) {
  memset(c, 0, sizeof(*c));
  buf_init(&c->shape);
  char url[1024];
  long long rnd = now_ms() % 99991;
  snprintf(c->sample, sizeof(c->sample), "/%s_%lld_%s", "no-such-path", rnd, "zz");
  join_path(url, sizeof(url), root, c->sample);
  fetch_t f;
  t_fetch(ctx, url, &f);
  if (f.err && !f.status) {
    c->valid = 0;
    fetch_free2(&f);
    return;
  }
  c->valid = 1;
  c->status = f.status;
  c->bytes = f.body ? strlen(f.body) : 0;
  web_shape(&c->shape, f.body ? f.body : "");
  fetch_free2(&f);
}

int calib_matches(const calib_t *c, int status, const char *body) {
  if (!c->valid) return 0;
  if (status != c->status) return 0;
  size_t bytes = body ? strlen(body) : 0;
  double diff = (double)bytes > (double)c->bytes ? (double)bytes - (double)c->bytes
                                                : (double)c->bytes - (double)bytes;
  double ratio = c->bytes > 0 ? diff / (double)c->bytes : (bytes ? 1.0 : 0.0);
  if (diff > 64 && ratio > 0.06) return 0;
  buf_t sh;
  buf_init(&sh);
  web_shape(&sh, body ? body : "");
  int same = strcmp(sh.data ? sh.data : "", c->shape.data ? c->shape.data : "") == 0;
  buf_free(&sh);
  return same;
}

void link_analysis(const char *body, const char *own_host, json_t *hosts,
                          json_t *suspicious) {
  json_t *links = j_arr();
  web_extract_links(body, links);
  int tld_n = 0;
  const char **tlds = rules_str_list("suspicious_tlds", &tld_n);
  for (int i = 0; i < j_len(links); i++) {
    json_t *l = j_at(links, i);
    if (!l || l->type != J_STR) continue;
    const char *u = l->str;
    if (!str_startswith(u, "http://") && !str_startswith(u, "https://") &&
        !str_startswith(u, "//")) {
      continue;
    }
    char host[256];
    web_url_parts(str_startswith(u, "//") ? "" : u, host, sizeof(host), NULL, 0);
    if (!host[0] || str_ieq(host, own_host)) continue;
    int dup = 0;
    for (int k = 0; k < j_len(hosts); k++) {
      if (str_ieq(j_at(hosts, k)->str, host)) { dup = 1; break; }
    }
    if (!dup) j_add(hosts, j_str(host));

    int bad = 0;
    for (int t = 0; t < tld_n; t++) {
      size_t lh = strlen(host), lt = strlen(tlds[t]);
      if (lh > lt && str_ieq(host + (lh - lt), tlds[t])) { bad = 1; break; }
    }
    int digits = 0, dots = 0;
    for (const char *c = host; *c; c++) {
      if (*c >= '0' && *c <= '9') digits++;
      else if (*c == '.') dots++;
    }
    if (dots == 3 && digits >= 4) bad = 1;
    if (bad) {
      int seen = 0;
      for (int k = 0; k < j_len(suspicious); k++) {
        if (str_icontains(j_at(suspicious, k)->str, host)) { seen = 1; break; }
      }
      if (!seen) j_add(suspicious, j_str(u));
    }
  }
  json_free(links);
}

void put_rules_note(json_t *data) {
  j_set_str(data, "rules_source", rules_source());
  j_set_bool(data, "rules_from_file", rules_from_file());
}

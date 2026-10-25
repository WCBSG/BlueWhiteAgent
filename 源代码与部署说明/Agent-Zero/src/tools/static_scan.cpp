
#include "tool_api.h"

static int version_of(const char *text, char *out, size_t cap) {
  if (!text) return 0;
  const char *p = text;
  while (*p) {
    if (isdigit((unsigned char)*p)) {
      int a = 0, b = 0, c = 0;
      if (sscanf(p, "%d.%d.%d", &a, &b, &c) == 3) {
        snprintf(out, cap, "%d.%d.%d", a, b, c);
        return 1;
      }
      if (sscanf(p, "%d.%d", &a, &b) == 2) {
        snprintf(out, cap, "%d.%d", a, b);
        return 1;
      }

      while (isdigit((unsigned char)*p) || *p == '.') p++;
      continue;
    }
    p++;
  }
  return 0;
}

static int version_lt(const char *a, const char *b) {
  int a1 = 0, a2 = 0, a3 = 0, b1 = 0, b2 = 0, b3 = 0;
  sscanf(a, "%d.%d.%d", &a1, &a2, &a3);
  sscanf(b, "%d.%d.%d", &b1, &b2, &b3);
  if (a1 != b1) return a1 < b1;
  if (a2 != b2) return a2 < b2;
  return a3 < b3;
}

static void scan_behaviors(const char *path, const char *text, const char *label,
                           json_t *hits, int max) {
  int n = rules_arr_count(path);
  for (int i = 0; i < n && j_len(hits) < max; i++) {
    int any_n = rules_sub_count(path, i, "any");
    int all_n = rules_sub_count(path, i, "all");
    const char *first_hit = NULL;
    int any_ok = any_n == 0;
    for (int k = 0; k < any_n; k++) {
      const char *needle = rules_sub_str(path, i, "any", k, "");
      if (needle[0] && str_icontains(text, needle)) { any_ok = 1; first_hit = needle; break; }
    }
    if (!any_ok) continue;
    int all_ok = 1;
    for (int k = 0; k < all_n; k++) {
      const char *needle = rules_sub_str(path, i, "all", k, "");
      if (needle[0] && !str_icontains(text, needle)) { all_ok = 0; break; }
    }
    if (!all_ok) continue;
    int and_n = rules_sub_count(path, i, "and_any");
    if (and_n > 0) {
      int hit = 0;
      for (int k = 0; k < and_n; k++) {
        const char *needle = rules_sub_str(path, i, "and_any", k, "");
        if (needle[0] && str_icontains(text, needle)) { hit = 1; first_hit = needle; break; }
      }
      if (!hit) continue;
    }

    json_t *h = j_obj();
    j_set_str(h, "id", rules_arr_str(path, i, "id", ""));
    j_set_str(h, "title", rules_arr_str(path, i, "title", ""));
    j_set_str(h, "severity", rules_arr_str(path, i, "severity", "低"));
    j_set_str(h, "impact", rules_arr_str(path, i, "impact", ""));
    j_set_str(h, "fix", rules_arr_str(path, i, "fix", ""));
    j_set_str(h, "url", label);
    j_set_str(h, "evidence", first_hit ? first_hit : "");
    j_add(hits, h);
  }
}

static int hit_exists(json_t *hits, const char *id, const char *url) {
  for (int i = 0; i < j_len(hits); i++) {
    json_t *h = j_at(hits, i);
    if (strcmp(j_s(h, "id", ""), id) == 0 && str_ieq(j_s(h, "url", ""), url)) return 1;
  }
  return 0;
}

static void scan_html_regions(const char *page_url, const char *html, json_t *hits) {
  json_t *regions = j_arr();
  web_regions(html, regions, 20);
  for (int i = 0; i < j_len(regions); i++) {
    const char *kind = j_s(j_at(regions, i), "kind", "");
    const char *txt = j_s(j_at(regions, i), "text", "");
    if (!txt[0]) continue;
    buf_t norm;
    buf_init(&norm);
    web_scan_text(&norm, txt);
    const char *t = norm.data ? norm.data : "";
    if (strcmp(kind, "comment") == 0) {

      if (!hit_exists(hits, "comment-content", page_url)) {
        json_t *h = j_obj();
        j_set_str(h, "id", "comment-content");
        j_set_str(h, "title", "页面注释里留有不该公开的内容");
        j_set_str(h, "severity", "低");
        j_set_str(h, "url", page_url);
        j_set_str(h, "evidence", t);
        j_set_str(h, "impact", "注释随页面一起发送给任何访问者,常含内部地址、账号或待办说明");
        j_set_str(h, "fix", "发布前清理模板注释;把它纳入上线检查");
        j_add(hits, h);
      }
    } else {
      scan_behaviors("static_scan.js_behaviors", t, page_url, hits, 40);
      if (strcmp(kind, "style") == 0) {
        scan_behaviors("static_scan.css_behaviors", t, page_url, hits, 40);
      }
    }
    buf_free(&norm);
  }
  json_free(regions);

  buf_t whole;
  buf_init(&whole);
  web_scan_text(&whole, html);
  json_t *more = j_arr();
  scan_behaviors("static_scan.js_behaviors", whole.data ? whole.data : "", page_url, more, 40);
  for (int i = 0; i < j_len(more); i++) {
    json_t *h = j_at(more, i);
    if (!hit_exists(hits, j_s(h, "id", ""), page_url)) j_add(hits, j_clone(h));
  }
  json_free(more);
  buf_free(&whole);
}

static void add_target(json_t *targets, const char *root, const char *link, int max_files) {
  char abs[1024];
  url_resolve(root, link, abs, sizeof(abs));
  if (!abs[0]) return;
  for (int k = 0; k < j_len(targets); k++) {
    if (str_ieq(j_at(targets, k)->str, abs)) return;
  }
  if (j_len(targets) < max_files) j_add(targets, j_str(abs));
}

int t_static_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  int max_files = (int)rules_number("static_scan.max_files", 12);
  if (max_files < 1) max_files = 12;
  if (max_files > 40) max_files = 40;
  int max_bytes = (int)rules_number("static_scan.max_bytes", 200000);
  if (max_bytes < 4096) max_bytes = 200000;

  char root[512];
  probe_root(j_s(args, "target", ""), root, sizeof(root));

  json_t *targets = j_arr();
  json_t *hits = j_arr();
  json_t *pages = j_arr();
  int page_requests = 0;

  if (root[0]) j_add(pages, j_str(root));
  {
    json_t *pg = j_get(args, "pages");
    if (pg && pg->type == J_ARR) {
      for (int i = 0; i < j_len(pg) && j_len(pages) < 8; i++) {
        json_t *v = j_at(pg, i);
        const char *u = (v && v->type == J_STR) ? v->str : "";
        if (!u[0]) continue;
        char key[512];
        web_url_key(u, key, sizeof(key));
        int dup = 0;
        for (int k = 0; k < j_len(pages); k++) {
          char kk[512];
          web_url_key(j_at(pages, k)->str, kk, sizeof(kk));
          if (str_ieq(kk, key)) dup = 1;
        }
        if (!dup) j_add(pages, j_str(u));
      }
    }
  }

  for (int i = 0; i < j_len(pages); i++) {
    const char *pu = j_at(pages, i)->str;
    if (!scope_ok(ctx, pu)) continue;
    fetch_t f;
    t_fetch(ctx, pu, &f);
    page_requests++;
    if (!(f.err && !f.status) && f.body && f.body[0]) {
      scan_html_regions(pu, f.body, hits);
      json_t *refs = j_arr();
      web_script_refs(f.body, refs, max_files * 2);
      for (int k = 0; k < j_len(refs); k++) add_target(targets, pu, j_s(j_at(refs, k), "url", ""), max_files);
      json_free(refs);
    }
    fetch_free2(&f);
  }

  {
    json_t *given = j_get(args, "urls");
    if (given && given->type == J_ARR && j_len(given) > 0) {
      json_free(targets);
      targets = j_arr();
      for (int i = 0; i < j_len(given) && i < max_files; i++) {
        json_t *v = j_at(given, i);
        if (v && v->type == J_STR && v->str && v->str[0]) j_add(targets, j_str(v->str));
      }
    }
  }

  json_t *components = j_arr();
  int scanned = 0, unreachable = 0, skipped = 0;

  for (int i = 0; i < j_len(targets) && scanned < max_files; i++) {
    const char *url = j_at(targets, i)->str;
    if (!scope_ok(ctx, url)) { skipped++; continue; }
    fetch_t f;
    t_fetch(ctx, url, &f);
    scanned++;
    if (f.err && !f.status) { unreachable++; fetch_free2(&f); continue; }
    if ((f.status < 200 || f.status >= 300) || !f.body || !f.body[0]) { fetch_free2(&f); continue; }

    size_t blen = strlen(f.body);
    if (blen > (size_t)max_bytes) blen = (size_t)max_bytes;
    char *text = xstrndup(f.body, blen);

    buf_t norm;
    buf_init(&norm);
    web_scan_text(&norm, text);
    scan_behaviors("static_scan.js_behaviors", norm.data ? norm.data : "", url, hits, 40);

    const char *dot = strrchr(url, '.');
    if (dot && str_ieq(dot, ".css")) {
      scan_behaviors("static_scan.css_behaviors", norm.data ? norm.data : "", url, hits, 40);
    }

    {
      int cn = rules_arr_count("static_scan.component_patterns");
      for (int c = 0; c < cn; c++) {
        const char *name = rules_arr_str("static_scan.component_patterns", c, "name", "");
        const char *hint = rules_arr_str("static_scan.component_patterns", c, "file_hint", "");
        const char *below = rules_arr_str("static_scan.component_patterns", c, "vulnerable_below", "");
        if (!name[0] || !below[0]) continue;

        int named = 0;
        if (hint[0] && str_icontains(url, hint)) named = 1;
        if (!named && str_icontains(text, name)) named = 1;
        if (!named) continue;

        char ver[32] = "";

        const char *at = str_icase_find(text, name);
        for (int tries = 0; at && tries < 3; tries++) {
          if (version_of(at, ver, sizeof(ver))) break;
          const char *next = str_icase_find(at + 1, name);
          if (!next) break;
          at = next;
        }
        if (!ver[0]) version_of(url, ver, sizeof(ver));
        if (!ver[0]) continue;

        if (version_lt(ver, below)) {
          json_t *c2 = j_obj();
          j_set_str(c2, "name", name);
          j_set_str(c2, "version", ver);
          j_set_str(c2, "fixed_in", below);
          j_set_str(c2, "severity",
                    rules_arr_str("static_scan.component_patterns", c, "severity", "中"));
          j_set_str(c2, "url", url);
          j_add(components, c2);
        }
      }
    }

    buf_free(&norm);
    free(text);
    fetch_free2(&f);
  }

  json_t *data = j_obj();
  j_set_str(data, "target", root);
  j_set_num(data, "pages", j_len(pages));
  j_set_num(data, "page_requests", page_requests);
  j_set_num(data, "scanned", scanned);
  j_set_num(data, "unreachable", unreachable);
  j_set_num(data, "skipped_out_of_pool", skipped);
  j_set_num(data, "hit_count", j_len(hits));
  j_set(data, "hits", hits);
  j_set_num(data, "component_count", j_len(components));
  j_set(data, "components", components);
  int page_count = j_len(pages);
  json_free(pages);
  json_free(targets);
  put_rules_note(data);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "静态资源扫描:扫了 %d 个页面、%d 个脚本/样式,发现 %d 处行为特征、%d 个受影响组件。",
             page_count, scanned, j_len(hits), j_len(components));
  for (int i = 0; i < j_len(hits); i++) {
    buf_printf(&t, "\n- [%s] %s(%s)", j_s(j_at(hits, i), "severity", ""),
               j_s(j_at(hits, i), "title", ""), j_s(j_at(hits, i), "url", ""));
  }
  for (int i = 0; i < j_len(components); i++) {
    buf_printf(&t, "\n- [组件] %s %s(建议 ≥ %s)", j_s(j_at(components, i), "name", ""),
               j_s(j_at(components, i), "version", ""), j_s(j_at(components, i), "fixed_in", ""));
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (j_len(hits) == 0 && j_len(components) == 0) {
    buf_printf(&s, "静态资源扫描完成:扫了 %d 个脚本/样式,没有发现可疑行为或受影响组件", scanned);
    if (unreachable) buf_printf(&s, "(%d 个取不到)", unreachable);
    if (skipped) buf_printf(&s, "(%d 个不在授权范围)", skipped);
    buf_puts(&s, "。");
  } else {
    buf_printf(&s, "静态资源扫描发现 %d 处行为特征、%d 个受影响组件:", j_len(hits), j_len(components));
    for (int i = 0; i < j_len(hits) && i < 6; i++) {
      buf_printf(&s, "\n  · %s(%s)", j_s(j_at(hits, i), "title", ""), j_s(j_at(hits, i), "url", ""));
    }
  }
  out->say = buf_take(&s);
  return 0;
}


#include "tool_api.h"

static void host_root_of(const char *root, char *out, size_t cap) {
  const char *scheme = strstr(root, "://");
  const char *p = scheme ? scheme + 3 : root;
  const char *slash = strchr(p, '/');
  size_t n = slash ? (size_t)(slash - root) : strlen(root);
  if (n >= cap) n = cap - 1;
  memcpy(out, root, n);
  out[n] = 0;
}

static void lead_abs(const char *root, const char *path, char *out, size_t cap) {
  char p[1024];
  snprintf(p, sizeof(p), "%s", path ? path : "");

  char *frag = strchr(p, '#');
  if (frag) *frag = 0;
  if (!p[0]) { out[0] = 0; return; }
  if (strstr(p, "://")) {

    snprintf(out, cap, "%s", p);
    return;
  }
  if (p[0] == '/') {
    char hr[512];
    host_root_of(root, hr, sizeof(hr));
    join_path(out, cap, hr, p);
    return;
  }

  char base[512];
  snprintf(base, sizeof(base), "%s", root);
  size_t bl = strlen(base);
  while (bl > 0 && base[bl - 1] == '/') base[--bl] = 0;
  snprintf(out, cap, "%s/%s", base, p);
}

static int lead_is_dir(const char *path) {
  size_t n = strlen(path);
  if (!n) return 0;
  if (path[n - 1] == '/') return 1;

  size_t plen = strcspn(path, "?#");
  const char *slash = NULL;
  for (size_t i = 0; i < plen; i++) {
    if (path[i] == '/') slash = path + i;
  }
  const char *base = slash ? slash + 1 : path;
  for (const char *q = base; q < path + plen; q++) {
    if (*q == '.') return 0;
  }
  return 1;
}

int t_lead_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char root[512];
  probe_root(j_s(args, "target", ""), root, sizeof(root));

  int max_leads = (int)rules_number("leads.max_leads", 40);
  if (max_leads < 1) max_leads = 40;
  if (max_leads > 120) max_leads = 120;

  int skip_n = 0;
  const char **skip_ext = rules_str_list("leads.skip_ext", &skip_n);

  json_t *leads = j_arr();
  json_t *sources = j_arr();
  int fetched = 0, unreachable = 0, skipped_scope = 0;

  json_t *seen = j_arr();

  {
    int n = 0;
    const char **rp = rules_str_list("leads.robots_paths", &n);
    for (int i = 0; i < n; i++) {
      char url[1024];
      join_path(url, sizeof(url), root, rp[i]);
      if (!scope_ok(ctx, url)) { skipped_scope++; continue; }
      fetch_t f;
      t_fetch(ctx, url, &f);
      fetched++;
      if (f.err && !f.status) { unreachable++; fetch_free2(&f); continue; }
      if (f.status != 200 || !f.body || !f.body[0]) { fetch_free2(&f); continue; }

      json_t *src = j_obj();
      j_set_str(src, "type", "robots");
      j_set_str(src, "url", url);
      j_add(sources, src);

      char **lines = NULL;
      int ln = str_split(f.body, '\n', &lines, 0);
      for (int k = 0; k < ln && j_len(leads) < max_leads; k++) {
        char *line = str_trim(lines[k]);
        if (!line[0] || line[0] == '#') continue;

        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = 0;
        char *key = str_trim(line);
        char *val = str_trim(colon + 1);
        if (!val[0]) continue;
        int is_sitemap = str_ieq(key, "Sitemap");
        if (!is_sitemap && !str_ieq(key, "Disallow") && !str_ieq(key, "Allow")) continue;
        if (*val == '*' || *val == '/') {

          if (str_ieq(val, "/")) continue;
        }

        char *star = strchr(val, '*');
        if (star) *star = 0;
        char *hash = strchr(val, '#');
        if (hash) *hash = 0;
        val = str_trim(val);
        if (!val[0]) continue;

        char abs[1024];
        lead_abs(root, val, abs, sizeof(abs));
        if (!abs[0] || !scope_ok(ctx, abs)) { skipped_scope++; continue; }
        int dup = 0;
        for (int s = 0; s < j_len(seen); s++) {
          if (strcmp(j_at(seen, s)->str, abs) == 0) { dup = 1; break; }
        }
        if (dup) continue;
        j_add(seen, j_str(abs));

        const char *dot = strrchr(abs, '.');
        int skip = 0;
        if (dot) {
          for (int e = 0; e < skip_n; e++) {
            if (str_ieq(dot, skip_ext[e])) { skip = 1; break; }
          }
        }
        if (skip) continue;

        json_t *l = j_obj();
        j_set_str(l, "url", abs);
        char pathbuf[1024];
        web_url_parts(abs, NULL, 0, pathbuf, sizeof(pathbuf));
        j_set_str(l, "path", pathbuf[0] ? pathbuf : val);
        j_set_str(l, "kind", strchr(abs, '?') ? "endpoint" : (lead_is_dir(val) ? "dir" : "file"));
        j_set_str(l, "source", is_sitemap ? "robots:sitemap" : "robots");
        j_add(leads, l);
      }
      str_free_list(lines, ln);
      fetch_free2(&f);
    }
  }

  {
    int n = 0;
    const char **sp = rules_str_list("leads.sitemap_paths", &n);
    for (int i = 0; i < n; i++) {
      char url[1024];
      join_path(url, sizeof(url), root, sp[i]);
      if (!scope_ok(ctx, url)) { skipped_scope++; continue; }
      fetch_t f;
      t_fetch(ctx, url, &f);
      fetched++;
      if (f.err && !f.status) { unreachable++; fetch_free2(&f); continue; }
      if (f.status != 200 || !f.body || !f.body[0]) { fetch_free2(&f); continue; }

      if (!str_icontains(f.body, "<loc>") && !str_icontains(f.body, "http")) {
        fetch_free2(&f); continue;
      }

      json_t *src = j_obj();
      j_set_str(src, "type", "sitemap");
      j_set_str(src, "url", url);
      j_add(sources, src);

      const char *p = f.body;
      while (p && j_len(leads) < max_leads) {
        const char *lt = str_icase_find(p, "<loc>");
        if (!lt) break;
        const char *vs = lt + 5;
        const char *ve = str_icase_find(vs, "</loc>");
        if (!ve) break;
        size_t vn = (size_t)(ve - vs);
        p = ve + 6;
        if (vn == 0 || vn > 1000) continue;
        char *raw = xstrndup(vs, vn);
        char *val = str_trim(raw);

        char abs[1024];
        lead_abs(root, val, abs, sizeof(abs));
        free(raw);
        if (!abs[0] || !scope_ok(ctx, abs)) { skipped_scope++; continue; }
        int dup = 0;
        for (int s = 0; s < j_len(seen); s++) {
          if (strcmp(j_at(seen, s)->str, abs) == 0) { dup = 1; break; }
        }
        if (dup) continue;
        j_add(seen, j_str(abs));

        const char *dot = strrchr(abs, '.');
        int skip = 0;
        if (dot) {
          for (int e = 0; e < skip_n; e++) {
            if (str_ieq(dot, skip_ext[e])) { skip = 1; break; }
          }
        }
        if (skip) continue;

        json_t *l = j_obj();
        j_set_str(l, "url", abs);
        char pathbuf[1024];
        web_url_parts(abs, NULL, 0, pathbuf, sizeof(pathbuf));
        j_set_str(l, "path", pathbuf[0] ? pathbuf : abs);

        j_set_str(l, "kind", strchr(abs, '?') ? "endpoint" : (lead_is_dir(abs) ? "dir" : "file"));
        j_set_str(l, "source", "sitemap");
        j_add(leads, l);
      }
      fetch_free2(&f);
    }
  }

  json_free(seen);

  {
    json_t *kept = j_arr();
    for (int i = 0; i < j_len(leads); i++) {
      json_t *l = j_at(leads, i);
      const char *u = j_s(l, "url", "");
      int is_src = 0;
      for (int s = 0; s < j_len(sources); s++) {
        if (strcmp(j_s(j_at(sources, s), "url", ""), u) == 0) { is_src = 1; break; }
      }
      if (!is_src) j_add(kept, j_clone(l));
    }
    json_free(leads);
    leads = kept;
  }

  json_t *data = j_obj();
  j_set_str(data, "target", root);
  j_set_num(data, "fetched", fetched);
  j_set_num(data, "unreachable", unreachable);
  j_set_num(data, "skipped_out_of_pool", skipped_scope);
  j_set_num(data, "lead_count", j_len(leads));
  j_set(data, "leads", leads);
  j_set(data, "sources", sources);

  int dirs = 0, files = 0, endpoints = 0;
  for (int i = 0; i < j_len(leads); i++) {
    const char *k = j_s(j_at(leads, i), "kind", "");
    if (strcmp(k, "dir") == 0) dirs++;
    else if (strcmp(k, "endpoint") == 0) endpoints++;
    else files++;
  }
  j_set_num(data, "dirs", dirs);
  j_set_num(data, "files", files);
  j_set_num(data, "endpoints", endpoints);
  put_rules_note(data);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "线索源 %s:取了 %d 个源文件,得到 %d 条线索(目录 %d / 文件 %d / 接口 %d)。",
             root, j_len(sources), j_len(leads), dirs, files, endpoints);
  for (int i = 0; i < j_len(leads) && i < 12; i++) {
    buf_printf(&t, "\n- [%s] %s", j_s(j_at(leads, i), "kind", ""),
               j_s(j_at(leads, i), "path", ""));
  }
  if (j_len(leads) > 12) buf_printf(&t, "\n…另有 %d 条", j_len(leads) - 12);
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (j_len(leads) == 0) {
    if (fetched > 0 && unreachable == fetched) {
      buf_printf(&s, "线索源取不到:%s 的 robots/sitemap 全部请求失败。", root);
      out->is_error = 1;
      j_set_str(data, "blocked", "unreachable");
    } else {
      buf_printf(&s, "线索源检查完成:%s 没有可用的 robots.txt / sitemap", root);
      if (skipped_scope) buf_printf(&s, "(%d 条被授权池排除)", skipped_scope);
      buf_puts(&s, ";这不是问题,继续用常规探测即可。");
      j_set_str(data, "note", "no_lead_source");
    }
  } else {
    buf_printf(&s, "从站点自己公布的清单里拿到 %d 条线索(目录 %d、文件 %d、接口 %d):",
               j_len(leads), dirs, files, endpoints);
    for (int i = 0; i < j_len(leads) && i < 8; i++) {
      buf_printf(&s, "\n  · %s", j_s(j_at(leads, i), "path", ""));
    }
    if (j_len(leads) > 8) buf_printf(&s, "\n  · …另有 %d 条", j_len(leads) - 8);
  }
  out->say = buf_take(&s);
  return 0;
}

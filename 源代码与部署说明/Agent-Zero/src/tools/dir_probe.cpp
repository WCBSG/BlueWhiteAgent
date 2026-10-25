
#include "tool_api.h"

static void probed_push(json_t *arr, const char *path, int status, const char *note) {
  if (!arr || j_len(arr) >= 60) return;
  json_t *p = j_obj();
  j_set_str(p, "path", path ? path : "");
  j_set_num(p, "status", status);
  if (note && *note) j_set_str(p, "note", note);
  j_add(arr, p);
}

int t_dir_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char root[512];
  probe_root(j_s(args, "target", ""), root, sizeof(root));

  json_t *dirs = j_arr();
  int given_n = 0;
  json_t *given = j_get(args, "dirs");
  if (given && given->type == J_ARR && given->count > 0) {
    for (int i = 0; i < given->count && i < 40; i++) {
      if (j_at(given, i)->type == J_STR) {
        j_add(dirs, j_str(j_at(given, i)->str));
        given_n++;
      }
    }
  }

  {
    int also = j_b(args, "also_defaults", 0);
    if (given_n == 0 || also) {
      int n = 0;
      const char **list = rules_str_list("dir_candidates", &n);
      int cap = (int)rules_number("max_dirs", 40);
      if (cap < 1) cap = 40;
      for (int i = 0; i < n && j_len(dirs) < cap; i++) {
        int dup = 0;
        for (int k = 0; k < j_len(dirs); k++) {
          if (str_ieq(j_at(dirs, k)->str, list[i])) { dup = 1; break; }
        }
        if (!dup) j_add(dirs, j_str(list[i]));
      }
    }
  }

  calib_t calib;
  calib_run(ctx, root, &calib);

  json_t *listings = j_arr();
  json_t *entries = j_arr();
  json_t *exposed = j_arr();
  json_t *restricted = j_arr();
  json_t *live_dirs = j_arr();
  json_t *probed = j_arr();
  int tested = 0, unreachable = 0, suppressed = 0, reachable = 0, skipped = 0;
  int listing_budget = 16;

  for (int i = 0; i < j_len(dirs); i++) {
    const char *dir = j_at(dirs, i)->str;
    char url[1024];
    join_path(url, sizeof(url), root, dir);
    if (!scope_ok(ctx, url)) { skipped++; continue; }
    fetch_t f;
    t_fetch(ctx, url, &f);
    tested++;
    if (f.err && !f.status) {
      probed_push(probed, dir, 0, "请求失败");
      unreachable++;
      fetch_free2(&f);
      continue;
    }
    if (f.status == 401 || f.status == 403) {
      probed_push(probed, dir, f.status, "存在但受限");
      json_t *r = j_obj();
      j_set_str(r, "path", dir);
      j_set_num(r, "status", f.status);
      j_add(restricted, r);
      reachable++;
      fetch_free2(&f);
      continue;
    }
    if (f.status < 200 || f.status >= 400) {
      probed_push(probed, dir, f.status, "无内容");
      fetch_free2(&f);
      continue;
    }
    if (calib_matches(&calib, f.status, f.body)) {
      probed_push(probed, dir, f.status, "默认页(软 404)");
      suppressed++;
      fetch_free2(&f);
      continue;
    }
    reachable++;
    j_add(live_dirs, j_str(dir));

    const char *body = f.body ? f.body : "";
    char title[160];
    web_title(body, title, sizeof(title));

    if (web_is_dir_listing(body)) {
      probed_push(probed, dir, f.status, "目录索引");
      json_t *e = j_arr();
      web_dir_listing_entries(body, e, 12);
      json_t *l = j_obj();
      j_set_str(l, "path", dir);
      j_set_str(l, "url", url);
      j_set_str(l, "title", title);
      j_set(l, "entries", e);
      j_add(listings, l);

      for (int k = 0; k < j_len(e) && listing_budget > 0 && k < 10; k++) {
        const char *name = j_at(e, k)->str;
        if (!name[0]) continue;
        size_t nl = strlen(name);
        if (name[nl - 1] == '/') continue;
        char u2[1024];
        join_path(u2, sizeof(u2), url, name);
        if (!scope_ok(ctx, u2)) continue;
        fetch_t f2;
        t_fetch(ctx, u2, &f2);
        listing_budget--;
        tested++;
        if (f2.err && !f2.status) { fetch_free2(&f2); continue; }
        if (f2.status != 200 || !f2.body || !f2.body[0]) { fetch_free2(&f2); continue; }
        if (calib_matches(&calib, f2.status, f2.body)) { fetch_free2(&f2); continue; }
        if (web_is_dir_listing(f2.body)) { fetch_free2(&f2); continue; }
        rules_sig_t sig2;
        memset(&sig2, 0, sizeof(sig2));
        if (rules_sig_match(u2, f2.body, &sig2) == 0) {
          json_t *h2 = j_obj();
          char pbuf[1024];
          web_url_parts(u2, NULL, 0, pbuf, sizeof(pbuf));
          j_set_str(h2, "path", pbuf);
          j_set_str(h2, "url", u2);
          j_set_str(h2, "signature", sig2.name);
          j_set_str(h2, "kind", sig2.kind);
          j_set_str(h2, "severity", sig2.severity);
          j_set_str(h2, "tag", sig2.tag);
          j_set_str(h2, "evidence", sig2.evidence);
          j_set_str(h2, "found_by", "listing");
          j_add(exposed, h2);
        }
        fetch_free2(&f2);
      }
    } else if (web_has_password_form(body)) {
      probed_push(probed, dir, f.status, "登录入口");
      json_t *m = j_obj();
      j_set_str(m, "path", dir);
      j_set_str(m, "url", url);
      j_set_str(m, "title", title);
      j_add(entries, m);
    } else {
      rules_sig_t sig;
      memset(&sig, 0, sizeof(sig));
      if (rules_sig_match(dir, body, &sig) == 0) {
        probed_push(probed, dir, f.status, "内容命中签名");
        json_t *h = j_obj();
        j_set_str(h, "path", dir);
        j_set_str(h, "url", url);
        j_set_str(h, "signature", sig.name);
        j_set_str(h, "kind", sig.kind);
        j_set_str(h, "severity", sig.severity);
        j_set_str(h, "tag", sig.tag);
        j_set_str(h, "evidence", sig.evidence);
        j_add(exposed, h);
      } else {
        probed_push(probed, dir, f.status, "存在,无可识别特征");
      }
    }
    fetch_free2(&f);
  }

  json_t *data = j_obj();
  j_set_str(data, "target", root);
  j_set_num(data, "tested", tested);
  j_set_num(data, "reachable", reachable);
  j_set_num(data, "suppressed_as_default_page", suppressed);
  j_set_num(data, "unreachable", unreachable);
  j_set_num(data, "skipped_out_of_pool", skipped);
  j_set_bool(data, "calibrated", calib.valid);
  j_set(data, "directory_listing", listings);
  j_set(data, "entry_points", entries);
  j_set(data, "exposed", exposed);
  j_set(data, "restricted", restricted);

  j_set(data, "existing_dirs", live_dirs);

  j_set(data, "probed", probed);
  j_set_num(data, "candidate_count", j_len(listings) + j_len(exposed));
  json_t *deep_hits = j_arr();
  {
    int max_dirs = (int)rules_number("backup_names.max_dirs", 5);
    int max_per = (int)rules_number("backup_names.max_per_dir", 14);
    if (max_dirs < 0) max_dirs = 5;
    if (max_per < 1) max_per = 14;

    json_t *dir_list = j_arr();
    for (int i = 0; i < j_len(live_dirs) && j_len(dir_list) < max_dirs; i++) {
      j_add(dir_list, j_str(j_at(live_dirs, i)->str));
    }
    for (int i = 0; i < j_len(listings) && j_len(dir_list) < max_dirs; i++) {
      const char *p = j_s(j_at(listings, i), "path", "");
      int dup = 0;
      for (int k = 0; k < j_len(dir_list); k++) if (str_ieq(j_at(dir_list, k)->str, p)) dup = 1;
      if (!dup && p[0]) j_add(dir_list, j_str(p));
    }
    for (int i = 0; i < j_len(restricted) && j_len(dir_list) < max_dirs; i++) {
      const char *p = j_s(j_at(restricted, i), "path", "");
      int dup = 0;
      for (int k = 0; k < j_len(dir_list); k++) if (str_ieq(j_at(dir_list, k)->str, p)) dup = 1;
      if (!dup && p[0]) j_add(dir_list, j_str(p));
    }

    int stems_n = 0, suf_n = 0, dot_n = 0;
    const char **stems = rules_str_list("backup_names.stems", &stems_n);
    const char **sufs = rules_str_list("backup_names.suffixes", &suf_n);
    const char **dots = rules_str_list("backup_names.dotfiles", &dot_n);

    int deep_tested = 0;
    for (int d = 0; d < j_len(dir_list); d++) {

      char dir[512];
      snprintf(dir, sizeof(dir), "%s", j_at(dir_list, d)->str);
      size_t dl = strlen(dir);
      while (dl > 0 && dir[dl - 1] == '/') dir[--dl] = 0;
      int per = 0;

      for (int i = 0; i < dot_n && per < max_per; i++) {
        char rel[512];
        snprintf(rel, sizeof(rel), "%s/%s", dir, dots[i]);
        char url[1024];
        join_path(url, sizeof(url), root, rel);
        if (!scope_ok(ctx, url)) continue;
        fetch_t f;
        t_fetch(ctx, url, &f);
        deep_tested++;
        per++;
        if (f.err && !f.status) { fetch_free2(&f); continue; }
        if (f.status != 200 || !f.body || !f.body[0]) { fetch_free2(&f); continue; }
        if (calib_matches(&calib, f.status, f.body)) { fetch_free2(&f); continue; }
        rules_sig_t sig;
        memset(&sig, 0, sizeof(sig));
        if (rules_sig_match(url, f.body, &sig) == 0) {
          json_t *h = j_obj();
          char pathbuf[1024];
          web_url_parts(url, NULL, 0, pathbuf, sizeof(pathbuf));
          j_set_str(h, "path", pathbuf);
          j_set_str(h, "url", url);
          j_set_str(h, "signature", sig.name);
          j_set_str(h, "kind", sig.kind);
          j_set_str(h, "severity", sig.severity);
          j_set_str(h, "tag", sig.tag);
          j_set_str(h, "evidence", sig.evidence);
          j_set_str(h, "found_by", "dotfile");
          j_add(deep_hits, h);
          j_add(exposed, j_clone(h));
        }
        fetch_free2(&f);
      }

      for (int x = 0; x < suf_n && per < max_per; x++) {
        for (int s = 0; s < stems_n && per < max_per; s++) {
          char rel[512];
          snprintf(rel, sizeof(rel), "%s/%s%s", dir, stems[s], sufs[x]);
          char url[1024];
          join_path(url, sizeof(url), root, rel);
          if (!scope_ok(ctx, url)) continue;
          fetch_t f;
          t_fetch(ctx, url, &f);
          deep_tested++;
          per++;
          if (f.err && !f.status) { fetch_free2(&f); continue; }
          if (f.status != 200 || !f.body || !f.body[0]) { fetch_free2(&f); continue; }
          if (calib_matches(&calib, f.status, f.body)) { fetch_free2(&f); continue; }

          if (web_is_dir_listing(f.body)) { fetch_free2(&f); continue; }
          rules_sig_t sig;
          memset(&sig, 0, sizeof(sig));
          if (rules_sig_match(url, f.body, &sig) == 0) {
            json_t *h = j_obj();
            char pathbuf[1024];
            web_url_parts(url, NULL, 0, pathbuf, sizeof(pathbuf));
            j_set_str(h, "path", pathbuf);
            j_set_str(h, "url", url);
            j_set_str(h, "signature", sig.name);
            j_set_str(h, "kind", sig.kind);
            j_set_str(h, "severity", sig.severity);
            j_set_str(h, "tag", sig.tag);
            j_set_str(h, "evidence", sig.evidence);
            j_set_str(h, "found_by", "backup-name");
            j_add(deep_hits, h);
            j_add(exposed, j_clone(h));
          }
          fetch_free2(&f);
        }
      }
    }
    j_set_num(data, "deep_tested", deep_tested);
    j_set_num(data, "deep_dirs", j_len(dir_list));
    j_set(data, "deep_hits", deep_hits);

      j_set_num(data, "candidate_count", j_len(listings) + j_len(exposed));
      json_free(dir_list);
  }
  put_rules_note(data);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "目录探测 %s:试了 %d 个目录(调用方指定 %d 个,规则补足 %d 个),可访问 %d 个,目录索引 %d 个,"
                 "疑似入口 %d 个,受限 %d 个,排除默认页 %d 个。",
             root, tested, given_n, tested - given_n, reachable, j_len(listings), j_len(entries),
             j_len(restricted), suppressed);
  if (skipped) buf_printf(&t, "\n另有 %d 个候选目录被授权池排除,未发起请求。", skipped);
  for (int i = 0; i < j_len(listings); i++) {
    buf_printf(&t, "\n- 目录索引:%s(%d 个条目)", j_s(j_at(listings, i), "path", ""),
               j_len(j_get(j_at(listings, i), "entries")));
  }
  for (int i = 0; i < j_len(entries); i++) {
    buf_printf(&t, "\n- 疑似入口:%s(%s)", j_s(j_at(entries, i), "path", ""),
               j_s(j_at(entries, i), "title", ""));
  }

  {
    int shown = 0, more = 0;
    for (int i = 0; i < j_len(probed); i++) {
      json_t *p = j_at(probed, i);
      const char *note = j_s(p, "note", "");
      if (!note[0] || strcmp(note, "无内容") == 0 || strncmp(note, "默认页", 6) == 0) continue;
      if (shown >= 16) { more++; continue; }
      buf_printf(&t, "\n- 探测:%s [%d] %s", j_s(p, "path", ""), (int)j_n(p, "status", 0), note);
      shown++;
    }
    if (more > 0) buf_printf(&t, "\n(另有 %d 条探测记录省略)", more);
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (tested > 0 && unreachable == tested) {
    buf_printf(&s, "目录探测没能得出结论:%s 的 %d 个目录全部请求失败。", root, tested);
    out->is_error = 1;
    j_set_str(data, "blocked", "unreachable");
  } else if (j_len(listings) == 0 && j_len(entries) == 0 && j_len(exposed) == 0) {
    buf_printf(&s, "目录探测完成:试了 %d 个常见目录,没有发现目录索引、暴露文件或可访问入口", tested);
    if (j_len(restricted) > 0) buf_printf(&s, "(%d 个目录存在但返回 401/403)", j_len(restricted));
    if (skipped) buf_printf(&s, "(%d 个候选被授权池排除)", skipped);
    buf_puts(&s, "。");
  } else {
    buf_printf(&s, "目录探测发现 %d 处目录索引、%d 处疑似管理入口、%d 处暴露文件。",
               j_len(listings), j_len(entries), j_len(exposed));
    for (int i = 0; i < j_len(listings) && i < 4; i++) {
      buf_printf(&s, "\n  · 目录索引 %s", j_s(j_at(listings, i), "path", ""));
    }
    for (int i = 0; i < j_len(entries) && i < 4; i++) {
      buf_printf(&s, "\n  · 疑似入口 %s", j_s(j_at(entries, i), "path", ""));
    }
  }
  out->say = buf_take(&s);
  calib_free(&calib);
  return 0;
}

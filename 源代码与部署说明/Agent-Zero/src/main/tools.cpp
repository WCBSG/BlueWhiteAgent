
#include "tools.h"
#include "tool_api.h"
#include "regex.h"
#include "profile.h"

#include "approval.h"
#include "automation.h"
#include "embed.h"
#include "ext.h"
#include "llm.h"
#include "llm_provider.h"
#include "net.h"
#include "rules.h"
#include "rules_domains.h"
#include "skills.h"
#include "store.h"
#include "tool_entry.h"
#include "webutil.h"

#include <ctype.h>

static tool_t *g_tools = NULL;
static int g_force_builtin = 0;
static int g_tool_count = 0;
static int g_tool_cap = 0;

typedef int (*tool_fn)(tool_ctx_t *, json_t *, tool_result_t *);

typedef struct {
  const char *impl;
  tool_fn run;
} prim_t;

#if defined(TOOL_ENTRY)

static const prim_t g_prims[] = {
    {"self", TOOL_ENTRY},
};
#else
static const prim_t g_prims[] = {
    {"pool_list", t_pool_list},
    {"agent_info", t_agent_info},
    {"settings_get", t_settings_get},
    {"settings_set", t_settings_set},
    {"sensitive_scan", t_sensitive_scan},
    {"password_check", t_password_check},
    {"site_crawl", t_site_crawl},
    {"sensitive_file_probe", t_sensitive_file_probe},
    {"dir_probe", t_dir_probe},
    {"lead_scan", t_lead_scan},
    {"static_scan", t_static_scan},
    {"page_diff", t_page_diff},
    {"nuclei_scan", t_nuclei_scan},
    {"sqli_probe", t_sqli_probe},
    {"asset_list", t_asset_list},
    {"http_get", t_http_get},
    {"record_finding", t_record_finding},
    {"fs_read", fs_tool_read},
    {"fs_list", fs_tool_list},
    {"fs_write", fs_tool_write},
};
#endif

static tool_fn prim_find(const char *impl) {
  if (!impl || !*impl) return NULL;
  for (size_t i = 0; i < sizeof(g_prims) / sizeof(g_prims[0]); i++) {
    if (str_ieq(g_prims[i].impl, impl)) return g_prims[i].run;
  }
  return NULL;
}

static int tool_push(const char *name, const char *desc, const char *kind, const char *src,
                     int readonly, tool_fn run) {
  if (!name || !*name || !run) return -1;
  if (tools_find(name)) return -1;
  if (g_tool_count >= g_tool_cap) {
    g_tool_cap = g_tool_cap ? g_tool_cap * 2 : 32;
    g_tools = (tool_t *)xrealloc(g_tools, sizeof(tool_t) * (size_t)g_tool_cap);
  }
  tool_t *t = &g_tools[g_tool_count++];
  memset(t, 0, sizeof(*t));
  t->name = xstrdup(name);
  t->description = xstrdup(desc && *desc ? desc : name);
  t->schema = xstrdup("{\"type\":\"object\",\"properties\":{}}");
  t->kind = xstrdup(kind && *kind ? kind : "内置");
  t->source_url = xstrdup(src ? src : "");
  t->readonly = readonly ? 1 : 0;
  t->run = run;
  return 0;
}

static int is_factory_decl(const char *name) {
  char key[MAX_PATH];
  snprintf(key, sizeof(key), "data/tools/bw_tools/%s.json", name);
  const char *data = NULL;
  size_t len = 0;
  return embed_lookup(key, &data, &len);
}

static int tool_load_spec_text(const char *text, const char *origin) {
  json_t *o = json_parse(text);
  if (!o || o->type != J_OBJ) { json_free(o); return 0; }

  const char *name = j_s(o, "name", "");
  if (!name[0]) { json_free(o); return 0; }

  const char *impl = j_s(o, "impl", "");
  json_t *en = j_get(o, "entry");
  if (!impl[0] && en && en->type == J_OBJ && str_ieq(j_s(en, "type", ""), "builtin")) {
    impl = j_s(en, "impl", "");
  }

  const char *kind = j_s(o, "kind", "内置");
  tool_fn run = NULL;

  if (j_b(o, "allow", 1) && tool_entry_parse(o, origin) == 1) {
    run = tool_entry_run;
  } else {
    run = prim_find(impl);

    if (!run) { json_free(o); return 1; }
  }

  if (tool_push(name, j_s(o, "description", ""), kind, j_s(o, "source", ""),
                (int)j_b(o, "readonly", 0), run) == 0) {
    json_t *sc = j_get(o, "schema");
    char *schema_txt = sc ? json_dump(sc) : NULL;
    tool_t *tool = tools_find(name);
    if (tool) {
      tool->external = is_factory_decl(name) ? 0 : 1;
      if (schema_txt) {
        free((void *)tool->schema);
        tool->schema = schema_txt;

        schema_txt = NULL;
      }
    }
    free(schema_txt);
  }
  json_free(o);
  return 1;
}

static int load_specs_dir(const char *dir) {
  int n = 0;
  std::vector<std::string> subs = fs_list_dirs(dir);
  for (const std::string &sub : subs) {
    char subdir[MAX_PATH * 2];
    snprintf(subdir, sizeof(subdir), "%s\\%s", dir, sub.c_str());
    std::vector<std::string> inner = fs_list_files(subdir, ".json");
    for (const std::string &f : inner) {
      char full[MAX_PATH * 2];
      snprintf(full, sizeof(full), "%s\\%s", subdir, f.c_str());
      size_t len = 0;
      char *text = file_read_all(full, &len);
      if (!text) continue;
      n += tool_load_spec_text(text, full);
      free(text);
    }
  }
  return n;
}

static int load_specs_embed(void) {
  int total = embed_count();
  int n = 0;
  for (int i = 0; i < total; i++) {
    const char *nm = embed_name_at(i);
    if (!nm || strncmp(nm, "data/tools/", 11) != 0) continue;
    const char *data = NULL;
    size_t len = 0;
    if (!embed_lookup(nm, &data, &len)) continue;
    n += tool_load_spec_text(data, nm);
  }
  return n;
}

void tools_init(void) {

  static int inited = 0;
  if (inited) return;
  inited = 1;

  char dir[MAX_PATH * 2];
  app_data_path(dir, sizeof(dir), "tools");
  ensure_dir(dir);
  int n = load_specs_dir(dir);
  if (n == 0) {
    log_warn("[工具] 数据目录里没有可用的工具声明(%s),改用 exe 内置的那份", dir);
    n = load_specs_embed();
  }
  log_info("[工具] 已装载 %d 个声明式工具(声明来自 %s)", n, dir);
}

void tools_reset_all(void) {
  for (int i = 0; i < g_tool_count; i++) {
    free((void *)g_tools[i].name);
    free((void *)g_tools[i].description);
    free((void *)g_tools[i].schema);
    free((void *)g_tools[i].kind);
    free((void *)g_tools[i].source_url);
    memset(&g_tools[i], 0, sizeof(tool_t));
  }
  g_tool_count = 0;
}

int tools_reload_specs(void) {
  tools_reset_all();
  tool_entry_reset();
  char dir[MAX_PATH * 2];
  app_data_path(dir, sizeof(dir), "tools");
  ensure_dir(dir);
  int n = load_specs_dir(dir);
  if (n == 0) n = load_specs_embed();
  log_info("[工具] 已重新装载 %d 个声明式工具", n);
  return n;
}

int tools_register_external(const char *name, const char *description,
                            const char *schema_json, const char *kind,
                            const char *source_url, int readonly,
                            int (*run)(tool_ctx_t *, json_t *, tool_result_t *)) {
  if (!name || !*name || !run) return -1;
  if (tools_find(name)) return -1;
  if (g_tool_count >= g_tool_cap) {
    g_tool_cap = g_tool_cap ? g_tool_cap * 2 : 32;
    g_tools = (tool_t *)xrealloc(g_tools, sizeof(tool_t) * (size_t)g_tool_cap);
  }
  tool_t *t = &g_tools[g_tool_count++];
  memset(t, 0, sizeof(*t));
  t->name = xstrdup(name);
  t->description = xstrdup(description ? description : "外部工具");
  t->schema = xstrdup(schema_json && *schema_json ? schema_json
                                                : "{\"type\":\"object\",\"properties\":{}}");
  t->kind = xstrdup(kind && *kind ? kind : "外部工具");
  t->source_url = xstrdup(source_url ? source_url : "");
  t->readonly = readonly ? 1 : 0;
  t->external = 1;
  t->run = run;
  return 0;
}

int tools_count(void) { return g_tool_count; }

int tools_count_external(void) {
  int n = 0;
  for (int i = 0; i < g_tool_count; i++) {
    if (g_tools[i].external && !str_startswith(g_tools[i].name, "mcp__")) n++;
  }
  return n;
}

int tools_is_readonly(const char *name) {
  tool_t *t = tools_find(name ? name : "");
  return t ? (t->readonly != 0) : 0;
}

tool_t *tools_get(int index) {
  return (index >= 0 && index < g_tool_count) ? &g_tools[index] : NULL;
}

tool_t *tools_find(const char *name) {
  for (int i = 0; i < g_tool_count; i++) {
    if (str_ieq(g_tools[i].name, name)) return &g_tools[i];
  }
  return NULL;
}

json_t *tools_decl_json(void) {
  json_t *arr = j_arr();
  for (int i = 0; i < g_tool_count; i++) {
    tool_t *t = &g_tools[i];
    json_t *o = j_obj();
    j_set_str(o, "name", t->name);
    j_set_str(o, "description", t->description);
    json_t *schema = json_parse(t->schema);
    j_set(o, "input_schema", schema ? schema : j_obj());
    j_set_str(o, "kind", t->kind);
    j_set_str(o, "source_url", t->source_url);
    j_add(arr, o);
  }
  return arr;
}

static const char *param_hint(const char *key, json_t *prop) {
  if (prop) {
    const char *h = j_s(prop, "hint", NULL);
    if (h && *h) return h;
  }
  if (!key || !*key) return NULL;
  if (str_ieq(key, "target")) return "起始地址";
  if (str_ieq(key, "url")) return "地址";
  if (str_ieq(key, "urls")) return "自选地址列表";
  if (str_ieq(key, "dirs")) return "自选目录/路径列表";
  if (str_ieq(key, "paths")) return "自选路径列表";
  if (str_ieq(key, "pages")) return "自选页面列表";
  if (str_ieq(key, "text")) return "待判定原文";
  if (str_ieq(key, "param")) return "要验的参数名";
  if (str_ieq(key, "method")) return "默认 GET";
  if (str_ieq(key, "limit")) return "条数上限";
  if (str_ieq(key, "kind")) return "筛选类别";
  if (str_ieq(key, "max_bytes")) return "最多读多少字节";
  return NULL;
}

void tools_manifest(buf_t *out) {
  for (int i = 0; i < g_tool_count; i++) {
    tool_t *t = &g_tools[i];

    buf_printf(out, "- %s", t->name);
    json_t *sc = t->schema && t->schema[0] ? json_parse(t->schema) : NULL;
    json_t *props = sc ? j_get(sc, "properties") : NULL;
    if (props && props->type == J_OBJ && props->count > 0) {
      buf_puts(out, "(");
      int shown = 0;
      for (int k = 0; k < props->count && shown < 8; k++) {
        const char *key = props->keys ? props->keys[k] : NULL;
        if (!key || !key[0]) continue;
        if (shown) buf_puts(out, ",");
        buf_puts(out, key);
        const char *hint = param_hint(key, props->items[k]);
        if (hint) {
          buf_puts(out, ":");
          buf_puts(out, hint);
        }
        shown++;
      }
      buf_puts(out, ")");
    }
    if (sc) json_free(sc);
    buf_puts(out, " —— ");
    size_t n = u8_prefix(t->description ? t->description : "", 150);
    if (n) buf_putn(out, t->description, n);
    if (t->description && strlen(t->description) > n) buf_puts(out, "…");
    buf_puts(out, "\n");
  }
}

int tools_validate(tool_t *t, json_t *args, buf_t *err) {
  if (!t) {
    if (err) buf_puts(err, "没有这个工具");
    return -1;
  }
  json_t *schema = json_parse(t->schema);
  if (!schema) return 0;
  json_t *required = j_get(schema, "required");
  int bad = 0;
  for (int i = 0; i < j_len(required); i++) {
    json_t *k = j_at(required, i);
    if (!k || k->type != J_STR) continue;
    json_t *v = j_get(args, k->str);
    if (!v || v->type == J_NULL || (v->type == J_STR && (!v->str || !v->str[0]))) {
      if (err) buf_printf(err, "缺少必填参数 %s", k->str);
      bad = 1;
      break;
    }
  }
  if (!bad) {

    json_t *props = j_get(schema, "properties");
    if (props && props->type == J_OBJ) {
      for (int i = 0; i < props->count; i++) {
        const char *key = props->keys[i];
        const char *want = j_s(props->items[i], "type", NULL);
        json_t *got = j_get(args, key);
        if (!want || !got || got->type == J_NULL) continue;
        int ok = (strcmp(want, "string") == 0 && got->type == J_STR) ||
                 (strcmp(want, "integer") == 0 && got->type == J_NUM) ||
                 (strcmp(want, "number") == 0 && got->type == J_NUM) ||
                 (strcmp(want, "boolean") == 0 && got->type == J_BOOL) ||
                 (strcmp(want, "array") == 0 && got->type == J_ARR) ||
                 (strcmp(want, "object") == 0 && got->type == J_OBJ);
        if (!ok) {
          if (err) buf_printf(err, "参数 %s 类型应为 %s", key, want);
          bad = 1;
          break;
        }
      }
    }
  }
  json_free(schema);
  return bad ? -1 : 0;
}

int tools_run(tool_ctx_t *ctx, const char *name, json_t *args, tool_result_t *out) {
  memset(out, 0, sizeof(*out));
  tool_t *t = tools_find(name);
  if (!t) {
    out->text = xstrdup("没有这个工具");
    out->is_error = 1;
    out->say = xstrdup("这个工具不存在,我换个做法。");
    return -1;
  }
  buf_t err;
  buf_init(&err);
  if (tools_validate(t, args, &err) != 0) {
    out->is_error = 1;
    buf_t tb;
    buf_init(&tb);
    buf_printf(&tb, "参数校验失败:%s", err.data);
    out->text = buf_take(&tb);
    buf_t sb;
    buf_init(&sb);
    buf_printf(&sb, "参数没给全(%s),这次先不执行。", err.data);
    out->say = buf_take(&sb);
    buf_free(&err);
    return -1;
  }
  buf_free(&err);

  if (g_force_builtin) {
    tool_fn fn = prim_find(name);
    if (fn) {
      ctx->current_tool = name;
      int brc = fn(ctx, args, out);
      ctx->current_tool = NULL;
      if (!out->say) out->say = xstrdup(out->text ? out->text : "");
      return brc;
    }
  }

  ctx->current_tool = name;
  int rc = t->run(ctx, args, out);
  ctx->current_tool = NULL;
  if (!out->say) out->say = xstrdup(out->text ? out->text : "");
  return rc;
}

void tools_set_force_builtin(int on) { g_force_builtin = on ? 1 : 0; }

int tools_run_builtin(tool_ctx_t *ctx, const char *name, json_t *args,
                      tool_result_t *out) {
  memset(out, 0, sizeof(*out));
  tool_fn fn = prim_find(name);
  if (!fn) {
    out->text = xstrdup("这个工具不在程序内实现表里");
    out->is_error = 1;
    out->say = xstrdup("这个工具没有可用的实现,我换个做法。");
    return -1;
  }
  if (!args) args = j_obj();

  ctx->current_tool = name;
  int rc = fn(ctx, args, out);
  ctx->current_tool = NULL;
  return rc;
}

void target_resolve(buf_t *out, const char *raw, const char *fallback_host) {
  const char *s = raw;
  if (!s || !*s) s = fallback_host;
  if (!s || !*s) return;
  while (*s == ' ' || *s == '"' || *s == '\'') s++;
  if (*s == '/') {
    buf_puts(out, fallback_host ? fallback_host : "");
    buf_puts(out, s);
    return;
  }
  if (strstr(s, "://")) {
    buf_puts(out, s);
  } else {
    buf_puts(out, "https://");
    buf_puts(out, s);
  }
}

int scope_allows(tool_ctx_t *ctx, const char *url, char **err) {
  char host[256];
  net_host_of(url, host, sizeof(host));
  if (!host[0]) {
    if (err) *err = xstrdup("URL 里没有主机名");
    return 0;
  }
  if (ctx->domain_count == 0) return 1;
  for (int i = 0; i < ctx->domain_count; i++) {
    const char *d = ctx->domains[i];
    if (str_ieq(host, d)) return 1;
    size_t lh = strlen(host), ld = strlen(d);
    if (lh > ld && str_ieq(host + (lh - ld), d) && host[lh - ld - 1] == '.') return 1;
  }
  buf_t b;
  buf_init(&b);
  buf_printf(&b, "目标 %s 不在授权域名内(授权:%s)", host,
             ctx->domain_count ? ctx->domains[0] : "未配置");
  if (err) *err = buf_take(&b);
  else buf_free(&b);
  return 0;
}

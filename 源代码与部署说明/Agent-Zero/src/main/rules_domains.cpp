
#include "rules_domains.h"

#include "res.h"
#include "rules.h"

#include <ctype.h>

#include <string>
#include <vector>

static const rules_domain_t g_domains[] = {
    {"detect", "检测口径", "detect.json",
     "版本、严重等级、内容特征、响应头、注入载荷、弱口令:判什么、按什么等级算"},
    {"sensitive", "敏感信息", "sensitive.json",
     "正文里出现即命中的识别规则(内置正则方言)"},
    {"probe", "探测参数", "probe.json",
     "每轮探多少、等多久,以及会去尝试的落点与目录"},
    {"alert", "告警与推送", "alert.json",
     "什么等级进告警、走哪个渠道"},
    {"org", "单位口径", "org.json",
     "本单位的关键词、文件类型、版本泄露头、错误回显与可疑域名后缀"},
    {"page", "页面与篡改", "page.json",
     "目录索引与口令字段的标记,以及外链数量阈值"},
};

static const int g_domain_count = (int)(sizeof(g_domains) / sizeof(g_domains[0]));

typedef struct {
  const char *domain;
  const char *keys[16];
} domain_keys_t;

static const domain_keys_t g_keys[] = {
    {"detect",
     {"version", "note", "severity_levels", "signatures", "weak_headers", "payloads",
      "weak_passwords",

      "header_policies", "leads", "backup_names", "static_scan", NULL}},
    {"sensitive", {"patterns", NULL}},
    {"probe", {"probing", "sensitive_paths", "dir_candidates", NULL}},
    {"alert", {"alerts", NULL}},
    {"org",
     {"profile_keywords", "profile_file_types", "server_header_keys", "error_signatures",
      "dangerous_methods", "suspicious_tlds", NULL}},
    {"page", {"markers", "tamper", NULL}},
};

static const char *const *keys_of(const char *id) {
  for (size_t i = 0; i < sizeof(g_keys) / sizeof(g_keys[0]); i++) {
    if (str_ieq(g_keys[i].domain, id)) return g_keys[i].keys;
  }
  return NULL;
}

int rules_domain_count(void) { return g_domain_count; }

const rules_domain_t *rules_domain_at(int i) {
  return (i >= 0 && i < g_domain_count) ? &g_domains[i] : NULL;
}

const rules_domain_t *rules_domain_find(const char *id) {
  if (!id || !*id) return NULL;
  for (int i = 0; i < g_domain_count; i++) {
    if (str_ieq(g_domains[i].id, id)) return &g_domains[i];
  }
  return NULL;
}

const rules_domain_t *rules_domain_of_key(const char *key) {
  if (!key || !*key) return NULL;
  for (int i = 0; i < g_domain_count; i++) {
    const char *const *keys = keys_of(g_domains[i].id);
    for (int k = 0; keys && keys[k]; k++) {
      if (strcmp(keys[k], key) == 0) return &g_domains[i];
    }
  }
  return NULL;
}

void rules_domain_dir(char *out, size_t cap) {
  if (!out || cap == 0) return;
  app_data_path(out, cap, "rules");
}

static void domain_path(const char *file, char *out, size_t cap) {
  char dir[MAX_PATH * 2];
  rules_domain_dir(dir, sizeof(dir));
  path_join(out, cap, dir, file);
}

static json_t *copy_node(json_t *v) {
  if (!v) return NULL;
  char *dump = json_dump(v);
  if (!dump) return NULL;
  json_t *cp = json_parse(dump);
  free(dump);
  return cp;
}

static json_t *factory_domain(const char *id, char *err, size_t errcap) {
  const rules_domain_t *d = rules_domain_find(id);
  if (!d) {
    if (err) snprintf(err, errcap, "不认识的规则域:%s", id ? id : "");
    return NULL;
  }
  char res[128];
  snprintf(res, sizeof(res), "data/rules/%s", d->file);
  size_t len = 0;
  char *text = NULL;
  if (!res_load_text(res, &text, &len) || !text) {
    if (err) snprintf(err, errcap, "exe 内置的出厂规则读不到(%s)", res);
    free(text);
    return NULL;
  }
  json_t *raw = json_parse(text);
  free(text);
  if (!raw) {
    if (err) snprintf(err, errcap, "出厂规则 %s 不是合法 JSON", res);
    return NULL;
  }

  const char *const *keys = keys_of(id);
  json_t *dom = j_obj();
  for (int i = 0; keys && keys[i]; i++) {
    json_t *v = j_get(raw, keys[i]);
    if (!v) continue;
    json_t *cp = copy_node(v);
    if (cp) j_set(dom, keys[i], cp);
  }
  json_free(raw);
  return dom;
}

json_t *rules_domains_factory(void) {
  json_t *all = j_obj();
  for (int i = 0; i < g_domain_count; i++) {
    json_t *dom = factory_domain(g_domains[i].id, NULL, 0);
    if (!dom) continue;
    for (int k = 0; k < dom->count; k++) {
      json_t *v = j_get(dom, dom->keys[k]);
      json_t *cp = copy_node(v);
      if (cp) j_set(all, dom->keys[k], cp);
    }
    json_free(dom);
  }
  return all;
}

static int write_domain_file(const char *id, json_t *dom, char *err, size_t errcap) {
  const rules_domain_t *d = rules_domain_find(id);
  if (!d) {
    if (err) snprintf(err, errcap, "不认识的规则域:%s", id ? id : "");
    return -1;
  }
  char dir[MAX_PATH * 2], path[MAX_PATH * 4];
  rules_domain_dir(dir, sizeof(dir));
  ensure_dir(dir);
  domain_path(d->file, path, sizeof(path));
  char *text = json_dump_pretty(dom);
  if (!text) {
    if (err) snprintf(err, errcap, "生成 %s 的内容失败", d->file);
    return -1;
  }
  int rc = file_write_all(path, text, strlen(text));
  free(text);
  if (rc != 0) {
    if (err) snprintf(err, errcap, "%s 写入失败(检查是否被别的程序占用)", path);
    return -1;
  }
  return 0;
}

int rules_domains_generate(char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  char dir[MAX_PATH * 2], path[MAX_PATH * 4];
  rules_domain_dir(dir, sizeof(dir));
  ensure_dir(dir);

  int made = 0;
  for (int i = 0; i < g_domain_count; i++) {
    domain_path(g_domains[i].file, path, sizeof(path));
    if (file_size(path) >= 0) continue;
    json_t *dom = factory_domain(g_domains[i].id, err, errcap);
    if (!dom) return -1;
    int rc = write_domain_file(g_domains[i].id, dom, err, errcap);
    json_free(dom);
    if (rc != 0) return -1;
    made++;
  }
  return made;
}

json_t *rules_domains_load_merged(char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;

  json_t *merged = rules_domains_factory();
  if (!merged) merged = j_obj();

  for (int i = 0; i < g_domain_count; i++) {
    char path[MAX_PATH * 4];
    domain_path(g_domains[i].file, path, sizeof(path));
    size_t len = 0;
    char *text = file_read_all(path, &len);
    if (!text) continue;
    json_t *dom = json_parse(text);
    free(text);
    if (!dom) {

      log_warn("[规则] %s 解析失败,这一域暂用出厂值", path);
      continue;
    }
    const char *const *keys = keys_of(g_domains[i].id);
    for (int k = 0; keys && keys[k]; k++) {
      json_t *v = j_get(dom, keys[k]);
      if (!v) continue;
      json_t *cp = copy_node(v);
      if (cp) j_set(merged, keys[k], cp);
    }
    json_free(dom);
  }
  return merged;
}

json_t *rules_domains_read(const char *id, char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  const rules_domain_t *d = rules_domain_find(id);
  if (!d) {
    if (err) snprintf(err, errcap, "不认识的规则域:%s", id ? id : "");
    return NULL;
  }
  char dir[MAX_PATH * 2], path[MAX_PATH * 4];
  rules_domain_dir(dir, sizeof(dir));
  ensure_dir(dir);
  domain_path(d->file, path, sizeof(path));

  size_t len = 0;
  char *text = file_read_all(path, &len);
  if (!text) {

    return factory_domain(id, err, errcap);
  }
  json_t *dom = json_parse(text);
  free(text);
  if (!dom) {
    if (err) snprintf(err, errcap, "%s 的 JSON 写坏了(先修好或删掉它,程序会重新生成)", d->file);
    return NULL;
  }
  return dom;
}

int rules_domains_save(const char *id, json_t *patch, char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  const rules_domain_t *d = rules_domain_find(id);
  if (!d) {
    if (err) snprintf(err, errcap, "不认识的规则域:%s", id ? id : "");
    return -1;
  }
  if (!patch || patch->type != J_OBJ) {
    if (err) snprintf(err, errcap, "需要 %s 这一个域的对象", id);
    return -1;
  }

  json_t *dom = rules_domains_read(id, err, errcap);
  if (!dom) return -1;

  const char *const *keys = keys_of(id);
  int touched = 0;
  for (int k = 0; keys && keys[k]; k++) {
    json_t *v = j_get(patch, keys[k]);
    if (!v) continue;
    json_t *cp = copy_node(v);
    if (!cp) continue;
    j_set(dom, keys[k], cp);
    touched++;
  }
  if (touched == 0) {
    json_free(dom);
    if (err) snprintf(err, errcap, "提交的内容里没有属于「%s」的字段", d->title);
    return -1;
  }
  int rc = write_domain_file(id, dom, err, errcap);
  json_free(dom);
  return rc;
}

int rules_domains_save_all(json_t *root, char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  if (!root || root->type != J_OBJ) {
    if (err) snprintf(err, errcap, "需要 rules 对象");
    return -1;
  }
  for (int i = 0; i < g_domain_count; i++) {
    json_t *dom = j_obj();
    const char *const *keys = keys_of(g_domains[i].id);
    for (int k = 0; keys && keys[k]; k++) {
      json_t *v = j_get(root, keys[k]);
      if (!v) continue;
      json_t *cp = copy_node(v);
      if (cp) j_set(dom, keys[k], cp);
    }
    if (j_len(dom) == 0) { json_free(dom); continue; }
    int rc = write_domain_file(g_domains[i].id, dom, err, errcap);
    json_free(dom);
    if (rc != 0) return -1;
  }
  return 0;
}

void rules_preset_dir(char *out, size_t cap) {
  char dir[MAX_PATH * 2];
  rules_domain_dir(dir, sizeof(dir));
  path_join(out, cap, dir, "presets");
}

static int preset_name_ok(const char *name) {
  if (!name || !*name || strlen(name) > 64) return 0;
  if (str_ieq(name, "出厂") || str_ieq(name, "custom")) return 1;
  for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
    if (*p < 0x80) {
      if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.' || *p == ' ')) return 0;
    }
  }
  if (strstr(name, "..") || strchr(name, ':') || strchr(name, '\\') || strchr(name, '/')) return 0;
  return 1;
}

int rules_preset_list(json_t **out, char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  json_t *arr = j_arr();
  json_t *factory = j_obj();
  j_set_str(factory, "name", "出厂");
  j_set_bool(factory, "factory", 1);
  j_add(arr, factory);

  char dir[MAX_PATH * 2];
  rules_preset_dir(dir, sizeof(dir));
  ensure_dir(dir);
  std::vector<std::string> subs = fs_list_dirs(dir);
  for (size_t i = 0; i < subs.size(); i++) {
    char one[MAX_PATH * 2];
    snprintf(one, sizeof(one), "%s\\%s", dir, subs[i].c_str());
    int files = 0;
    for (int d = 0; d < g_domain_count; d++) {
      char f[MAX_PATH * 4];
      snprintf(f, sizeof(f), "%s\\%s", one, g_domains[d].file);
      if (file_size(f) >= 0) files++;
    }
    json_t *o = j_obj();
    j_set_str(o, "name", subs[i].c_str());
    j_set_bool(o, "factory", 0);
    j_set_num(o, "files", files);
    j_add(arr, o);
  }
  *out = arr;
  return j_len(arr);
}

static int copy_domain_file(const char *src, const char *dst, const char *file) {
  char a[MAX_PATH * 4], b[MAX_PATH * 4];
  snprintf(a, sizeof(a), "%s\\%s", src, file);
  snprintf(b, sizeof(b), "%s\\%s", dst, file);
  size_t len = 0;
  char *text = file_read_all(a, &len);
  if (!text) return 0;
  int rc = file_write_all(b, text, len);
  free(text);
  return rc == 0;
}

int rules_preset_save(const char *name, char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  if (!preset_name_ok(name) || str_ieq(name, "出厂")) {
    if (err) snprintf(err, errcap, "预设名只能用字母、数字、下划线、连字符与中文,且不能用「出厂」");
    return -1;
  }
  char dir[MAX_PATH * 2], dst[MAX_PATH * 4];
  rules_domain_dir(dir, sizeof(dir));
  rules_preset_dir(dst, sizeof(dst));
  char one[MAX_PATH * 4];
  snprintf(one, sizeof(one), "%s\\%s", dst, name);
  ensure_dir(one);

  int n = 0;
  for (int i = 0; i < g_domain_count; i++) {
    n += copy_domain_file(dir, one, g_domains[i].file);
  }
  if (n == 0) {
    if (err) snprintf(err, errcap, "当前规则读不到,无法保存预设");
    return -1;
  }
  return n;
}

int rules_preset_apply(const char *name, char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  char dir[MAX_PATH * 2];
  rules_domain_dir(dir, sizeof(dir));
  ensure_dir(dir);

  if (str_ieq(name, "出厂") || !name || !*name) {
    for (int i = 0; i < g_domain_count; i++) {
      char path[MAX_PATH * 4];
      domain_path(g_domains[i].file, path, sizeof(path));
      json_t *dom = factory_domain(g_domains[i].id, err, errcap);
      if (!dom) return -1;
      int rc = write_domain_file(g_domains[i].id, dom, err, errcap);
      json_free(dom);
      if (rc != 0) return -1;
    }
    return g_domain_count;
  }

  if (!preset_name_ok(name)) {
    if (err) snprintf(err, errcap, "预设名不合法");
    return -1;
  }
  char base[MAX_PATH * 2], src[MAX_PATH * 4];
  rules_preset_dir(base, sizeof(base));
  snprintf(src, sizeof(src), "%s\\%s", base, name);
  if (file_size(src) < 0) {
    if (err) snprintf(err, errcap, "找不到预设「%s」", name);
    return -1;
  }
  int n = 0;
  for (int i = 0; i < g_domain_count; i++) {
    n += copy_domain_file(src, dir, g_domains[i].file);
  }
  if (n == 0) {
    if (err) snprintf(err, errcap, "预设「%s」里没有可用的规则文件", name);
    return -1;
  }
  return n;
}

int rules_preset_delete(const char *name, char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  if (!preset_name_ok(name) || str_ieq(name, "出厂")) {
    if (err) snprintf(err, errcap, "「出厂」不能删除");
    return -1;
  }
  char base[MAX_PATH * 2], one[MAX_PATH * 4];
  rules_preset_dir(base, sizeof(base));
  snprintf(one, sizeof(one), "%s\\%s", base, name);
  if (file_size(one) < 0) {
    if (err) snprintf(err, errcap, "找不到预设「%s」", name);
    return -1;
  }

  for (int i = 0; i < g_domain_count; i++) {
    char f[MAX_PATH * 4];
    snprintf(f, sizeof(f), "%s\\%s", one, g_domains[i].file);
    wchar_t *w = u8_to_w(f);
    if (w) { DeleteFileW(w); free(w); }
  }
  wchar_t *w = u8_to_w(one);
  if (w) { RemoveDirectoryW(w); free(w); }
  return 0;
}

const char *rules_preset_active(void) { return ""; }

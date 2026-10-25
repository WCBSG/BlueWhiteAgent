
#ifndef AGENT_TOOL_API_H
#define AGENT_TOOL_API_H

#include "agent.h"
#include "approval.h"
#include "automation.h"
#include "common.h"
#include "embed.h"
#include "ext.h"
#include "json.h"
#include "llm.h"
#include "llm_provider.h"
#include "net.h"
#include "profile.h"
#include "regex.h"
#include "rules.h"
#include "rules_domains.h"
#include "skills.h"
#include "store.h"
#include "tool_entry.h"
#include "tools.h"
#include "webutil.h"

#include <ctype.h>

int  do_fetch(tool_ctx_t *ctx, const char *url, const char *method, int *status, char **body,
              char **err);

int  scope_ok(tool_ctx_t *ctx, const char *url);

typedef struct {
  int status;
  char *headers;
  char *body;
  char *err;
} fetch_t;
void t_fetch_m(tool_ctx_t *ctx, const char *url, const char *method, fetch_t *f);
void t_fetch(tool_ctx_t *ctx, const char *url, fetch_t *f);
void fetch_free2(fetch_t *f);

void probe_root(const char *url, char *out, size_t cap);

void normalize_target(const char *in, char *out, size_t cap);

void join_path(char *out, size_t cap, const char *root, const char *path);

typedef struct {
  int valid;
  int status;
  size_t bytes;
  buf_t shape;
  char sample[256];
} calib_t;
void calib_free(calib_t *c);
void calib_run(tool_ctx_t *ctx, const char *root, calib_t *c);
int  calib_matches(const calib_t *c, int status, const char *body);

void link_analysis(const char *body, const char *own_host, json_t *hosts, json_t *flags);

void put_rules_note(json_t *data);

int  looks_like_html(const char *ct);
void extract_links(const char *html, json_t *out);
const char *classify_kind(const char *url);
void url_path_query(const char *url, char *out, size_t cap);
void url_origin(const char *url, char *out, size_t cap);
void path_normalize(const char *in, char *out, size_t cap);
void url_resolve(const char *base_url, const char *link, char *out, size_t cap);
int  path_in_scope(const char *path, const char *scope);

void mask_into(buf_t *out, const char *s, int len);
int  scan_text_into(tool_ctx_t *ctx, const char *text, json_t *hits);

int  tools_regex_first(const char *pattern, const char *text, int *off, int *len);

void   value_text(buf_t *out, json_t *v);
void   join_keys(buf_t *out, json_t *obj);
void   settings_audit(tool_ctx_t *ctx, const char *action, const char *target,
                      const char *detail);
json_t *obj_arg(json_t *args, const char *key);
json_t *value_arg(json_t *args, const char *key);
int    top_key_of(const char *path, char *out, size_t cap);
int    deep_set(json_t *root, const char *path, json_t *value);
int    settings_fail(tool_result_t *out, buf_t *msg);

int t_pool_list(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_agent_info(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_settings_get(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_settings_set(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_sensitive_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_password_check(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_site_crawl(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_sensitive_file_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_dir_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_page_diff(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_nuclei_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_sqli_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out);

int t_asset_list(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_http_get(tool_ctx_t *ctx, json_t *args, tool_result_t *out);

int t_lead_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out);

int t_static_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_record_finding(tool_ctx_t *ctx, json_t *args, tool_result_t *out);

int  abs_path(const char *raw, wchar_t *out, size_t cap);
int  under_root(const wchar_t *path, const char *root_u8);
int  check_allowed(const wchar_t *full, int for_write, char *err, size_t err_cap);
void split_lines(const char *data, size_t len, int *total_out);

int  fs_tool_read(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int  fs_tool_list(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int  fs_tool_write(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
void fs_tool_set_extra_root(const char *dir);

#endif


#ifndef AGENT_TOOLS_H
#define AGENT_TOOLS_H

#include "agent.h"
#include "common.h"
#include "io.h"
#include "json.h"

struct tool_ctx {
  const char *data_dir;
  const char *task_id;
  const char *run_id;
  const char **domains;
  int domain_count;
  tools_io_t io;
  void *store;
  buf_t *note;
  int http_calls;
  const char *current_tool;
};

void        tools_init(void);
int         tools_count(void);

int         tools_regex_first(const char *pattern, const char *text, int *off, int *len);
tool_t     *tools_get(int index);
tool_t     *tools_find(const char *name);

int         tools_register_external(const char *name, const char *description,
                                    const char *schema_json, const char *kind,
                                    const char *source_url, int readonly,
                                    int (*run)(tool_ctx_t *, json_t *, tool_result_t *));

int         tools_is_readonly(const char *name);

void        tools_reset_all(void);

int         tools_reload_specs(void);

int         tools_count_external(void);
json_t     *tools_decl_json(void);
void        tools_manifest(buf_t *out);

int         tools_validate(tool_t *t, json_t *args, buf_t *err);
int         tools_run(tool_ctx_t *ctx, const char *name, json_t *args,
                      tool_result_t *out);

int         tools_run_builtin(tool_ctx_t *ctx, const char *name, json_t *args,
                              tool_result_t *out);

void        tools_set_force_builtin(int on);

void        target_resolve(buf_t *out, const char *raw, const char *fallback_host);

int         scope_allows(tool_ctx_t *ctx, const char *url, char **err);

#endif

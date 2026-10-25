
#ifndef AGENT_STORE_H
#define AGENT_STORE_H

#include "common.h"
#include "json.h"

typedef struct store store_t;

store_t *store_open(const char *data_dir);
void     store_close(store_t *s);
const char *store_dir(store_t *s);

char *store_next_id(store_t *s, const char *collection);

int store_append(store_t *s, const char *collection, json_t *obj);

int store_save(store_t *s, const char *collection, json_t *obj);

json_t *store_all(store_t *s, const char *collection);
json_t *store_get(store_t *s, const char *collection, const char *id);

int store_delete(store_t *s, const char *collection, const char *id);
json_t *store_find(store_t *s, const char *collection, const char *key, const char *value);

int  store_link_run(store_t *s, const char *run_id, const char *finding_id, int is_new);
json_t *store_findings_of_run(store_t *s, const char *run_id);

void store_audit(store_t *s, const char *action, const char *target, int allowed,
                 const char *detail, const char *task_id, const char *run_id);

void store_set_chat(const char *session_id);

char *store_write_snapshot(store_t *s, const char *id, const char *content);
char *store_read_snapshot(store_t *s, const char *content_ref);

typedef struct {
  const char *kind;
  const char *severity;
  const char *title;
  const char *target;
  const char *evidence;
  const char *impact;
  const char *fix;
  const char *source_tool;
  const char *dedup_tag;
  const char *task_id;
  const char *run_id;
} finding_in_t;

char *store_upsert_finding(store_t *s, const finding_in_t *in, int *is_new);

int store_update_finding(store_t *s, json_t *finding);

json_t *store_findings_of_task(store_t *s, const char *task_id);

char *store_ensure_task(store_t *s, const char **domains, int count, const char *name,
                        const char *profile_id);
char *store_ensure_profile(store_t *s, const char *name, json_t *keywords,
                           json_t *file_types, json_t *samples);

int   store_upsert_asset(store_t *s, const char *task_id, const char *url, const char *kind,
                         int status_code, int depth, const char *parent_url);

char *store_run_start(store_t *s, const char *task_id, const char *triggered_by,
                      const char *scope);
int   store_run_finish(store_t *s, const char *run_id, const char *status, int pages_found,
                       int tools_called, int findings_new, const char *error);

int store_count(store_t *s, const char *collection);

void store_set_trigger(const char *label);
const char *store_trigger_label(void);

void mask_evidence(buf_t *out, const char *text);

#endif

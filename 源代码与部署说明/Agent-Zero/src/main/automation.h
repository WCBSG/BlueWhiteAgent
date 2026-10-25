
#ifndef AGENT_AUTOMATION_H
#define AGENT_AUTOMATION_H

#include "common.h"
#include "json.h"
#include "store.h"

typedef enum {
  AUTO_SCOPE_FULL = 0,
  AUTO_SCOPE_LEAK,
  AUTO_SCOPE_INTEGRITY,
  AUTO_SCOPE_RECON,
  AUTO_SCOPE_RETEST,
} auto_scope_t;

typedef struct {
  char id[24];
  char name[200];
  char domain[256];
  char scope[24];
  char kind[16];
  int  every_min;
  int  at_hour;
  int  at_min;
  int  weekday;
  int  enabled;
  int  run_count;
  int  change_count;
  long long next_at;
  char last_run_at[40];
  char last_run_id[24];
  char created_at[40];
  char profile_id[24];
  char checks[160];

} auto_rule_t;

const char *auto_scope_instruction(const char *scope);
const char *auto_scope_label(const char *scope);

void auto_checks_instruction(const char *checks, const char *scope, char *out, size_t cap);

void auto_checks_signature(const char *checks, const char *scope, char *out, size_t cap);

void auto_cycle_text(const auto_rule_t *r, char *out, size_t cap);

long long auto_next_at(const auto_rule_t *r, long long from);

void auto_from_json(json_t *o, auto_rule_t *r);
json_t *auto_to_json(const auto_rule_t *r);

const char *auto_validate(const auto_rule_t *r);

int auto_list(store_t *s, auto_rule_t **out, int *count);
void auto_free_list(auto_rule_t *list);
int auto_find(store_t *s, const char *id, auto_rule_t *out);
int auto_save(store_t *s, auto_rule_t *r);
int auto_remove(store_t *s, const char *id);

int auto_resync(store_t *s, auto_rule_t *list, int count);

int auto_take_due(store_t *s, auto_rule_t *out, long long now);

int auto_after_run(store_t *s, auto_rule_t *r, const char *run_id);

char *auto_latest_run_of_domain(store_t *s, const char *domain);

#endif


#ifndef AGENT_RULES_H
#define AGENT_RULES_H

#include "common.h"
#include "json.h"

typedef struct {
  const char *name;
  const char *kind;
  const char *severity;
  const char *tag;
  const char *evidence;
} rules_sig_t;

void rules_init(const char *base_dir);
void rules_shutdown(void);

const char *rules_source(void);
int  rules_from_file(void);

const char **rules_str_list(const char *key, int *count);

int  rules_arr_count(const char *path);
const char *rules_arr_str(const char *path, int index, const char *field, const char *def);
double rules_arr_num(const char *path, int index, const char *field, double def);

int  rules_sub_count(const char *path, int index, const char *field);
const char *rules_sub_str(const char *path, int index, const char *field, int k, const char *def);

int  rules_severity_rank(const char *name, int def);

double rules_number(const char *key, double fallback);
int    rules_flag(const char *key, int fallback);

const char *rules_text(const char *path, const char *def);

int rules_sig_match(const char *path, const char *body, rules_sig_t *out);

int rules_weak_header_count(void);
const char *rules_weak_header(int index, const char *field, const char *fallback);
int rules_weak_header_num(int index, const char *field, int fallback);

json_t *rules_root(void);

const char *rules_default_json(void);

#endif

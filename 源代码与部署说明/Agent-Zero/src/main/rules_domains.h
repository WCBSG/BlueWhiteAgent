
#ifndef AGENT_RULES_DOMAINS_H
#define AGENT_RULES_DOMAINS_H

#include "common.h"
#include "json.h"

typedef struct {
  const char *id;
  const char *title;
  const char *file;
  const char *note;
} rules_domain_t;

int              rules_domain_count(void);
const rules_domain_t *rules_domain_at(int i);
const rules_domain_t *rules_domain_find(const char *id);

void rules_domain_dir(char *out, size_t cap);

int rules_domains_generate(char *err, size_t errcap);

json_t *rules_domains_load_merged(char *err, size_t errcap);

json_t *rules_domains_factory(void);

json_t *rules_domains_read(const char *id, char *err, size_t errcap);

int rules_domains_save(const char *id, json_t *patch, char *err, size_t errcap);

int rules_domains_save_all(json_t *root, char *err, size_t errcap);

const rules_domain_t *rules_domain_of_key(const char *key);

void   rules_preset_dir(char *out, size_t cap);

int    rules_preset_list(json_t **out, char *err, size_t errcap);

int    rules_preset_save(const char *name, char *err, size_t errcap);

int    rules_preset_apply(const char *name, char *err, size_t errcap);

int    rules_preset_delete(const char *name, char *err, size_t errcap);

const char *rules_preset_active(void);

#endif

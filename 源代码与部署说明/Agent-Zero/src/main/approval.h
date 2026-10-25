
#ifndef AGENT_APPROVAL_H
#define AGENT_APPROVAL_H

#include "common.h"
#include "json.h"

typedef enum {
  APPROVAL_ALLOW = 0,
  APPROVAL_ASK = 1,
  APPROVAL_DENY = 2,
} approval_action_t;

typedef struct {
  char id[24];
  char name[64];
  char mode[16];
  char note[200];

  char rules[1024];
} approval_policy_t;

void approval_set_path(const char *path);
void approval_load(void);
void approval_save(void);

json_t *approval_list_json(void);

const char *approval_active_id(void);

int approval_activate(const char *id);

char *approval_save_policy(json_t *p, char *err, size_t err_cap);
int approval_delete_policy(const char *id);

approval_action_t approval_decide(const char *tool, int readonly);

int approval_is_readonly_only(void);

int approval_is_allow_all(void);

const char *approval_mode_text(void);

#endif

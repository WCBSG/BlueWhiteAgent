

#ifndef AGENT_AGENT_H
#define AGENT_AGENT_H

#include "common.h"
#include "json.h"

typedef struct tool_ctx tool_ctx_t;

typedef struct {
  char *text;
  json_t *data;
  char *say;
  int is_error;
} tool_result_t;

typedef struct tool tool_t;
struct tool {
  const char *name;
  const char *description;
  const char *schema;
  const char *kind;
  const char *source_url;

  int readonly;

  int external;
  int (*run)(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
};

typedef struct skill skill_t;

typedef enum { ACT_ACT, ACT_ANSWER, ACT_ASK } act_kind_t;

typedef struct {
  act_kind_t kind;
  char *tool;
  json_t *args;
  char *text;
  char *reason;
  char *raw;
  int from_model;
} decision_t;

void decision_free(decision_t *d);

#define MAX_STEPS_DEFAULT 50

typedef struct {
  buf_t transcript;
  json_t *steps;
  int step_count;
  int stop_code;
  char stop_reason[320];
} loop_state_t;

enum {
  STOP_NONE = 0,
  STOP_ANSWERED,
  STOP_NEED_USER,
  STOP_NO_PROGRESS,
  STOP_BUDGET,
  STOP_OUT_OF_SCOPE,
  STOP_ERROR,
  STOP_ANSWERING_ONLY,
  STOP_CANCELLED,
};

typedef struct agent agent_t;

typedef struct {
  void *userdata;

  void (*on_thinking)(void *ud, const char *text);

  void (*on_action)(void *ud, const char *tool, json_t *args, const char *reason);

  void (*on_status)(void *ud, const char *tool, const char *status, const char *note);

  void (*on_observation)(void *ud, const char *tool, tool_result_t *result);

  void (*on_answer)(void *ud, const char *text);

  void (*on_ask)(void *ud, const char *text);

  int (*on_approval)(void *ud, const char *tool, json_t *args, char **reason);

  int (*on_question)(void *ud, const char *payload, char **answer);

  void (*on_delta)(void *ud, const char *text);
} agent_hooks_t;

agent_t *agent_create(const char *session_id);
void     agent_free(agent_t *a);

void     agent_cancel(agent_t *a);
void     agent_cancel_clear(agent_t *a);
int      agent_cancelled(agent_t *a);

void     agent_emit_delta(agent_t *a, const char *text);
void     agent_set_hooks(agent_t *a, const agent_hooks_t *hooks);

void     agent_set_scope(agent_t *a, const char *task_id, const char **domains, int n);

void     agent_set_store(agent_t *a, void *store, const char *run_id);

void     agent_set_unattended(agent_t *a, int on);
int      agent_unattended(agent_t *a);

long long agent_llm_ms(agent_t *a);
void      agent_llm_ms_reset(agent_t *a);

void agent_set_ctx_used(agent_t *a, int tokens);
int  agent_ctx_used(agent_t *a);

void agent_set_ctx_window(agent_t *a, int window, int reserve);
int  agent_ctx_window(agent_t *a);
int  agent_ctx_reserve(agent_t *a);

int         agent_ctx_compressed(agent_t *a);
const char *agent_ctx_summary(agent_t *a);
void agent_ctx_set_summary(agent_t *a, const char *summary, int compacted_turns);

void agent_history_keep_recent(agent_t *a, int keep);

void     agent_add_history(agent_t *a, const char *role, const char *text);

int        agent_history_count(agent_t *a);
const char *agent_history_at(agent_t *a, int i, const char **role_out);

int agent_run_turn(agent_t *a, const char *user_text, loop_state_t *st);

void agent_print_tools(void);
void agent_print_skills(void);
json_t *agent_skill_list_json(void);
json_t *agent_tool_list_json(void);

#endif

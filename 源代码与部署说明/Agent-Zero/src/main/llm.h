
#ifndef AGENT_LLM_H
#define AGENT_LLM_H

#include "agent.h"
#include "common.h"
#include "json.h"
#include "llm_provider.h"

void llm_init(const char *env_dir);
int  llm_enabled(void);

void llm_set_test_mode(int on);

void        llm_set_last_error(const char *msg);
const char *llm_last_error(void);

void llm_reset_error(void);

int llm_decide(agent_t *a, const char *user_text, json_t *observations,
               const char *scope_note, decision_t *out);

int llm_extract_action(const char *raw, decision_t *out);

int llm_ask(const char *prompt, buf_t *out);

#endif


#ifndef AGENT_LLM_PROVIDER_H
#define AGENT_LLM_PROVIDER_H

#include "common.h"
#include "json.h"

typedef enum {
  PROVIDER_DAS = 0,
  PROVIDER_OPENAI = 1,
  PROVIDER_ANTHROPIC = 2
} provider_kind_t;

#define PROVIDER_MAX 16

typedef struct {
  char id[64];
  char name[80];
  int  kind;
  char base_url[256];
  char model[128];
  char api_key[256];
  char api_secret[256];
  char user_app_key[128];
  char agent_id[128];
  char agent_keyword[128];
  char headers[512];
  double timeout_ms;
  double temperature;
  int    max_tokens;
  int    context_tokens;
  int    enabled;
} provider_t;

typedef void (*provider_emit_fn)(void *ud, const char *text);

void providers_init(void);
int  providers_count(void);
provider_t *provider_at(int i);
provider_t *provider_find(const char *id);
int  providers_active_index(void);
const char *providers_active_id(void);

int  provider_ready(const provider_t *p);
int  providers_ready_count(void);

const char *providers_display_name(void);

void providers_last_tokens(int *prompt, int *completion);
void providers_reset_tokens(void);

int providers_context_tokens(void);
const char *provider_kind_name(int kind);
int  provider_kind_from_name(const char *name);
const char *providers_path(void);

char *providers_json(int mask_secret);

int  providers_apply(json_t *root, char *err, size_t errcap);
int  providers_save(void);

int provider_chat(const provider_t *p, const char *prompt, provider_emit_fn emit,
                  void *ud, buf_t *out, char *err, size_t errcap);

int providers_test(const char *id, char *detail, size_t detailcap);

void llm_make_sign(const char *app_key, const char *app_secret, char *out, size_t cap);

#endif

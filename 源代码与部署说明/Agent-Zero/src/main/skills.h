
#ifndef AGENT_SKILLS_H
#define AGENT_SKILLS_H

#include "agent.h"
#include "common.h"
#include "io.h"
#include "json.h"
#include "tools.h"

typedef struct skill skill_t;

typedef struct {
  char *summary;
  json_t *data;
  int is_error;
  int finding_count;
} skill_result_t;

struct skill {
  const char *name;
  const char *title;
  const char *purpose;
  const char *when;
  const char *tools;
  int multi_step;
  int (*run)(tool_ctx_t *ctx, json_t *args, skill_result_t *out);
  const char *body;
};

void     skills_init(void);
int      skills_count(void);
skill_t *skills_get(int index);
skill_t *skills_find(const char *name);
json_t  *skills_decl_json(void);
void     skills_manifest(buf_t *out);
int      skills_run(tool_ctx_t *ctx, const char *name, json_t *args,
                    skill_result_t *out);
void     skill_result_free(skill_result_t *r);

int      skill_closure_run(tool_ctx_t *ctx, const char *name, json_t *args,
                           skill_result_t *out);

int      skills_register_external(const char *name, const char *title, const char *purpose,
                                  const char *when, const char *tools,
                                  int (*run)(tool_ctx_t *, json_t *, skill_result_t *));

int      skills_override_text(const char *name, const char *title, const char *purpose,
                              const char *when, const char *tools, const char *body);

void     skills_reset_external(void);

#endif

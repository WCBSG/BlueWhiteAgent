
#ifndef AGENT_TOOL_ENTRY_H
#define AGENT_TOOL_ENTRY_H

#include "agent.h"
#include "json.h"

int tool_entry_parse(json_t *spec, const char *origin);

int tool_entry_run(tool_ctx_t *ctx, json_t *args, tool_result_t *out);

void tool_entry_reset(void);
int  tool_entry_count(void);

#endif

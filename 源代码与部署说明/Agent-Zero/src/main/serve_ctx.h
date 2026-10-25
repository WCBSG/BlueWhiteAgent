
#ifndef AGENT_SERVE_CTX_H
#define AGENT_SERVE_CTX_H

#include "common.h"
#include "http.h"
#include "store.h"

store_t *serve_store(void);
const char *serve_task_id(void);
void serve_audit_line(const char *action, const char *target, const char *detail);

void serve_refresh_status(void);

#endif

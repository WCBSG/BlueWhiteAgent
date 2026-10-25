
#ifndef AGENT_SERVE_H
#define AGENT_SERVE_H

#include "common.h"

int serve_run(const char *domain, int port, int open_ui);

const char *serve_token(void);

#endif

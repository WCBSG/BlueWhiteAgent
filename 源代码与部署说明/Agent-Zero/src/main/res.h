
#ifndef AGENT_RES_H
#define AGENT_RES_H

#include "common.h"

int res_load_text(const char *name, char **out, size_t *out_len);

int res_exists(const char *name);

int res_bootstrap_data_dir(void);

#endif

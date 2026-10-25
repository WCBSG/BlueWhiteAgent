
#ifndef AGENT_EXT_H
#define AGENT_EXT_H

#include "agent.h"
#include "common.h"
#include "json.h"

int  ext_load_all(void);

int  ext_list_files(const char *dir, const char *ext, char ***out);

void ext_register_all(void);

void ext_shutdown(void);

void ext_stats(int *tools, int *skills, int *mcp, int *mcp_tools);

const char *ext_dir(char *out, size_t cap, const char *child);

void ext_bootstrap(void);

int  ext_run_capture(const char *cmdline, const char *workdir, int timeout_ms,
                     char **out_text, int *out_exit);

int ext_reload_local(void);

json_t *ext_inventory_json(void);

#endif

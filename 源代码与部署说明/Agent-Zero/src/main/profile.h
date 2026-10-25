
#ifndef AGENT_PROFILE_H
#define AGENT_PROFILE_H

#include "common.h"
#include "json.h"

int  profile_set_active(json_t *profile);
void profile_clear_active(void);
int  profile_is_active(void);
const char *profile_active_id(void);
const char *profile_active_name(void);

int profile_active_paths(const char **out, int cap);

int profile_scan_text(const char *text, char *kind, size_t kind_cap, char *severity,
                      size_t sev_cap, char *masked, size_t masked_cap);

int profile_type_hit(const char *path_or_url);

#endif

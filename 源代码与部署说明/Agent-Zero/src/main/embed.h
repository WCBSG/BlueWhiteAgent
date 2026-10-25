
#ifndef AGENT_EMBED_H
#define AGENT_EMBED_H

#include <stddef.h>

int embed_lookup(const char *name, const char **data, size_t *len);

int embed_count(void);
const char *embed_name_at(int index);

#endif


#ifndef AGENT_REGEX_H
#define AGENT_REGEX_H

#include <stddef.h>

typedef struct rx_pattern rx_pattern;
rx_pattern *rx_compile(const char *pattern, char *err, size_t err_cap);
void        rx_free(rx_pattern *re);

int rx_search(const rx_pattern *re, const char *text, int *out_off, int *out_len);

int rx_find(const char *pattern, const char *text, int *out_off, int *out_len,
            char *err, size_t err_cap);

#endif

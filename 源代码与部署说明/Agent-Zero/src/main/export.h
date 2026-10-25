
#ifndef AGENT_EXPORT_H
#define AGENT_EXPORT_H

#include "common.h"
#include "store.h"

int export_supported(const char *fmt);

int export_report(store_t *s, const char *report_id, const char *fmt, buf_t *out,
                  char *err, size_t err_cap);

void export_filename(const char *report_id, const char *fmt, char *out, size_t cap);

#endif

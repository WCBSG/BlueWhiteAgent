
#ifndef AGENT_IO_H
#define AGENT_IO_H

#include "common.h"
#include "json.h"

typedef struct {
  int (*fetch)(void *ud, const char *url, const char *method,
               int *status, char **body, size_t *body_len, char **err);
  int (*fetch_ex)(void *ud, const char *url, const char *method, int *status,
                  char **headers, char **body, size_t *body_len, char **err);

  int (*in_scope)(void *ud, const char *url);
  void *userdata;
} tools_io_t;

#endif


#ifndef AGENT_HTTP_H
#define AGENT_HTTP_H

#include "common.h"
#include "json.h"

#include <ws2tcpip.h>

typedef struct {
  char method[8];
  char path[512];
  char raw_path[512];
  char query[1024];
  char *body;
  size_t body_len;
  int keep_alive;

  char host[256];
  char origin[256];
  char content_type[128];
  char token[160];
} http_req_t;

typedef struct {
  SOCKET sock;
  int header_sent;
  int status;
  int aborted;
  int no_reuse;
} http_res_t;

typedef void (*http_handler_t)(const http_req_t *req, http_res_t *res, void *ud);

#define HTTP_MAX_BODY (1024 * 1024)

const char *http_query(const http_req_t *req, const char *key, char *out, size_t cap,
                       const char *def);
char *http_url_decode(const char *s);

void http_res_text(http_res_t *res, int status, const char *ctype, const char *body);
void http_res_json(http_res_t *res, int status, const char *json);
void http_res_404(http_res_t *res);

void http_res_bytes(http_res_t *res, int status, const char *ctype, const char *data,
                    size_t len);

void http_res_file(http_res_t *res, int status, const char *ctype, const char *filename,
                   const char *data, size_t len);

int http_sse_begin(http_res_t *res);

int http_sse_json(http_res_t *res, const char *json);

int  http_startup(void);
void http_shutdown(void);

int  http_serve(const char *bind_ip, int port, http_handler_t handler, void *ud);
void http_stop(void);
const char *http_last_error(void);

int  http_is_running(void);

#endif

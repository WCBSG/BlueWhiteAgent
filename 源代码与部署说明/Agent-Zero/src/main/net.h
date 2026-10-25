
#ifndef AGENT_NET_H
#define AGENT_NET_H

#include "common.h"
#include "io.h"
#include "json.h"

typedef struct {
  int status;
  char *headers;
  char *body;
  size_t body_len;
  char *error;
  int rate_limited;
  int ms;
} http_resp_t;

void net_init(void);
void net_shutdown(void);

void net_set_readonly(int on);

void net_set_scope(const char *task_id, const char **domains, int count);

void net_pool_set(const char **entries, int count);

int net_pool_load_file(const char *path);
int  net_pool_count(void);

int  net_pool_snapshot(char ***out);

int  net_pool_has(const char *host, int port, const char *path);

int  net_scope_violation(void);
void net_scope_violation_clear(void);

int  net_url_allowed(const char *url);
void net_set_audit_path(const char *path);
void net_set_rate_limit(double qps);

void net_set_cancel(volatile LONG *flag);
int  net_cancelled(void);

typedef int (*net_stream_fn)(void *ud, const char *data, size_t len);
void net_post_stream(const char *url, const char *headers, int timeout_ms,
                     const char *body, net_stream_fn cb, void *ud, http_resp_t *resp);

int net_get_text(const char *url, char **out, size_t *out_len, char *err, size_t errcap);

void net_set_target_base(const char *base);

void net_align_url(const char *url, char *out, size_t cap);

void net_request(const char *url, const char *method, const char *content_type,
                 const char *body, size_t body_len, http_resp_t *resp);
void http_resp_free(http_resp_t *r);

void net_audit(const char *action, const char *target, int allowed, const char *detail,
               const char *run_id);

int  net_http_calls(void);

int  net_bench(const char *url, int n, int *out_conns, int *out_requests);

void net_webhook_post(const char *url, const char *token, const char *body,
                      http_resp_t *resp);

void *net_io(void);

tools_io_t *net_io_impl(void);

void net_host_of(const char *url, char *out, size_t cap);
int  net_same_host(const char *a, const char *b);

int  net_host_port_of(const char *in, char *host_out, size_t hcap);

void net_align_base_from(const char *host_or_url);

#endif

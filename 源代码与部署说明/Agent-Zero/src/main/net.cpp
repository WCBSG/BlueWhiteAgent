
#include "net.h"

#include "rules.h"
#include "tools.h"

#include <winhttp.h>

static HINTERNET g_session = NULL;
static int g_readonly = 0;

struct thread_scope_t {
  char task_id[64] = {0};
  char *domains[32] = {NULL};
  int count = 0;
  int violation = 0;
  char target_base[512] = {0};

  ~thread_scope_t() {
    for (int i = 0; i < count; i++) free(domains[i]);
  }
  void set(const char *tid, const char **d, int n) {
    for (int i = 0; i < count; i++) free(domains[i]);
    count = 0;
    snprintf(task_id, sizeof(task_id), "%s", tid ? tid : "");
    if (d && n > 0) {
      int cap = (int)(sizeof(domains) / sizeof(domains[0]));
      for (int i = 0; i < n && count < cap; i++) domains[count++] = xstrdup(d[i]);
    }
  }
};

static thread_local thread_scope_t g_scope;

static char **g_pool = NULL;
static int g_pool_count = 0;

static int host_allowed(const char *host, int port, const char *path);

static char g_audit_path[MAX_PATH * 2] = {0};
static double g_qps = 2.0;
static long long g_last_ms = 0;
static CRITICAL_SECTION g_net_lock;
static int g_lock_ready = 0;
static int g_http_calls = 0;

static char *net_error_text(DWORD err, const char *phase) {
  buf_t b;
  buf_init(&b);
  const char *hint = NULL;
  switch (err) {
    case ERROR_WINHTTP_NAME_NOT_RESOLVED: hint = "域名解析不了,检查域名是否写错或 DNS"; break;
    case ERROR_WINHTTP_CANNOT_CONNECT: hint = "连不上端口,检查服务是否在跑、端口是否正确"; break;
    case ERROR_WINHTTP_TIMEOUT: hint = "请求超时,站点慢或被防火墙丢弃"; break;
    case ERROR_WINHTTP_SECURE_FAILURE: hint = "TLS 证书校验没通过,检查证书是否过期或自签"; break;
    case ERROR_WINHTTP_INVALID_SERVER_RESPONSE: hint = "响应格式不合规,可能是中间设备拦截或站点异常"; break;
    case ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED: hint = "站点要求客户端证书"; break;
    case ERROR_WINHTTP_CONNECTION_ERROR: hint = "连接被重置,可能是防火墙或 WAF 拦截"; break;
    default: hint = "网络层错误,可先用浏览器确认该地址是否可达"; break;
  }
  buf_printf(&b, "%s失败(err=%lu:%s)", phase ? phase : "请求", err, hint);
  return buf_take(&b);
}

static void net_lock_init(void) {
  if (!g_lock_ready) {
    InitializeCriticalSection(&g_net_lock);
    g_lock_ready = 1;
  }
}

static volatile LONG g_conn_created = 0;

void net_reset_counters(void) { InterlockedExchange(&g_conn_created, 0); }

void net_init(void) {
  net_lock_init();
  if (!g_session) {
    g_session = WinHttpOpen(L"SecInspectAgent/1.0 (non-destructive; C edition)",
                            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_session) {
      log_error("WinHTTP 会话创建失败 (err=%lu)", GetLastError());
    } else {

      DWORD decompress = WINHTTP_DECOMPRESSION_FLAG_ALL;
      WinHttpSetOption(g_session, WINHTTP_OPTION_DECOMPRESSION, &decompress,
                       sizeof(decompress));
    }
  }
}

void net_shutdown(void) {
  if (g_session) { WinHttpCloseHandle(g_session); g_session = NULL; }
  g_scope.set("", NULL, 0);
  net_lock_init();
  EnterCriticalSection(&g_net_lock);
  if (g_pool) { str_free_list(g_pool, g_pool_count); g_pool = NULL; g_pool_count = 0; }
  LeaveCriticalSection(&g_net_lock);
}

void net_set_readonly(int on) { g_readonly = on ? 1 : 0; }

void net_set_scope(const char *task_id, const char **domains, int count) {
  g_scope.set(task_id, domains, count);
}

void net_set_audit_path(const char *path) {
  strncpy_s(g_audit_path, sizeof(g_audit_path), path ? path : "", _TRUNCATE);
}

void net_pool_set(const char **entries, int count) {
  net_lock_init();
  EnterCriticalSection(&g_net_lock);
  if (g_pool) { str_free_list(g_pool, g_pool_count); g_pool = NULL; }
  g_pool_count = 0;
  if (entries && count > 0) {
    g_pool = (char **)xcalloc((size_t)count, sizeof(char *));
    for (int i = 0; i < count; i++) g_pool[i] = xstrdup(entries[i]);
    g_pool_count = count;
  }
  LeaveCriticalSection(&g_net_lock);
}

int net_pool_count(void) {
  EnterCriticalSection(&g_net_lock);
  int n = g_pool_count;
  LeaveCriticalSection(&g_net_lock);
  return n;
}

int net_pool_snapshot(char ***out) {
  if (out) *out = NULL;
  net_lock_init();
  EnterCriticalSection(&g_net_lock);
  int n = g_pool_count;
  char **list = NULL;
  if (n > 0) {
    list = (char **)xcalloc((size_t)n, sizeof(char *));
    for (int i = 0; i < n; i++) list[i] = xstrdup(g_pool[i]);
  }
  LeaveCriticalSection(&g_net_lock);
  if (!out) {
    str_free_list(list, n);
    return n;
  }
  *out = list;
  return n;
}

int net_pool_load_file(const char *path) {
  if (!path || !*path) return -1;
  size_t len = 0;
  char *text = file_read_all(path, &len);
  if (!text) return -1;
  json_t *root = json_parse(text);
  free(text);
  if (!root) return -1;
  json_t *hosts = j_get(root, "hosts");
  const char *list[512];
  int n = 0;
  for (int i = 0; i < j_len(hosts) && n < 512; i++) {
    json_t *v = j_at(hosts, i);
    if (!v) continue;
    if (v->type == J_STR && v->str) list[n++] = v->str;
    else if (v->type == J_OBJ) {
      const char *h = j_s(v, "host", "");
      if (h[0]) list[n++] = h;
    }
  }
  net_pool_set(list, n);
  json_free(root);
  return n;
}

int net_pool_has(const char *host, int port, const char *path) {
  if (!host || !*host) return 0;
  return host_allowed(host, port, path);
}

int net_scope_violation(void) { return g_scope.violation; }
void net_scope_violation_clear(void) { g_scope.violation = 0; }

void net_set_rate_limit(double qps) { g_qps = (qps > 0) ? qps : 2.0; }

static thread_local volatile LONG *g_cancel_flag = NULL;

void net_set_cancel(volatile LONG *flag) { g_cancel_flag = flag; }
int net_cancelled(void) { return (g_cancel_flag && *g_cancel_flag) ? 1 : 0; }void net_set_target_base(const char *base) {
  strncpy_s(g_scope.target_base, sizeof(g_scope.target_base), base ? base : "", _TRUNCATE);
  char *t = str_trim(g_scope.target_base);
  if (t != g_scope.target_base) memmove(g_scope.target_base, t, strlen(t) + 1);
}

void net_align_url(const char *url, char *out, size_t cap) {
  const char *base = g_scope.target_base;
  if (!base[0] || !url || !*url) {
    snprintf(out, cap, "%s", url ? url : "");
    return;
  }
  char base_host[256], url_host[256];
  net_host_of(base, base_host, sizeof(base_host));
  net_host_of(url, url_host, sizeof(url_host));
  if (!str_ieq(base_host, url_host)) {
    snprintf(out, cap, "%s", url);
    return;
  }

  const char *scheme_end = strstr(base, "://");
  size_t scheme_len = scheme_end ? (size_t)(scheme_end - base) + 3 : 0;
  const char *auth = base + scheme_len;
  size_t auth_len = 0;
  while (auth[auth_len] && auth[auth_len] != '/' && auth[auth_len] != '?' &&
         auth[auth_len] != '#') {
    auth_len++;
  }

  const char *path = strstr(url, "://");
  path = path ? strchr(path + 3, '/') : NULL;
  snprintf(out, cap, "%.*s%.*s%s", (int)scheme_len, base, (int)auth_len, auth,
           path ? path : "/");
}

void net_host_of(const char *url, char *out, size_t cap) {
  out[0] = 0;
  if (!url) return;
  const char *p = strstr(url, "://");
  p = p ? p + 3 : url;
  size_t i = 0;
  while (p[i] && p[i] != '/' && p[i] != '?' && p[i] != '#' && i < cap - 1) {
    out[i] = (char)tolower((unsigned char)p[i]);
    i++;
  }
  out[i] = 0;
  char *at = strchr(out, '@');
  if (at) memmove(out, at + 1, strlen(at));
  char *colon = strchr(out, ':');
  if (colon) *colon = 0;
}

int net_host_port_of(const char *in, char *host_out, size_t hcap) {
  if (host_out && hcap) host_out[0] = 0;
  if (!in) return 0;
  net_host_of(in, host_out, hcap);
  const char *p = strstr(in, "://");
  p = p ? p + 3 : in;
  const char *end = p + strcspn(p, "/?#");
  const char *colon = NULL;
  for (const char *q = p; q < end; q++) if (*q == ':') colon = q;
  if (!colon || colon + 1 >= end) return 0;
  int port = 0;
  for (const char *q = colon + 1; q < end; q++) {
    if (*q < '0' || *q > '9') return 0;
    port = port * 10 + (*q - '0');
    if (port > 65535) return 0;
  }
  return port;
}

void net_align_base_from(const char *host_or_url) {
  char host[256];
  int port = net_host_port_of(host_or_url, host, sizeof(host));
  if (port <= 0 || !host[0]) return;
  char base[320];
  snprintf(base, sizeof(base), "%s://%s:%d", port == 443 ? "https" : "http", host, port);
  net_set_target_base(base);
  log_info("[目标] 目标地址带端口,巡检请求对齐到 %s", base);
}

int net_same_host(const char *a, const char *b) {  char ha[256], hb[256];
  net_host_of(a, ha, sizeof(ha));
  net_host_of(b, hb, sizeof(hb));
  return ha[0] && strcmp(ha, hb) == 0;
}

typedef struct {
  int deny;
  char host[256];
  int port;
  char path[512];
} pool_entry_t;

static int pool_parse_entry(const char *raw, pool_entry_t *out) {
  memset(out, 0, sizeof(*out));
  if (!raw || !*raw) return -1;
  const char *p = raw;
  if (*p == '!') { out->deny = 1; p++; }
  if (!*p) return -1;
  char body[768];
  snprintf(body, sizeof(body), "%s", p);
  char *slash = strchr(body, '/');
  if (slash) {
    snprintf(out->path, sizeof(out->path), "%s", slash);
    *slash = 0;
    if (!out->path[0]) snprintf(out->path, sizeof(out->path), "/");
  }
  if (!body[0]) return -1;
  out->port = net_host_port_of(body, out->host, sizeof(out->host));
  if (!out->host[0]) return -1;
  return 0;
}

static int entry_matches(const char *entry, const char *host, int port, const char *path) {
  pool_entry_t e;
  if (pool_parse_entry(entry, &e) != 0) return 0;
  if (e.port > 0 && port > 0 && e.port != port) return 0;

  int host_hit = str_ieq(host, e.host);
  if (!host_hit) {
    size_t lh = strlen(host), ld = strlen(e.host);
    if (lh > ld && str_ieq(host + (lh - ld), e.host) && host[lh - ld - 1] == '.') host_hit = 1;
  }
  if (!host_hit) return 0;

  if (e.path[0]) {

    const char *q = path && path[0] ? path : "/";
    size_t pl = strlen(e.path);
    int hit = 0;
    if (strncmp(q, e.path, pl) == 0) {
      hit = (e.path[pl - 1] == '/') ? 1
                                    : (q[pl] == 0 || q[pl] == '/' || q[pl] == '?' || q[pl] == '#');
    } else if (e.path[pl - 1] == '/' && pl > 1 && strncmp(q, e.path, pl - 1) == 0) {
      char next = q[pl - 1];
      hit = (next == 0 || next == '/' || next == '?' || next == '#');
    }
    if (!hit) return 0;
  }
  return 1;
}

static int host_allowed(const char *host, int port, const char *path) {
  if (!host || !*host) return 0;
  EnterCriticalSection(&g_net_lock);
  int have_pool = g_pool_count > 0;
  int denied = 0, allowed = 0;
  if (have_pool) {
    for (int i = 0; i < g_pool_count; i++) {
      pool_entry_t e;
      if (pool_parse_entry(g_pool[i], &e) != 0) continue;
      if (!entry_matches(g_pool[i], host, port, path)) continue;
      if (e.deny) denied = 1;
      else allowed = 1;
    }
  }
  LeaveCriticalSection(&g_net_lock);
  if (have_pool) return denied ? 0 : allowed;

  for (int i = 0; i < g_scope.count; i++) {
    if (entry_matches(g_scope.domains[i], host, port, path)) return 1;
  }
  return 0;
}

void net_audit(const char *action, const char *target, int allowed, const char *detail,
               const char *run_id) {
  if (!g_audit_path[0]) return;
  json_t *row = j_obj();
  char ts[40];
  now_iso(ts, sizeof(ts));
  j_set_str(row, "time", ts);
  j_set_str(row, "actor", "agent-c");
  j_set_str(row, "action", action ? action : "");
  j_set_str(row, "target", target ? target : "");
  j_set_str(row, "task_id", g_scope.task_id);
  j_set_str(row, "run_id", run_id ? run_id : "");
  j_set_bool(row, "allowed", allowed);
  j_set_str(row, "detail", detail ? detail : "");
  char *line = json_dump(row);
  buf_t out;
  buf_init(&out);
  buf_puts(&out, line);
  buf_putc_(&out, '\n');
  file_append(g_audit_path, out.data, out.len);
  buf_free(&out);
  free(line);
  json_free(row);
}

static void rate_wait(void) {
  net_lock_init();
  EnterCriticalSection(&g_net_lock);
  long long now = now_ms();
  long long min_gap = (long long)(1000.0 / g_qps);
  long long wait = g_last_ms + min_gap - now;
  if (wait > 0) {
    LeaveCriticalSection(&g_net_lock);
    Sleep((DWORD)wait);
    EnterCriticalSection(&g_net_lock);
    now = now_ms();
  }
  g_last_ms = now;
  g_http_calls++;
  LeaveCriticalSection(&g_net_lock);
}

int net_http_calls(void) { return g_http_calls; }

static void parse_url(const char *url, wchar_t *host, size_t host_cap,
                      wchar_t *path, size_t path_cap, int *https, INTERNET_PORT *port) {
  wchar_t *wurl = u8_to_w(url);
  URL_COMPONENTS uc;
  memset(&uc, 0, sizeof(uc));
  uc.dwStructSize = sizeof(uc);
  uc.dwHostNameLength = (DWORD)-1;
  uc.dwUrlPathLength = (DWORD)-1;
  uc.dwExtraInfoLength = (DWORD)-1;
  *https = 0;
  *port = 0;
  host[0] = 0;
  wcscpy_s(path, path_cap, L"/");

  if (wurl && WinHttpCrackUrl(wurl, 0, 0, &uc)) {
    if (uc.lpszHostName) {
      size_t n = uc.dwHostNameLength < host_cap - 1 ? uc.dwHostNameLength : host_cap - 1;
      wcsncpy_s(host, host_cap, uc.lpszHostName, n);
    }
    *https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    *port = uc.nPort;

    size_t used = 0;
    if (uc.lpszUrlPath && uc.dwUrlPathLength) {
      wcsncpy_s(path, path_cap, uc.lpszUrlPath, uc.dwUrlPathLength);
      used = uc.dwUrlPathLength;
    }
    if (uc.lpszExtraInfo && uc.dwExtraInfoLength && used < path_cap - 1) {
      wcsncat_s(path, path_cap, uc.lpszExtraInfo,
                path_cap - used - 1 < uc.dwExtraInfoLength ? path_cap - used - 1 : uc.dwExtraInfoLength);
    }
  }
  free(wurl);
}

typedef struct {
  char host[256];
  int port;
  char path[1024];
} url_scope_t;

static void url_scope_of(const char *url, url_scope_t *s) {
  net_host_of(url, s->host, sizeof(s->host));
  char host_only[256];
  s->port = net_host_port_of(url, host_only, sizeof(host_only));
  snprintf(s->path, sizeof(s->path), "/");
  const char *scheme = strstr(url, "://");
  const char *p = scheme ? strchr(scheme + 3, '/') : strchr(url, '/');
  if (!p || !p[0]) return;
  size_t n = strlen(p);
  if (n >= sizeof(s->path)) n = sizeof(s->path) - 1;
  memcpy(s->path, p, n);
  s->path[n] = 0;
  char *q = strpbrk(s->path, "?#");
  if (q) *q = 0;
}

int net_url_allowed(const char *url) {
  if (!url || !*url) return 0;
  char aligned[2048];
  net_align_url(url, aligned, sizeof(aligned));
  url_scope_t sc;
  url_scope_of(aligned, &sc);
  if (!sc.host[0]) return 0;

  if (net_pool_count() == 0 && g_scope.count == 0) return 1;
  return host_allowed(sc.host, sc.port, sc.path);
}

typedef struct {
  const char *method;
  const char *headers;
  const void *body;
  size_t body_len;
  int timeout_ms;
  int hdr_timeout_ms;
  int deadline_ms;
  int slice_ms;
  size_t max_body;
  net_stream_fn cb;
  void *cb_ud;
  int check_scope;
  int check_cancel;
  int retry_invalid;
  const char *audit_tag;
} http_call_t;

static void http_call(const char *url, const http_call_t *opt, http_resp_t *resp) {
  memset(resp, 0, sizeof(*resp));
  long long t0 = now_ms();
  if (!url || !*url) {
    resp->error = xstrdup("空 URL");
    return;
  }
  if (!g_session) net_init();
  if (!g_session) {
    resp->error = xstrdup("WinHTTP 未初始化");
    return;
  }

  const char *m = (opt->method && *opt->method) ? opt->method : "GET";
  const char *tag = (opt->audit_tag && *opt->audit_tag) ? opt->audit_tag : "fetch";
  const char *body = (const char *)opt->body;
  size_t body_len = body ? opt->body_len : 0;

  char aligned[2048];
  if (opt->check_scope) {
    net_align_url(url, aligned, sizeof(aligned));
    url = aligned;
  }

  if (opt->check_scope) {

    if (g_readonly && !str_ieq(m, "GET") && !str_ieq(m, "HEAD") && !str_ieq(m, "OPTIONS")) {
      resp->error = xstrdup("只读模式:只允许 GET/HEAD/OPTIONS(非破坏性要求)");
      net_audit(tag, url, 0, "只读模式拒绝非只读方法", NULL);
      return;
    }
    url_scope_t sc;
    url_scope_of(url, &sc);
    int pooled = net_pool_count() > 0;

    if (!pooled && g_scope.count == 0) {
      resp->error = xstrdup("还没有授权目标:先把主机加进授权池");
      g_scope.violation = 1;
      net_audit("authorize", url, 0, resp->error, NULL);
      return;
    }
    if (!host_allowed(sc.host, sc.port, sc.path)) {
      buf_t e;
      buf_init(&e);
      if (pooled && host_allowed(sc.host, sc.port, "/"))
        buf_printf(&e, "路径 %s 被授权池的排除规则拦下(主机本身在池内)", sc.path);
      else if (pooled) buf_printf(&e, "目标 %s 不在授权池内", sc.host);
      else buf_printf(&e, "目标 %s 不在授权域名内", sc.host);
      resp->error = buf_take(&e);

      g_scope.violation = 1;
      net_audit("authorize", url, 0, resp->error, NULL);
      log_warn("[合规] 拒绝越权目标: %s", url);
      return;
    }

    if (net_cancelled()) {
      resp->error = xstrdup("本轮已被叫停,不再发请求");
      return;
    }
    rate_wait();
  }

  wchar_t whost[256], wpath[2048];
  int https = 0;
  INTERNET_PORT port = 0;
  parse_url(url, whost, 256, wpath, 2048, &https, &port);

  int timeout = opt->timeout_ms > 0 ? opt->timeout_ms : 20000;
  int slice = opt->slice_ms > 0 ? opt->slice_ms : 800;
  size_t max_body = opt->max_body > 0 ? opt->max_body : (size_t)8 * 1024 * 1024;

  HINTERNET conn = WinHttpConnect(g_session, whost, port, 0);
  InterlockedIncrement(&g_conn_created);
  if (!conn) {
    buf_t e;
    buf_init(&e);
    buf_printf(&e, "连接 %ls 失败 (err=%lu)", whost, GetLastError());
    resp->error = buf_take(&e);
  } else {
    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    LPCWSTR accept_types[] = {L"*/*", NULL};
    HINTERNET req = WinHttpOpenRequest(conn, u8_to_w(m), wpath, NULL,
                                       WINHTTP_NO_REFERER, accept_types, flags);
    if (!req) {
      resp->error = xstrdup("创建请求失败");
    } else {

      DWORD conn_to = 8000, send_to = 15000;

      DWORD hdr_to = (DWORD)(opt->hdr_timeout_ms > 0 ? opt->hdr_timeout_ms : timeout);
      WinHttpSetOption(req, WINHTTP_OPTION_CONNECT_TIMEOUT, &conn_to, sizeof(conn_to));
      WinHttpSetOption(req, WINHTTP_OPTION_SEND_TIMEOUT, &send_to, sizeof(send_to));
      WinHttpSetOption(req, WINHTTP_OPTION_RECEIVE_TIMEOUT, &hdr_to, sizeof(hdr_to));

      const wchar_t *ua = L"SecInspectAgent/1.0 (non-destructive security inspection)";
      WinHttpSetOption(req, WINHTTP_OPTION_USER_AGENT, (LPVOID)ua,
                       (DWORD)(wcslen(ua) * sizeof(wchar_t)));

      DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
      WinHttpSetOption(req, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy,
                       sizeof(redirect_policy));

      const wchar_t *whdrs = (opt->headers && opt->headers[0]) ? u8_to_w(opt->headers) : NULL;
      DWORD deadline = opt->deadline_ms > 0 ? GetTickCount() + (DWORD)opt->deadline_ms : 0;

      BOOL ok = WinHttpSendRequest(req, whdrs ? whdrs : WINHTTP_NO_ADDITIONAL_HEADERS,
                                   whdrs ? (DWORD)-1L : 0,
                                   (LPVOID)(body_len ? body : NULL), (DWORD)body_len,
                                   (DWORD)body_len, 0);
      BOOL recv_ok = ok ? WinHttpReceiveResponse(req, NULL) : FALSE;
      DWORD e2 = recv_ok ? 0 : GetLastError();

      if (ok && !recv_ok && opt->retry_invalid && e2 == ERROR_WINHTTP_INVALID_SERVER_RESPONSE) {
        log_warn("[网络] %s 首次响应异常(err=12152),按协议重试一次", url);
        if (WinHttpSendRequest(req, whdrs ? whdrs : WINHTTP_NO_ADDITIONAL_HEADERS,
                               whdrs ? (DWORD)-1L : 0,
                               (LPVOID)(body_len ? body : NULL), (DWORD)body_len,
                               (DWORD)body_len, 0) &&
            WinHttpReceiveResponse(req, NULL)) {
          recv_ok = TRUE;
          e2 = 0;
        }
      }
      if (whdrs) free((void *)whdrs);

      if (!ok) {
        resp->error = net_error_text(GetLastError(), "发送请求");
      } else if (!recv_ok) {

        buf_t e;
        buf_init(&e);
        buf_printf(&e, "接收响应失败 (err=%lu)", e2);
        resp->error = buf_take(&e);
      } else {
        DWORD status = 0, len = sizeof(status);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &len, WINHTTP_NO_HEADER_INDEX);
        resp->status = (int)status;

        DWORD hlen = 0;
        WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                            WINHTTP_HEADER_NAME_BY_INDEX, NULL, &hlen, WINHTTP_NO_HEADER_INDEX);
        if (hlen > 0) {
          wchar_t *wbuf = (wchar_t *)xmalloc(hlen + sizeof(wchar_t));
          if (WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                  WINHTTP_HEADER_NAME_BY_INDEX, wbuf, &hlen,
                                  WINHTTP_NO_HEADER_INDEX)) {
            resp->headers = w_to_u8(wbuf);
          }
          free(wbuf);
        }

        DWORD slice_to = (DWORD)slice;
        WinHttpSetOption(req, WINHTTP_OPTION_RECEIVE_TIMEOUT, &slice_to, sizeof(slice_to));
        buf_t acc;
        buf_init(&acc);
        for (;;) {
          if (opt->check_cancel && net_cancelled()) {
            resp->error = xstrdup("本轮已被叫停");
            break;
          }
          DWORD avail = 0;
          if (!WinHttpQueryDataAvailable(req, &avail)) {
            DWORD err = GetLastError();
            if (err == ERROR_WINHTTP_TIMEOUT) {

              if (deadline && (long)(GetTickCount() - deadline) >= 0) {

                if (acc.len == 0) resp->error = xstrdup("等待响应超时");
                break;
              }
              continue;
            }
            if (!resp->error) {
              buf_t e;
              buf_init(&e);
              buf_printf(&e, "读取响应失败 (err=%lu)", err);
              resp->error = buf_take(&e);
            }
            break;
          }
          if (avail == 0) break;
          if (acc.len > max_body) break;
          char *chunk = (char *)xmalloc(avail + 1);
          DWORD got = 0;
          if (!WinHttpReadData(req, chunk, avail, &got) || got == 0) { free(chunk); break; }
          chunk[got] = 0;

          if (opt->cb && opt->cb(opt->cb_ud, chunk, got)) {
            buf_putn(&acc, chunk, got);
            free(chunk);
            break;
          }
          buf_putn(&acc, chunk, got);
          free(chunk);
        }
        resp->body = buf_take(&acc);
        resp->body_len = resp->body ? strlen(resp->body) : 0;
      }
      WinHttpCloseHandle(req);
    }
    WinHttpCloseHandle(conn);
  }

  resp->ms = (int)(now_ms() - t0);

  {
    buf_t d;
    buf_init(&d);
    buf_printf(&d, "%s %d %dms%s%s", m, resp->status, resp->ms,
               resp->error ? " err=" : "", resp->error ? resp->error : "");
    net_audit(tag, url, resp->error ? 0 : 1, d.data, NULL);
    buf_free(&d);
  }
}

void net_request(const char *url, const char *method, const char *content_type,
                 const char *body, size_t body_len, http_resp_t *resp) {
  http_call_t opt;
  memset(&opt, 0, sizeof(opt));
  opt.method = method;
  opt.body = body;
  opt.body_len = body_len;
  opt.check_scope = 1;
  opt.check_cancel = 1;
  opt.retry_invalid = 1;
  opt.audit_tag = "fetch";
  opt.max_body = 4 * 1024 * 1024;
  opt.timeout_ms = (int)rules_number("timeout_ms", 20000);
  if (opt.timeout_ms < 3000) opt.timeout_ms = 3000;
  if (opt.timeout_ms > 120000) opt.timeout_ms = 120000;

  buf_t hdrs;
  buf_init(&hdrs);
  if (body_len > 0) {
    buf_printf(&hdrs, "Content-Type: %s\r\n",
               (content_type && *content_type) ? content_type : "application/json");
    opt.headers = hdrs.data;
  }
  http_call(url, &opt, resp);
  buf_free(&hdrs);
}
void http_resp_free(http_resp_t *r) {
  if (!r) return;
  free(r->headers);
  free(r->body);
  free(r->error);
  r->headers = NULL;
  r->body = NULL;
  r->error = NULL;
}

int net_bench(const char *url, int n, int *out_conns, int *out_requests) {
  if (n <= 0) n = 10;
  double saved_qps = g_qps;
  g_qps = 100000.0;
  net_reset_counters();
  int before_calls = g_http_calls;
  long long t0 = now_ms();
  int ok = 0;
  for (int i = 0; i < n; i++) {
    http_resp_t resp;
    memset(&resp, 0, sizeof(resp));
    net_request(url, "GET", NULL, NULL, 0, &resp);
    if (!resp.error && resp.status > 0) ok++;
    http_resp_free(&resp);
  }  long long dt = now_ms() - t0;
  int conns = (int)g_conn_created;
  int reqs = g_http_calls - before_calls;
  g_qps = saved_qps;
  if (out_conns) *out_conns = conns;
  if (out_requests) *out_requests = reqs;
  if (ok == 0) {
    printf("一次都没成功:目标不可达或未授权(%s)\n", url);
    return -1;
  }
  printf("  请求 %d 次(成功 %d),实际建连 %d 条,总耗时 %lld ms,平均 %.0f ms/次\n",
         reqs, ok, conns, dt, reqs > 0 ? (double)dt / reqs : 0.0);
  return (int)(dt / (reqs > 0 ? reqs : 1));
}

static void post_json_ex(const char *url, const char *headers, int timeout_ms,
                         const char *body, net_stream_fn cb, void *ud,
                         http_resp_t *resp, const char *audit_tag) {
  http_call_t opt;
  memset(&opt, 0, sizeof(opt));
  opt.method = "POST";
  opt.headers = headers;
  opt.body = body;
  opt.body_len = body ? strlen(body) : 0;
  opt.timeout_ms = timeout_ms > 0 ? timeout_ms : 20000;
  opt.hdr_timeout_ms = opt.timeout_ms;
  opt.deadline_ms = opt.timeout_ms;
  opt.slice_ms = 800;
  opt.max_body = 8 * 1024 * 1024;
  opt.cb = cb;
  opt.cb_ud = ud;
  opt.check_scope = 0;
  opt.check_cancel = 1;
  opt.retry_invalid = 1;
  opt.audit_tag = audit_tag;
  http_call(url, &opt, resp);
}

void net_post_stream(const char *url, const char *headers, int timeout_ms,
                     const char *body, net_stream_fn cb, void *ud, http_resp_t *resp) {
  post_json_ex(url, headers, timeout_ms, body, cb, ud, resp, "post");
}

int net_get_text(const char *url, char **out, size_t *out_len, char *err, size_t errcap) {
  if (out) *out = NULL;
  if (out_len) *out_len = 0;
  if (err && errcap) err[0] = 0;
  if (!url || !*url) {
    if (err) snprintf(err, errcap, "缺少地址");
    return -1;
  }
  if (!str_startswith(url, "http://") && !str_startswith(url, "https://")) {
    if (err) snprintf(err, errcap, "只接受 http:// 或 https:// 地址");
    return -1;
  }
  if (!g_session) net_init();
  if (!g_session) {
    if (err) snprintf(err, errcap, "WinHTTP 未初始化");
    return -1;
  }

  wchar_t whost[256], wpath[2048];
  int https = 0;
  INTERNET_PORT port = 0;
  parse_url(url, whost, 256, wpath, 2048, &https, &port);

  int rc = -1;
  HINTERNET conn = WinHttpConnect(g_session, whost, port, 0);
  if (!conn) {
    if (err) snprintf(err, errcap, "连接失败");
  } else {
    HINTERNET req = WinHttpOpenRequest(conn, L"GET", wpath, NULL,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       https ? WINHTTP_FLAG_SECURE : 0);
    if (!req) {
      if (err) snprintf(err, errcap, "创建请求失败");
    } else {
      DWORD conn_to = 8000, recv_to = 20000;
      WinHttpSetOption(req, WINHTTP_OPTION_CONNECT_TIMEOUT, &conn_to, sizeof(conn_to));
      WinHttpSetOption(req, WINHTTP_OPTION_RECEIVE_TIMEOUT, &recv_to, sizeof(recv_to));
      if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) ||
          !WinHttpReceiveResponse(req, NULL)) {
        if (err) snprintf(err, errcap, "下载失败(err=%lu)", GetLastError());
      } else {
        DWORD status = 0, slen = sizeof(status);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen, WINHTTP_NO_HEADER_INDEX);
        if (status != 200) {
          if (err) snprintf(err, errcap, "服务器返回 HTTP %lu", status);
        } else {
          buf_t acc;
          buf_init(&acc);
          DWORD avail = 0;
          int too_big = 0;
          while (WinHttpQueryDataAvailable(req, &avail) && avail > 0) {
            if (acc.len > 512 * 1024) { too_big = 1; break; }
            char *chunk = (char *)xmalloc(avail + 1);
            DWORD got = 0;
            if (!WinHttpReadData(req, chunk, avail, &got) || got == 0) { free(chunk); break; }
            chunk[got] = 0;
            buf_putn(&acc, chunk, got);
            free(chunk);
          }
          if (too_big) {
            if (err) snprintf(err, errcap, "文件超过 512KB,不像是一份技能/工具定义");
            buf_free(&acc);
          } else {
            *out = buf_take(&acc);
            if (out_len) *out_len = *out ? strlen(*out) : 0;
            rc = 0;
          }
        }
      }
      WinHttpCloseHandle(req);
    }
    WinHttpCloseHandle(conn);
  }
  {
    buf_t d;
    buf_init(&d);
    buf_printf(&d, "GET %s%s%s", rc == 0 ? "ok" : "fail",
               rc == 0 ? "" : " ", rc == 0 ? "" : (err ? err : ""));
    net_audit("import", url, rc == 0 ? 1 : 0, d.data, NULL);
    buf_free(&d);
  }
  return rc;
}

void net_webhook_post(const char *url, const char *token, const char *body,
                      http_resp_t *resp) {
  buf_t hdrs;
  buf_init(&hdrs);
  buf_puts(&hdrs, "Content-Type: application/json\r\n");
  if (token && token[0]) buf_printf(&hdrs, "Authorization: Bearer %s\r\n", token);
  post_json_ex(url, hdrs.data, 15000, body, NULL, NULL, resp, "notify");
  buf_free(&hdrs);
}

static int io_fetch(void *ud, const char *url, const char *method,
                    int *status, char **body, size_t *body_len, char **err) {
  (void)ud;
  http_resp_t r;
  net_request(url, method, NULL, NULL, 0, &r);
  if (status) *status = r.status;
  if (r.error) {
    if (err) *err = xstrdup(r.error);
    if (body) *body = NULL;
    if (body_len) *body_len = 0;
    http_resp_free(&r);
    return -1;
  }
  if (body) *body = r.body;
  else free(r.body);
  if (body_len) *body_len = r.body_len;
  if (err) *err = NULL;
  free(r.error);
  return 0;
}

static int io_fetch_ex(void *ud, const char *url, const char *method, int *status,
                       char **headers, char **body, size_t *body_len, char **err) {
  (void)ud;
  http_resp_t r;
  net_request(url, method, NULL, NULL, 0, &r);
  if (status) *status = r.status;
  if (r.error) {
    if (err) *err = xstrdup(r.error);
    if (headers) *headers = NULL;
    if (body) *body = NULL;
    if (body_len) *body_len = 0;
    http_resp_free(&r);
    return -1;
  }
  if (headers) *headers = r.headers; else free(r.headers);
  if (body) *body = r.body; else free(r.body);
  if (body_len) *body_len = r.body_len;
  if (err) *err = NULL;
  free(r.error);
  return 0;
}

static int io_in_scope(void *ud, const char *url) {
  (void)ud;
  return net_url_allowed(url);
}

tools_io_t *net_io_impl(void) {
  static tools_io_t io;
  io.fetch = io_fetch;
  io.fetch_ex = io_fetch_ex;
  io.in_scope = io_in_scope;
  io.userdata = NULL;
  return &io;
}

void *net_io(void) { return net_io_impl(); }

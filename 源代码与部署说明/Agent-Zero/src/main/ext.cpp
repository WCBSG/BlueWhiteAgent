
#include "ext.h"

#include <ctype.h>

#include "json.h"
#include "res.h"
#include "rules.h"
#include "skills.h"
#include "store.h"
#include "tools.h"

typedef struct {
  char *name;
  char *title;
  char *when;
  char *purpose;
  char *tools;
  char *body;
  char *source_file;
} ext_skill_t;

typedef struct {
  char *name;
  int pid;
  HANDLE hwrite, hread;
  char *pending_buf;
  int initialized;
  int allow;
  json_t *tools;
} mcp_server_t;

static ext_skill_t *g_eskills = NULL;
static int g_eskill_count = 0;
static mcp_server_t *g_mcp = NULL;
static int g_mcp_count = 0;
static int g_mcp_tool_count = 0;

const char *ext_dir(char *out, size_t cap, const char *child) {
  if (!child || !*child) return app_data_path(out, cap, "");
  char rel[MAX_PATH];
  snprintf(rel, sizeof(rel), "%s", child);
  return app_data_path(out, cap, rel);
}

static int list_files(const char *dir, const char *ext, char ***out) {
  if (out) *out = NULL;
  char **list = NULL;
  int n = 0;
  wchar_t wdir[MAX_PATH * 2];
  wchar_t wpattern[MAX_PATH * 2];
  char *u8dir = NULL;

  u8dir = xstrdup(dir ? dir : "");
  wchar_t *w = u8_to_w(u8dir);
  if (!w) { free(u8dir); return 0; }

  wchar_t *wext = u8_to_w(ext ? ext : "");
  swprintf(wdir, MAX_PATH * 2, L"%ls", w);
  swprintf(wpattern, MAX_PATH * 2, L"%ls\\*%ls", w, wext ? wext : L"");
  free(w);
  free(wext);

  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW(wpattern, &fd);
  if (h == INVALID_HANDLE_VALUE) {

    if (GetLastError() != ERROR_FILE_NOT_FOUND) {
      char *dbg = w_to_u8_alloc(wpattern, (int)wcslen(wpattern));
      log_warn("[扩展] 目录列不出来: %s (err=%lu)", dbg ? dbg : "?", GetLastError());
      free(dbg);
    }
    free(u8dir);
    return 0;
  }
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    char *name = w_to_u8(fd.cFileName);
    if (!name) continue;
    char full[MAX_PATH * 2];
    snprintf(full, sizeof(full), "%s\\%s", u8dir, name);
    free(name);
    list = (char **)xrealloc(list, sizeof(char *) * (size_t)(n + 1));
    list[n++] = xstrdup(full);
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  free(u8dir);
  if (out) *out = list;
  else str_free_list(list, n);
  return n;
}

static char *shell_wrap(const char *cmdline) {
  if (!cmdline || !*cmdline) return NULL;
  const char *p = cmdline;
  while (*p == ' ' || *p == '\t') p++;
  if (_strnicmp(p, "cmd ", 4) == 0 || _strnicmp(p, "cmd.exe", 7) == 0 ||
      _strnicmp(p, "cmd/", 4) == 0 || _strnicmp(p, "cmd\\", 4) == 0) {
    return xstrdup(cmdline);
  }
  buf_t b;
  buf_init(&b);

  buf_puts(&b, "cmd.exe /d /s /c \"");
  buf_puts(&b, cmdline);
  buf_putc_(&b, '"');
  return buf_take(&b);
}

static int run_capture(const char *cmdline, const char *workdir, int timeout_ms,
                       char **out_text, int *out_exit) {
  if (out_text) *out_text = NULL;
  if (out_exit) *out_exit = -1;
  if (!cmdline || !*cmdline) return -1;

  SECURITY_ATTRIBUTES sa;
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  HANDLE rd = NULL, wr = NULL;
  if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
  SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = wr;
  si.hStdError = wr;
  si.hStdInput = NULL;

  PROCESS_INFORMATION pi;
  memset(&pi, 0, sizeof(pi));

  char *wrapped = shell_wrap(cmdline);
  wchar_t *wcmd = wrapped ? u8_to_w(wrapped) : NULL;
  wchar_t *wdir = workdir && *workdir ? u8_to_w(workdir) : NULL;
  free(wrapped);
  if (!wcmd) { CloseHandle(rd); CloseHandle(wr); return -1; }

  BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                           NULL, wdir, &si, &pi);
  free(wcmd);
  free(wdir);
  CloseHandle(wr);
  if (!ok) {
    CloseHandle(rd);
    return -1;
  }

  buf_t acc;
  buf_init(&acc);
  DWORD deadline = GetTickCount() + (DWORD)(timeout_ms > 0 ? timeout_ms : 20000);
  int timed_out = 0;
  char chunk[4096];
  for (;;) {
    DWORD avail = 0;
    if (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail > 0) {
      DWORD got = 0;
      if (!ReadFile(rd, chunk, sizeof(chunk) - 1, &got, NULL) || got == 0) break;
      chunk[got] = 0;
      buf_putn(&acc, chunk, got);
      if (acc.len > 512 * 1024) break;
      continue;
    }
    DWORD w = WaitForSingleObject(pi.hProcess, 60);
    if (w == WAIT_OBJECT_0) {

      DWORD got = 0;
      while (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail > 0 &&
             ReadFile(rd, chunk, sizeof(chunk) - 1, &got, NULL) && got > 0) {
        chunk[got] = 0;
        buf_putn(&acc, chunk, got);
        if (acc.len > 512 * 1024) break;
      }
      break;
    }
    if (GetTickCount() > deadline) { timed_out = 1; TerminateProcess(pi.hProcess, 1); break; }
  }

  DWORD code = 0;
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(rd);

  if (out_text) *out_text = buf_take(&acc);
  else buf_free(&acc);
  if (out_exit) *out_exit = (int)code;
  return timed_out ? -2 : 0;
}

int ext_run_capture(const char *cmdline, const char *workdir, int timeout_ms,
                    char **out_text, int *out_exit) {
  return run_capture(cmdline, workdir, timeout_ms, out_text, out_exit);
}

static char *read_file_utf8(const char *path) {
  size_t len = 0;
  char *text = file_read_all(path, &len);

  if (text && len >= 3 && (unsigned char)text[0] == 0xEF &&
      (unsigned char)text[1] == 0xBB && (unsigned char)text[2] == 0xBF) {
    memmove(text, text + 3, len - 3);
    text[len - 3] = 0;
  }
  return text;
}

static void parse_front_matter(char *text, ext_skill_t *sk, char **body_out) {
  char *body = text;
  if (str_startswith(text, "---")) {
    char *nl = strchr(text, '\n');
    if (nl) {
      char *p = nl + 1;
      char *end = strstr(p, "\n---");
      if (end) {
        *end = 0;
        body = end + 4;
        while (*body == '\r' || *body == '\n') body++;

        char **lines = NULL;
        int n = str_split(p, '\n', &lines, 0);
        for (int i = 0; i < n; i++) {
          char *line = str_trim(lines[i]);
          if (!line[0] || line[0] == '#') continue;
          char *colon = strchr(line, ':');
          if (!colon) continue;
          *colon = 0;
          char *k = str_trim(line);
          char *v = str_trim(colon + 1);

          size_t vl = strlen(v);
          if (vl >= 2 && ((v[0] == '"' && v[vl - 1] == '"') || (v[0] == '\'' && v[vl - 1] == '\''))) {
            v[vl - 1] = 0;
            v++;
          }
          if (str_ieq(k, "name")) sk->name = xstrdup(v);
          else if (str_ieq(k, "title")) sk->title = xstrdup(v);
          else if (str_ieq(k, "when")) sk->when = xstrdup(v);
          else if (str_ieq(k, "purpose")) sk->purpose = xstrdup(v);
          else if (str_ieq(k, "tools")) sk->tools = xstrdup(v);
          else if (str_ieq(k, "command") || str_ieq(k, "allow") || str_ieq(k, "timeout_ms")) {

            log_warn("[扩展] 技能声明里的 %s 已不再支持(命令行技能已删除),这个键会被忽略", k);
          }
        }
        str_free_list(lines, n);
      }
    }
  }
  *body_out = xstrdup(body);
}

static int load_one_skill(const char *path, int *overridden) {
  char *text = read_file_utf8(path);
  if (!text) return 0;

  char *p_text = text;
  if ((unsigned char)p_text[0] == 0xEF && (unsigned char)p_text[1] == 0xBB &&
      (unsigned char)p_text[2] == 0xBF) {
    p_text += 3;
  }
  ext_skill_t sk;
  memset(&sk, 0, sizeof(sk));
  char *body = NULL;
  parse_front_matter(p_text, &sk, &body);
  free(text);
  if (!sk.name || !sk.name[0]) {
    char base[MAX_PATH];
    snprintf(base, sizeof(base), "%s", path);
    const char *slash = strrchr(base, '\\');
    char *fname = (char *)(slash ? slash + 1 : base);
    if (str_ieq(fname, "SKILL.md")) {

      base[slash - base] = 0;
      const char *up = strrchr(base, '\\');
      fname = (char *)(up ? up + 1 : base);
      free(sk.name);
      sk.name = xstrdup(fname);
    } else {
      char *dot = strrchr(fname, '.');
      if (dot) *dot = 0;
      free(sk.name);
      sk.name = xstrdup(fname);
    }
  }
  if (!sk.title) sk.title = xstrdup(sk.name);
  if (!sk.when) sk.when = xstrdup(sk.title);
  if (!sk.purpose) sk.purpose = xstrdup(sk.when);

  if (skills_override_text(sk.name, sk.title, sk.purpose, sk.when, sk.tools, body)) {
    (*overridden)++;
    free(sk.name); free(sk.title); free(sk.purpose); free(sk.when); free(sk.tools);
    free(body);
    return 0;
  }

  sk.body = body;
  sk.source_file = xstrdup(path);
  g_eskills = (ext_skill_t *)xrealloc(g_eskills, sizeof(ext_skill_t) * (size_t)(g_eskill_count + 1));
  g_eskills[g_eskill_count++] = sk;
  log_info("[扩展] 载入技能包 %s(%s)", sk.name, path);
  return 1;
}

static int load_skills_dir(const char *dir) {
  int n = 0;
  int overridden = 0;
  std::vector<std::string> subs = fs_list_dirs(dir);
  for (size_t i = 0; i < subs.size(); i++) {
    char p[MAX_PATH * 2];
    snprintf(p, sizeof(p), "%s\\%s\\SKILL.md", dir, subs[i].c_str());
    if (file_size(p) < 0) continue;
    n += load_one_skill(p, &overridden);
  }
  if (overridden > 0) {
    log_info("[扩展] 数据目录里有 %d 个技能说明被采用", overridden);
  }
  return n;
}

static int ext_skill_index(const char *name);

static int mcp_launch(mcp_server_t *s, const char *command, const char *cwd) {
  SECURITY_ATTRIBUTES sa;
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  HANDLE in_rd = NULL, in_wr = NULL, out_rd = NULL, out_wr = NULL;
  if (!CreatePipe(&in_rd, &in_wr, &sa, 0)) return -1;
  if (!CreatePipe(&out_rd, &out_wr, &sa, 0)) { CloseHandle(in_rd); CloseHandle(in_wr); return -1; }
  SetHandleInformation(in_wr, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdInput = in_rd;
  si.hStdOutput = out_wr;

  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

  PROCESS_INFORMATION pi;
  memset(&pi, 0, sizeof(pi));
  char *wrapped = shell_wrap(command);
  wchar_t *wcmd = wrapped ? u8_to_w(wrapped) : NULL;
  wchar_t *wdir = (cwd && *cwd) ? u8_to_w(cwd) : NULL;
  free(wrapped);
  BOOL ok = wcmd && CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                                   NULL, wdir, &si, &pi);
  free(wcmd);
  free(wdir);
  CloseHandle(in_rd);
  CloseHandle(out_wr);
  if (!ok) {
    CloseHandle(in_wr);
    CloseHandle(out_rd);
    return -1;
  }
  s->pid = (int)pi.dwProcessId;
  s->hwrite = in_wr;
  s->hread = out_rd;
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return 0;
}

static int mcp_send(mcp_server_t *s, json_t *msg) {
  if (!s->hwrite) return -1;
  char *body = json_dump(msg);
  if (!body) return -1;

  int ok = 1;
  DWORD wrote = 0;
  size_t n = strlen(body);
  if (!WriteFile(s->hwrite, body, (DWORD)n, &wrote, NULL) || wrote != (DWORD)n) ok = 0;
  if (ok && (!WriteFile(s->hwrite, "\n", 1, &wrote, NULL) || wrote != 1)) ok = 0;
  FlushFileBuffers(s->hwrite);
  free(body);
  return ok ? 0 : -1;
}

static json_t *mcp_recv(mcp_server_t *s, int timeout_ms) {
  if (!s->hread) return NULL;
  buf_t acc;
  buf_init(&acc);
  if (s->pending_buf && *s->pending_buf) {
    buf_puts(&acc, s->pending_buf);
    free(s->pending_buf);
    s->pending_buf = NULL;
  }

  DWORD deadline = GetTickCount() + (DWORD)(timeout_ms > 0 ? timeout_ms : 8000);
  char chunk[2048];

  while (GetTickCount() < deadline) {
    const char *data = acc.data ? acc.data : "";

    while (*data == '\r' || *data == '\n') data++;

    if (data[0] == '{') {

      const char *nl = strchr(data, '\n');
      if (nl) {
        json_t *j = json_parse_n(data, (size_t)(nl - data));
        size_t consumed = (size_t)(nl - acc.data) + 1;
        if (acc.len > consumed) s->pending_buf = xstrdup(acc.data + consumed);
        buf_free(&acc);
        return j;
      }
    } else if (!strncmp(data, "Content-Length:", 15) || !strncmp(data, "content-length:", 15)) {
      const char *hdr_end = strstr(data, "\r\n\r\n");
      if (hdr_end) {
        long need = atol(data + 15);
        size_t body_start = (size_t)(hdr_end + 4 - acc.data);
        if ((long)(acc.len - body_start) >= need) {
          json_t *j = json_parse_n(acc.data + body_start, (size_t)need);
          size_t consumed = body_start + (size_t)need;
          if (acc.len > consumed) s->pending_buf = xstrdup(acc.data + consumed);
          buf_free(&acc);
          return j;
        }
      }
    }

    DWORD avail = 0;
    if (PeekNamedPipe(s->hread, NULL, 0, NULL, &avail, NULL) && avail > 0) {
      DWORD got = 0;
      DWORD want = avail < sizeof(chunk) - 1 ? avail : (DWORD)(sizeof(chunk) - 1);
      if (ReadFile(s->hread, chunk, want, &got, NULL) && got > 0) {
        chunk[got] = 0;
        buf_putn(&acc, chunk, got);
        continue;
      }
    }
    Sleep(20);
  }
  if (acc.len) s->pending_buf = buf_take(&acc);
  else buf_free(&acc);
  return NULL;
}

static int mcp_call(mcp_server_t *s, const char *method, json_t *params, int id,
                    json_t **out_result) {
  json_t *req = j_obj();
  j_set_str(req, "jsonrpc", "2.0");
  j_set_num(req, "id", id);
  j_set_str(req, "method", method);
  if (params) j_set(req, "params", params);
  else json_free(params);
  int rc = mcp_send(s, req);
  json_free(req);
  if (rc != 0) return -1;

  for (int i = 0; i < 50; i++) {
    json_t *msg = mcp_recv(s, 10000);
    if (!msg) return -1;
    if (j_n(msg, "id", -1) == id) {
      json_t *err = j_get(msg, "error");
      json_t *res = j_get(msg, "result");
      if (err) {
        json_free(msg);
        return -2;
      }
      if (out_result) *out_result = res ? j_clone(res) : NULL;
      json_free(msg);
      return 0;
    }
    json_free(msg);
  }
  return -1;
}

static int mcp_start(mcp_server_t *s) {
  json_t *params = j_obj();
  json_t *info = j_obj();
  j_set_str(info, "name", "bw-agent");
  j_set_str(info, "version", "1.0.0");
  j_set(info, "capabilities", j_obj());
  json_t *ci = j_obj();
  j_set_str(ci, "protocolVersion", "2024-11-05");
  j_set(ci, "clientInfo", info);
  j_set(ci, "capabilities", j_obj());
  json_free(params);
  params = ci;
  int rc = mcp_call(s, "initialize", params, 1, NULL);
  if (rc != 0) return -1;

  json_t *note = j_obj();
  j_set_str(note, "jsonrpc", "2.0");
  j_set_str(note, "method", "notifications/initialized");
  mcp_send(s, note);
  json_free(note);
  s->initialized = 1;

  json_t *res = NULL;
  if (mcp_call(s, "tools/list", j_obj(), 2, &res) != 0 || !res) {
    log_warn("[扩展] MCP 服务器 %s 的 tools/list 没有正常返回", s->name);
    return -1;
  }
  json_t *tools = j_get(res, "tools");
  s->tools = tools ? j_clone(tools) : j_arr();
  json_free(res);
  return 0;
}

static void mcp_shutdown_all(void) {
  for (int i = 0; i < g_mcp_count; i++) {
    if (g_mcp[i].hwrite) { CloseHandle(g_mcp[i].hwrite); g_mcp[i].hwrite = NULL; }
    if (g_mcp[i].hread) { CloseHandle(g_mcp[i].hread); g_mcp[i].hread = NULL; }
    if (g_mcp[i].pid) {
      HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)g_mcp[i].pid);
      if (h) { TerminateProcess(h, 0); CloseHandle(h); }
      g_mcp[i].pid = 0;
    }
  }
}

void ext_shutdown(void) { mcp_shutdown_all(); }

static int load_mcp_config(const char *path) {
  char *text = read_file_utf8(path);
  if (!text) return 0;
  json_t *j = json_parse(text);
  free(text);
  if (!j) return 0;
  json_t *servers = j_get(j, "servers");
  int n = 0;
  for (int i = 0; i < j_len(servers); i++) {
    json_t *o = j_at(servers, i);
    const char *name = j_s(o, "name", "");
    const char *cmd = j_s(o, "command", "");
    if (!name[0] || !cmd[0]) continue;
    int allow = j_b(o, "allow", 0);
    mcp_server_t s;
    memset(&s, 0, sizeof(s));
    s.name = xstrdup(name);
    s.allow = allow;
    s.pending_buf = NULL;
    s.tools = j_arr();
    if (allow) {
      if (mcp_launch(&s, cmd, j_s(o, "cwd", "")) == 0 && mcp_start(&s) == 0) {
        g_mcp_tool_count += j_len(s.tools);
        log_info("[扩展] MCP 服务器 %s 已连接,%d 个工具", name, j_len(s.tools));
      } else {
        log_warn("[扩展] MCP 服务器 %s 连接失败(命令:%s)", name, cmd);
      }
    } else {
      log_warn("[扩展] MCP 服务器 %s 未启用(清单里 allow 不为 true)", name);
    }
    g_mcp = (mcp_server_t *)xrealloc(g_mcp, sizeof(mcp_server_t) * (size_t)(g_mcp_count + 1));
    g_mcp[g_mcp_count++] = s;
    n++;
  }
  json_free(j);
  return n;
}

static int mcp_find_tool(const char *full_name, mcp_server_t **srv_out, const char **tool_out) {
  if (!str_startswith(full_name, "mcp__")) return 0;
  const char *rest = full_name + 5;
  const char *sep = strstr(rest, "__");
  if (!sep) return 0;
  char sname[128];
  size_t sl = (size_t)(sep - rest);
  if (sl >= sizeof(sname)) sl = sizeof(sname) - 1;
  memcpy(sname, rest, sl);
  sname[sl] = 0;
  const char *tname = sep + 2;
  for (int i = 0; i < g_mcp_count; i++) {
    if (str_ieq(g_mcp[i].name, sname)) {
      for (int k = 0; k < j_len(g_mcp[i].tools); k++) {
        if (strcmp(j_s(j_at(g_mcp[i].tools, k), "name", ""), tname) == 0) {
          if (srv_out) *srv_out = &g_mcp[i];
          if (tool_out) *tool_out = tname;
          return 1;
        }
      }
    }
  }
  return 0;
}

static int mcp_run(tool_ctx_t *ctx, const char *full_name, json_t *args, tool_result_t *out) {
  (void)ctx;
  mcp_server_t *srv = NULL;
  const char *tname = NULL;
  if (!mcp_find_tool(full_name, &srv, &tname)) {
    out->is_error = 1;
    out->text = xstrdup("没有这个 MCP 工具");
    out->say = xstrdup("没有这个 MCP 工具。");
    return -1;
  }
  json_t *params = j_obj();
  j_set_str(params, "name", tname);
  j_set(params, "arguments", args ? j_clone(args) : j_obj());
  json_t *res = NULL;
  int mrc = mcp_call(srv, "tools/call", params, 3, &res);
  if (mrc != 0 || !res) {
    log_warn("[扩展] MCP %s 调用 %s 失败(rc=%d%s)", srv->name, tname, mrc,
             mrc == -2 ? ",服务器返回 error" : "");
    out->is_error = 1;
    out->text = xstrdup("MCP 工具调用失败(服务器无响应或返回错误)");
    out->say = xstrdup("MCP 工具没能调用成功。");
    return -1;
  }

  buf_t text;
  buf_init(&text);
  json_t *content = j_get(res, "content");
  for (int i = 0; i < j_len(content); i++) {
    json_t *c = j_at(content, i);
    const char *t = j_s(c, "text", "");
    if (t[0]) {
      if (text.len) buf_putc_(&text, '\n');
      buf_puts(&text, t);
    }
  }
  int is_err = j_b(res, "isError", 0);
  out->text = buf_take(&text);
  if (!out->text) out->text = xstrdup("(空结果)");
  out->data = j_clone(res);
  out->is_error = is_err;
  buf_t say;
  buf_init(&say);
  buf_printf(&say, "%s 返回:%s", full_name, out->text);
  out->say = buf_take(&say);
  json_free(res);
  return is_err ? -1 : 0;
}

static int ext_skill_index(const char *name) {
  for (int i = 0; i < g_eskill_count; i++) {
    if (str_ieq(g_eskills[i].name, name)) return i;
  }
  return -1;
}

static int ext_skill_run(tool_ctx_t *ctx, const char *ext_name, skill_result_t *out) {
  (void)ctx;
  int idx = ext_skill_index(ext_name);
  if (idx < 0) return -1;
  ext_skill_t *s = &g_eskills[idx];
  json_t *data = j_obj();
  j_set_str(data, "skill", s->name);
  j_set_str(data, "title", s->title);
  j_set_str(data, "source", s->source_file);
  j_set_bool(data, "external", 1);
  j_set_str(data, "steps", s->body ? s->body : "");
  out->data = data;

  buf_t b;
  buf_init(&b);
  buf_printf(&b, "【%s】按下面的步骤做(来自技能包 %s):\n%s", s->title, s->name,
             s->body ? s->body : "");
  out->summary = buf_take(&b);
  return 0;
}

static int ext_mcp_adapter(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  return mcp_run(ctx, ctx->current_tool ? ctx->current_tool : "", args, out);
}

static int ext_skill_adapter(tool_ctx_t *ctx, json_t *args, skill_result_t *out) {
  (void)args;
  return ext_skill_run(ctx, ctx->current_tool ? ctx->current_tool : "", out);
}

void ext_register_all(void) {
  for (int i = 0; i < g_eskill_count; i++) {
    ext_skill_t *s = &g_eskills[i];
    skills_register_external(s->name, s->title, s->purpose, s->when, s->tools,
                             ext_skill_adapter);
  }
  for (int i = 0; i < g_mcp_count; i++) {
    mcp_server_t *s = &g_mcp[i];
    for (int k = 0; k < j_len(s->tools); k++) {
      json_t *t = j_at(s->tools, k);
      const char *tname = j_s(t, "name", "");
      if (!tname[0]) continue;
      char full[256];
      snprintf(full, sizeof(full), "mcp__%s__%s", s->name, tname);
      char desc[1024];
      snprintf(desc, sizeof(desc), "[MCP:%s] %s", s->name,
               j_s(t, "description", "外部 MCP 工具"));
      char *schema = json_dump(j_get(t, "inputSchema"));
      tools_register_external(full, desc, schema ? schema : "", "MCP", s->name, 0,
                              ext_mcp_adapter);
      free(schema);
    }
  }
}

void ext_bootstrap(void) {
  char path[MAX_PATH * 2];
  ext_dir(path, sizeof(path), "tools");
  ensure_dir(path);
  ext_dir(path, sizeof(path), "skills");
  ensure_dir(path);
}

int ext_list_files(const char *dir, const char *ext, char ***out) {
  return list_files(dir, ext, out);
}

int ext_load_all(void) {
  char dir[MAX_PATH * 2];
  int n = 0;

  ext_dir(dir, sizeof(dir), "skills");
  n += load_skills_dir(dir);
  ext_dir(dir, sizeof(dir), "mcp.json");
  n += load_mcp_config(dir);

  if (g_eskill_count || g_mcp_count) {
    log_info("[扩展] 技能包 %d 个、MCP 服务器 %d 个(共 %d 个 MCP 工具)",
             g_eskill_count, g_mcp_count, g_mcp_tool_count);
  }
  return n;
}

void ext_stats(int *tools, int *skills, int *mcp, int *mcp_tools) {

  if (tools) *tools = tools_count_external();
  if (skills) *skills = g_eskill_count;
  if (mcp) *mcp = g_mcp_count;
  if (mcp_tools) *mcp_tools = g_mcp_tool_count;
}

json_t *ext_inventory_json(void) {
  json_t *root = j_obj();

  json_t *skills = j_arr();
  for (int i = 0; i < g_eskill_count; i++) {
    ext_skill_t *s = &g_eskills[i];
    json_t *o = j_obj();
    j_set_str(o, "name", s->name);
    j_set_str(o, "title", s->title ? s->title : "");
    j_set_str(o, "purpose", s->purpose ? s->purpose : "");
    j_set_str(o, "when", s->when ? s->when : "");
    j_set_str(o, "tools", s->tools ? s->tools : "");
    j_set_str(o, "body", s->body ? s->body : "");
    j_set_str(o, "file", s->source_file ? s->source_file : "");
    j_add(skills, o);
  }
  j_set(root, "skills", skills);

  json_t *mcp = j_arr();
  for (int i = 0; i < g_mcp_count; i++) {
    json_t *o = j_obj();
    j_set_str(o, "name", g_mcp[i].name);
    j_set_num(o, "tools", j_len(g_mcp[i].tools));
    j_set_bool(o, "allowed", g_mcp[i].allow ? 1 : 0);
    j_add(mcp, o);
  }
  j_set(root, "mcp", mcp);
  return root;
}

int ext_reload_local(void) {
  for (int i = 0; i < g_eskill_count; i++) {
    ext_skill_t *s = &g_eskills[i];
    free(s->name); free(s->title); free(s->when); free(s->purpose);
    free(s->tools); free(s->body); free(s->source_file);
  }
  free(g_eskills);
  g_eskills = NULL;
  g_eskill_count = 0;

  skills_reset_external();

  char dir[MAX_PATH * 2];
  int n = tools_reload_specs();

  ext_dir(dir, sizeof(dir), "skills");
  n += load_skills_dir(dir);

  ext_register_all();
  log_info("[扩展] 已重新加载:外置工具 %d 个、技能包 %d 个", tools_count_external(),
           g_eskill_count);
  return n;
}

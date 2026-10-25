
#include "common.h"

#include <shellapi.h>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <exception>

void buf_init(buf_t *b) {
  b->cap = 256;
  b->len = 0;
  b->data = (char *)xmalloc(b->cap);
  b->data[0] = 0;
}

void buf_free(buf_t *b) {
  free(b->data);
  b->data = NULL;
  b->len = b->cap = 0;
}

void buf_clear(buf_t *b) {
  b->len = 0;
  if (b->data) b->data[0] = 0;
}

void buf_reserve(buf_t *b, size_t extra) {
  if (b->len + extra + 1 <= b->cap) return;
  while (b->len + extra + 1 > b->cap) b->cap = b->cap ? b->cap * 2 : 256;
  b->data = (char *)xrealloc(b->data, b->cap);
}

void buf_putn(buf_t *b, const char *s, size_t n) {
  if (!s || !n) return;
  buf_reserve(b, n);
  memcpy(b->data + b->len, s, n);
  b->len += n;
  b->data[b->len] = 0;
}

void buf_puts(buf_t *b, const char *s) {
  if (s) buf_putn(b, s, strlen(s));
}

void buf_putc_(buf_t *b, char c) {
  buf_reserve(b, 1);
  b->data[b->len++] = c;
  b->data[b->len] = 0;
}

void buf_printf(buf_t *b, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int need = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (need <= 0) return;
  buf_reserve(b, (size_t)need);
  va_start(ap, fmt);
  vsnprintf(b->data + b->len, (size_t)need + 1, fmt, ap);
  va_end(ap);
  b->len += (size_t)need;
}

void buf_json_str(buf_t *b, const char *s) {
  buf_putc_(b, '"');
  if (s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
      switch (*p) {
        case '"':  buf_puts(b, "\\\""); break;
        case '\\': buf_puts(b, "\\\\"); break;
        case '\n': buf_puts(b, "\\n"); break;
        case '\r': buf_puts(b, "\\r"); break;
        case '\t': buf_puts(b, "\\t"); break;
        case '\b': buf_puts(b, "\\b"); break;
        case '\f': buf_puts(b, "\\f"); break;
        default:
          if (*p < 0x20) {
            buf_printf(b, "\\u%04x", *p);
          } else if (*p < 0x80) {
            buf_putc_(b, (char)*p);
          } else {
            int n = utf8_seq_len(p);
            if (n > 0) {
              buf_putn(b, (const char *)p, n);
              p += n - 1;
            } else {
              buf_puts(b, "\xEF\xBF\xBD");
            }
          }
      }
    }
  }
  buf_putc_(b, '"');
}

char *buf_take(buf_t *b) {
  char *out = b->data;
  b->data = NULL;
  b->len = b->cap = 0;
  return out;
}

int utf8_seq_len(const unsigned char *p) {
  if (!p || !*p) return 0;
  unsigned c = p[0];
  if (c < 0x80) return 1;
  if (c >= 0xC2 && c <= 0xDF) return (p[1] >= 0x80 && p[1] <= 0xBF) ? 2 : 0;
  if (c == 0xE0) return (p[1] >= 0xA0 && p[1] <= 0xBF && p[2] >= 0x80 && p[2] <= 0xBF) ? 3 : 0;
  if ((c >= 0xE1 && c <= 0xEC) || c == 0xEE || c == 0xEF)
    return (p[1] >= 0x80 && p[1] <= 0xBF && p[2] >= 0x80 && p[2] <= 0xBF) ? 3 : 0;
  if (c == 0xED) return (p[1] >= 0x80 && p[1] <= 0x9F && p[2] >= 0x80 && p[2] <= 0xBF) ? 3 : 0;
  if (c == 0xF0) return (p[1] >= 0x90 && p[1] <= 0xBF && p[2] >= 0x80 && p[2] <= 0xBF &&
                         p[3] >= 0x80 && p[3] <= 0xBF) ? 4 : 0;
  if (c >= 0xF1 && c <= 0xF3)
    return (p[1] >= 0x80 && p[1] <= 0xBF && p[2] >= 0x80 && p[2] <= 0xBF &&
            p[3] >= 0x80 && p[3] <= 0xBF) ? 4 : 0;
  if (c == 0xF4) return (p[1] >= 0x80 && p[1] <= 0x8F && p[2] >= 0x80 && p[2] <= 0xBF &&
                         p[3] >= 0x80 && p[3] <= 0xBF) ? 4 : 0;
  return 0;
}

int utf8_valid(const char *s) {
  if (!s) return 1;
  const unsigned char *p = (const unsigned char *)s;
  while (*p) {
    int n = utf8_seq_len(p);
    if (n <= 0) return 0;
    p += n;
  }
  return 1;
}

void b64_encode(const unsigned char *src, size_t len, buf_t *out) {
  static const char *tab =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i = 0;
  while (i + 2 < len) {
    unsigned int v = ((unsigned)src[i] << 16) | ((unsigned)src[i + 1] << 8) | src[i + 2];
    buf_putc_(out, tab[(v >> 18) & 63]);
    buf_putc_(out, tab[(v >> 12) & 63]);
    buf_putc_(out, tab[(v >> 6) & 63]);
    buf_putc_(out, tab[v & 63]);
    i += 3;
  }
  if (i + 1 == len) {
    unsigned int v = (unsigned)src[i] << 16;
    buf_putc_(out, tab[(v >> 18) & 63]);
    buf_putc_(out, tab[(v >> 12) & 63]);
    buf_puts(out, "==");
  } else if (i + 2 == len) {
    unsigned int v = ((unsigned)src[i] << 16) | ((unsigned)src[i + 1] << 8);
    buf_putc_(out, tab[(v >> 18) & 63]);
    buf_putc_(out, tab[(v >> 12) & 63]);
    buf_putc_(out, tab[(v >> 6) & 63]);
    buf_putc_(out, '=');
  }
}

int b64_decode(const char *src, size_t len, buf_t *out) {
  if (!src || !out) return -1;
  int val = 0, bits = 0, n = 0;
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)src[i];
    int d;
    if (c >= 'A' && c <= 'Z') d = c - 'A';
    else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
    else if (c >= '0' && c <= '9') d = c - '0' + 52;
    else if (c == '+' || c == '-') d = 62;
    else if (c == '/' || c == '_') d = 63;
    else if (c == '=') break;
    else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
    else return -1;
    val = (val << 6) | d;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      buf_putc_(out, (char)((val >> bits) & 0xFF));
      n++;
    }
  }
  return n;
}

void hex_encode(const unsigned char *src, size_t len, char *out, size_t cap) {  static const char *tab = "0123456789abcdef";
  size_t o = 0;
  for (size_t i = 0; i < len && o + 3 < cap; i++) {
    out[o++] = tab[src[i] >> 4];
    out[o++] = tab[src[i] & 15];
  }
  if (cap) out[o < cap ? o : cap - 1] = 0;
}

void *xmalloc(size_t n) {
  void *p = malloc(n ? n : 1);
  if (!p) { fprintf(stderr, "out of memory (%zu)\n", n); exit(2); }
  return p;
}

void *xcalloc(size_t n, size_t sz) {
  void *p = calloc(n ? n : 1, sz ? sz : 1);
  if (!p) { fprintf(stderr, "out of memory\n"); exit(2); }
  return p;
}

void *xrealloc(void *p, size_t n) {
  void *q = realloc(p, n ? n : 1);
  if (!q) { fprintf(stderr, "out of memory\n"); exit(2); }
  return q;
}

char *xstrdup(const char *s) {
  if (!s) return NULL;
  size_t n = strlen(s);
  char *out = (char *)xmalloc(n + 1);
  memcpy(out, s, n + 1);
  return out;
}

char *xstrndup(const char *s, size_t n) {
  if (!s) return NULL;
  size_t len = 0;
  while (len < n && s[len]) len++;
  char *out = (char *)xmalloc(len + 1);
  memcpy(out, s, len);
  out[len] = 0;
  return out;
}

wchar_t *u8_to_w(const char *s) {
  if (!s) return NULL;
  int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
  if (n <= 0) return NULL;
  wchar_t *w = (wchar_t *)xcalloc((size_t)n + 1, sizeof(wchar_t));
  MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
  return w;
}

char *w_to_u8_alloc(const wchar_t *w, int chars) {
  if (!w) return NULL;
  int n = WideCharToMultiByte(CP_UTF8, 0, w, chars, NULL, 0, NULL, NULL);
  if (n < 0) n = 0;
  char *out = (char *)xmalloc((size_t)n + 1);
  if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w, chars, out, n, NULL, NULL);
  out[n] = 0;
  return out;
}

char *w_to_u8(const wchar_t *w) {
  return w ? w_to_u8_alloc(w, -1) : NULL;
}

size_t u8_prefix(const char *s, size_t max_bytes) {
  if (!s || max_bytes == 0) return 0;
  size_t n = 0;
  while (s[n] && n < max_bytes) {
    unsigned char c = (unsigned char)s[n];
    size_t clen = c < 0x80 ? 1 : (c & 0xE0) == 0xC0 ? 2 : (c & 0xF0) == 0xE0 ? 3
                  : (c & 0xF8) == 0xF0 ? 4 : 1;
    if (n + clen > max_bytes) break;
    n += clen;
  }
  return n;
}

size_t est_tokens(const char *s) {
  if (!s) return 0;
  size_t tokens_x100 = 0;
  const unsigned char *p = (const unsigned char *)s;
  while (*p) {
    unsigned char c = *p;
    if (c < 0x80) {

      tokens_x100 += 25;
      p++;
    } else if ((c & 0xE0) == 0xC0) { tokens_x100 += 100; p += 2; }
    else if ((c & 0xF0) == 0xE0) { tokens_x100 += 100; p += 3; }
    else if ((c & 0xF8) == 0xF0) { tokens_x100 += 150; p += 4; }
    else { p++; }
  }
  return tokens_x100 / 100 + 1;
}

static long long filetime_to_ms(FILETIME ft) {

  ULARGE_INTEGER u;
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  return (long long)(u.QuadPart / 10000ULL) - 11644473600000LL;
}

void ms_to_iso(long long ms, char *out, size_t cap) {
  time_t secs = (time_t)(ms / 1000);
  int milli = (int)(ms % 1000);
  if (milli < 0) { milli += 1000; secs -= 1; }
  struct tm tm_utc;
  gmtime_s(&tm_utc, &secs);
  snprintf(out, cap, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
           tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
           tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec, milli);
}

void now_iso(char *out, size_t cap) {
  ms_to_iso(now_ms(), out, cap);
}

void now_iso_at(FILETIME ft, char *out, size_t cap) {
  ms_to_iso(filetime_to_ms(ft), out, cap);
}

long long now_ms(void) {
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  return filetime_to_ms(ft);
}

static FILE *g_log_file = NULL;
static log_level_t g_log_level = LOG_INFO;
static CRITICAL_SECTION g_log_lock;
static int g_log_lock_ready = 0;

void console_init(void) {

  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);

  std::set_terminate([]() {
    log_error("程序因未捕获的 C++ 异常终止(通常是内存不足)。日志见数据目录 agent.log");
    std::abort();
  });
}

static void bind_std_streams(void) {
  freopen("CONOUT$", "w", stdout);
  freopen("CONOUT$", "w", stderr);
  freopen("CONIN$", "r", stdin);
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
}

int app_console_init(int want_window) {
  if (GetConsoleWindow() != NULL) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    return 1;
  }

  if (want_window && AllocConsole()) {
    bind_std_streams();
    printf("—— 调试窗口(--debug):运行日志与提示都显示在这里 ——\n\n");
    return 1;
  }

  HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
  HANDLE herr = GetStdHandle(STD_ERROR_HANDLE);
  if ((hout && hout != INVALID_HANDLE_VALUE) || (herr && herr != INVALID_HANDLE_VALUE)) return 1;
  if (AttachConsole(ATTACH_PARENT_PROCESS)) {
    bind_std_streams();
    return 1;
  }
  return 0;
}

char **app_argv_from_command_line(int *argc_out) {
  if (argc_out) *argc_out = 0;
  LPWSTR wcmd = GetCommandLineW();
  if (!wcmd) return NULL;
  int n = 0;
  LPWSTR *wargv = CommandLineToArgvW(wcmd, &n);
  if (!wargv) return NULL;
  char **argv = (char **)xmalloc(sizeof(char *) * (size_t)(n + 1));
  for (int i = 0; i < n; i++) {
    char *u8 = w_to_u8(wargv[i]);
    argv[i] = u8 ? u8 : xstrdup("");
  }
  argv[n] = NULL;
  LocalFree(wargv);
  if (argc_out) *argc_out = n;
  return argv;
}

void free_argv(int argc, char **argv) {
  if (!argv) return;
  for (int i = 0; i < argc; i++) free(argv[i]);
  free(argv);
}

void app_fix_argv_encoding(int argc, char **argv) {
  UINT acp = GetACP();
  if (acp == CP_UTF8) return;
  for (int i = 0; i < argc; i++) {
    if (!argv[i] || !*argv[i]) continue;

    wchar_t *probe = u8_to_w(argv[i]);
    if (probe) {
      char *back = w_to_u8(probe);
      int same = back && strcmp(back, argv[i]) == 0;
      free(probe);
      free(back);
      if (same) continue;
    }
    int need = MultiByteToWideChar(acp, 0, argv[i], -1, NULL, 0);
    if (need <= 0) continue;
    wchar_t *w = (wchar_t *)xmalloc((size_t)need * sizeof(wchar_t));
    MultiByteToWideChar(acp, 0, argv[i], -1, w, need);
    char *u8 = w_to_u8(w);
    free(w);
    if (!u8) continue;

    argv[i] = xstrdup(u8);
    free(u8);
  }
}

static FILE *fopen_utf8(const char *path, const wchar_t *mode) {
  wchar_t *w = u8_to_w(path);
  if (!w) return NULL;
  FILE *fp = _wfopen(w, mode);
  free(w);
  return fp;
}

void log_open(const char *path) {
  if (!g_log_lock_ready) {
    InitializeCriticalSection(&g_log_lock);
    g_log_lock_ready = 1;
  }
  if (path) {
    char dir[MAX_PATH];
    path_dir_of(path, dir, sizeof(dir));
    ensure_dir(dir);

    long sz = file_size(path);
    if (sz > 2 * 1024 * 1024) {
      char old_path[MAX_PATH * 2];
      snprintf(old_path, sizeof(old_path), "%s.1", path);
      wchar_t *wfrom = u8_to_w(path);
      wchar_t *wto = u8_to_w(old_path);
      if (wfrom && wto) {
        DeleteFileW(wto);
        MoveFileW(wfrom, wto);
      }
      free(wfrom);
      free(wto);
    }
    g_log_file = fopen_utf8(path, L"a");

    if (g_log_file && sz < 0) fwrite("\xEF\xBB\xBF", 1, 3, g_log_file);
  }
}

void log_close(void) {
  if (g_log_file) { fclose(g_log_file); g_log_file = NULL; }
}

void log_set_level(log_level_t level) { g_log_level = level; }

void log_write(log_level_t level, const char *fmt, ...) {
  if (level < g_log_level) return;
  static const char *names[] = {"DEBUG", "INFO", "WARN", "ERROR"};

  char ts[40];
  now_iso(ts, sizeof(ts));

  buf_t line;
  buf_init(&line);
  buf_printf(&line, "[%s] %-5s ", ts, names[level]);
  va_list ap;
  va_start(ap, fmt);
  int need = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (need > 0) {
    buf_reserve(&line, (size_t)need + 2);
    va_start(ap, fmt);
    vsnprintf(line.data + line.len, (size_t)need + 1, fmt, ap);
    va_end(ap);
    line.len += (size_t)need;
  }
  buf_puts(&line, "\n");

  if (g_log_lock_ready) EnterCriticalSection(&g_log_lock);
  fputs(line.data, stderr);
  fflush(stderr);
  if (g_log_file) {
    fputs(line.data, g_log_file);
    fflush(g_log_file);
  }
  if (g_log_lock_ready) LeaveCriticalSection(&g_log_lock);
  buf_free(&line);
}

int str_ieq(const char *a, const char *b) {
  if (!a || !b) return a == b;
  return _stricmp(a, b) == 0;
}

int str_startswith(const char *s, const char *prefix) {
  if (!s || !prefix) return 0;
  size_t n = strlen(prefix);
  return strncmp(s, prefix, n) == 0;
}

int str_endswith(const char *s, const char *suffix) {
  if (!s || !suffix) return 0;
  size_t ls = strlen(s), lf = strlen(suffix);
  return ls >= lf && strcmp(s + ls - lf, suffix) == 0;
}

char *str_trim(char *s) {
  if (!s) return s;
  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
  size_t n = strlen(s);
  while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) {
    s[--n] = 0;
  }
  return s;
}

int str_contains(const char *hay, const char *needle) {
  return hay && needle && strstr(hay, needle) != NULL;
}

static char *lower_dup(const char *s) {
  char *out = xstrdup(s);
  for (char *p = out; *p; p++) *p = (char)tolower((unsigned char)*p);
  return out;
}

int str_icontains(const char *hay, const char *needle) {
  if (!hay || !needle) return 0;
  char *h = lower_dup(hay), *n = lower_dup(needle);
  int hit = strstr(h, n) != NULL;
  free(h); free(n);
  return hit;
}

const char *str_icase_find(const char *hay, const char *needle) {
  if (!hay || !needle || !*needle) return NULL;
  size_t nl = strlen(needle);
  for (const char *p = hay; *p; p++) {
    size_t i = 0;
    while (i < nl && p[i] &&
           tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
      i++;
    }
    if (i == nl) return p;
  }
  return NULL;
}

const char *fail_code(const char *text) {
  if (!text || !*text) return "";
  if (str_icontains(text, "不在授权池内") || str_icontains(text, "不在授权域名内") ||
      str_icontains(text, "out_of_scope")) {
    return "out_of_scope";
  }
  if (str_icontains(text, "超时") || str_icontains(text, "timeout") ||
      str_icontains(text, "timed out")) {
    return "timeout";
  }
  if (str_icontains(text, "不可达") || str_icontains(text, "连不上") ||
      str_icontains(text, "域名解析") || str_icontains(text, "unreachable") ||
      str_icontains(text, "拒绝连接") || str_icontains(text, "ERR_CONNECTION")) {
    return "unreachable";
  }
  return "fetch_error";
}

int str_split(const char *s, char sep, char ***out, int max_parts) {
  *out = NULL;
  if (!s) return 0;
  int cap = 8;
  char **list = (char **)xcalloc((size_t)cap, sizeof(char *));
  int n = 0;
  const char *start = s;
  for (const char *p = s;; p++) {
    if (*p == sep || *p == 0) {

      if (n + 1 >= cap) {
        int new_cap = cap * 2;
        list = (char **)xrealloc(list, sizeof(char *) * (size_t)new_cap);
        for (int i = cap; i < new_cap; i++) list[i] = NULL;
        cap = new_cap;
      }
      if (max_parts > 0 && n == max_parts - 1) {
        list[n++] = xstrdup(start);
        break;
      }
      list[n++] = xstrndup(start, (size_t)(p - start));
      if (*p == 0) break;
      start = p + 1;
      if (max_parts > 0 && n >= max_parts) break;
    }
  }
  *out = list;
  return n;
}

void str_free_list(char **list, int n) {
  if (!list) return;
  for (int i = 0; i < n; i++) free(list[i]);
  free(list);
}

static char g_app_dir[MAX_PATH] = {0};
static char g_app_exe[MAX_PATH] = {0};

void app_init_paths(void) {

  wchar_t wexe[MAX_PATH] = {0};
  GetModuleFileNameW(NULL, wexe, MAX_PATH);
  char *u8 = w_to_u8(wexe);
  if (u8) {
    strncpy_s(g_app_exe, MAX_PATH, u8, _TRUNCATE);
    free(u8);
  }
  strncpy_s(g_app_dir, MAX_PATH, g_app_exe, _TRUNCATE);
  char *slash1 = strrchr(g_app_dir, '\\');
  char *slash2 = strrchr(g_app_dir, '/');
  char *slash = (slash2 > slash1) ? slash2 : slash1;
  if (slash) *(slash + 1) = 0;
}

const char *app_dir(void) { return g_app_dir; }
const char *app_exe(void) { return g_app_exe; }

static char g_data_dir[MAX_PATH * 2] = {0};

static int env_utf8(const wchar_t *name, char *out, size_t cap) {
  if (out && cap) out[0] = 0;
  DWORD need = GetEnvironmentVariableW(name, NULL, 0);
  if (need == 0) return 0;
  wchar_t *buf = (wchar_t *)xmalloc((size_t)need * sizeof(wchar_t));
  DWORD got = GetEnvironmentVariableW(name, buf, need);
  if (got > 0 && got < need) {
    char *u = w_to_u8(buf);
    if (u) {
      if (out && cap) snprintf(out, cap, "%s", u);
      free(u);
    }
  }
  free(buf);
  return out && out[0] != 0;
}

static void make_data_default(char *out, size_t cap) {
  char *home = NULL;
  char env[MAX_PATH * 2];
  if (env_utf8(L"USERPROFILE", env, sizeof(env))) {
    home = xstrdup(env);
  } else {
    char drive[MAX_PATH] = {0};
    char path[MAX_PATH] = {0};
    if (env_utf8(L"HOMEDRIVE", drive, sizeof(drive)) &&
        env_utf8(L"HOMEPATH", path, sizeof(path))) {
      size_t hlen = strlen(drive) + strlen(path) + 1;
      home = (char *)xmalloc(hlen);
      snprintf(home, hlen, "%s%s", drive, path);
    } else {
      home = xstrdup(app_dir());
      if (home[0] && home[strlen(home) - 1] == '\\') home[strlen(home) - 1] = 0;
    }
  }
  snprintf(out, cap, "%s\\.bw_agent\\", home);
  free(home);
}

const char *app_data_dir(void) {
  if (g_data_dir[0]) return g_data_dir;
  char override[MAX_PATH * 2];
  if (env_utf8(L"BW_AGENT_HOME", override, sizeof(override))) {
    snprintf(g_data_dir, sizeof(g_data_dir), "%s", override);
  } else {
    make_data_default(g_data_dir, sizeof(g_data_dir));
  }
  return g_data_dir;
}

void app_set_data_dir(const char *dir) {
  if (!dir || !*dir) return;
  snprintf(g_data_dir, sizeof(g_data_dir), "%s", dir);
}

const char *app_data_path(char *out, size_t cap, const char *child) {
  const char *base = app_data_dir();
  size_t n = strlen(base);
  while (n > 0 && (base[n - 1] == '\\' || base[n - 1] == '/')) n--;
  if (!child || !*child) snprintf(out, cap, "%.*s", (int)n, base);
  else snprintf(out, cap, "%.*s\\%s", (int)n, base, child);
  return out;
}

void path_dir_of(const char *path, char *out, size_t cap) {
  strncpy_s(out, cap, path ? path : "", _TRUNCATE);
  char *slash = strrchr(out, '\\');
  char *slash2 = strrchr(out, '/');
  if (slash2 > slash) slash = slash2;
  if (slash) *(slash + 1) = 0;
}

int path_join(char *out, size_t cap, const char *dir, const char *name) {
  if (!dir || !name) return -1;
  size_t n = strlen(dir);
  int need_sep = (n > 0 && dir[n - 1] != '\\' && dir[n - 1] != '/');
  return snprintf(out, cap, "%s%s%s", dir, need_sep ? "\\" : "", name) > 0 ? 0 : -1;
}

void ensure_dir(const char *dir) {
  if (!dir || !*dir) return;
  char tmp[MAX_PATH * 2];
  strncpy_s(tmp, sizeof(tmp), dir, _TRUNCATE);
  for (char *p = tmp; *p; p++) if (*p == '/') *p = '\\';

  for (char *p = tmp + 3; *p; p++) {
    if (*p == '\\') {
      *p = 0;
      wchar_t *w = u8_to_w(tmp);
      if (w) { CreateDirectoryW(w, NULL); free(w); }
      *p = '\\';
    }
  }
  wchar_t *w = u8_to_w(tmp);
  if (w) { CreateDirectoryW(w, NULL); free(w); }
}

long file_size(const char *path) {

  if (!path) return -1;
  wchar_t *w = u8_to_w(path);
  if (!w) return -1;
  WIN32_FILE_ATTRIBUTE_DATA fad;
  BOOL ok = GetFileAttributesExW(w, GetFileExInfoStandard, &fad);
  free(w);
  if (!ok) return -1;
  LARGE_INTEGER li;
  li.HighPart = fad.nFileSizeHigh;
  li.LowPart = fad.nFileSizeLow;
  return (long)li.QuadPart;
}

char *file_read_all(const char *path, size_t *out_len) {
  FILE *fp = fopen_utf8(path, L"rb");
  if (!fp) return NULL;
  fseek(fp, 0, SEEK_END);
  long n = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  if (n < 0) { fclose(fp); return NULL; }
  char *data = (char *)xmalloc((size_t)n + 1);
  size_t got = fread(data, 1, (size_t)n, fp);
  fclose(fp);
  data[got] = 0;
  if (out_len) *out_len = got;
  return data;
}

int file_write_all(const char *path, const char *data, size_t len) {
  FILE *fp = fopen_utf8(path, L"wb");
  if (!fp) return -1;
  size_t put = fwrite(data, 1, len, fp);
  fclose(fp);
  return put == len ? 0 : -1;
}

int file_append(const char *path, const char *data, size_t len) {
  FILE *fp = fopen_utf8(path, L"ab");
  if (!fp) return -1;
  size_t put = fwrite(data, 1, len, fp);
  fclose(fp);
  return put == len ? 0 : -1;
}

std::vector<std::string> fs_list_files(const char *dir, const char *ext) {
  std::vector<std::string> out;
  if (!dir || !*dir) return out;
  char pattern[MAX_PATH * 2];
  snprintf(pattern, sizeof(pattern), "%s\\*", dir);
  wchar_t *wpat = u8_to_w(pattern);
  if (!wpat) return out;
  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW(wpat, &fd);
  free(wpat);
  if (h == INVALID_HANDLE_VALUE) return out;
  const std::string want_ext = ext ? ext : "";
  do {
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    char *name8 = w_to_u8(fd.cFileName);
    if (!name8) continue;
    std::string name = name8;
    free(name8);
    if (!want_ext.empty() && !str_endswith(name.c_str(), want_ext.c_str())) continue;
    out.push_back(name);
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  std::sort(out.begin(), out.end());
  return out;
}

std::vector<std::string> fs_list_dirs(const char *dir) {
  std::vector<std::string> out;
  if (!dir || !*dir) return out;
  char pattern[MAX_PATH * 2];
  snprintf(pattern, sizeof(pattern), "%s\\*", dir);
  wchar_t *wpat = u8_to_w(pattern);
  if (!wpat) return out;
  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW(wpat, &fd);
  free(wpat);
  if (h == INVALID_HANDLE_VALUE) return out;
  do {
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
    char *name8 = w_to_u8(fd.cFileName);
    if (!name8) continue;
    out.push_back(name8);
    free(name8);
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  std::sort(out.begin(), out.end());
  return out;
}

void fs_remove_tree(const char *dir) {  if (!dir || !*dir) return;

  char pattern[MAX_PATH * 2];
  snprintf(pattern, sizeof(pattern), "%s\\*", dir);
  wchar_t *wpat = u8_to_w(pattern);
  if (wpat) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(wpat, &fd);
    free(wpat);
    if (h != INVALID_HANDLE_VALUE) {
      do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        char *name8 = w_to_u8(fd.cFileName);
        if (!name8) continue;
        char child[MAX_PATH * 2];
        snprintf(child, sizeof(child), "%s\\%s", dir, name8);
        free(name8);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
          fs_remove_tree(child);
        } else {
          wchar_t *wfile = u8_to_w(child);
          if (wfile) { DeleteFileW(wfile); free(wfile); }
        }
      } while (FindNextFileW(h, &fd));
      FindClose(h);
    }
  }
  wchar_t *wdir = u8_to_w(dir);
  if (wdir) { RemoveDirectoryW(wdir); free(wdir); }
}

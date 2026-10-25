
#ifndef AGENT_COMMON_H
#define AGENT_COMMON_H

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

struct handle_closer {
  void operator()(void *h) const {
    if (h && h != (void *)INVALID_HANDLE_VALUE) CloseHandle((HANDLE)h);
  }
};
using unique_handle_t = std::unique_ptr<void, handle_closer>;

template <class Fn>
Fn dll_sym(HMODULE mod, const char *name) {
  return mod ? reinterpret_cast<Fn>(reinterpret_cast<void *>(GetProcAddress(mod, name)))
             : nullptr;
}

typedef struct {
  char *data;
  size_t len;
  size_t cap;
} buf_t;

void buf_init(buf_t *b);
void buf_free(buf_t *b);
void buf_clear(buf_t *b);
void buf_reserve(buf_t *b, size_t extra);
void buf_puts(buf_t *b, const char *s);
void buf_putn(buf_t *b, const char *s, size_t n);
void buf_putc_(buf_t *b, char c);
void buf_printf(buf_t *b, const char *fmt, ...);

void buf_json_str(buf_t *b, const char *s);
char *buf_take(buf_t *b);

int  utf8_seq_len(const unsigned char *p);
int  utf8_valid(const char *s);

void b64_encode(const unsigned char *src, size_t len, buf_t *out);

int  b64_decode(const char *src, size_t len, buf_t *out);

void hex_encode(const unsigned char *src, size_t len, char *out, size_t cap);

void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

wchar_t *u8_to_w(const char *s);
char *w_to_u8(const wchar_t *w);
char *w_to_u8_alloc(const wchar_t *w, int chars);

size_t u8_prefix(const char *s, size_t max_bytes);

size_t est_tokens(const char *s);

void now_iso(char *out, size_t cap);
void now_iso_at(FILETIME ft, char *out, size_t cap);
long long now_ms(void);
void ms_to_iso(long long ms, char *out, size_t cap);

typedef enum { LOG_DEBUG = 0, LOG_INFO, LOG_WARN, LOG_ERROR } log_level_t;
void log_open(const char *path);
void log_close(void);
void log_set_level(log_level_t level);
void log_write(log_level_t level, const char *fmt, ...);

void console_init(void);

int app_console_init(int want_window);

char **app_argv_from_command_line(int *argc_out);
void free_argv(int argc, char **argv);

void app_fix_argv_encoding(int argc, char **argv);

#define log_debug(...) log_write(LOG_DEBUG, __VA_ARGS__)
#define log_info(...)  log_write(LOG_INFO,  __VA_ARGS__)
#define log_warn(...)  log_write(LOG_WARN,  __VA_ARGS__)
#define log_error(...) log_write(LOG_ERROR, __VA_ARGS__)

int  str_ieq(const char *a, const char *b);
int  str_startswith(const char *s, const char *prefix);
int  str_endswith(const char *s, const char *suffix);
char *str_trim(char *s);
int  str_contains(const char *hay, const char *needle);
int  str_icontains(const char *hay, const char *needle);

const char *str_icase_find(const char *hay, const char *needle);

const char *fail_code(const char *text);
int  str_split(const char *s, char sep, char ***out, int max_parts);
void str_free_list(char **list, int n);

void path_dir_of(const char *path, char *out, size_t cap);
int  path_join(char *out, size_t cap, const char *dir, const char *name);
void ensure_dir(const char *dir);
long file_size(const char *path);
char *file_read_all(const char *path, size_t *out_len);
int  file_write_all(const char *path, const char *data, size_t len);
int  file_append(const char *path, const char *data, size_t len);

std::vector<std::string> fs_list_files(const char *dir, const char *ext);

std::vector<std::string> fs_list_dirs(const char *dir);

void fs_remove_tree(const char *dir);

void app_init_paths(void);
const char *app_dir(void);
const char *app_exe(void);

const char *app_data_dir(void);

void        app_set_data_dir(const char *dir);

const char *app_data_path(char *out, size_t cap, const char *child);

#endif

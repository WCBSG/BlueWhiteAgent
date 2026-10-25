
#include "tool_api.h"

#include <windows.h>

#include "json.h"

int abs_path(const char *raw, wchar_t *out, size_t cap) {
  if (!raw || !*raw) return 0;
  char tmp[MAX_PATH * 2];
  snprintf(tmp, sizeof(tmp), "%s", raw);
  for (char *p = tmp; *p; p++) {
    if (*p == '/') *p = '\\';
  }
  wchar_t *wrel = u8_to_w(tmp);
  if (!wrel) return 0;

  wchar_t *bw = u8_to_w(app_data_dir());
  if (!bw) {
    free(wrel);
    return 0;
  }

  wchar_t combined[MAX_PATH * 4];
  size_t clen = wcslen(wrel);
  if (clen >= 2 && wrel[1] == L':') {
    wcsncpy(combined, wrel, MAX_PATH * 4 - 1);
    combined[MAX_PATH * 4 - 1] = 0;
  } else if (wrel[0] == L'\\') {

    wcsncpy(combined, bw, 2);
    combined[2] = 0;
    wcsncat(combined, wrel, MAX_PATH * 4 - wcslen(combined) - 1);
  } else {
    wcsncpy(combined, bw, MAX_PATH * 4 - 1);
    combined[MAX_PATH * 4 - 1] = 0;
    size_t n = wcslen(combined);
    if (n && combined[n - 1] != L'\\') wcsncat(combined, L"\\", 1);
    wcsncat(combined, wrel, MAX_PATH * 4 - wcslen(combined) - 1);
  }
  free(wrel);
  free(bw);

  wchar_t full[MAX_PATH * 4];
  DWORD got = GetFullPathNameW(combined, (DWORD)(sizeof(full) / sizeof(full[0])), full, NULL);
  if (got == 0 || got >= sizeof(full) / sizeof(full[0])) return 0;

  size_t len = wcslen(full);
  while (len > 3 && full[len - 1] == L'\\') full[--len] = L'\0';
  if (len + 1 > cap) return 0;
  wcscpy(out, full);
  return 1;
}

int under_root(const wchar_t *path, const char *root_u8) {
  wchar_t *rw = u8_to_w(root_u8);
  if (!rw) return 0;
  wchar_t root[MAX_PATH * 4];
  DWORD got = GetFullPathNameW(rw, (DWORD)(sizeof(root) / sizeof(root[0])), root, NULL);
  free(rw);
  if (got == 0) return 0;
  size_t n = wcslen(root);
  while (n > 3 && root[n - 1] == L'\\') root[--n] = L'\0';
  if (_wcsnicmp(path, root, n) != 0) return 0;
  return path[n] == L'\0' || path[n] == L'\\';
}

static char g_extra_root[MAX_PATH * 4];

void fs_tool_set_extra_root(const char *dir) {
  if (!dir || !*dir) {
    g_extra_root[0] = 0;
    return;
  }
  snprintf(g_extra_root, sizeof(g_extra_root), "%s", dir);
}

int check_allowed(const wchar_t *full, int for_write, char *err, size_t err_cap) {
  if (for_write) {
    if (under_root(full, app_data_dir())) return 1;
    snprintf(err, err_cap, "只能往数据目录里写(%s),程序目录是只读的", app_data_dir());
    return 0;
  }
  if (under_root(full, app_data_dir())) return 1;
  if (under_root(full, app_dir())) return 1;
  if (g_extra_root[0] && under_root(full, g_extra_root)) return 1;
  snprintf(err, err_cap, "只能读数据目录(%s)或程序目录(%s)下的文件", app_data_dir(),
           app_dir());
  return 0;
}

void split_lines(const char *data, size_t len, int *total_out) {
  int total = 0;
  if (len == 0) {
    *total_out = 0;
    return;
  }
  for (size_t i = 0; i < len; i++) {
    if (data[i] == '\n') total++;
  }
  if (data[len - 1] != '\n') total++;
  *total_out = total;
}

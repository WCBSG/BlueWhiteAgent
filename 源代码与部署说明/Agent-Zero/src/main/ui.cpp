
#include "ui.h"

#include "common.h"
#include "http.h"
#include "tray.h"

#include <shellapi.h>
#include <tlhelp32.h>

static PROCESS_INFORMATION g_pi;
static int g_have_proc = 0;
static char g_mode[32] = "auto";

const char *ui_mode_name(void) { return g_mode; }

static int file_exists_w(const wchar_t *p) {
  DWORD a = GetFileAttributesW(p);
  return (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static int find_chromium(char *out, size_t cap) {
  const char *cands[] = {
      "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
      "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
      NULL};
  for (int i = 0; cands[i]; i++) {
    wchar_t *w = u8_to_w(cands[i]);
    int ok = w && file_exists_w(w);
    free(w);
    if (ok) {
      snprintf(out, cap, "%s", cands[i]);
      return 1;
    }
  }

  HKEY k;
  const char *keys[] = {
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe",
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe", NULL};
  for (int i = 0; keys[i]; i++) {
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &k) == ERROR_SUCCESS) {
      char v[1024];
      DWORD sz = sizeof(v), type = 0;
      if (RegQueryValueExA(k, NULL, NULL, &type, (LPBYTE)v, &sz) == ERROR_SUCCESS) {
        RegCloseKey(k);
        snprintf(out, cap, "%s", v);
        return 1;
      }
      RegCloseKey(k);
    }
  }
  return 0;
}

static void remove_tree(const char *dir) {
  char pattern[MAX_PATH * 2];
  snprintf(pattern, sizeof(pattern), "%s\\*", dir);
  wchar_t *wpat = u8_to_w(pattern);
  if (!wpat) return;
  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW(wpat, &fd);
  free(wpat);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
      char *name8 = w_to_u8(fd.cFileName);
      char child[MAX_PATH * 2];
      snprintf(child, sizeof(child), "%s\\%s", dir, name8 ? name8 : "");
      free(name8);
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        remove_tree(child);
      } else {
        wchar_t *wfile = u8_to_w(child);
        if (wfile) { DeleteFileW(wfile); free(wfile); }
      }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }
  wchar_t *wdir = u8_to_w(dir);
  if (wdir) { RemoveDirectoryW(wdir); free(wdir); }
}

static int g_stop_on_close = 1;

void ui_set_stop_on_close(int on) { g_stop_on_close = on ? 1 : 0; }
int  ui_stop_on_close(void) { return g_stop_on_close; }

static DWORD WINAPI watch_thread(LPVOID param) {
  HANDLE h = (HANDLE)param;
  WaitForSingleObject(h, INFINITE);
  if (!g_stop_on_close) {
    log_info("界面窗口已关闭(--debug:服务继续运行,界面地址仍然可用;关掉命令行窗口或按 Ctrl+C 结束)");
    return 0;
  }

  if (tray_active()) {
    log_info("界面窗口已关闭,程序已最小化到托盘(右键托盘图标可重新打开或彻底退出)");
    g_have_proc = 0;
    tray_balloon("仍在后台运行", "周期巡检会继续。右键托盘图标可重新打开界面或彻底退出。");
    return 0;
  }
  log_info("界面窗口已关闭,服务随之停止");
  http_stop();
  return 0;
}

static void watch_window_close(HANDLE proc) {
  if (!proc) return;
  HANDLE th = CreateThread(NULL, 0, watch_thread, (LPVOID)proc, 0, NULL);
  if (th) CloseHandle(th);
}

static int port_alive(int port) {
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return 0;
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons((u_short)port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  u_long nb = 1;
  ioctlsocket(s, FIONBIO, &nb);
  int ok = 0;
  if (connect(s, (struct sockaddr *)&a, sizeof(a)) == 0) {
    ok = 1;
  } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
    fd_set wr;
    FD_ZERO(&wr);
    FD_SET(s, &wr);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (select(0, NULL, &wr, NULL, &tv) > 0) {
      int err = 0, elen = sizeof(err);
      getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &elen);
      ok = (err == 0);
    }
  }
  closesocket(s);
  return ok;
}

static int wait_service_ready(int port, int timeout_ms) {
  for (int waited = 0; waited < timeout_ms; waited += 50) {
    if (http_is_running() && port_alive(port)) return 1;
    Sleep(50);
  }
  return 0;
}

static int launch_app_window(const char *exe, int port) {
  char url[128];
  snprintf(url, sizeof(url), "http://127.0.0.1:%d/", port);

  char profile[MAX_PATH * 2];
  app_data_path(profile, sizeof(profile), "ui-profile");
  ensure_dir(profile);

  buf_t cmd;
  buf_init(&cmd);
  buf_puts(&cmd, "\"");
  buf_puts(&cmd, exe);
  buf_puts(&cmd, "\" --app=");
  buf_puts(&cmd, url);
  buf_puts(&cmd, " --user-data-dir=\"");
  buf_puts(&cmd, profile);
  buf_puts(&cmd, "\" --no-first-run --no-default-browser-check");
  buf_puts(&cmd, " --disable-features=msEdgeSidebarV2 ");

  {
    int dpi = 96;
    HMODULE u = GetModuleHandleW(L"user32.dll");
    typedef UINT(WINAPI * get_dpi_fn)(void);
    get_dpi_fn get_dpi = dll_sym<get_dpi_fn>(u, "GetDpiForSystem");
    if (get_dpi) dpi = (int)get_dpi();
    RECT work;
    if (!SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0)) {
      work.left = 0; work.top = 0;
      work.right = GetSystemMetrics(SM_CXSCREEN);
      work.bottom = GetSystemMetrics(SM_CYSCREEN);
    }
    int maxW = (int)((work.right - work.left) * 0.92f);
    int maxH = (int)((work.bottom - work.top) * 0.92f);
    int w = MulDiv(1280, dpi, 96), h = MulDiv(860, dpi, 96);
    if (w > maxW) w = maxW;
    if (h > maxH) h = maxH;
    buf_printf(&cmd, "--window-size=%d,%d", w, h);
  }

  wchar_t *wcmd = u8_to_w(cmd.data);
  buf_free(&cmd);
  if (!wcmd) return 0;

  STARTUPINFOW si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&g_pi, 0, sizeof(g_pi));

  BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, FALSE,
                           CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &g_pi);
  free(wcmd);
  if (ok) {
    g_have_proc = 1;
    snprintf(g_mode, sizeof(g_mode), "app");
    log_info("界面已用 --app 应用窗口打开(%s)", exe);
    watch_window_close(g_pi.hProcess);
    return 1;
  }
  log_warn("--app 启动失败(code=%lu)", (unsigned long)GetLastError());
  return 0;
}

static int launch_shell(int port) {
  char url[128];
  snprintf(url, sizeof(url), "http://127.0.0.1:%d/", port);
  HINSTANCE h = ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
  if ((INT_PTR)h > 32) {
    snprintf(g_mode, sizeof(g_mode), "browser");
    log_info("界面已用系统默认浏览器打开");
    return 1;
  }
  return 0;
}

static DWORD WINAPI open_thread(LPVOID param) {
  int port = (int)(INT_PTR)param;
  const char *force = getenv("UI_MODE");
  int want_browser = force && str_ieq(force, "browser");

  if (force && (str_ieq(force, "off") || str_ieq(force, "none"))) {
    snprintf(g_mode, sizeof(g_mode), "off");
    log_info("界面窗口已按要求跳过(UI_MODE=%s),界面地址仍然可用", force);
    return 0;
  }

  if (!wait_service_ready(port, 3000)) {
    log_warn("服务没有起来(端口 %d),不再打开界面窗口", port);
    return 0;
  }

  char exe[MAX_PATH];
  if (!want_browser && find_chromium(exe, sizeof(exe))) {
    if (launch_app_window(exe, port)) return 0;
  }
  launch_shell(port);
  return 0;
}

void ui_open_url_async(int port) {
  HANDLE th = CreateThread(NULL, 0, open_thread, (LPVOID)(INT_PTR)port, 0, NULL);
  if (th) CloseHandle(th);
}

static BOOL CALLBACK find_ours_proc(HWND h, LPARAM lp) {
  if (!IsWindowVisible(h)) return TRUE;
  RECT r;
  if (!GetWindowRect(h, &r)) return TRUE;
  if (r.right - r.left < 320 || r.bottom - r.top < 240) return TRUE;
  wchar_t title[256];
  if (GetWindowTextW(h, title, 256) <= 0) return TRUE;

  if (wcscmp(title, L"BlueWhiteAgent") != 0 &&
      wcscmp(title, L"网站安全巡检") != 0) {
    return TRUE;
  }
  *(HWND *)lp = h;
  return FALSE;
}

static HWND find_app_window(int port) {
  HWND h = FindWindowW(L"BwAgentWebViewWnd", NULL);
  if (h) return h;
  h = FindWindowW(L"BwAgentNativeWnd", NULL);
  if (h) return h;

  wchar_t want[128];
  swprintf(want, 128, L"BlueWhiteAgent · %d", port);
  h = FindWindowW(L"Chrome_WidgetWin_1", want);
  if (h && IsWindowVisible(h)) return h;
  h = FindWindowW(NULL, want);
  if (h && IsWindowVisible(h)) return h;

  h = FindWindowW(NULL, L"BlueWhiteAgent");
  if (h && IsWindowVisible(h)) return h;
  h = FindWindowW(NULL, L"网站安全巡检");
  if (h && IsWindowVisible(h)) return h;
  HWND hit = NULL;
  EnumWindows(find_ours_proc, (LPARAM)&hit);
  return hit;
}

static void bring_to_front(HWND h) {
  if (IsIconic(h)) ShowWindow(h, SW_RESTORE);
  else ShowWindow(h, SW_SHOW);

  HWND fg = GetForegroundWindow();
  DWORD fg_tid = fg ? GetWindowThreadProcessId(fg, NULL) : 0;
  DWORD my_tid = GetCurrentThreadId();
  int attached = 0;
  if (fg_tid && fg_tid != my_tid) attached = AttachThreadInput(my_tid, fg_tid, TRUE);

  BringWindowToTop(h);
  int ok = SetForegroundWindow(h);

  if (attached) AttachThreadInput(my_tid, fg_tid, FALSE);
  if (!ok) {

    FLASHWINFO fi;
    memset(&fi, 0, sizeof(fi));
    fi.cbSize = sizeof(fi);
    fi.hwnd = h;
    fi.dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG;
    fi.uCount = 3;
    FlashWindowEx(&fi);
    log_warn("窗口已置顶,但系统没允许直接抢焦点(任务栏已闪烁提示)");
  }
}

int ui_show_existing(int port) {
  HWND h = find_app_window(port);
  if (h) {
    bring_to_front(h);
    snprintf(g_mode, sizeof(g_mode), "focus");
    log_info("已把运行中的界面唤到前台(端口 %d)", port);
    return 1;
  }

  const char *force = getenv("UI_MODE");
  int want_browser = force && str_ieq(force, "browser");
  char exe[MAX_PATH];
  if (!want_browser && find_chromium(exe, sizeof(exe))) {
    if (launch_app_window(exe, port)) {
      log_info("已重新打开界面窗口,指向运行中的服务(端口 %d)", port);
      return 2;
    }
  }
  if (launch_shell(port)) {
    log_info("已在默认浏览器打开运行中的界面(端口 %d)", port);
    return 2;
  }
  log_warn("没能打开界面窗口(端口 %d),请手动访问 http://127.0.0.1:%d/", port, port);
  return 0;
}

void ui_close(void) {
  if (!g_have_proc) return;

  DWORD pid = g_pi.dwProcessId;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);

    for (int pass = 0; pass < 2; pass++) {
      if (!Process32FirstW(snap, &pe)) break;
      do {
        if (pe.th32ParentProcessID == pid) {
          HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
          if (h) { TerminateProcess(h, 0); CloseHandle(h); }
        }
      } while (Process32NextW(snap, &pe));
      if (pass == 0) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) { TerminateProcess(h, 0); CloseHandle(h); }
      }
    }
    CloseHandle(snap);
  }
  g_have_proc = 0;
}


#include "common.h"
#include "tray.h"

#include <shellapi.h>

#include "http.h"
#include "ui.h"
#include "webview.h"

#define TRAY_WM   (WM_APP + 7)
#define ID_OPEN   1001
#define ID_EXIT   1002

static HWND  g_hwnd = NULL;
static HANDLE g_thread = NULL;
static DWORD g_tid = 0;
static int   g_port = 0;
static HICON g_icon = NULL;
static volatile LONG g_ready = 0;

static void reopen_ui(void) {

  if (webview_active()) { webview_show(); return; }
  if (g_port > 0) {
    if (webview_start(g_port, "BlueWhiteAgent") == 0) { webview_show(); return; }
    ui_open_url_async(g_port);
  }
}

static void show_menu(HWND hwnd) {
  POINT pt;
  GetCursorPos(&pt);
  HMENU m = CreatePopupMenu();
  if (!m) return;
  AppendMenuW(m, MF_STRING, ID_OPEN, L"打开界面");
  AppendMenuW(m, MF_SEPARATOR, 0, NULL);
  AppendMenuW(m, MF_STRING, ID_EXIT, L"彻底退出");

  SetForegroundWindow(hwnd);
  TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, NULL);
  DestroyMenu(m);
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case TRAY_WM:
      if (LOWORD(lp) == WM_LBUTTONDBLCLK) { reopen_ui(); return 0; }
      if (LOWORD(lp) == WM_RBUTTONUP || LOWORD(lp) == WM_CONTEXTMENU) { show_menu(hwnd); return 0; }
      return 0;
    case WM_COMMAND:
      switch (LOWORD(wp)) {
        case ID_OPEN: reopen_ui(); return 0;
        case ID_EXIT:
          log_info("托盘:用户选择彻底退出");
          http_stop();
          PostQuitMessage(0);
          return 0;        default: return 0;
      }
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
    default: break;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

static int make_window(void) {
  WNDCLASSEXW wc;
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = wnd_proc;
  wc.hInstance = GetModuleHandleW(NULL);
  wc.lpszClassName = L"BwAgentTrayWnd";
  if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return -1;

  g_hwnd = CreateWindowExW(0, L"BwAgentTrayWnd", L"BW Agent Tray", 0,
                           0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, NULL);
  return g_hwnd ? 0 : -1;
}

static void add_icon(void) {
  NOTIFYICONDATAW nid;
  memset(&nid, 0, sizeof(nid));
  nid.cbSize = sizeof(nid);
  nid.hWnd = g_hwnd;
  nid.uID = 1;
  nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
  nid.uCallbackMessage = TRAY_WM;

  if (!g_icon) g_icon = LoadIconW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(1));
  if (!g_icon) g_icon = LoadIconW(NULL, MAKEINTRESOURCEW(32512));
  nid.hIcon = g_icon;

  wcsncpy_s(nid.szTip, 128, L"BlueWhiteAgent", _TRUNCATE);
  Shell_NotifyIconW(NIM_ADD, &nid);
}

static DWORD WINAPI tray_thread(LPVOID param) {
  (void)param;
  if (make_window() != 0) {
    log_warn("托盘:窗口创建失败,关掉界面后仍按原样退出程序");
    return 1;
  }
  add_icon();
  g_tid = GetCurrentThreadId();
  InterlockedExchange(&g_ready, 1);

  log_info("托盘图标已建立(窗口句柄 %p)", (void *)g_hwnd);

  MSG msg;
  while (GetMessageW(&msg, NULL, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }

  NOTIFYICONDATAW nid;
  memset(&nid, 0, sizeof(nid));
  nid.cbSize = sizeof(nid);
  nid.hWnd = g_hwnd;
  nid.uID = 1;
  Shell_NotifyIconW(NIM_DELETE, &nid);
  if (g_hwnd) { DestroyWindow(g_hwnd); g_hwnd = NULL; }
  InterlockedExchange(&g_ready, 0);
  return 0;
}

int tray_start(int port, const char *tip) {
  (void)tip;
  if (g_thread) return 0;
  g_port = port;
  g_thread = CreateThread(NULL, 0, tray_thread, NULL, 0, NULL);
  if (!g_thread) return -1;

  for (int i = 0; i < 40 && !g_ready; i++) Sleep(25);
  return g_ready ? 0 : -1;
}

void tray_balloon(const char *title, const char *text) {
  if (!g_hwnd) return;
  NOTIFYICONDATAW nid;
  memset(&nid, 0, sizeof(nid));
  nid.cbSize = sizeof(nid);
  nid.hWnd = g_hwnd;
  nid.uID = 1;
  nid.uFlags = NIF_INFO;
  nid.dwInfoFlags = NIIF_INFO;
  wchar_t *w1 = u8_to_w(title ? title : "");
  wchar_t *w2 = u8_to_w(text ? text : "");
  if (w1) { wcsncpy_s(nid.szInfoTitle, 64, w1, _TRUNCATE); free(w1); }
  if (w2) { wcsncpy_s(nid.szInfo, 256, w2, _TRUNCATE); free(w2); }
  Shell_NotifyIconW(NIM_MODIFY, &nid);
}

int tray_active(void) { return g_ready ? 1 : 0; }

void tray_stop(void) {
  if (!g_thread) return;
  if (g_tid) PostThreadMessageW(g_tid, WM_QUIT, 0, 0);
  WaitForSingleObject(g_thread, 3000);
  CloseHandle(g_thread);
  g_thread = NULL;
  g_tid = 0;
}

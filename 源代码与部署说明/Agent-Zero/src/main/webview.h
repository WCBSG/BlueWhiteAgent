
#ifndef AGENT_WEBVIEW_H
#define AGENT_WEBVIEW_H

int  webview_start(int port, const char *title);

void webview_show(void);

void webview_stop(void);

int  webview_active(void);

int  webview_backend_is_native(void);

#endif

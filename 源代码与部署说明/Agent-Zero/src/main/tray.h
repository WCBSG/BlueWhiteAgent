
#ifndef AGENT_TRAY_H
#define AGENT_TRAY_H

int  tray_start(int port, const char *tip);

void tray_balloon(const char *title, const char *text);

void tray_stop(void);

int  tray_active(void);

#endif


#ifndef AGENT_UI_H
#define AGENT_UI_H

void ui_open_url_async(int port);

int ui_show_existing(int port);

void ui_close(void);

void ui_set_stop_on_close(int on);
int  ui_stop_on_close(void);

const char *ui_mode_name(void);

#endif

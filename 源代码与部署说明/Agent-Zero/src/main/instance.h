
#ifndef AGENT_INSTANCE_H
#define AGENT_INSTANCE_H

int instance_acquire(void);

int instance_owned(void);

void instance_publish(int port);

void instance_unpublish(void);

int instance_running_port(int wait_ms);

const char *instance_note(void);

int instance_pick_free_port(int from, int to);

#endif

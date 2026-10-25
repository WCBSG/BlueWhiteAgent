
#ifndef AGENT_SESSION_STORE_H
#define AGENT_SESSION_STORE_H

#include "common.h"
#include "json.h"

#define SESSION_SCHEMA 3

void    sess_init(const char *data_dir);

json_t *sess_ensure(const char *id, const char *title);

json_t *sess_get(const char *id);

json_t *sess_list(void);

int sess_set_title(const char *id, const char *title);
int sess_set_flags(const char *id, int archived, int pinned);
int sess_delete(const char *id);

int sess_set_input(const char *id, json_t *input);

int sess_set_context(const char *id, json_t *ctx);

int sess_begin_turn(const char *id, json_t *user_blocks, json_t *request);

int sess_turn_add_step(const char *id, int index, json_t *step);

int sess_step_patch(const char *id, int index, int step_index, const char *key, json_t *value);

int sess_turn_patch(const char *id, int index, const char *key, json_t *value);

int sess_turn_finish(const char *id, int index, json_t *response, const char *status);

char *sess_artifact_write(const char *id, const char *tag, const char *text, size_t len);

char *sess_artifact_read(const char *rel_path, size_t *len);

json_t *sess_blocks_text(const char *text);

#endif

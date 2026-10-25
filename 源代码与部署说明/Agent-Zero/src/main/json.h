
#ifndef AGENT_JSON_H
#define AGENT_JSON_H

#include "common.h"

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } jtype_t;

typedef struct json json_t;
struct json {
  jtype_t type;

  int b;
  double num;
  char *str;

  json_t **items;
  char **keys;
  int count;
  int cap;
};

json_t *json_parse(const char *text);
json_t *json_parse_n(const char *text, size_t len);
void    json_free(json_t *j);

json_t *j_null(void);
json_t *j_bool(int v);
json_t *j_num(double v);
json_t *j_str(const char *s);
json_t *j_arr(void);
json_t *j_obj(void);

void    j_set(json_t *obj, const char *key, json_t *value);
void    j_set_str(json_t *obj, const char *key, const char *value);
void    j_set_num(json_t *obj, const char *key, double value);
void    j_set_bool(json_t *obj, const char *key, int value);
void    j_set_null(json_t *obj, const char *key);
void    j_add(json_t *arr, json_t *value);

json_t      *j_get(json_t *obj, const char *key);
const char  *j_s(json_t *obj, const char *key, const char *fallback);
double       j_n(json_t *obj, const char *key, double fallback);
int          j_b(json_t *obj, const char *key, int fallback);
json_t      *j_at(json_t *arr, int index);
int          j_len(json_t *arr_or_obj);

json_t      *j_path(json_t *root, const char *path);
const char  *j_path_s(json_t *root, const char *path, const char *fallback);

void  json_write(buf_t *out, json_t *j);
char *json_dump(json_t *j);
char *json_dump_pretty(json_t *j);

json_t *j_clone(json_t *src);
const char *j_type_name(jtype_t t);

char *json_unescape(const char *s, size_t n, size_t *out_len);

#endif

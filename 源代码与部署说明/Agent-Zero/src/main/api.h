
#ifndef AGENT_API_H
#define AGENT_API_H

#include "http.h"

void api_rules(const http_req_t *req, http_res_t *res);

void api_rules_preset(const http_req_t *req, http_res_t *res);

void api_config_list(const http_req_t *req, http_res_t *res);
void api_config_get(const http_req_t *req, http_res_t *res);
void api_config_save(const http_req_t *req, http_res_t *res);
void api_reload(const http_req_t *req, http_res_t *res);

void api_models(const http_req_t *req, http_res_t *res);

void api_caps(const http_req_t *req, http_res_t *res);

void api_automation_list(const http_req_t *req, http_res_t *res);

void api_automation_history(const http_req_t *req, http_res_t *res);
void api_automation_post(const http_req_t *req, http_res_t *res);

void api_profiles(const http_req_t *req, http_res_t *res);

#endif

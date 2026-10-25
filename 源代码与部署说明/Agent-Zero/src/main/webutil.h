
#ifndef AGENT_WEBUTIL_H
#define AGENT_WEBUTIL_H

#include "common.h"
#include "json.h"

int  sha256_hex(const char *data, size_t len, char *out, size_t cap);

int  web_body_hash(const char *body, char *out, size_t cap);

void web_norm_text(buf_t *out, const char *body);

void web_shape(buf_t *out, const char *body);

int  web_same_shape(const char *a, const char *b);

void web_title(const char *body, char *out, size_t cap);

int  web_header(const char *raw_headers, const char *name, buf_t *out);

int  web_header_count(const char *raw_headers, const char *name);

int  web_header_at(const char *raw_headers, const char *name, int idx, buf_t *out);

int  web_headers_available(const char *raw_headers);

json_t *web_headers_json(const char *raw_headers);

int  web_is_dir_listing(const char *body);

void web_dir_listing_entries(const char *body, json_t *out, int max);

int  web_has_password_form(const char *body);

int  web_has_mixed_content(const char *body);

void web_url_parts(const char *url, char *host, size_t hcap, char *path, size_t pcap);
void web_url_encode(const char *s, buf_t *out);

void web_url_key(const char *url, char *out, size_t cap);

void web_url_set_param(const char *url, const char *key, const char *value, buf_t *out);

void web_url_params(const char *url, json_t *out);

int  web_url_get_param(const char *url, const char *key, buf_t *out);

void web_extract_links(const char *html, json_t *out);

int  web_count_icase(const char *hay, const char *needle);

void web_decode_entities(buf_t *out, const char *s);

void web_strip_invisible(buf_t *out, const char *s);

void web_merge_js_strings(buf_t *out, const char *s);

void web_decode_b64_fragments(const char *s, int min_len, buf_t *out);

void web_scan_text(buf_t *out, const char *raw);

void web_attr_values(const char *html, const char *attr, json_t *out, int max);

void web_script_refs(const char *html, json_t *out, int max);

void web_regions(const char *html, json_t *out, int max);

#endif

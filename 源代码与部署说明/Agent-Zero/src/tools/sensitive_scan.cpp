
#include "tool_api.h"

int t_sensitive_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  const char *text = j_s(args, "text", "");
  const char *url = j_s(args, "url", "");
  buf_t body;
  buf_init(&body);
  int fetched_status = 0;

  if ((!text || !*text) && url && *url) {
    if (!scope_ok(ctx, url)) {
      out->is_error = 1;
      out->text = xstrdup("这个地址不在授权范围内,已拒绝取回。");
      out->say = xstrdup("地址在授权池外,这次没有发起请求。");
      buf_free(&body);
      return 0;
    }
    fetch_t f;
    t_fetch(ctx, url, &f);
    fetched_status = f.status;
    if (f.err && !f.status) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "取回 %s 失败:%s", url, f.err);
      out->is_error = 1;
      out->text = buf_take(&m);
      out->say = xstrdup("这个地址取不到,判断不了内容。");
      fetch_free2(&f);
      buf_free(&body);
      return 0;
    }
    if (f.body && f.body[0]) buf_puts(&body, f.body);
    fetch_free2(&f);
    text = body.data ? body.data : "";
  }

  if (!text || !*text) {
    out->is_error = 1;
    out->text = xstrdup("要扫描什么?给 text(一段原文)或 url(一个地址),给一个就行。");
    out->say = xstrdup("没拿到要判定的内容。");
    buf_free(&body);
    return 0;
  }

  json_t *hits = j_arr();
  int n = scan_text_into(ctx, text, hits);
  json_t *data = j_obj();
  j_set(hits, "hits", hits);
  j_set_num(data, "hit_count", n);
  j_set_num(data, "bytes", (double)strlen(text));
  if (url && *url && fetched_status) {
    j_set_str(data, "url", url);
    j_set_num(data, "status", fetched_status);
  }
  out->data = data;

  buf_t t;
  buf_init(&t);
  if (url && *url && fetched_status) {
    buf_printf(&t, "取回 %s(%d)后扫描 %zu 字节内容。\n", url, fetched_status, strlen(text));
  }
  if (n == 0) {
    buf_puts(&t, "未发现敏感信息");
    out->say = xstrdup("这段内容里没发现敏感信息。");
  } else {
    int restored = 0;
    buf_printf(&t, "命中 %d 处敏感信息:\n", n);
    for (int i = 0; i < j_len(hits) && i < 20; i++) {
      json_t *h = j_at(hits, i);
      const char *via = j_s(h, "via", "");
      if (via[0]) restored++;
      buf_printf(&t, "- [%s] %s: %s%s\n", j_s(h, "severity", ""), j_s(h, "kind", ""),
                 j_s(h, "masked", ""), via[0] ? "(编码还原后才出现)" : "");
    }
    if (restored > 0) {
      buf_printf(&t, "\n其中 %d 处是还原(实体/零宽/拼接/Base64)后才出现的:"
                     "原文直接搜不到,属于刻意规避,建议按同一手法再查同源页面。\n",
                 restored);
    }
    buf_t s;
    buf_init(&s);
    buf_printf(&s, "发现 %d 处敏感信息,已在结果卡片中列出(展示时已去敏),建议核实来源后处理。", n);
    out->say = buf_take(&s);
  }
  out->text = buf_take(&t);
  buf_free(&body);
  return 0;
}

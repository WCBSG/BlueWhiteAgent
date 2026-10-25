
#include "tool_api.h"

static const char *norm_severity(const char *in) {
  if (!in || !*in) return "中";
  if (str_ieq(in, "严重") || str_ieq(in, "critical") || str_ieq(in, "crit")) return "严重";
  if (str_ieq(in, "高") || str_ieq(in, "高危") || str_ieq(in, "high")) return "高";
  if (str_ieq(in, "中") || str_ieq(in, "medium") || str_ieq(in, "moderate")) return "中";
  if (str_ieq(in, "低") || str_ieq(in, "low")) return "低";
  return "信息";
}

int t_record_finding(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  const char *title = j_s(args, "title", "");
  const char *severity = norm_severity(j_s(args, "severity", ""));
  const char *kind = j_s(args, "kind", "漏洞");
  const char *target = j_s(args, "target", "");
  const char *evidence = j_s(args, "evidence", "");
  const char *impact = j_s(args, "impact", "");
  const char *fix = j_s(args, "fix", "");

  if (!title[0] || !evidence[0]) {
    out->is_error = 1;
    out->text = xstrdup("拒收:title 与 evidence 都必须有。证据可以是响应片段、状态码差异或链路里的关键一步。");
    out->say = xstrdup("这条结论没有证据,我不落库。");
    return -1;
  }
  if (!target[0] && ctx && ctx->domain_count > 0) target = ctx->domains[0];
  if (!target[0]) target = "(未指明目标)";
  if (!ctx || !ctx->store) {
    out->is_error = 1;
    out->text = xstrdup("这次运行没有挂上存储,发现落不了盘。");
    out->say = xstrdup("没有存储,落不了库。");
    return -1;
  }

  char tag[512];
  snprintf(tag, sizeof(tag), "model|%s|%s", target, title);

  finding_in_t in;
  memset(&in, 0, sizeof(in));
  in.kind = kind;
  in.severity = severity;
  in.title = title;
  in.target = target;
  in.evidence = evidence;
  in.impact = impact;
  in.fix = fix;
  in.source_tool = "model_analysis";
  in.dedup_tag = tag;
  in.task_id = ctx->task_id;
  in.run_id = ctx->run_id;

  int is_new = 0;
  char *id = store_upsert_finding((store_t *)ctx->store, &in, &is_new);

  json_t *data = j_obj();
  j_set_str(data, "id", id ? id : "");
  j_set_bool(data, "is_new", is_new);
  j_set_str(data, "severity", severity);
  j_set_str(data, "kind", kind);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "已记录发现 %s[%s]%s → %s", id ? id : "", severity, title, target);
  if (!is_new) buf_puts(&t, "(这条之前记过,已更新)");
  if (!impact[0]) buf_puts(&t, "\n提示:没有写影响说明,报告里会显示为待补。");
  if (!fix[0]) buf_puts(&t, "\n提示:没有写修复建议,报告里会显示为待补。");
  out->text = buf_take(&t);
  out->say = xstrdup(is_new ? "我把这条结论记下来了。" : "这条之前记过,我更新一下。");
  free(id);
  return 0;
}

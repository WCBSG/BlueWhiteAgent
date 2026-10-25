
#include "serve.h"

#include <bcrypt.h>
#include <signal.h>

#include <ctime>

#include "agent.h"
#include "api.h"
#include "approval.h"
#include "automation.h"
#include "embed.h"
#include "export.h"
#include "profile.h"
#include "regex.h"
#include "ext.h"
#include "http.h"
#include "instance.h"
#include "llm.h"
#include "net.h"
#include "profile.h"
#include "res.h"
#include "rules.h"
#include "serve_ctx.h"
#include "skills.h"
#include "store.h"
#include "tools.h"
#include "session_store.h"
#include "tray.h"
#include "ui.h"
#include "webview.h"

static store_t *g_store = NULL;
static CRITICAL_SECTION g_lock;
static CRITICAL_SECTION g_status_lock;

static char *g_status_cache = NULL;
static char g_session[128] = "web-session";

static char g_task_disp[64] = "WEB-TASK";
static char g_domain_disp[256] = "";

static thread_local char g_task[64] = "";
static thread_local char g_domain[256] = "";

static char g_pool_file[512] = "";
static char g_pool_json[16384] = "{\"hosts\":[]}";
static int g_turn_seq = 0;
static char g_data_dir[512];

static char g_token[64] = "";
static int g_port = 0;

typedef struct {
  http_res_t *res;
  char message_id[64];
  int index;
  int step;
  int tool_seq;
  char tool_use_id[96];
  int text_open;
  int tool_open;
  char pending_note[512];
  int aborted;
  char session[128];
  buf_t answer;
  int turn;
  int step_seq;
  int step_index;
  long long step_t0;
  long long t_start;
  long long first_byte_ms;
  long long wait_ms;
  long long llm_ms;

  int ctx_used;
  int ctx_window;
  int ctx_reserve;
  int ctx_compressed;
} sse_ctx_t;

static thread_local sse_ctx_t *g_sse = NULL;

static void sse_send(sse_ctx_t *c, const char *json) {
  if (!c || c->aborted) return;
  if (!http_sse_json(c->res, json)) c->aborted = 1;
}

static void ev_message_start(sse_ctx_t *c) {
  char ts[64];
  now_iso(ts, sizeof(ts));
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"message_start\",\"messageId\":");
  buf_json_str(&b, c->message_id);
  buf_puts(&b, ",\"sessionId\":");
  buf_json_str(&b, c->session[0] ? c->session : g_session);
  buf_puts(&b, ",\"timestamp\":");
  buf_json_str(&b, ts);
  buf_puts(&b, "}");
  sse_send(c, b.data);
  buf_free(&b);
}

static void ev_block_start(sse_ctx_t *c, int index, const char *type,
                           const char *tool_use_id, const char *tool_name) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"block_start\",\"messageId\":");
  buf_json_str(&b, c->message_id);
  buf_printf(&b, ",\"index\":%d,\"blockType\":", index);
  buf_json_str(&b, type);
  if (!strcmp(type, "tool_use")) {
    buf_puts(&b, ",\"toolUseId\":");
    buf_json_str(&b, tool_use_id ? tool_use_id : "");
    buf_puts(&b, ",\"toolName\":");
    buf_json_str(&b, tool_name ? tool_name : "");
  }
  buf_puts(&b, "}");
  sse_send(c, b.data);
  buf_free(&b);
}

static void ev_block_delta_text(sse_ctx_t *c, int index, const char *text) {
  if (!text || !*text) return;
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"block_delta\",\"messageId\":");
  buf_json_str(&b, c->message_id);
  buf_printf(&b, ",\"index\":%d,\"delta\":{\"type\":\"text_delta\",\"text\":", index);
  buf_json_str(&b, text);
  buf_puts(&b, "}}");
  sse_send(c, b.data);
  buf_free(&b);
}

static void ev_block_delta_json(sse_ctx_t *c, int index, const char *partial) {
  if (!partial || !*partial) return;
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"block_delta\",\"messageId\":");
  buf_json_str(&b, c->message_id);
  buf_printf(&b,
             ",\"index\":%d,\"delta\":{\"type\":\"input_json_delta\",\"partialJson\":",
             index);
  buf_json_str(&b, partial);
  buf_puts(&b, "}}");
  sse_send(c, b.data);
  buf_free(&b);
}

static void ev_block_stop(sse_ctx_t *c, int index) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"block_stop\",\"messageId\":");
  buf_json_str(&b, c->message_id);
  buf_printf(&b, ",\"index\":%d}", index);
  sse_send(c, b.data);
  buf_free(&b);
}

static void ev_tool_status(sse_ctx_t *c, const char *tool_use_id,
                           const char *status, const char *note) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"tool_status\",\"toolUseId\":");
  buf_json_str(&b, tool_use_id ? tool_use_id : "");
  buf_puts(&b, ",\"status\":");
  buf_json_str(&b, status);
  buf_puts(&b, ",\"note\":");
  buf_json_str(&b, note ? note : "");
  buf_puts(&b, "}");
  sse_send(c, b.data);
  buf_free(&b);
}

static void ev_message_stop(sse_ctx_t *c, const char *stop_reason, const char *detail,
                            const loop_state_t *st) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"message_stop\",\"messageId\":");
  buf_json_str(&b, c->message_id);
  buf_puts(&b, ",\"stopReason\":");
  buf_json_str(&b, stop_reason);

  if (detail && *detail) {
    buf_puts(&b, ",\"stopDetail\":");
    buf_json_str(&b, detail);
  }

  buf_printf(&b, ",\"durationMs\":%lld,\"waitMs\":%lld",
             c->t_start ? now_ms() - c->t_start : 0, c->wait_ms);

  if (st) {
    json_t *steps = (st->steps && st->steps->type == J_ARR) ? st->steps : j_get(st->steps, "steps");
    int by_model = 0, by_direct = 0;
    for (int i = 0; i < j_len(steps); i++) {
      if (j_b(j_at(steps, i), "from_model", 0)) by_model++;
      else by_direct++;
    }
    buf_printf(&b, ",\"modelSteps\":%d,\"directSteps\":%d", by_model, by_direct);
  }
  buf_printf(&b, ",\"llmMs\":%lld", (long long)(c->llm_ms > 0 ? c->llm_ms : 0));

  buf_printf(&b,
             ",\"context\":{\"used\":%d,\"window\":%d,\"reserve\":%d,\"compressed\":%d}",
             c->ctx_used, c->ctx_window, c->ctx_reserve, c->ctx_compressed);
  buf_puts(&b, "}");
  sse_send(c, b.data);
  buf_free(&b);
}

static void t_close_text(sse_ctx_t *c) {
  if (c->text_open) {
    ev_block_stop(c, c->index);
    c->index++;
    c->text_open = 0;
  }
}

static void t_close_tool(sse_ctx_t *c) {
  if (c->tool_open) {
    ev_block_stop(c, c->index);
    c->index++;
    c->tool_open = 0;
  }
}

static void t_put_text(sse_ctx_t *c, const char *text) {
  if (!text || !*text) return;
  if (!c->text_open) {
    ev_block_start(c, c->index, "text", NULL, NULL);
    c->text_open = 1;
  }
  ev_block_delta_text(c, c->index, text);
}

static void hook_thinking(void *ud, const char *text) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c) return;

  if (!text || !*text) return;
  t_close_tool(c);

  t_close_text(c);
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "\n[第 ");
  buf_printf(&b, "%d", c->step + 1);
  buf_puts(&b, " 步 · 思考] ");
  buf_puts(&b, text ? text : "");
  buf_puts(&b, "\n");
  t_put_text(c, b.data);
  t_close_text(c);
  buf_free(&b);

  if (c->turn >= 0) {
    json_t *it = j_obj();
    j_set_str(it, "type", "think");
    j_set_str(it, "text", text);
    j_set_num(it, "at", (double)(now_ms() - c->t_start));
    c->step_seq++;
    sess_turn_add_step(c->session, c->turn, it);
  }
}

static void hook_action(void *ud, const char *tool, json_t *args, const char *reason) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c) return;

  c->step++;
  t_close_text(c);
  t_close_tool(c);

  snprintf(c->tool_use_id, sizeof(c->tool_use_id), "tu-%s-%d",
           c->message_id, ++c->tool_seq);

  ev_block_start(c, c->index, "tool_use", c->tool_use_id, tool);
  c->tool_open = 1;

  char *dump = args ? json_dump(args) : NULL;
  ev_block_delta_json(c, c->index, dump ? dump : "{}");

  c->step_index = -1;
  if (c->turn >= 0) {
    json_t *it = j_obj();
    j_set_str(it, "type", "tool");
    j_set_str(it, "name", tool ? tool : "");
    j_set_str(it, "step_id", c->tool_use_id);
    j_set(it, "args", args ? j_clone(args) : j_obj());
    j_set_str(it, "status", "running");
    j_set_num(it, "at", (double)(now_ms() - c->t_start));

    c->step_index = c->step_seq++;
    sess_turn_add_step(c->session, c->turn, it);
  }
  c->step_t0 = now_ms();
  if (dump) free(dump);

  if (c->pending_note[0]) {
    ev_tool_status(c, c->tool_use_id, "running", c->pending_note);
    c->pending_note[0] = 0;
  } else {
    ev_tool_status(c, c->tool_use_id, "running",
                   reason && *reason ? reason : "开始执行");
  }
}

static void hook_status(void *ud, const char *tool, const char *status, const char *note) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c) return;
  buf_t b;
  buf_init(&b);
  buf_puts(&b, tool ? tool : "");
  if (status && *status) buf_printf(&b, " %s", status);
  if (note && *note) buf_printf(&b, " —— %s", note);
  if (c->tool_open) {
    ev_tool_status(c, c->tool_use_id, "running", b.data);
  } else {

    snprintf(c->pending_note, sizeof(c->pending_note), "%s", b.data);
  }
  buf_free(&b);
}

static void hook_observation(void *ud, const char *tool, tool_result_t *r) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c) return;
  const char *txt = (r && r->text) ? r->text : "";
  const char *status = (r && r->is_error) ? "error" : "done";
  ev_tool_status(c, c->tool_use_id, status, txt);
  t_close_tool(c);

  if (c->turn >= 0 && c->step_index >= 0) {
    buf_t line;
    buf_init(&line);
    for (const char *p = txt; *p && *p != '\n' && line.len < 200; p++) buf_putc_(&line, *p);
    sess_step_patch(c->session, c->turn, c->step_index, "note", j_str(line.data ? line.data : ""));
    sess_step_patch(c->session, c->turn, c->step_index, "status", j_str(status));
    if (c->step_t0) {
      sess_step_patch(c->session, c->turn, c->step_index, "duration_ms",
                      j_num((double)(now_ms() - c->step_t0)));
    }
    if (strlen(txt) > 2000) {
      char tag[64];
      snprintf(tag, sizeof(tag), "step-%d", c->step_index);
      char *rel = sess_artifact_write(c->session, tag, txt, strlen(txt));
      if (rel) {
        sess_step_patch(c->session, c->turn, c->step_index, "artifact", j_str(rel));
        free(rel);
      }
    }
    buf_free(&line);
    c->step_index = -1;
  }
}

static void hook_answer(void *ud, const char *text) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c) return;
  t_close_tool(c);
  t_put_text(c, text);
  t_close_text(c);

  if (text && *text) {
    buf_clear(&c->answer);
    buf_puts(&c->answer, text);
  }
}

static void hook_delta(void *ud, const char *text) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c || !text || !*text) return;
  if (c->tool_open) t_close_tool(c);
  if (!c->first_byte_ms && c->t_start) c->first_byte_ms = now_ms() - c->t_start;
  t_put_text(c, text);
}

static void hook_ask(void *ud, const char *text) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c) return;
  t_close_tool(c);
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "\n[需要你补充信息] ");
  buf_puts(&b, text ? text : "");
  buf_puts(&b, "\n");
  t_put_text(c, b.data);
  buf_free(&b);
  t_close_text(c);
}

typedef struct {
  HANDLE event;
  char id[40];
  int decision;
  int pending;
} approval_slot_t;

#define MAX_APPROVAL_SLOTS 8

static approval_slot_t g_appr_slots[MAX_APPROVAL_SLOTS];
static CRITICAL_SECTION g_appr_lock;
static int g_appr_ready = 0;
static volatile LONG g_appr_seq = 0;

static thread_local int g_appr_unattended = 0;

static void approval_init(void) {
  if (g_appr_ready) return;
  InitializeCriticalSection(&g_appr_lock);
  for (int i = 0; i < MAX_APPROVAL_SLOTS; i++) {
    g_appr_slots[i].event = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_appr_slots[i].id[0] = 0;
    g_appr_slots[i].pending = 0;
    g_appr_slots[i].decision = 0;
  }
  g_appr_ready = 1;
}

static int hook_approval(void *ud, const char *tool, json_t *args, char **reason) {
  (void)ud;
  approval_init();
  if (reason) *reason = NULL;

  approval_action_t act = approval_decide(tool ? tool : "", tools_is_readonly(tool));
  if (act == APPROVAL_ALLOW) return 1;

  if (act == APPROVAL_ASK && g_appr_unattended) return 1;
  if (act == APPROVAL_DENY) {
    if (reason) *reason = xstrdup("按当前审批策略,这个动作被直接拒绝");
    return 0;
  }

  sse_ctx_t *c = g_sse;
  if (!c) {

    if (reason) *reason = xstrdup("当前是「询问」策略,但这一轮没有界面在等确认");
    return 0;
  }

  int seq = (int)InterlockedIncrement(&g_appr_seq);
  char id[40];
  snprintf(id, sizeof(id), "ap-%ld-%04d", (long)GetCurrentProcessId(), seq);

  approval_slot_t *slot = NULL;
  EnterCriticalSection(&g_appr_lock);
  for (int i = 0; i < MAX_APPROVAL_SLOTS; i++) {
    if (!g_appr_slots[i].pending) { slot = &g_appr_slots[i]; break; }
  }
  if (slot) {
    snprintf(slot->id, sizeof(slot->id), "%s", id);
    slot->decision = 0;
    slot->pending = 1;
    ResetEvent(slot->event);
  }
  LeaveCriticalSection(&g_appr_lock);

  if (!slot) {
    if (reason) *reason = xstrdup("同时等待确认的动作太多了,这一步先不执行");
    return 0;
  }

  char *argtext = args ? json_dump(args) : NULL;
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"approval_request\",\"id\":");
  buf_json_str(&b, id);
  buf_puts(&b, ",\"tool\":");
  buf_json_str(&b, tool ? tool : "");
  buf_puts(&b, ",\"args\":");
  buf_json_str(&b, argtext ? argtext : "{}");
  buf_puts(&b, ",\"policy\":");
  buf_json_str(&b, approval_mode_text());
  buf_puts(&b, "}");
  sse_send(c, b.data);
  buf_free(&b);
  free(argtext);

  ev_tool_status(c, c->tool_use_id, "waiting_approval", "等你确认:允许还是拒绝?");

  DWORD wait_ms = 15 * 60 * 1000;
  long long w0 = now_ms();
  DWORD got = WaitForSingleObject(slot->event, wait_ms);

  if (c) c->wait_ms += now_ms() - w0;

  EnterCriticalSection(&g_appr_lock);
  int decision = slot->decision;
  slot->pending = 0;
  LeaveCriticalSection(&g_appr_lock);

  if (got != WAIT_OBJECT_0 || decision == 0) {
    if (reason) *reason = xstrdup("等你确认超时了,这一步没有执行");
    return 0;
  }
  if (decision == 1) return 1;
  if (reason) *reason = xstrdup("你拒绝了这一步");
  return 0;
}

typedef struct {
  HANDLE event;
  char id[40];
  char *answer;
  int pending;
} ask_slot_t;

#define MAX_ASK_SLOTS 8
static ask_slot_t g_ask_slots[MAX_ASK_SLOTS];
static CRITICAL_SECTION g_ask_lock;
static int g_ask_ready = 0;
static volatile LONG g_ask_seq = 0;

static void ask_init(void) {
  if (g_ask_ready) return;
  InitializeCriticalSection(&g_ask_lock);
  for (int i = 0; i < MAX_ASK_SLOTS; i++) {
    g_ask_slots[i].event = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_ask_slots[i].id[0] = 0;
    g_ask_slots[i].answer = NULL;
    g_ask_slots[i].pending = 0;
  }
  g_ask_ready = 1;
}

static int hook_question(void *ud, const char *payload, char **answer_out) {
  (void)ud;
  ask_init();
  if (answer_out) *answer_out = NULL;
  sse_ctx_t *c = g_sse;
  if (!c) return 0;

  int seq = (int)InterlockedIncrement(&g_ask_seq);
  char id[40];
  snprintf(id, sizeof(id), "q-%ld-%04d", (long)GetCurrentProcessId(), seq);

  ask_slot_t *slot = NULL;
  EnterCriticalSection(&g_ask_lock);
  for (int i = 0; i < MAX_ASK_SLOTS; i++) {
    if (!g_ask_slots[i].pending) { slot = &g_ask_slots[i]; break; }
  }
  if (slot) {
    snprintf(slot->id, sizeof(slot->id), "%s", id);
    free(slot->answer);
    slot->answer = NULL;
    ResetEvent(slot->event);
    slot->pending = 1;
  }
  LeaveCriticalSection(&g_ask_lock);
  if (!slot) return 0;

  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"question_request\",\"id\":");
  buf_json_str(&b, id);
  buf_puts(&b, ",\"payload\":");
  buf_puts(&b, (payload && *payload) ? payload : "{}");
  buf_puts(&b, "}");
  sse_send(c, b.data);
  buf_free(&b);

  ev_tool_status(c, c->tool_use_id, "waiting_answer", "等你回答");

  DWORD got = WaitForSingleObject(slot->event, 15 * 60 * 1000);
  EnterCriticalSection(&g_ask_lock);
  char *answer = slot->answer;
  slot->answer = NULL;
  slot->pending = 0;
  LeaveCriticalSection(&g_ask_lock);

  if (got != WAIT_OBJECT_0 || !answer) return 0;
  if (answer_out) *answer_out = answer;
  else free(answer);
  return 1;
}

static const agent_hooks_t g_hooks = {
    NULL, hook_thinking, hook_action, hook_status,
    hook_observation, hook_answer, hook_ask, hook_approval, hook_question, hook_delta};

#define MAX_AGENT_SLOTS 8
typedef struct {
  char id[64];
  agent_t *a;
  CRITICAL_SECTION lock;
} agent_slot_t;

static agent_slot_t g_agents[MAX_AGENT_SLOTS];
static int g_agent_count = 0;
static CRITICAL_SECTION g_agent_lock;
static agent_t *g_sched_agent = NULL;

static void agents_init(void) {
  InitializeCriticalSection(&g_agent_lock);
}

static agent_slot_t *agent_slot_of(const char *sid) {
  char key[64];
  snprintf(key, sizeof(key), "%s", (sid && *sid) ? sid : g_session);
  agent_slot_t *found = NULL;
  EnterCriticalSection(&g_agent_lock);
  for (int i = 0; i < g_agent_count; i++) {
    if (strcmp(g_agents[i].id, key) == 0) { found = &g_agents[i]; break; }
  }
  if (!found && g_agent_count < MAX_AGENT_SLOTS) {
    found = &g_agents[g_agent_count++];
    snprintf(found->id, sizeof(found->id), "%s", key);
    InitializeCriticalSection(&found->lock);
    found->a = agent_create(found->id);
    agent_set_store(found->a, g_store, "");
    agent_set_hooks(found->a, &g_hooks);
  }
  LeaveCriticalSection(&g_agent_lock);
  return found;
}

static agent_slot_t *agent_slot_find(const char *sid) {
  char key[64];
  snprintf(key, sizeof(key), "%s", (sid && *sid) ? sid : g_session);
  agent_slot_t *found = NULL;
  EnterCriticalSection(&g_agent_lock);
  for (int i = 0; i < g_agent_count; i++) {
    if (strcmp(g_agents[i].id, key) == 0) { found = &g_agents[i]; break; }
  }
  LeaveCriticalSection(&g_agent_lock);
  return found;
}

static void pool_apply(void) {
  json_t *root = json_parse(g_pool_json);
  if (!root) return;
  json_t *hosts = j_get(root, "hosts");
  const char *list[512];
  int n = 0;
  for (int i = 0; i < j_len(hosts) && n < 512; i++) {
    json_t *v = j_at(hosts, i);
    if (!v) continue;
    if (v->type == J_STR && v->str) list[n++] = v->str;
    else if (v->type == J_OBJ) list[n++] = j_s(v, "host", "");
  }
  net_pool_set(list, n);
  json_free(root);
}

static void pool_save(void) {
  if (!g_pool_file[0]) return;
  json_t *root = json_parse(g_pool_json);
  char *text = root ? json_dump_pretty(root) : NULL;
  if (text) file_write_all(g_pool_file, text, strlen(text));
  free(text);
  if (root) json_free(root);
}

static void pool_load(void) {
  app_data_path(g_pool_file, sizeof(g_pool_file), "pool.json");
  size_t len = 0;
  char *text = file_read_all(g_pool_file, &len);
  if (text && len > 0 && len < sizeof(g_pool_json)) {

    const char *body = text;
    if (len >= 3 && (unsigned char)body[0] == 0xEF && (unsigned char)body[1] == 0xBB &&
        (unsigned char)body[2] == 0xBF) {
      body += 3;
    }
    snprintf(g_pool_json, sizeof(g_pool_json), "%s", body);
    char *norm = json_dump(json_parse(g_pool_json));
    if (norm) {
      snprintf(g_pool_json, sizeof(g_pool_json), "%s", norm);
      free(norm);
    }
  }
  free(text);
  if (!json_parse(g_pool_json)) snprintf(g_pool_json, sizeof(g_pool_json), "{\"hosts\":[]}");
  pool_apply();
}

static int pool_contains(const char *entry) {
  if (!entry || !entry[0]) return 0;
  char host[256];
  int port = net_host_port_of(entry, host, sizeof(host));
  if (!host[0]) snprintf(host, sizeof(host), "%s", entry);

  return net_pool_has(host, port, "/");
}

static int pool_add(const char *entry) {
  if (!entry || !entry[0]) return -1;
  if (strstr(entry, "://") || strchr(entry, ' ') || strchr(entry, '\t')) return -1;
  if (strstr(entry, "..")) return -1;
  const char *body = entry[0] == '!' ? entry + 1 : entry;
  if (!body[0]) return -1;
  char hostport[300];
  snprintf(hostport, sizeof(hostport), "%s", body);
  char *slash = strchr(hostport, '/');
  if (slash) {
    *slash = 0;
    if (slash[1] == 0) return -1;
  }
  if (!hostport[0]) return -1;

  for (const char *p = hostport; *p; p++) {
    char c = *p;
    if (!(isalnum((unsigned char)c) || c == '.' || c == '-' || c == ':' || c == '[' || c == ']')) return -1;
  }
  json_t *root = json_parse(g_pool_json);
  if (!root) root = j_obj();
  json_t *hosts = j_get(root, "hosts");
  if (!hosts || hosts->type != J_ARR) { hosts = j_arr(); j_set(root, "hosts", hosts); }
  for (int i = 0; i < j_len(hosts); i++) {
    const char *cur = j_at(hosts, i)->type == J_STR ? j_at(hosts, i)->str : j_s(j_at(hosts, i), "host", "");
    if (str_ieq(cur, entry)) { json_free(root); return 0; }
  }
  j_add(hosts, j_str(entry));
  char *text = json_dump(root);
  snprintf(g_pool_json, sizeof(g_pool_json), "%s", text ? text : "{\"hosts\":[]}");
  free(text);
  json_free(root);
  pool_save();
  pool_apply();
  return 1;
}

static int pool_remove(const char *entry) {
  json_t *root = json_parse(g_pool_json);
  if (!root) return -1;
  json_t *hosts = j_get(root, "hosts");
  json_t *keep = j_arr();
  int removed = 0;
  for (int i = 0; i < j_len(hosts); i++) {
    json_t *v = j_at(hosts, i);
    const char *cur = v->type == J_STR ? v->str : j_s(v, "host", "");
    if (str_ieq(cur, entry)) { removed = 1; continue; }
    j_add(keep, j_clone(v));
  }
  j_set(root, "hosts", keep);
  char *text = json_dump(root);
  snprintf(g_pool_json, sizeof(g_pool_json), "%s", text ? text : "{\"hosts\":[]}");
  free(text);
  json_free(root);
  if (!removed) return 0;
  pool_save();
  pool_apply();
  return 1;
}

static void apply_scope(const char *domain) {
  if (domain && *domain) {
    snprintf(g_domain, sizeof(g_domain), "%s", domain);
    snprintf(g_domain_disp, sizeof(g_domain_disp), "%s", domain);

    char host_only[256];
    net_host_port_of(domain, host_only, sizeof(host_only));
    if (!host_only[0]) snprintf(host_only, sizeof(host_only), "%s", domain);
    net_align_base_from(domain);
    const char *doms[1];
    doms[0] = host_only;

    const char *scope_entry[1];
    scope_entry[0] = domain;

    if (g_store) {
      int nk = 0, nf = 0;
      const char **kw = rules_str_list("profile_keywords", &nk);
      const char **ft = rules_str_list("profile_file_types", &nf);
      json_t *kws = j_arr();
      for (int i = 0; i < nk; i++) j_add(kws, j_str(kw[i]));
      json_t *fts = j_arr();
      for (int i = 0; i < nf; i++) j_add(fts, j_str(ft[i]));
      char *pid = store_ensure_profile(g_store, "默认敏感信息定义(随规则层)",
                                      kws, fts, NULL);
      char tname[320];
      snprintf(tname, sizeof(tname), "对 %s 的授权巡检", g_domain);
      char *tid = store_ensure_task(g_store, doms, 1, tname, pid);
      if (tid) {
        snprintf(g_task, sizeof(g_task), "%s", tid);
        snprintf(g_task_disp, sizeof(g_task_disp), "%s", tid);
      }
      free(pid);
      free(tid);
      json_free(kws);
      json_free(fts);
    }

    net_set_scope(g_task, scope_entry, 1);
  } else {
    g_domain[0] = 0;
    g_domain_disp[0] = 0;
    net_set_scope(g_task, NULL, 0);
  }
}

static char *build_status_json(void) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"ok\":true,\"sessionId\":");
  buf_json_str(&b, g_session);
  buf_puts(&b, ",\"taskId\":");
  buf_json_str(&b, g_task_disp);
  buf_puts(&b, ",\"domain\":");
  buf_json_str(&b, g_domain_disp);
  buf_printf(&b, ",\"authorized\":%s", (g_domain_disp[0] || net_pool_count() > 0) ? "true" : "false");
  buf_puts(&b, ",\"pool\":");
  buf_puts(&b, g_pool_json);
  buf_printf(&b, ",\"poolSize\":%d", net_pool_count());

  buf_puts(&b, ",\"approval\":{\"active\":");
  buf_json_str(&b, approval_active_id());
  buf_puts(&b, ",\"name\":");
  buf_json_str(&b, approval_mode_text());
  buf_printf(&b, ",\"allowAll\":%s}", approval_is_allow_all() ? "true" : "false");
  buf_printf(&b, ",\"model\":%s", llm_enabled() ? "true" : "false");
  buf_puts(&b, ",\"modelName\":");
  buf_json_str(&b, providers_display_name());

  buf_puts(&b, ",\"modelError\":");
  buf_json_str(&b, llm_last_error());

  buf_printf(&b, ",\"modelFailed\":%s", llm_last_error()[0] ? "true" : "false");
  buf_printf(&b, ",\"tools\":%d,\"skills\":%d", tools_count(), skills_count());
  buf_printf(&b, ",\"maxSteps\":%d", MAX_STEPS_DEFAULT);

  {
    agent_slot_t *cur = agent_slot_find(g_session);
    int used = cur ? agent_ctx_used(cur->a) : 0;
    int window = providers_context_tokens();
    int reserve = window / 8;
    int compressed = cur ? agent_ctx_compressed(cur->a) : 0;
    buf_printf(&b,
               ",\"context\":{\"used\":%d,\"window\":%d,\"reserve\":%d,\"compressed\":%d}",
               used, window, reserve, compressed);
  }

  json_t *findings = store_all(g_store, "findings");
  int n = findings ? j_len(findings) : 0;
  buf_printf(&b, ",\"findingCount\":%d", n);
  buf_puts(&b, ",\"findings\":");
  if (findings) {
    char *dump = json_dump(findings);
    buf_puts(&b, dump ? dump : "[]");
    if (dump) free(dump);
    json_free(findings);
  } else {
    buf_puts(&b, "[]");
  }
  buf_puts(&b, "}");
  char *out = buf_take(&b);
  buf_free(&b);
  return out;
}

store_t *serve_store(void) { return g_store; }
const char *serve_task_id(void) { return g_task; }

void serve_audit_line(const char *action, const char *target, const char *detail) {
  if (!g_store) return;
  store_audit(g_store, action, target, 1, detail, g_task, "");
}

static void refresh_status_cache(void);

void serve_refresh_status(void) { refresh_status_cache(); }

static void refresh_status_cache(void) {
  char *j = build_status_json();
  EnterCriticalSection(&g_status_lock);
  free(g_status_cache);
  g_status_cache = j;
  LeaveCriticalSection(&g_status_lock);
}

static char *status_snapshot(void) {
  EnterCriticalSection(&g_status_lock);
  char *j = xstrdup(g_status_cache ? g_status_cache : "{\"ok\":true}");
  LeaveCriticalSection(&g_status_lock);
  return j;
}

static void make_token(char *out, size_t cap) {
  unsigned char raw[16];
  if (BCryptGenRandom(NULL, raw, (ULONG)sizeof(raw),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {

    DWORD t = GetTickCount();
    for (size_t i = 0; i < sizeof(raw); i++) raw[i] = (unsigned char)((t >> ((i % 4) * 8)) ^ (i * 31));
  }
  size_t o = 0;
  for (size_t i = 0; i < sizeof(raw) && o + 2 < cap; i++) {
    o += (size_t)snprintf(out + o, cap - o, "%02x", raw[i]);
  }
  out[o < cap ? o : cap - 1] = 0;
}

static int host_ok(const http_req_t *req) {
  if (!req->host[0]) return 1;
  const char *h = req->host;
  int loopback = (strncmp(h, "127.0.0.1", 9) == 0) ||
                 (strncmp(h, "localhost", 9) == 0) ||
                 (strncmp(h, "[::1]", 5) == 0);
  if (!loopback) return 0;
  const char *colon = strrchr(h, ':');
  if (colon && g_port > 0) {
    int p = atoi(colon + 1);
    if (p != g_port) return 0;
  }
  return 1;
}

static int origin_ok(const http_req_t *req) {
  if (!req->origin[0]) return 1;
  char expect1[64], expect2[64];
  snprintf(expect1, sizeof(expect1), "http://127.0.0.1:%d", g_port);
  snprintf(expect2, sizeof(expect2), "http://localhost:%d", g_port);
  return str_ieq(req->origin, expect1) || str_ieq(req->origin, expect2);
}

static int token_ok(const http_req_t *req) {
  if (!g_token[0]) return 1;
  if (req->token[0] && strcmp(req->token, g_token) == 0) return 1;

  char t[sizeof(g_token)];
  http_query(req, "t", t, sizeof(t), "");
  return t[0] && strcmp(t, g_token) == 0;
}

static int api_guard(const http_req_t *req, http_res_t *res) {
  if (!host_ok(req)) {
    log_warn("[接口] 拒绝请求:Host=%s 不是本机", req->host);
    http_res_text(res, 403, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"只接受来自本机地址的请求\"}");
    return 0;
  }
  if (!origin_ok(req)) {
    log_warn("[接口] 拒绝请求:Origin=%s 不是本站", req->origin);
    http_res_text(res, 403, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"跨站来源被拒绝\"}");
    return 0;
  }
  if (strcmp(req->path, "/api/health") != 0 && !token_ok(req)) {
    http_res_text(res, 401, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"缺少或错误的接口令牌(请从本程序打开的界面操作)\"}");
    return 0;
  }
  if (strcmp(req->method, "POST") == 0 && req->body_len > 0 &&
      !str_icontains(req->content_type, "application/json")) {
    http_res_text(res, 415, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"只接受 application/json\"}");
    return 0;
  }
  return 1;
}

static void apply_profile(const char *profile_id) {
  if (!profile_id || !profile_id[0]) { profile_clear_active(); return; }
  json_t *p = store_get(g_store, "profiles", profile_id);
  if (!p) { profile_clear_active(); return; }
  profile_set_active(p);
  json_free(p);
}

static void h_approvals(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "POST") == 0) {
    json_t *body = req->body ? json_parse(req->body) : NULL;
    if (!body) { http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}"); return; }
    const char *action = j_s(body, "action", "activate");
    char err[256] = {0};

    if (str_ieq(action, "activate")) {
      const char *id = j_s(body, "id", "");
      int ok = approval_activate(id);
      if (!ok) { json_free(body); http_res_json(res, 404, "{\"ok\":false,\"error\":\"没有这条审批策略\"}"); return; }

      EnterCriticalSection(&g_lock);
      refresh_status_cache();
      LeaveCriticalSection(&g_lock);
      json_free(body);
      store_audit(g_store, "切换审批策略", id, 1, approval_mode_text(), g_task, "");
      json_t *root = j_obj();
      j_set_bool(root, "ok", 1);
      j_set_str(root, "active", approval_active_id());
      j_set_bool(root, "allowAll", approval_is_allow_all());
      j_set(root, "items", approval_list_json());
      char *text = json_dump(root);
      http_res_json(res, 200, text);
      free(text);
      json_free(root);
      return;
    }

    if (str_ieq(action, "save")) {
      json_t *p = j_get(body, "policy");
      char *id = approval_save_policy(p, err, sizeof(err));
      if (!id) {
        json_free(body);
        buf_t b;
        buf_init(&b);
        buf_puts(&b, "{\"ok\":false,\"error\":");
        buf_json_str(&b, err);
        buf_puts(&b, "}");
        http_res_json(res, 400, b.data);
        buf_free(&b);
        return;
      }
      store_audit(g_store, "保存审批策略", j_s(p, "name", ""), 1, id, g_task, "");
      EnterCriticalSection(&g_lock);
      refresh_status_cache();
      LeaveCriticalSection(&g_lock);
      json_t *root = j_obj();
      j_set_bool(root, "ok", 1);
      j_set_str(root, "id", id);
      j_set(root, "items", approval_list_json());
      char *text = json_dump(root);
      free(id);
      json_free(body);
      http_res_json(res, 200, text);
      free(text);
      json_free(root);
      return;
    }

    if (str_ieq(action, "delete")) {
      int ok = approval_delete_policy(j_s(body, "id", ""));
      json_free(body);
      EnterCriticalSection(&g_lock);
      refresh_status_cache();
      LeaveCriticalSection(&g_lock);
      json_t *root = j_obj();
      j_set_bool(root, "ok", ok ? 1 : 0);
      j_set(root, "items", approval_list_json());
      char *text = json_dump(root);
      http_res_json(res, ok ? 200 : 404, text);
      free(text);
      json_free(root);
      return;
    }

    json_free(body);
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"未知的 action\"}");
    return;
  }

  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set_str(root, "active", approval_active_id());
  j_set_str(root, "modeText", approval_mode_text());
  j_set_bool(root, "allowAll", approval_is_allow_all());
  j_set(root, "items", approval_list_json());
  char *text = json_dump(root);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
}

static void h_approval_decision(const http_req_t *req, http_res_t *res) {
  json_t *body = req->body ? json_parse(req->body) : NULL;
  const char *id = body ? j_s(body, "id", "") : "";
  const char *decision = body ? j_s(body, "decision", "") : "";
  if (!id[0] || !decision[0]) {
    if (body) json_free(body);
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"需要 id 与 decision\"}");
    return;
  }
  approval_init();
  int match = 0;
  EnterCriticalSection(&g_appr_lock);
  for (int i = 0; i < MAX_APPROVAL_SLOTS; i++) {
    if (g_appr_slots[i].pending && strcmp(g_appr_slots[i].id, id) == 0) {
      g_appr_slots[i].decision = str_ieq(decision, "allow") ? 1 : 2;
      SetEvent(g_appr_slots[i].event);
      match = 1;
      break;
    }
  }
  LeaveCriticalSection(&g_appr_lock);
  if (body) json_free(body);
  if (!match) {
    http_res_json(res, 409,
                  "{\"ok\":false,\"error\":\"这条审批请求已经不在了(可能超时或已处理)\"}");
    return;
  }
  http_res_json(res, 200, "{\"ok\":true}");
}

static void h_answer(const http_req_t *req, http_res_t *res) {
  json_t *body = req->body ? json_parse(req->body) : NULL;
  const char *id = body ? j_s(body, "id", "") : "";
  json_t *answers = body ? j_get(body, "answers") : NULL;
  if (!id[0] || !answers) {
    if (body) json_free(body);
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"需要 id 与 answers\"}");
    return;
  }
  char *text = json_dump(answers);
  ask_init();
  int match = 0;
  EnterCriticalSection(&g_ask_lock);
  for (int i = 0; i < MAX_ASK_SLOTS; i++) {
    if (g_ask_slots[i].pending && strcmp(g_ask_slots[i].id, id) == 0) {
      free(g_ask_slots[i].answer);
      g_ask_slots[i].answer = text;
      text = NULL;
      SetEvent(g_ask_slots[i].event);
      match = 1;
      break;
    }
  }
  LeaveCriticalSection(&g_ask_lock);
  if (text) free(text);
  if (body) json_free(body);
  if (!match) {
    http_res_json(res, 409, "{\"ok\":false,\"error\":\"这条提问已经不在了(可能超时或已回答)\"}");
    return;
  }
  http_res_json(res, 200, "{\"ok\":true}");
}

static void h_export(const http_req_t *req, http_res_t *res) {
  char fmt[16], rid[24];
  http_query(req, "format", fmt, sizeof(fmt), "md");
  http_query(req, "report", rid, sizeof(rid), "");

  buf_t out;
  buf_init(&out);
  char err[512];
  if (export_report(g_store, rid, fmt, &out, err, sizeof(err)) != 0) {
    buf_free(&out);
    buf_t b;
    buf_init(&b);
    buf_puts(&b, "{\"ok\":false,\"error\":");
    buf_json_str(&b, err[0] ? err : "导出失败");
    buf_puts(&b, "}");
    http_res_json(res, 400, b.data);
    buf_free(&b);
    return;
  }

  const char *ctype = "application/octet-stream";
  if (str_ieq(fmt, "md") || str_ieq(fmt, "markdown")) ctype = "text/markdown; charset=utf-8";
  else if (str_ieq(fmt, "html")) ctype = "text/html; charset=utf-8";
  else if (str_ieq(fmt, "csv")) ctype = "text/csv; charset=utf-8";
  else if (str_ieq(fmt, "json")) ctype = "application/json; charset=utf-8";
  else if (str_ieq(fmt, "docx")) ctype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
  else if (str_ieq(fmt, "pdf")) ctype = "application/pdf";

  char fname[128];
  export_filename(rid[0] ? rid : "latest", fmt, fname, sizeof(fname));
  http_res_file(res, 200, ctype, fname, out.data, out.len);
  buf_free(&out);
}

static volatile LONG g_sched_stop = 0;
static HANDLE g_sched_thread = NULL;

static DWORD WINAPI sched_thread(LPVOID param) {
  (void)param;
  {
    auto_rule_t *list = NULL;
    int n = 0;
    auto_list(g_store, &list, &n);
    int fixed = auto_resync(g_store, list, n);
    auto_free_list(list);
    if (fixed) log_info("周期巡检:启动时有 %d 条规则的到期时间已顺延(停机期间不补跑)", fixed);
  }

  while (!g_sched_stop) {
    Sleep(1000);
    if (g_sched_stop) break;
    if (!g_sched_agent) break;

    if (!TryEnterCriticalSection(&g_lock)) continue;

    auto_rule_t rule;
    long long now = (long long)time(NULL);
    if (!auto_take_due(g_store, &rule, now)) {
      LeaveCriticalSection(&g_lock);
      continue;
    }

    if (!pool_contains(rule.domain)) {
      log_warn("周期巡检: %s 的目标 %s 不在授权池内,本轮跳过(不擅自扩权)", rule.id, rule.domain);
      store_audit(g_store, "周期巡检跳过", rule.domain, 0, "目标不在授权池内", g_task, "");
      LeaveCriticalSection(&g_lock);
      continue;
    }
    char prev_domain[256];
    snprintf(prev_domain, sizeof(prev_domain), "%s", g_domain);
    char prev_task[64];
    snprintf(prev_task, sizeof(prev_task), "%s", g_task);
    char prev_profile[24];
    snprintf(prev_profile, sizeof(prev_profile), "%s", profile_active_id());

    apply_profile(rule.profile_id);
    apply_scope(rule.domain);
    char instr[1400];
    {
      char scope_txt[1024];
      auto_checks_instruction(rule.checks, rule.scope, scope_txt, sizeof(scope_txt));
      snprintf(instr, sizeof(instr), "【周期巡检 %s】对 %s 现在开始,不要问我确认。%s",
               rule.id, rule.domain, scope_txt);
    }
    char sig[128];
    auto_checks_signature(rule.checks, rule.scope, sig, sizeof(sig));
    log_info("周期巡检: %s → %s(范围 %s%s%s)", rule.id, rule.domain, sig,
             rule.profile_id[0] ? ",定义 " : "", rule.profile_id);

    LeaveCriticalSection(&g_lock);

    int is_full = str_ieq(sig, "full");
    int calls_before = net_http_calls();
    char *wrap_run = NULL;
    if (!is_full) {
      wrap_run = store_run_start(g_store, g_task, "周期巡检", sig);
      agent_set_store(g_sched_agent, g_store, wrap_run ? wrap_run : "");
    }

    store_set_trigger("周期巡检");
    g_appr_unattended = 1;
    agent_set_unattended(g_sched_agent, 1);
    net_scope_violation_clear();
    loop_state_t st;
    memset(&st, 0, sizeof(st));
    int rc = agent_run_turn(g_sched_agent, instr, &st);
    int violated = net_scope_violation();
    net_scope_violation_clear();
    g_appr_unattended = 0;
    agent_set_unattended(g_sched_agent, 0);
    store_set_trigger("手动");

    char *run_id = is_full ? auto_latest_run_of_domain(g_store, rule.domain)
                           : (wrap_run ? xstrdup(wrap_run) : NULL);
    if (!is_full && wrap_run) {
      json_t *fs = store_findings_of_run(g_store, wrap_run);
      int nf = j_len(fs);
      json_free(fs);
      store_run_finish(g_store, wrap_run, rc == 0 ? "done" : "failed",
                       0, net_http_calls() - calls_before, nf, rc == 0 ? "" : "巡检未正常收束");
      agent_set_store(g_sched_agent, g_store, "");
    }

    int changed = 0;

    if (rc == 0 && run_id && !violated) changed = auto_after_run(g_store, &rule, run_id);

    {
      char dir[MAX_PATH * 2];
      app_data_path(dir, sizeof(dir), "time");
      char sub[MAX_PATH * 2];
      snprintf(sub, sizeof(sub), "%s\\%s", dir, rule.id);
      ensure_dir(sub);
      char stamp[32];
      {
        char iso[40];
        now_iso(iso, sizeof(iso));
        size_t k = 0;
        for (const char *s = iso; *s && k + 1 < sizeof(stamp); s++) {
          char c = *s;
          if (c == ':' || c == '.' || c == 'T' || c == 'Z') continue;
          if (c == '-') c = '-';
          stamp[k++] = c;
        }
        stamp[k] = 0;
      }
      char file[MAX_PATH * 4];
      snprintf(file, sizeof(file), "%s\\%s.jsonl", sub, stamp);

      json_t *rec = j_obj();
      j_set_str(rec, "rule", rule.id);
      j_set_str(rec, "name", rule.name);
      j_set_str(rec, "domain", rule.domain);
      j_set_str(rec, "scope", rule.scope);
      j_set_str(rec, "checks", sig);
      j_set_str(rec, "profile", rule.profile_id);
      j_set_str(rec, "run_id", run_id ? run_id : "");
      j_set_str(rec, "status", rc == 0 ? "done" : "failed");
      j_set_str(rec, "stop_reason", st.stop_reason);
      j_set_num(rec, "steps", st.steps ? j_len(st.steps) : 0);
      j_set_num(rec, "http_calls", net_http_calls() - calls_before);
      j_set_bool(rec, "changed", changed > 0);
      j_set_bool(rec, "violated", violated);
      char ts[40];
      now_iso(ts, sizeof(ts));
      j_set_str(rec, "at", ts);
      char *line = json_dump(rec);
      if (line) {
        buf_t b;
        buf_init(&b);
        buf_puts(&b, line);
        buf_putc_(&b, '\n');
        file_append(file, b.data, b.len);
        buf_free(&b);
        free(line);
      }
      json_free(rec);
    }

    log_info("周期巡检: %s %s,停止原因 %s%s", rule.id,
             rc == 0 ? "完成" : "失败", st.stop_reason[0] ? st.stop_reason : "—",
             violated ? " · 有请求越出授权池,本轮中止且不做差分"
                      : (!run_id ? " · 没拿到运行记录,这轮不做差分"
                                 : (changed == 2 ? " · 同类范围的首轮,已建立基线(不告警)"
                                                : (changed ? " · 与上一轮相比有变化,已写告警"
                                                           : " · 与上一轮相比没有变化"))));
    free(run_id);
    free(wrap_run);
    if (st.steps) json_free(st.steps);
    buf_free(&st.transcript);

    apply_scope(prev_domain[0] ? prev_domain : NULL);
    apply_profile(prev_profile);
    if (prev_task[0]) snprintf(g_task, sizeof(g_task), "%s", prev_task);
    refresh_status_cache();
  }
  return 0;
}

static void sched_start(void) {
  g_sched_stop = 0;
  g_sched_thread = CreateThread(NULL, 0, sched_thread, NULL, 0, NULL);
}

static void sched_stop(void) {
  InterlockedExchange(&g_sched_stop, 1);
  if (g_sched_thread) {
    WaitForSingleObject(g_sched_thread, 5000);
    CloseHandle(g_sched_thread);
    g_sched_thread = NULL;
  }
}

typedef struct {
  const char *name;
  const char *ctype;
} ui_asset_t;

static const ui_asset_t g_assets[] = {
    {"index.html", "text/html; charset=utf-8"},
    {"app.css", "text/css; charset=utf-8"},
    {"app.js", "application/javascript; charset=utf-8"},
    {"logo.ico", "image/x-icon"},
    {"logo.png", "image/png"},
    {"favicon.ico", "image/x-icon"},
    {NULL, NULL}};

static const char *asset_type(const char *name) {
  for (int i = 0; g_assets[i].name; i++) {
    if (strcmp(g_assets[i].name, name) == 0) return g_assets[i].ctype;
  }
  return NULL;
}

static void serve_asset(const char *name, http_res_t *res) {
  const char *ctype = asset_type(name);
  if (!ctype) {
    http_res_404(res);
    return;
  }

  char rel[256];
  snprintf(rel, sizeof(rel), "ui/%s", name);
  char *data = NULL;
  size_t len = 0;
  if (!res_load_text(rel, &data, &len)) {
    log_warn("界面资源取不到: %s(磁盘与内置都没有)", rel);
    http_res_text(res, 500, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"界面资源缺失\"}");
    return;
  }
  if (strcmp(ctype, "image/x-icon") == 0 || strcmp(ctype, "image/png") == 0) {
    http_res_bytes(res, 200, ctype, data, len);
    free(data);
    return;
  }
  if (strcmp(name, "index.html") == 0) {

    buf_t b;
    buf_init(&b);
    const char *tag = "<meta name=\"bw-token\"";
    const char *at = strstr(data, tag);
    if (at) {

      size_t head = (size_t)(at - data);
      buf_putn(&b, data, head);
      buf_puts(&b, "<meta name=\"bw-token\" content=\"");
      buf_puts(&b, g_token);
      buf_puts(&b, "\">");
      const char *gt = strchr(at, '>');
      buf_puts(&b, gt ? gt + 1 : "");
    } else {
      const char *head_end = strstr(data, "</head>");
      size_t head = head_end ? (size_t)(head_end - data) : len;
      buf_putn(&b, data, head);
      buf_printf(&b, "<meta name=\"bw-token\" content=\"%s\">", g_token);
      buf_puts(&b, data + head);
    }
    http_res_text(res, 200, ctype, b.data);
    buf_free(&b);
    free(data);
    return;
  }
  http_res_text(res, 200, ctype, data);
  free(data);
}

static void h_health(const http_req_t *req, http_res_t *res) {
  (void)req;
  buf_t b;
  buf_init(&b);

  buf_printf(&b,
             "{\"ok\":true,\"app\":\"bwagent-zero\",\"service\":\"BlueWhiteAgent(C 版)\",\"pid\":%lu}",
             (unsigned long)GetCurrentProcessId());
  http_res_json(res, 200, b.data);
  buf_free(&b);
}

static void h_manifest(const http_req_t *req, http_res_t *res) {
  (void)req;
  buf_t b;  buf_init(&b);
  buf_puts(&b, "{\"tools\":");
  char *t = json_dump(agent_tool_list_json());
  buf_puts(&b, t);
  free(t);
  buf_puts(&b, ",\"skills\":");
  char *s = json_dump(agent_skill_list_json());
  buf_puts(&b, s);
  free(s);
  buf_puts(&b, "}");
  http_res_json(res, 200, b.data);
  buf_free(&b);
}

static void h_status(const http_req_t *req, http_res_t *res) {
  (void)req;
  char *j = status_snapshot();
  http_res_json(res, 200, j);
  free(j);
}

static void h_collection(const http_req_t *req, http_res_t *res) {
  char name[32];
  http_query(req, "name", name, sizeof(name), "findings");
  static const char *ALLOWED[] = {"findings", "assets", "alerts", "runs", "reports",
                                  "tasks", "profiles", "testcases",
                                  "baselines", "diffs", "automations", NULL};
  int ok = 0;
  for (int i = 0; ALLOWED[i]; i++) if (strcmp(ALLOWED[i], name) == 0) ok = 1;
  if (!ok) {
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"不在白名单里的集合名\"}");
    return;
  }
  char limit_s[16];
  http_query(req, "limit", limit_s, sizeof(limit_s), "50");
  int limit = atoi(limit_s);
  if (limit <= 0 || limit > 500) limit = 50;

  json_t *all = store_all(g_store, name);
  json_t *out = j_arr();
  int n = j_len(all);
  int from = n > limit ? n - limit : 0;
  for (int i = from; i < n; i++) j_add(out, j_clone(j_at(all, i)));
  json_t *root = j_obj();
  j_set_str(root, "ok", "true");
  j_set_str(root, "collection", name);
  j_set_num(root, "total", n);
  j_set(root, "items", out);
  char *text = json_dump(root);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
  json_free(all);
}

static void h_rules(const http_req_t *req, http_res_t *res) {
  (void)req;
  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set_str(root, "source", rules_source());
  j_set_bool(root, "from_file", rules_from_file());
  json_t *sigs = j_arr();
  int n = 0;
  json_t *arr = rules_root() ? j_get(rules_root(), "signatures") : NULL;
  for (int i = 0; i < j_len(arr); i++) {
    json_t *s = j_at(arr, i);
    json_t *o = j_obj();
    j_set_str(o, "name", j_s(s, "name", ""));
    j_set_str(o, "kind", j_s(s, "kind", ""));
    j_set_str(o, "severity", j_s(s, "severity", ""));
    j_set_str(o, "tag", j_s(s, "tag", ""));
    j_add(sigs, o);
    n++;
  }
  j_set_num(root, "signature_count", n);
  j_set(root, "signatures", sigs);
  const char **list = NULL;
  int np = 0;
  list = rules_str_list("sensitive_paths", &np);
  json_t *paths = j_arr();
  for (int i = 0; i < np; i++) j_add(paths, j_str(list[i]));
  j_set(root, "sensitive_paths", paths);
  int nd = 0;
  const char **dirs = rules_str_list("dir_candidates", &nd);
  json_t *darr = j_arr();
  for (int i = 0; i < nd; i++) j_add(darr, j_str(dirs[i]));
  j_set(root, "dir_candidates", darr);
  char *text = json_dump(root);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
}

static void h_scope(const http_req_t *req, http_res_t *res) {
  json_t *body = req->body ? json_parse(req->body) : NULL;
  const char *domain = body ? j_s(body, "domain", "") : "";
  int authorized = body ? (int)j_n(body, "authorized", 0) : 0;
  if (!domain[0] || !authorized) {
    if (body) json_free(body);
    http_res_json(res, 400,
                  "{\"ok\":false,\"error\":\"需提供 domain 且 authorized 必须为真\"}");
    return;
  }
  EnterCriticalSection(&g_lock);

  pool_add(domain);
  apply_scope(domain);
  refresh_status_cache();
  char *j = status_snapshot();
  LeaveCriticalSection(&g_lock);
  store_audit(g_store, "授权池加入目标", domain, 1, "界面确认已获授权", g_task, "");
  if (body) json_free(body);
  http_res_json(res, 200, j);
  free(j);
}

static int pool_add_text(const char *text, int *added, int *skipped, buf_t *bad, int max_add) {
  if (!text || !text[0]) return 0;
  *added = 0;
  *skipped = 0;
  char *copy = xstrdup(text);

  for (char *p = copy; *p; p++) {
    if (*p == ',' || *p == ';' || *p == '\r' || *p == '\t') *p = '\n';
  }
  char **lines = NULL;
  int n = str_split(copy, '\n', &lines, 400);
  for (int i = 0; i < n; i++) {
    char *e = str_trim(lines[i]);
    if (!e[0] || e[0] == '#') continue;
    if (*added >= max_add) break;
    int rc = pool_add(e);
    if (rc > 0) (*added)++;
    else if (rc == 0) (*skipped)++;
    else {
      if (bad && bad->len < 400) {
        if (bad->len) buf_puts(bad, "、");
        buf_printf(bad, "%s(格式不对)", e);
      }
      (*skipped)++;
    }
  }
  str_free_list(lines, n);
  free(copy);
  return *added;
}

static void h_pool(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "POST") == 0) {
    json_t *body = req->body ? json_parse(req->body) : NULL;
    if (!body) { http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}"); return; }
    const char *action = j_s(body, "action", "add");
    const char *entry = j_s(body, "entry", "");
    if (!entry[0]) entry = j_s(body, "domain", "");
    int changed = 0, added = 0, skipped = 0;
    buf_t bad;
    buf_init(&bad);

    if (str_ieq(action, "remove")) {
      changed = pool_remove(entry);
    } else if (str_ieq(action, "batch")) {

      json_t *arr = j_get(body, "entries");
      if (arr && arr->type == J_ARR) {
        buf_t joined;
        buf_init(&joined);
        for (int i = 0; i < j_len(arr); i++) {
          json_t *v = j_at(arr, i);
          if (!v || v->type != J_STR || !v->str) continue;
          if (joined.len) buf_putc_(&joined, '\n');
          buf_puts(&joined, v->str);
        }
        changed = pool_add_text(joined.data, &added, &skipped, &bad, 400);
        buf_free(&joined);
      } else {
        const char *text = j_s(body, "text", "");
        if (!text[0]) text = entry;
        changed = pool_add_text(text, &added, &skipped, &bad, 400);
      }
      if (added) store_audit(g_store, "授权池批量加入", "批量", 1, "", g_task, "");
    } else {
      changed = pool_add(entry);
      if (changed < 0) {
        json_free(body);
        buf_free(&bad);
        http_res_json(res, 400,
                      "{\"ok\":false,\"error\":\"只填主机名(可带端口，前面加 ! 表示不允许；不允许写成 http:// 或带空格)\"}");
        return;
      }
      added = changed > 0 ? 1 : 0;
      if (changed > 0) store_audit(g_store, "授权池加入", entry, 1, "界面操作", g_task, "");
    }
    json_free(body);
    EnterCriticalSection(&g_lock);
    refresh_status_cache();
    LeaveCriticalSection(&g_lock);
    buf_t b;
    buf_init(&b);
    buf_puts(&b, "{\"ok\":true,\"changed\":");
    buf_printf(&b, "%d,\"added\":%d,\"skipped\":%d", changed > 0 ? 1 : 0, added, skipped);
    if (bad.len) {
      buf_puts(&b, ",\"rejected\":");
      buf_json_str(&b, bad.data);
    }
    buf_puts(&b, ",\"pool\":");
    buf_puts(&b, g_pool_json);
    buf_puts(&b, "}");
    http_res_json(res, 200, b.data);
    buf_free(&b);
    buf_free(&bad);
    return;
  }
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"ok\":true,\"pool\":");
  buf_puts(&b, g_pool_json);
  buf_puts(&b, "}");
  http_res_json(res, 200, b.data);
  buf_free(&b);
}

static char *attach_read(const char *sid, const char *id, size_t cap, size_t *out_len);

static int text_has_target(const char *s) {
  for (const char *p = s; p && *p; p++) {
    if (!isalnum((unsigned char)*p)) continue;
    const char *q = p;
    while (*q && (isalnum((unsigned char)*q) || *q == '.' || *q == '-' || *q == '_')) q++;
    size_t n = (size_t)(q - p);
    if (n > 3 && n < 120 && memchr(p, '.', n)) return 1;
    if (q > p) p = q - 1;
  }
  return 0;
}

static int wants_whole_pool(const char *q) {
  if (!q || !*q) return 0;
  static const char *all_words[] = {"所有", "全部", "每个", "逐个", "挨个", "逐一", "批量",
                                    "授权列表", "授权池", "清单里", "池里", "池子", NULL};
  static const char *verbs[] = {"巡检", "检查", "扫一遍", "扫一下", "查一遍", "过一遍",
                                "都查", "都过", "全查", NULL};
  int has_all = 0, has_verb = 0;
  for (int i = 0; all_words[i]; i++) {
    if (str_icontains(q, all_words[i])) { has_all = 1; break; }
  }
  if (!has_all) return 0;
  for (int i = 0; verbs[i]; i++) {
    if (str_icontains(q, verbs[i])) { has_verb = 1; break; }
  }
  if (!has_verb) return 0;
  return text_has_target(q) ? 0 : 1;
}

static void ctx_save_used(const char *sid, agent_t *a) {
  if (!sid || !*sid || !a) return;
  json_t *sess = sess_get(sid);
  json_t *old = j_get(sess, "context");

  char sum[1600] = "";
  char at[48] = "";
  snprintf(sum, sizeof(sum), "%s", j_s(old, "summary", ""));
  snprintf(at, sizeof(at), "%s", j_s(old, "at", ""));
  int cut = (int)j_n(old, "compacted_turns", 0);
  json_free(sess);

  json_t *ctx = j_obj();
  j_set_num(ctx, "tokens", agent_ctx_used(a));
  if (sum[0]) j_set_str(ctx, "summary", sum);
  if (cut > 0) j_set_num(ctx, "compacted_turns", cut);
  if (at[0]) j_set_str(ctx, "at", at);
  sess_set_context(sid, ctx);
}

static int do_compact(const char *sid, int keep, char *summary_out, size_t cap);

static void h_chat(const http_req_t *req, http_res_t *res) {

  char q[4096];
  char sid[64];
  http_query(req, "q", q, sizeof(q), "");
  http_query(req, "sid", sid, sizeof(sid), "");
  if ((!q[0] || !sid[0]) && req->body) {
    json_t *body = json_parse(req->body);
    if (body) {
      if (!q[0]) snprintf(q, sizeof(q), "%s", j_s(body, "q", ""));
      if (!sid[0]) snprintf(sid, sizeof(sid), "%s", j_s(body, "sid", ""));
      json_free(body);
    }
  }
  if (!q[0]) {
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"缺少参数 q\"}");
    return;
  }

  buf_t input;
  buf_init(&input);
  buf_puts(&input, q);
  json_t *att_list = j_arr();
  {
    char att_ids[1024];
    http_query(req, "att", att_ids, sizeof(att_ids), "");
    if (att_ids[0]) {
      char **ids = NULL;
      int n = str_split(att_ids, ',', &ids, 0);
      int budget = 24000;
      for (int i = 0; i < n; i++) {
        char *id = str_trim(ids[i]);
        if (!id[0]) continue;
        json_t *a = j_obj();
        j_set_str(a, "id", id);
        j_set_str(a, "kind", str_startswith(id, "img-") ? "image" : "text");
        if (str_startswith(id, "img-")) {
          j_add(att_list, a);
          buf_printf(&input,
                     "\n\n[附件] %s(图片已存档;当前模型不支持读图,不要据此推断图片内容)", id);
          continue;
        }
        size_t len = 0;
        char *text = attach_read(sid, id, 8000, &len);
        if (!text) { json_free(a); continue; }
        j_add(att_list, a);
        buf_printf(&input, "\n\n【用户附上的材料:%s】\n", id);
        int take = (int)len;
        if (take > budget) take = budget;
        buf_putn(&input, text, (size_t)take);
        budget -= take;
        free(text);
        if (budget <= 0) {
          buf_puts(&input, "\n(附件总量已达上限,后续附件内容从略)");
          break;
        }
      }
      str_free_list(ids, n);
    }
  }

  char target[256];
  http_query(req, "target", target, sizeof(target), "");
  int target_named = (target[0] != 0);
  if (!target[0]) snprintf(target, sizeof(target), "%s", g_domain_disp);

  int batch = (!target_named && wants_whole_pool(q));
  if (batch) target[0] = 0;
  if (target[0]) {
    if (!pool_contains(target)) {
      buf_t msg;
      buf_init(&msg);
      buf_printf(&msg, "目标 %s 不在授权池内:先把主机加进授权池,再对它发起巡检", target);
      buf_t e;
      buf_init(&e);
      buf_puts(&e, "{\"ok\":false,\"error\":");
      buf_json_str(&e, msg.data);
      buf_puts(&e, "}");
      http_res_json(res, 403, e.data);
      buf_free(&msg);
      buf_free(&e);
      return;
    }
    EnterCriticalSection(&g_lock);
    apply_scope(target);
    LeaveCriticalSection(&g_lock);
  }

  agent_slot_t *slot = agent_slot_of(sid);
  if (!slot) {
    http_res_json(res, 503,
                  "{\"ok\":false,\"error\":\"同时打开的会话太多了,先关掉一个再试\"}");
    return;
  }

  if (!http_sse_begin(res)) return;

  sse_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.res = res;
  ctx.t_start = now_ms();
  snprintf(ctx.session, sizeof(ctx.session), "%s", sid[0] ? sid : g_session);
  buf_init(&ctx.answer);
  ctx.turn = -1;
  ctx.step_index = -1;
  providers_reset_tokens();
  EnterCriticalSection(&g_lock);
  snprintf(ctx.message_id, sizeof(ctx.message_id), "msg-%04d", ++g_turn_seq);
  LeaveCriticalSection(&g_lock);
  ev_message_start(&ctx);

  {
    sess_ensure(sid, NULL);
    json_t *blocks = j_arr();
    json_t *b = j_obj();
    j_set_str(b, "type", "text");
    j_set_str(b, "text", q);
    j_add(blocks, b);
    if (j_len(att_list) > 0) {
      json_t *ab = j_obj();
      j_set_str(ab, "type", "attachment");
      j_set(ab, "items", att_list);
      j_add(blocks, ab);
    } else {
      json_free(att_list);
    }
    json_t *request = j_obj();
    j_set_str(request, "model", providers_active_id());
    j_set_str(request, "model_name", providers_display_name());
    j_set_str(request, "approval", approval_active_id());
    j_set_num(request, "max_steps", MAX_STEPS_DEFAULT);
    j_set_num(request, "tools", tools_count());
    if (target[0]) j_set_str(request, "target", target);
    ctx.turn = sess_begin_turn(sid, blocks, request);
    ctx.step_index = -1;
  }
  store_set_chat(sid);

  EnterCriticalSection(&slot->lock);

  {
    int win = providers_context_tokens();
    agent_set_ctx_window(slot->a, win, win / 8);
    json_t *sess0 = sess_get(sid);
    json_t *ctx0 = j_get(sess0, "context");
    const char *sum0 = j_s(ctx0, "summary", "");
    if (sum0 && *sum0) {
      agent_ctx_set_summary(slot->a, sum0, (int)j_n(ctx0, "compacted_turns", 0));
    }
    json_free(sess0);
  }

  char **batch_targets = NULL;
  int batch_n = 0, batch_more = 0;
  if (batch) {
    const int kBatchMax = 8;
    char **pool = NULL;
    int pn = net_pool_snapshot(&pool);
    if (pn > 0) batch_targets = (char **)xcalloc((size_t)pn, sizeof(char *));
    for (int i = 0; i < pn; i++) {
      const char *e = pool[i];
      if (!e || !e[0] || e[0] == '!') continue;
      int dup = 0;
      for (int k = 0; k < batch_n; k++) {
        if (str_ieq(batch_targets[k], e)) { dup = 1; break; }
      }
      if (dup) continue;
      if (batch_n >= kBatchMax) { batch_more = 1; continue; }
      batch_targets[batch_n++] = xstrdup(e);
    }
    str_free_list(pool, pn);
  }

  if (batch_n > 0) {
    const char *domvs[1];
    domvs[0] = batch_targets[0];
    agent_set_scope(slot->a, g_task, domvs, 1);
  } else if (g_domain[0]) {
    const char *domvs[1];
    domvs[0] = g_domain;
    agent_set_scope(slot->a, g_task, domvs, 1);
  } else {
    agent_set_scope(slot->a, g_task, NULL, 0);
  }

  net_scope_violation_clear();
  g_sse = &ctx;

  int runs_before = store_count(g_store, "runs");
  int assets_before = store_count(g_store, "assets");
  int findings_before = store_count(g_store, "findings");

  loop_state_t st;
  memset(&st, 0, sizeof(st));

  if (batch && batch_n == 0) {

    buf_t n;
    buf_init(&n);
    buf_puts(&n, "授权池里还没有可巡检的目标 —— 一个请求都不会发出去。\n");
    buf_puts(&n, "请先在右上角「设置授权」里把要检查的主机加进授权池(可加多条),"
                 "然后再说一次「把授权列表都巡检一遍」。");
    t_close_text(&ctx);
    t_put_text(&ctx, n.data);
    buf_free(&n);
    st.stop_code = STOP_NEED_USER;
    snprintf(st.stop_reason, sizeof(st.stop_reason), "授权池为空,没有可巡检的目标");
  } else if (batch_n > 0) {

    for (int i = 0; i < batch_n; i++) {
      if (agent_cancelled(slot->a)) break;
      t_close_text(&ctx);
      buf_t head;
      buf_init(&head);
      buf_printf(&head, "\n── 授权列表巡检 %d/%d:%s ──\n", i + 1, batch_n, batch_targets[i]);
      t_put_text(&ctx, head.data);
      buf_free(&head);

      EnterCriticalSection(&g_lock);
      apply_scope(batch_targets[i]);
      LeaveCriticalSection(&g_lock);
      {
        const char *domvs[1];
        domvs[0] = batch_targets[i];
        agent_set_scope(slot->a, g_task, domvs, 1);
      }
      net_scope_violation_clear();

      buf_t instr;
      buf_init(&instr);
      buf_printf(&instr, "【授权列表巡检 %d/%d】这次只处理 %s。原始要求:", i + 1, batch_n,
                 batch_targets[i]);
      buf_puts(&instr, input.data ? input.data : q);
      loop_state_t sti;
      memset(&sti, 0, sizeof(sti));
      agent_run_turn(slot->a, instr.data, &sti);
      buf_free(&instr);

      st.step_count += sti.step_count;
      st.stop_code = sti.stop_code;
      snprintf(st.stop_reason, sizeof(st.stop_reason), "%s", sti.stop_reason);
      if (sti.steps) json_free(sti.steps);
      buf_free(&sti.transcript);
      if (agent_cancelled(slot->a)) break;
    }
    if (batch_more) {
      buf_t more;
      buf_init(&more);
      buf_printf(&more, "\n这次只跑了 %d 个站(一轮上限),授权池里还有别的目标,"
                        "要接着查就再说一次。\n", batch_n);
      t_put_text(&ctx, more.data);
      buf_free(&more);
    }
    if (!st.stop_reason[0]) snprintf(st.stop_reason, sizeof(st.stop_reason), "已完成");
  } else {
    agent_run_turn(slot->a, input.data ? input.data : q, &st);
  }

  for (int i = 0; i < batch_n; i++) free(batch_targets[i]);
  free(batch_targets);
  g_sse = NULL;
  buf_free(&input);

  const char *reason = st.stop_reason[0] ? st.stop_reason : "已完成";
  ctx.llm_ms = agent_llm_ms(slot->a);
  const char *stop = (st.stop_code == STOP_NEED_USER) ? "refusal" : "end_turn";
  if (st.stop_code == STOP_ANSWERED || st.stop_code == STOP_ANSWERING_ONLY) {
    stop = "end_turn";
  }

  int pages_delta = store_count(g_store, "assets") - assets_before;
  int fresh_delta = store_count(g_store, "findings") - findings_before;
  int did_work = (ctx.tool_seq > 0) || pages_delta > 0 || fresh_delta > 0;

  if (did_work && store_count(g_store, "runs") == runs_before) {

    char scope[48] = "chat";
    const char *label = "对话";
    char labelBuf[96] = {0};
    json_t *stepsArr = NULL;
    if (st.steps) {

      if (st.steps->type == J_ARR) stepsArr = st.steps;
      else {
        json_t *inner = j_get(st.steps, "steps");
        if (inner && inner->type == J_ARR) stepsArr = inner;
      }
    }
    for (int i = 0; stepsArr && i < j_len(stepsArr); i++) {
      const char *act = j_s(j_at(stepsArr, i), "action", "");
      if (str_startswith(act, "skill_") && act[6]) {
        snprintf(scope, sizeof(scope), "%s", act + 6);
        skill_t *sk = skills_find(act);
        snprintf(labelBuf, sizeof(labelBuf), "%s", (sk && sk->title && sk->title[0]) ? sk->title : scope);
        label = labelBuf;
      }
    }
    char *rid = store_run_start(g_store, g_task, label, scope);
    if (rid) {
      int pages = pages_delta > 0 ? pages_delta : 0;
      int fresh = fresh_delta > 0 ? fresh_delta : 0;
      store_run_finish(g_store, rid, st.stop_code == STOP_ERROR ? "failed" : "done",
                       pages, ctx.tool_seq, fresh,
                       st.stop_code == STOP_ERROR ? reason : "");
      free(rid);
    }
  }

  ctx.ctx_used = agent_ctx_used(slot->a);
  ctx.ctx_window = agent_ctx_window(slot->a);
  ctx.ctx_reserve = agent_ctx_reserve(slot->a);
  ctx.ctx_compressed = agent_ctx_compressed(slot->a);
  t_close_tool(&ctx);
  t_close_text(&ctx);
  ev_message_stop(&ctx, stop, reason, &st);

  buf_free(&st.transcript);
  if (st.steps) json_free(st.steps);

  {
    long long total = ctx.t_start ? now_ms() - ctx.t_start : 0;
    json_t *resp = j_obj();
    j_set_str(resp, "text", ctx.answer.data ? ctx.answer.data : "");
    j_set_str(resp, "stop_reason", stop);
    j_set_str(resp, "stop_detail", reason);
    j_set_num(resp, "stop_code", st.stop_code);
    j_set_num(resp, "steps", st.step_count);
    j_set_num(resp, "tool_calls", ctx.tool_seq);
    j_set_num(resp, "llm_ms", (double)ctx.llm_ms);
    j_set_num(resp, "first_byte_ms", (double)ctx.first_byte_ms);
    j_set_num(resp, "duration_ms", (double)total);
    j_set_num(resp, "wait_ms", (double)ctx.wait_ms);
    json_t *tokens = j_obj();
    int tp = 0, tc = 0;
    providers_last_tokens(&tp, &tc);
    j_set_num(tokens, "prompt", tp);
    j_set_num(tokens, "completion", tc);
    j_set(resp, "tokens", tokens);
    const char *status = st.stop_code == STOP_ERROR ? "error"
                        : (st.stop_code == STOP_CANCELLED ? "aborted" : "complete");
    if (ctx.turn >= 0) sess_turn_finish(sid, ctx.turn, resp, status);
    else json_free(resp);
  }
  store_set_chat("");
  buf_free(&ctx.answer);
  ctx_save_used(sid, slot->a);

  {
    int used = agent_ctx_used(slot->a);
    int window = agent_ctx_window(slot->a);
    int reserve = agent_ctx_reserve(slot->a);
    int limit = window - reserve;
    if (limit > 0 && used > (limit * 9) / 10) {
      char sum[1600] = "";
      int cut = do_compact(sid, 2, sum, sizeof(sum));
      if (cut > 0) {
        agent_ctx_set_summary(slot->a, sum, agent_ctx_compressed(slot->a) + cut);
        agent_history_keep_recent(slot->a, 6);
        log_info("[上下文] 用量 %d/%d,已自动压缩 %d 轮", used, window, cut);
      }
    }
  }
  LeaveCriticalSection(&slot->lock);
  refresh_status_cache();
}

static void h_attach(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "POST") != 0) {
    http_res_json(res, 405, "{\"ok\":false,\"error\":\"只接受 POST\"}");
    return;
  }
  json_t *body = req->body ? json_parse(req->body) : NULL;
  if (!body) {
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}");
    return;
  }
  const char *sid = j_s(body, "sid", "");
  const char *name = j_s(body, "name", "attachment");
  const char *kind = j_s(body, "kind", "text");
  const char *text = j_s(body, "text", "");
  if (!text[0]) {
    json_free(body);
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"附件是空的\"}");
    return;
  }
  char safe_sid[64], safe_name[96];
  snprintf(safe_sid, sizeof(safe_sid), "%s", (sid && *sid) ? sid : "default");
  for (char *p = safe_sid; *p; p++) {
    if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') *p = '_';
  }
  snprintf(safe_name, sizeof(safe_name), "%s", (name && *name) ? name : "attachment");
  for (char *p = safe_name; *p; p++) {
    if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.') *p = '_';
  }

  char dir[MAX_PATH * 2], path[MAX_PATH * 4];
  path_join(dir, sizeof(dir), g_data_dir, "attachments");
  path_join(dir, sizeof(dir), dir, safe_sid);
  ensure_dir(dir);

  char id[MAX_PATH];
  snprintf(id, sizeof(id), "%s-%lld-%s", str_ieq(kind, "image") ? "img" : "txt",
           (long long)now_ms(), safe_name);
  path_join(path, sizeof(path), dir, id);
  size_t len = strlen(text);
  file_write_all(path, text, len);

  json_t *out = j_obj();
  j_set_bool(out, "ok", 1);
  j_set_str(out, "id", id);
  j_set_str(out, "name", name ? name : "");
  j_set_str(out, "kind", str_ieq(kind, "image") ? "image" : "text");
  j_set_num(out, "size", (double)len);
  char *dump = json_dump(out);
  http_res_json(res, 200, dump);
  free(dump);
  json_free(out);
  json_free(body);
}

static char *attach_read(const char *sid, const char *id, size_t cap, size_t *out_len) {
  if (out_len) *out_len = 0;
  if (!sid || !id || !*id) return NULL;
  if (strchr(id, '\\') || strchr(id, '/') || strstr(id, "..")) return NULL;
  char safe_sid[64];
  snprintf(safe_sid, sizeof(safe_sid), "%s", sid);
  for (char *p = safe_sid; *p; p++) {
    if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') *p = '_';
  }
  char dir[MAX_PATH * 2], path[MAX_PATH * 4];
  path_join(dir, sizeof(dir), g_data_dir, "attachments");
  path_join(dir, sizeof(dir), dir, safe_sid);
  path_join(path, sizeof(path), dir, id);
  size_t len = 0;
  char *text = file_read_all(path, &len);
  if (!text) return NULL;
  if (len > cap) {
    text[cap] = 0;
    len = cap;
  }
  if (out_len) *out_len = len;
  return text;
}

static void turn_to_line(json_t *turn, buf_t *out) {
  char ts[40] = "";
  const char *started = j_s(turn, "started_at", "");
  snprintf(ts, sizeof(ts), "%s", started);
  json_t *ub = j_get(j_get(turn, "user"), "blocks");
  const char *utext = "";
  for (int i = 0; i < j_len(ub); i++) {
    if (strcmp(j_s(j_at(ub, i), "type", ""), "text") == 0) { utext = j_s(j_at(ub, i), "text", ""); break; }
  }
  json_t *resp = j_get(turn, "response");
  const char *ans = j_s(resp, "text", "");
  const char *stop = j_s(resp, "stop_detail", j_s(resp, "stop_reason", ""));
  buf_printf(out, "- [%s] 用户:", ts);

  buf_t a;
  buf_init(&a);
  buf_putn(&a, utext ? utext : "", u8_prefix(utext ? utext : "", 160));
  buf_puts(out, a.data ? a.data : "");
  buf_free(&a);

  buf_puts(out, " → 结论:");
  buf_t c;
  buf_init(&c);
  buf_putn(&c, ans ? ans : "", u8_prefix(ans ? ans : "", 200));
  buf_puts(out, c.data ? c.data : "");
  buf_free(&c);
  if (stop && *stop) buf_printf(out, "(停止:%s)", stop);
  buf_puts(out, "\n");
}

static int do_compact(const char *sid, int keep, char *summary_out, size_t cap) {
  if (!sid || !*sid) return 0;
  json_t *sess = sess_get(sid);
  json_t *turns = j_get(sess, "turns");
  int total = j_len(turns);
  if (total <= keep) { json_free(sess); return 0; }
  int cut = total - keep;

  buf_t raw;
  buf_init(&raw);
  for (int i = 0; i < cut; i++) turn_to_line(j_at(turns, i), &raw);
  if (!raw.data || !raw.len) { buf_free(&raw); json_free(sess); return 0; }

  buf_t prompt;
  buf_init(&prompt);
  buf_puts(&prompt,
      "把下面这段巡检对话压缩成不超过 300 字的中文摘要。要求:\n"
      "1. 保留:查过哪些目标、做了什么、得出什么结论(尤其是发现/异常);\n"
      "2. 保留:用户明确表达过的偏好或后续要接着做的事;\n"
      "3. 不要编造、不要复述步骤细节、不要用列表以外的格式。\n\n");
  buf_puts(&prompt, raw.data);
  buf_t sum;
  buf_init(&sum);
  const char *use = raw.data;
  char *model_sum = NULL;
  if (llm_enabled() && llm_ask(prompt.data, &sum) == 0 && sum.len > 0) {
    model_sum = sum.data;
    use = model_sum;
  }
  buf_free(&prompt);

  json_t *old = j_get(sess, "context");
  int prev = (int)j_n(old, "compacted_turns", 0);
  buf_t merged;
  buf_init(&merged);
  const char *prev_sum = j_s(old, "summary", "");
  if (prev_sum && *prev_sum) {
    buf_puts(&merged, prev_sum);
    buf_puts(&merged, "\n");
  }
  buf_putn(&merged, use, u8_prefix(use, 1200));

  json_t *ctx = j_obj();
  j_set_str(ctx, "summary", merged.data ? merged.data : "");
  j_set_num(ctx, "compacted_turns", prev + cut);

  j_set_num(ctx, "tokens", (int)j_n(old, "tokens", 0));
  char ts[40];
  now_iso(ts, sizeof(ts));
  j_set_str(ctx, "at", ts);
  sess_set_context(sid, ctx);

  if (summary_out) snprintf(summary_out, cap, "%s", merged.data ? merged.data : "");
  buf_free(&merged);
  buf_free(&sum);
  buf_free(&raw);
  json_free(sess);
  return cut;
}

static void h_compact(const http_req_t *req, http_res_t *res) {
  char sid[64];
  http_query(req, "sid", sid, sizeof(sid), "");
  if (!sid[0] && req->body) {
    json_t *b = json_parse(req->body);
    if (b) { snprintf(sid, sizeof(sid), "%s", j_s(b, "sid", "")); json_free(b); }
  }
  if (!sid[0]) { http_res_json(res, 400, "{\"ok\":false,\"error\":\"需要 sid\"}"); return; }

  agent_slot_t *slot = agent_slot_of(sid);
  int window = providers_context_tokens();
  if (slot) {
    agent_set_ctx_window(slot->a, window, window / 8);
    int keep = 6;
    char sum[1600] = "";
    int cut = do_compact(sid, 2, sum, sizeof(sum));
    if (cut > 0) {
      agent_ctx_set_summary(slot->a, sum, agent_ctx_compressed(slot->a) + cut);
      agent_history_keep_recent(slot->a, keep);
      log_info("[上下文] 会话 %s 压缩了 %d 轮(留最近 2 轮)", sid, cut);
    }
    json_t *root = j_obj();
    j_set_bool(root, "ok", 1);
    j_set_num(root, "compacted", cut);
    j_set_str(root, "summary", sum);
    j_set_num(root, "used", agent_ctx_used(slot->a));
    j_set_num(root, "window", window);
    char *text = json_dump(root);
    http_res_json(res, 200, text);
    free(text);
    json_free(root);
    return;  }

  char sum[1600] = "";
  int cut = do_compact(sid, 2, sum, sizeof(sum));
  buf_t out;
  buf_init(&out);
  buf_printf(&out, "{\"ok\":true,\"compacted\":%d,\"summary\":", cut);
  buf_json_str(&out, sum);
  buf_puts(&out, "}");
  http_res_json(res, 200, out.data);
  buf_free(&out);
}

static void h_chats(const http_req_t *req, http_res_t *res) {

  if (strcmp(req->method, "POST") == 0) {
    json_t *body = req->body ? json_parse(req->body) : NULL;
    const char *action = body ? j_s(body, "action", "") : "";
    const char *id = body ? j_s(body, "id", "") : "";
    const char *sid = body ? j_s(body, "sid", "") : "";

    if (str_ieq(action, "input") && sid[0]) {
      json_t *input = j_get(body, "input");
      sess_set_input(sid, input ? j_clone(input) : j_obj());
      if (body) json_free(body);
      http_res_json(res, 200, "{\"ok\":true}");
      return;
    }
    if (!id[0] || (!str_ieq(action, "archive") && !str_ieq(action, "unarchive") &&
                   !str_ieq(action, "pin") && !str_ieq(action, "unpin"))) {
      if (body) json_free(body);
      http_res_json(res, 400, "{\"ok\":false,\"error\":\"需要 id 与 action\"}");
      return;
    }
    int archived = str_ieq(action, "archive") ? 1 : (str_ieq(action, "unarchive") ? 0 : -1);
    int pinned = str_ieq(action, "pin") ? 1 : (str_ieq(action, "unpin") ? 0 : -1);
    sess_set_flags(id, archived, pinned);
    if (body) json_free(body);
    json_t *root = j_obj();
    j_set_bool(root, "ok", 1);
    j_set_str(root, "id", id);
    j_set_bool(root, "archived", archived > 0);
    j_set_bool(root, "pinned", pinned > 0);
    char *text = json_dump(root);
    http_res_json(res, 200, text);
    free(text);
    json_free(root);
    return;
  }

  char arch[8];
  http_query(req, "archived", arch, sizeof(arch), "");
  if (arch[0]) {
    json_t *all = sess_list();
    json_t *items = j_arr();
    for (int i = 0; i < j_len(all); i++) {
      json_t *m = j_at(all, i);
      json_t *o = j_obj();
      j_set_str(o, "id", j_s(m, "id", ""));
      j_set_bool(o, "archived", j_b(m, "archived", 0));
      j_set_bool(o, "pinned", j_b(m, "pinned", 0));
      j_add(items, o);
    }
    json_free(all);
    json_t *root = j_obj();
    j_set_bool(root, "ok", 1);
    j_set(root, "items", items);
    char *text = json_dump(root);
    http_res_json(res, 200, text);
    free(text);
    json_free(root);
    return;
  }

  char run_id[32];
  http_query(req, "run", run_id, sizeof(run_id), "");
  if (run_id[0]) {
    json_t *r = store_get(g_store, "runs", run_id);
    json_t *fs = store_findings_of_run(g_store, run_id);
    json_t *root = j_obj();
    j_set_bool(root, "ok", 1);
    j_set_str(root, "session", r ? j_s(r, "session", "") : "");
    j_set(root, "run", r ? r : j_obj());
    j_set(root, "findings", fs ? fs : j_arr());
    char *text = json_dump(root);
    http_res_json(res, 200, text);
    free(text);
    json_free(root);
    return;
  }

  char sid[64];
  http_query(req, "sid", sid, sizeof(sid), "");
  if (sid[0]) {
    json_t *sess = sess_get(sid);
    json_t *root = j_obj();
    j_set_bool(root, "ok", 1);
    j_set_str(root, "id", sid);
    j_set_str(root, "title", j_s(sess, "title", ""));
    j_set(root, "session", sess ? sess : j_obj());
    char *text = json_dump(root);
    http_res_json(res, 200, text);
    free(text);
    json_free(root);
    return;
  }
  json_t *list = sess_list();
  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set(root, "items", list);
  char *text = json_dump(root);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
}

static void h_quit(const http_req_t *req, http_res_t *res) {
  (void)req;
  log_info("收到退出请求,服务即将停止");
  http_res_json(res, 200, "{\"ok\":true,\"bye\":true}");

  Sleep(120);
  http_stop();
}

static void h_cancel(const http_req_t *req, http_res_t *res) {
  char sid[64];
  http_query(req, "sid", sid, sizeof(sid), "");
  if (!sid[0] && req->body) {
    json_t *body = json_parse(req->body);
    if (body) {
      snprintf(sid, sizeof(sid), "%s", j_s(body, "sid", ""));
      json_free(body);
    }
  }
  agent_slot_t *slot = agent_slot_find(sid);
  if (!slot) {
    http_res_json(res, 404, "{\"ok\":false,\"error\":\"没有这个会话\"}");
    return;
  }
  int was = agent_cancelled(slot->a);
  agent_cancel(slot->a);
  http_res_json(res, 200, was ? "{\"ok\":true,\"already\":true}" : "{\"ok\":true}");
}

static void router(const http_req_t *req, http_res_t *res, void *ud) {
  (void)ud;
  if (strcmp(req->method, "GET") != 0 && strcmp(req->method, "POST") != 0) {
    http_res_json(res, 405, "{\"ok\":false,\"error\":\"方法不允许\"}");
    return;
  }
  const char *p = req->path;

  if (!strcmp(p, "/") || !strcmp(p, "/index.html")) {
    serve_asset("index.html", res);
    return;
  }
  if (str_startswith(p, "/ui/")) {
    serve_asset(p + 4, res);
    return;
  }

  if (str_startswith(p, "/api/")) {
    if (!api_guard(req, res)) return;
    if (!strcmp(p, "/api/health")) { h_health(req, res); return; }
    if (!strcmp(p, "/api/manifest")) { h_manifest(req, res); return; }
    if (!strcmp(p, "/api/status")) { h_status(req, res); return; }
    if (!strcmp(p, "/api/rules")) { h_rules(req, res); return; }
    if (!strcmp(p, "/api/data")) { h_collection(req, res); return; }
    if (!strcmp(p, "/api/scope")) { h_scope(req, res); return; }
    if (!strcmp(p, "/api/pool")) { h_pool(req, res); return; }
    if (!strcmp(p, "/api/cancel")) { h_cancel(req, res); return; }
    if (!strcmp(p, "/api/chats")) { h_chats(req, res); return; }
    if (!strcmp(p, "/api/compact")) { h_compact(req, res); return; }
    if (!strcmp(p, "/api/attach")) { h_attach(req, res); return; }
    if (!strcmp(p, "/api/settings")) { api_rules(req, res); return; }
    if (!strcmp(p, "/api/rules/preset")) { api_rules_preset(req, res); return; }
    if (!strcmp(p, "/api/caps")) { api_caps(req, res); return; }
    if (!strcmp(p, "/api/models")) { api_models(req, res); return; }
    if (!strcmp(p, "/api/quit")) { h_quit(req, res); return; }
    if (!strcmp(p, "/api/chat")) { h_chat(req, res); return; }
    if (!strcmp(p, "/api/config/list")) { api_config_list(req, res); return; }
    if (!strcmp(p, "/api/config")) {
      if (strcmp(req->method, "POST") == 0) api_config_save(req, res);
      else api_config_get(req, res);
      return;
    }
    if (!strcmp(p, "/api/reload")) { api_reload(req, res); return; }
    if (!strcmp(p, "/api/automations/history")) { api_automation_history(req, res); return; }
    if (!strcmp(p, "/api/automations")) {
      if (strcmp(req->method, "POST") == 0) api_automation_post(req, res);
      else api_automation_list(req, res);
      return;
    }
    if (!strcmp(p, "/api/export")) { h_export(req, res); return; }
    if (!strcmp(p, "/api/profiles")) { api_profiles(req, res); return; }
    if (!strcmp(p, "/api/approvals")) { h_approvals(req, res); return; }
    if (!strcmp(p, "/api/approval")) { h_approval_decision(req, res); return; }
    if (!strcmp(p, "/api/answer")) { h_answer(req, res); return; }
    http_res_404(res);
    return;
  }

  if (asset_type(p[0] == '/' ? p + 1 : p)) {
    serve_asset(p[0] == '/' ? p + 1 : p, res);
    return;
  }
  http_res_404(res);
}

static BOOL WINAPI on_console_ctrl(DWORD type) {
  if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
    printf("\n正在停止服务……\n");
    http_stop();
    return TRUE;
  }
  return FALSE;
}

int serve_run(const char *domain, int port, int open_ui) {
  if (port <= 0) port = 8765;
  if (!http_startup()) {
    printf("网络初始化失败:%s\n", http_last_error());
    return 1;
  }

  const char *ddir = app_data_dir();
  ensure_dir(ddir);

  instance_publish(port);
  res_bootstrap_data_dir();
  snprintf(g_data_dir, sizeof(g_data_dir), "%s", ddir);
  g_store = store_open(g_data_dir);

  sess_init(g_data_dir);

  pool_load();
  if (net_pool_count() == 0 && domain && *domain) pool_add(domain);
  {
    char apath[MAX_PATH * 2];
    app_data_path(apath, sizeof(apath), "approval.json");
    approval_set_path(apath);
    approval_load();
    approval_init();
  }
  {
    char audit_path[MAX_PATH * 2];
    app_data_path(audit_path, sizeof(audit_path), "audit.jsonl");
    net_set_audit_path(audit_path);
  }
  net_set_readonly(1);

  {
    const char *base = getenv("TARGET_BASE_URL");
    if (base && *base) net_set_target_base(base);
  }

  InitializeCriticalSection(&g_lock);
  InitializeCriticalSection(&g_status_lock);

  g_port = port;
  make_token(g_token, sizeof(g_token));
  agents_init();
  approval_init();
  g_sched_agent = agent_create("scheduler");
  agent_set_store(g_sched_agent, g_store, "");
  agent_set_hooks(g_sched_agent, &g_hooks);
  apply_scope(domain);
  refresh_status_cache();

  printf("════════════════════════════════════════════════════════\n");
  printf("  BlueWhiteAgent(C 版) · 后端服务已启动\n");
  printf("════════════════════════════════════════════════════════\n");
  printf("  界面地址 : http://127.0.0.1:%d/\n", port);
  printf("  决策模型 : %s\n", providers_display_name());
  printf("  授权域名 : %s\n", g_domain[0] ? g_domain : "(未授权 —— 不会对外发请求)");
  printf("  工具/技能: %d 个 / %d 个\n", tools_count(), skills_count());

  {
    int n = embed_count();
    printf("  自带资源 : %d 项(界面与默认规则已内置,无需附带任何目录)\n", n);
    if (res_exists("ui/index.html")) {
      long sz = file_size("ui\\index.html");
      if (sz >= 0) printf("  说明     : 检测到磁盘上的 ui\\ 目录,将优先使用它(可自行替换界面)\n");
      else printf("  说明     : 本次使用 exe 内置界面\n");
    }
  }
  printf("  数据目录 : %s\\\n", g_data_dir);
  printf("  停止服务 : 关掉本窗口或按 Ctrl+C\n\n");

  SetConsoleCtrlHandler(on_console_ctrl, TRUE);

  sched_start();

  if (open_ui) {

    tray_start(port, "BlueWhiteAgent");

    const char *ui_mode = getenv("UI_MODE");
    int force_browser = ui_mode && str_ieq(ui_mode, "browser");
    int ok = 0;
    if (!force_browser) {
      ok = (webview_start(port, "BlueWhiteAgent") == 0);
      if (!ok) log_warn("WebView2 窗口起不来,退回系统 Edge 的 --app 窗口");
    }
    if (!ok) ui_open_url_async(port);
  }

  int serve_rc = http_serve(NULL, port, router, NULL);
  if (serve_rc != 0) {

    log_error("HTTP 服务启动失败:%s", http_last_error());
    printf("  %s\n", http_last_error());
  }
  instance_unpublish();

  sched_stop();
  printf("服务已停止。\n");
  webview_stop();
  ui_close();
  tray_stop();
  int port_busy = (serve_rc != 0) && str_icontains(http_last_error(), "占用");
  for (int i = 0; i < g_agent_count; i++) {
    agent_free(g_agents[i].a);
    DeleteCriticalSection(&g_agents[i].lock);
  }
  g_agent_count = 0;
  agent_free(g_sched_agent);
  g_sched_agent = NULL;
  store_close(g_store);
  free(g_status_cache);
  DeleteCriticalSection(&g_status_lock);
  DeleteCriticalSection(&g_lock);
  http_shutdown();
  if (port_busy) return 2;
  return serve_rc == 0 ? 0 : 1;
}

const char *serve_token(void) { return g_token; }

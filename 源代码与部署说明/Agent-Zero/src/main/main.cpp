
#include "agent.h"
#include "common.h"
#include "ext.h"
#include "instance.h"
#include "json.h"
#include "llm.h"
#include "net.h"
#include "approval.h"
#include "profile.h"
#include "res.h"
#include "rules.h"
#ifndef BW_RELEASE
#include "selftest.h"
#endif
#include "serve.h"
#include "skills.h"
#include "store.h"
#include "tools.h"

int toolhost_run(const char *tool_arg);
#include "ui.h"
#include "webutil.h"

#include <ctype.h>

static void cli_on_answer(void *ud, const char *text) {
  (void)ud;
  printf("\n%s\n\n", text ? text : "");
}
static void cli_on_thinking(void *ud, const char *text) {
  (void)ud;
  printf("· 思考:%s\n", text ? text : "");
}
static void cli_on_action(void *ud, const char *tool, json_t *args, const char *reason) {
  (void)ud;
  char *dump = args ? json_dump(args) : NULL;
  printf("· 动作:%s %s%s%s\n", tool ? tool : "", dump ? dump : "",
         (reason && *reason) ? "  —— " : "", (reason && *reason) ? reason : "");
  free(dump);
}
static void cli_on_status(void *ud, const char *tool, const char *status, const char *note) {
  (void)ud;
  if (note && *note) printf("· 状态:%s %s —— %s\n", tool ? tool : "", status ? status : "", note);
}
static void cli_on_observation(void *ud, const char *tool, tool_result_t *r) {
  (void)ud;
  const char *first = (r && r->text) ? r->text : "";
  printf("· 观察:%s %s%s\n", tool ? tool : "", (r && r->is_error) ? "[失败] " : "",
         first);
}
static void cli_on_ask(void *ud, const char *text) {
  (void)ud;
  printf("· 需要你补充:%s\n", text ? text : "");
}

static json_t *args_from_argv(int argc, char **argv, int start, const char *target,
                             const char *tool_name) {
  json_t *args = j_obj();
  const char *pos_key = "target";
  if (tool_name && *tool_name) {
    tool_t *t = tools_find(tool_name);
    json_t *schema = t ? json_parse(t->schema) : NULL;
    if (schema) {
      json_t *props = j_get(schema, "properties");
      if (props && !j_get(props, "target")) {
        json_t *req = j_get(schema, "required");
        if (j_len(req) == 1 && j_at(req, 0) && j_at(req, 0)->type == J_STR) {
          pos_key = j_at(req, 0)->str;
        }
      }
      json_free(schema);
    }
  }
  if (target && *target) {
    if (strcmp(pos_key, "target") == 0) j_set_str(args, "target", target);
    else j_set_str(args, pos_key, target);
  }
  if (start >= argc) return args;

  const char *first = argv[start];
  while (*first == ' ') first++;
  if (*first == '{') {
    buf_t b;
    buf_init(&b);
    for (int i = start; i < argc; i++) {
      if (i > start) buf_putc_(&b, ' ');
      buf_puts(&b, argv[i]);
    }
    json_t *j = json_parse(b.data);
    buf_free(&b);
    if (j && j->type == J_OBJ) {
      if (target && *target && !j_get(j, "target")) j_set_str(j, "target", target);
      json_free(args);
      return j;
    }
    json_free(j);
  }

  for (int i = start; i < argc; i++) {
    const char *eq = strchr(argv[i], '=');
    if (!eq) continue;
    char key[64];
    size_t kl = (size_t)(eq - argv[i]);
    if (kl >= sizeof(key)) kl = sizeof(key) - 1;
    memcpy(key, argv[i], kl);
    key[kl] = 0;
    const char *val = eq + 1;

    int all_digit = *val != 0;
    for (const char *p = val; *p; p++) if (*p < '0' || *p > '9') { all_digit = 0; break; }
    if (all_digit && *val) j_set_num(args, key, atof(val));
    else if (str_ieq(val, "true") || str_ieq(val, "false")) j_set_bool(args, key, str_ieq(val, "true"));
    else j_set_str(args, key, val);
  }
  return args;
}

static void set_dpi_aware(void) {
  HMODULE u = GetModuleHandleW(L"user32.dll");
  typedef BOOL(WINAPI * set_ctx_fn)(HANDLE);
  set_ctx_fn set_ctx =
      dll_sym<set_ctx_fn>(u, "SetProcessDpiAwarenessContext");
  if (set_ctx) {
    if (set_ctx((HANDLE)-4)) return;
    if (set_ctx((HANDLE)-3)) return;
  }
  SetProcessDPIAware();
}

int app_main(int argc, char **argv) {
  set_dpi_aware();

  int want_console = 0;
  int debug_flag_at = -1;
  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    if (!a) continue;
    if (str_ieq(a, "--debug") || str_ieq(a, "-debug") || str_ieq(a, "/debug")) {
      want_console = 1;
      if (debug_flag_at < 0) debug_flag_at = i;
    }
  }
  const char *env_dbg = getenv("BW_AGENT_DEBUG");
  if (env_dbg && *env_dbg && !str_ieq(env_dbg, "0")) want_console = 1;

  int have_console = app_console_init(want_console);
  if (have_console) console_init();

  if (want_console) ui_set_stop_on_close(0);

  if (debug_flag_at > 0) {
    for (int i = debug_flag_at; i + 1 < argc; i++) argv[i] = argv[i + 1];
    argv[argc - 1] = NULL;
    argc--;
  }

  app_fix_argv_encoding(argc, argv);
  app_init_paths();

  if (argc > 1 && str_ieq(argv[1], "toolhost")) freopen("NUL", "w", stderr);

  int have_log_file = 0;
  {
    const char *c = (argc > 1) ? argv[1] : "start";
    int long_running = str_ieq(c, "start") || str_ieq(c, "serve");
    if (!have_console || long_running) {
      char log_path[MAX_PATH * 2];
      app_data_path(log_path, sizeof(log_path), "agent.log");
      log_open(log_path);
      have_log_file = 1;
      log_info("—— 启动(%s):日志见本文件 ——", have_console ? "控制台可用" : "无控制台");
    }
  }
  log_set_level((have_console || have_log_file) ? LOG_INFO : LOG_WARN);

  int allow_multi = 0;
  {
    int w = 1;
    for (int i = 1; i < argc; i++) {
      const char *a = argv[i] ? argv[i] : "";
      if (str_ieq(a, "--multi") || str_ieq(a, "-multi")) {
        allow_multi = 1;
        continue;
      }
      argv[w++] = argv[i];
    }
    argv[w] = NULL;
    argc = w;
  }
  {
    const char *first = (argc > 1) ? argv[1] : "start";
    int long_running = str_ieq(first, "start") || str_ieq(first, "serve");
    if (long_running && !allow_multi && !instance_acquire()) {
      int want_ui = 1;
      const char *um = getenv("UI_MODE");
      if (um && (str_ieq(um, "off") || str_ieq(um, "none"))) want_ui = 0;
      for (int i = 2; i < argc; i++) {
        if (str_ieq(argv[i], "--no-ui")) want_ui = 0;
      }
      int running = instance_running_port(2500);
      if (running > 0) {
        printf("\n  程序已经在运行(端口 %d),本次启动只把它的界面叫到前台。\n", running);
        log_info("检测到已有实例(端口 %d):%s", running, instance_note());
        if (want_ui && ui_show_existing(running) == 0) {
          printf("  没能自动打开界面,请手动访问 http://127.0.0.1:%d/\n", running);
        }
        printf("  想强制再开一个:加 --multi。\n\n");
        return 0;
      }
      printf("\n  程序已经在运行,但没找到它的服务端口(可能正在启动,或已经卡住)。\n"
             "  稍等几秒再试;或在任务管理器里结束它;要强制多开请加 --multi。\n\n");
      log_warn("检测到已有实例但探活失败:%s", instance_note());
      return 1;
    }
  }

#ifdef BW_RELEASE
  int is_selftest = 0;
#else
  int is_selftest = (argc > 1 && str_ieq(argv[1], "selftest"));
#endif
  if (!is_selftest) res_bootstrap_data_dir();

  tools_init();
  skills_init();
  rules_init(app_dir());

  ext_bootstrap();
  ext_load_all();
  ext_register_all();
  llm_init(app_dir());
  net_init();

  const char *cmd = (argc > 1) ? argv[1] : "start";

  if (str_ieq(cmd, "toolhost")) {
    int rc = toolhost_run((argc > 2) ? argv[2] : "");
    net_shutdown();
    rules_shutdown();
    return rc;
  }

#ifdef BW_RELEASE

  if (str_ieq(cmd, "selftest") || str_ieq(cmd, "regextest") || str_ieq(cmd, "netbench")) {
    printf("%s 是调试功能,发布版不带。需要它请用 agent-dev.exe(build.bat debug 构建)。\n", cmd);
    net_shutdown();
    rules_shutdown();
    return 1;
  }
#endif

#ifndef BW_RELEASE

  if (str_ieq(cmd, "selftest")) {
    printf("BlueWhiteAgent(C 版)· 自检\n");
    printf("程序目录: %s\n", app_dir());
    int rc = selftest_run();
    net_shutdown();
    rules_shutdown();
    return rc;
  }
#endif

  if (str_ieq(cmd, "tools")) {
    agent_print_tools();
    printf("\n");
    agent_print_skills();
    net_shutdown();
    return 0;
  }

  if (str_ieq(cmd, "skills")) {
    agent_print_skills();
    net_shutdown();
    return 0;
  }

  if (str_ieq(cmd, "rules")) {

    char default_rules_path[MAX_PATH * 2];
    app_data_path(default_rules_path, sizeof(default_rules_path), "rules.default.json");
    const char *out_path = (argc > 2) ? argv[2] : default_rules_path;
    const char *text = rules_default_json();
    if (file_write_all(out_path, text, strlen(text)) == 0) {
      printf("已写出内置默认规则:%s(%d 字节)\n", out_path, (int)strlen(text));
      printf("当前生效规则来源:%s\n", rules_source());
    } else {
      printf("写出失败:%s\n", out_path);
    }
    rules_shutdown();
    net_shutdown();
    return 0;
  }

  if (str_ieq(cmd, "manifest")) {

    json_t *root = j_obj();
    j_set_str(root, "version", "v1");
    j_set(root, "tools", agent_tool_list_json());
    j_set(root, "skills", agent_skill_list_json());
    char *pretty = json_dump_pretty(root);
    const char *out_path = (argc > 2) ? argv[2] : "manifest.json";
    file_write_all(out_path, pretty, strlen(pretty));
    printf("已写出 %s(工具 %d 个、技能 %d 个)\n", out_path, tools_count(), skills_count());
    free(pretty);
    json_free(root);
    net_shutdown();
    return 0;
  }

  if (str_ieq(cmd, "run")) {

    const char *skill = (argc > 2) ? argv[2] : "skill_recon";
    const char *target = (argc > 3) ? argv[3] : "";
    const char *ddir = app_data_dir();
    ensure_dir(ddir);
    res_bootstrap_data_dir();
    store_t *store = store_open(ddir);
    char audit_path[MAX_PATH * 2];
    app_data_path(audit_path, sizeof(audit_path), "audit.jsonl");
    net_set_audit_path(audit_path);
    net_set_readonly(1);
    const char *base = getenv("TARGET_BASE_URL");
    if (base && *base) net_set_target_base(base);

    char host[256];
    net_host_of(target, host, sizeof(host));
    net_align_base_from(target);

    {
      char pool_path[MAX_PATH * 2];
      app_data_path(pool_path, sizeof(pool_path), "pool.json");
      int pn = net_pool_load_file(pool_path);
      if (pn > 0) printf("授权池:%d 条(含 ! 不允许条目)\n", pn);
    }
    const char *doms[1];
    int nd = 0;
    if (host[0]) { doms[0] = host; nd = 1; }

    char task_id[64] = "CLI-TASK";
    int nk = 0, nf = 0;
    const char **kw = rules_str_list("profile_keywords", &nk);
    const char **ft = rules_str_list("profile_file_types", &nf);
    json_t *kws = j_arr();
    for (int i = 0; i < nk; i++) j_add(kws, j_str(kw[i]));
    json_t *fts = j_arr();
    for (int i = 0; i < nf; i++) j_add(fts, j_str(ft[i]));
    char *pid = store_ensure_profile(store, "默认敏感信息定义(随规则层)", kws, fts, NULL);
    if (nd) {
      char tn[320];
      snprintf(tn, sizeof(tn), "对 %s 的命令行授权巡检", host);
      char *tid = store_ensure_task(store, doms, nd, tn, pid);
      if (tid) snprintf(task_id, sizeof(task_id), "%s", tid);
      free(tid);
    } else {

      task_id[0] = 0;
    }
    free(pid);
    json_free(kws);
    json_free(fts);

    tool_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.io = *net_io_impl();
    ctx.store = store;
    ctx.task_id = task_id;
    ctx.domains = nd ? doms : NULL;
    ctx.domain_count = nd;
    net_set_scope(task_id, nd ? doms : NULL, nd);

    json_t *args = j_obj();
    j_set_str(args, "target", target);
    skill_result_t sr;
    memset(&sr, 0, sizeof(sr));
    printf("规则来源:%s\n", rules_source());
    printf("技能:%s   目标:%s   授权:%s\n\n", skill, target,
           nd ? "已按命令行域名授权" : "(未授权,不会对外发请求)");
    if (!nd && target[0] == 0) {
      printf("提示:未指定目标,复测/报告/证据核对按全部历史发现处理。\n\n");
    }
    int rc = skills_run(&ctx, skill, args, &sr);
    printf("[%s] %s\n\n", rc == 0 && !sr.is_error ? "OK" : "ERROR",
           sr.summary ? sr.summary : "(无结论)");
    if (sr.data) {
      char *pj = json_dump_pretty(sr.data);
      printf("--- 结构化结果 ---\n%s\n", pj);
      free(pj);
    }
    printf("\n(本次共发起 %d 次请求)\n", ctx.http_calls);
    json_free(args);
    skill_result_free(&sr);
    store_close(store);
    net_shutdown();
    rules_shutdown();
    return rc == 0 ? 0 : 1;
  }

  if (str_ieq(cmd, "tool")) {

    const char *tname = (argc > 2) ? argv[2] : "sensitive_file_probe";
    const char *target = (argc > 3) ? argv[3] : "";
    int args_start = 4;

    if (argc > 3) {
      const char *p = argv[3];
      while (*p == ' ') p++;
      if (*p == '{' || strchr(p, '=')) {
        target = "";
        args_start = 3;
      }
    }
    const char *ddir = app_data_dir();
    ensure_dir(ddir);
    res_bootstrap_data_dir();
    store_t *store = store_open(ddir);
    char audit_path[MAX_PATH * 2];
    app_data_path(audit_path, sizeof(audit_path), "audit.jsonl");
    net_set_audit_path(audit_path);
    net_set_readonly(1);
    const char *base = getenv("TARGET_BASE_URL");
    if (base && *base) net_set_target_base(base);

    char host[256];
    net_host_of(target, host, sizeof(host));
    net_align_base_from(target);
    const char *doms[1];
    int nd = 0;
    if (host[0]) { doms[0] = host; nd = 1; }

    tool_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.io = *net_io_impl();
    ctx.store = store;
    ctx.task_id = "CLI-TOOL";
    ctx.domains = nd ? doms : NULL;
    ctx.domain_count = nd;
    net_set_scope(ctx.task_id, nd ? doms : NULL, nd);

    {
      const char *pid = getenv("BW_PROFILE");
      if (pid && *pid) {
        json_t *p = store_get(store, "profiles", pid);
        if (p) {
          profile_set_active(p);
          printf("本单位定义:%s(%s)\n", j_s(p, "name", ""), pid);
          json_free(p);
        } else {
          printf("本单位定义:%s 不存在,按出厂口径跑\n", pid);
        }
      }
    }

    {
      char pool_path[MAX_PATH * 2];
      app_data_path(pool_path, sizeof(pool_path), "pool.json");
      int pn = net_pool_load_file(pool_path);
      if (pn > 0) printf("授权池:%d 条(含 ! 不允许条目)\n", pn);
    }

    json_t *args = args_from_argv(argc, argv, args_start, target, tname);
    tool_result_t tr;
    memset(&tr, 0, sizeof(tr));
    printf("规则来源:%s\n", rules_source());
    printf("工具:%s   目标:%s\n", tname, target);
    {
      int et = 0, es = 0, em = 0, emt = 0;
      ext_stats(&et, &es, &em, &emt);
      if (et || es || em) {
        printf("外部能力:工具 %d 个、技能包 %d 个、MCP %d 个(共 %d 个 MCP 工具)\n",
               et, es, em, emt);
      }
    }
    printf("参数:%s\n\n", json_dump(args));
    int rc = tools_run(&ctx, tname, args, &tr);
    printf("[%s] %s\n\n", rc == 0 && !tr.is_error ? "OK" : "ERROR",
           tr.say ? tr.say : "(无汇报语)");
    if (tr.text) printf("--- 结果文本 ---\n%s\n", tr.text);
    if (tr.data) {
      char *pj = json_dump_pretty(tr.data);
      printf("--- 结构化结果 ---\n%s\n", pj);
      free(pj);
    }
    printf("\n(本次共发起 %d 次请求)\n", ctx.http_calls);
    json_free(args);
    free(tr.text);
    free(tr.say);
    json_free(tr.data);
    store_close(store);
    net_shutdown();
    rules_shutdown();
    return rc == 0 ? 0 : 1;
  }

  if (str_ieq(cmd, "regextest")) {
#ifdef BW_RELEASE
    printf("发布版不带 regextest。要验自定义正则,请用调试版(agent-dev.exe)。\n");
    net_shutdown();
    rules_shutdown();
    return 1;
#else

    const char *pattern = (argc > 2) ? argv[2] : "";
    const char *text = (argc > 3) ? argv[3] : "";
    if (!pattern[0] || !text[0]) {
      printf("用法: agent.exe regextest \"<正则>\" \"<样本文本>\"\n");
      printf("      例: agent.exe regextest \"EMP[0-9]{8}\" \"工号 EMP2024001234\"\n");
      net_shutdown();
      rules_shutdown();
      return 1;
    }
    int off = 0, len = 0;
    printf("正则: %s\n样本: %s\n", pattern, text);
    if (tools_regex_first(pattern, text, &off, &len)) {
      printf("命中: 位置 %d,长度 %d → \"%.*s\"\n", off, len, len, text + off);
    } else {
      printf("没有命中(检查字符类/量词写法,或样本是否真的包含它)\n");
    }

    printf("当前生效规则: %s\n", rules_source());
    net_shutdown();
    rules_shutdown();
    return 0;
#endif
  }

  if (str_ieq(cmd, "netbench")) {
#ifdef BW_RELEASE
    printf("发布版不带 netbench。要看网络层基准,请用调试版(agent-dev.exe)。\n");
    net_shutdown();
    rules_shutdown();
    return 1;
#else

    const char *target = (argc > 2) ? argv[2] : "";
    int n = (argc > 3) ? atoi(argv[3]) : 20;
    if (!target[0]) {
      printf("用法: agent.exe netbench <授权域名或URL> [次数]\n");
      return 1;
    }
    char host[256];
    net_host_port_of(target, host, sizeof(host));
    net_align_base_from(target);
    const char *doms[1];
    int nd = 0;
    if (host[0]) { doms[0] = host; nd = 1; }
    net_set_scope("BENCH", nd ? doms : NULL, nd);
    char url[512];
    snprintf(url, sizeof(url), "%s", target);
    if (!str_icontains(url, "://")) {
      snprintf(url, sizeof(url), "http://%s/", target);
    }
    printf("基准目标:%s(授权域名:%s)\n\n", url, nd ? host : "(未限定)");
    int conns = 0, reqs = 0;
    int avg = net_bench(url, n, &conns, &reqs);
    printf("\n提示:这一项是「网络层到底快不快」的实测口子。当前结论是 ——\n"
           "      WinHTTP 会话本身就带连接池,手工缓存连接句柄没有可测量收益(已实测);\n"
           "      真正影响检出与速度的是解压开关、超时与限速(rules.json 的 probing)。\n");
    net_shutdown();
    rules_shutdown();
    return avg < 0 ? 1 : 0;
#endif
  }

  if (str_ieq(cmd, "chat")) {

    const char *domain = (argc > 2) ? argv[2] : NULL;
    char scope_host[256];
    scope_host[0] = 0;
    const char *domains[1];
    int nd = 0;
    if (domain) {
      net_host_port_of(domain, scope_host, sizeof(scope_host));
      if (!scope_host[0]) snprintf(scope_host, sizeof(scope_host), "%s", domain);
      domains[0] = scope_host;
      nd = 1;
      net_align_base_from(domain);
    }

    const char *ddir = app_data_dir();
    ensure_dir(ddir);
    res_bootstrap_data_dir();
    store_t *store = store_open(ddir);
    char audit_path[MAX_PATH * 2];
    app_data_path(audit_path, sizeof(audit_path), "audit.jsonl");
    net_set_audit_path(audit_path);
    net_set_readonly(1);
    {

      const char *base = getenv("TARGET_BASE_URL");
      if (base && *base) net_set_target_base(base);
    }

    agent_t *a = agent_create("cli-session");

    char task_id[64] = "CLI-TASK";
    {
      int nk = 0, nf = 0;
      const char **kw = rules_str_list("profile_keywords", &nk);
      const char **ft = rules_str_list("profile_file_types", &nf);
      json_t *kws = j_arr();
      for (int i = 0; i < nk; i++) j_add(kws, j_str(kw[i]));
      json_t *fts = j_arr();
      for (int i = 0; i < nf; i++) j_add(fts, j_str(ft[i]));
      char *pid = store_ensure_profile(store, "默认敏感信息定义(随规则层)", kws, fts, NULL);
      if (nd) {
        char tname[320];
        snprintf(tname, sizeof(tname), "对 %s 的命令行授权巡检", domains[0]);
        char *tid = store_ensure_task(store, domains, nd, tname, pid);
        if (tid) snprintf(task_id, sizeof(task_id), "%s", tid);
        free(tid);
      }
      free(pid);
      json_free(kws);
      json_free(fts);
    }
    agent_set_scope(a, task_id, nd ? domains : NULL, nd);
    agent_set_store(a, store, "");
    agent_hooks_t h;
    memset(&h, 0, sizeof(h));
    h.on_thinking = cli_on_thinking;
    h.on_action = cli_on_action;
    h.on_status = cli_on_status;
    h.on_observation = cli_on_observation;
    h.on_ask = cli_on_ask;
    h.on_answer = cli_on_answer;
    agent_set_hooks(a, &h);

    printf("模型:%s\n", providers_display_name());
    printf("配置:%s\n", providers_path());
    printf("授权域名:%s\n", nd ? domains[0] : "(未设置 —— 不会对外发请求)");
    printf("输入问题,回车执行;输入 exit 退出。\n\n");

    char line[2048];
    while (1) {
      printf("你> ");
      fflush(stdout);
      if (!fgets(line, sizeof(line), stdin)) break;
      char *t = str_trim(line);
      if (!t[0]) continue;
      if (str_ieq(t, "exit") || str_ieq(t, "quit")) break;

      loop_state_t st;
      agent_run_turn(a, t, &st);
      printf("\n--- 本轮留痕(%d 步,停止原因:%s)---\n%s\n", st.step_count,
             st.stop_reason, st.transcript.data ? st.transcript.data : "");
      buf_free(&st.transcript);
      json_free(st.steps);
    }
    agent_free(a);
    store_close(store);
    net_shutdown();
    return 0;
  }

  if (str_ieq(cmd, "start")) {

    SetConsoleTitleW(L"BlueWhiteAgent —— 关掉本窗口即停止");

    printf("\n");
    printf("  ╔══════════════════════════════════════════════════════════╗\n");
    printf("  ║  BlueWhiteAgent · 网站安全巡检智能体                     ║\n");
    printf("  ╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  正在启动,界面窗口会自动打开 ……\n");
    printf("\n");
    printf("  · 第一次使用:在弹出的窗口里填「目标域名」并勾选授权,然后直接说话,\n");
    printf("    例如「把这个站完整巡检一遍」\"复测一下\"\"出报告\"\"核对证据\"。\n");
    printf("  · 界面对话与结果都保存在 %s\\ 下(数据目录,可用 BW_AGENT_HOME 改)。\n",
           app_data_dir());
    printf("  · 想停止:关掉这个黑色窗口即可(界面窗口也可以关了)。\n");
    printf("\n");
    printf("  ────────────────────────────────────────────────────────────\n");

    const char *domain = getenv("DAS_TARGET");
    int ok = 0;
    printf("  数据目录 : %s\\\n\n", app_data_dir());

    int port = instance_pick_free_port(8765, 8775);
    if (port <= 0) {
      printf("\n  8765-8775 都已被占用,无法启动。\n"
             "  关掉占用这些端口的程序再试,或用 `agent.exe serve <域名> <端口>` 指定一个空闲端口。\n\n");
      log_error("启动失败:8765-8775 全部被占用");
      net_shutdown();
      return 1;
    }
    if (port != 8765) log_info("默认端口 8765 被占用,改用 %d", port);
    if (serve_run(domain, port, 1) == 0) ok = 1;
    net_shutdown();
    if (!ok) {
      printf("\n  启动失败。请把上面的提示截图反馈。\n");
      printf("  按回车键关闭窗口……");
      getchar();
    }
    return ok ? 0 : 1;
  }

  if (str_ieq(cmd, "serve")) {

    const char *domain = NULL;
    int port = 8765;
    int open_ui = 1;
    for (int i = 2; i < argc; i++) {
      int all_digit = argv[i][0] != 0;
      for (const char *p = argv[i]; *p; p++) {
        if (*p < '0' || *p > '9') { all_digit = 0; break; }
      }
      if (str_ieq(argv[i], "--no-ui")) {
        open_ui = 0;
      } else if (str_ieq(argv[i], "--port") && i + 1 < argc) {
        port = atoi(argv[++i]);
      } else if (all_digit) {
        port = atoi(argv[i]);
      } else {
        domain = argv[i];
      }
    }
    int rc = serve_run(domain, port, open_ui);
    net_shutdown();
    return rc;
  }

  net_shutdown();
  return 0;
}

#ifdef AGENT_GUI_BUILD
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
  (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShow;
  int argc = 0;
  char **argv = app_argv_from_command_line(&argc);
  int rc = app_main(argc, argv);
  free_argv(argc, argv);
  log_close();
  return rc;
}
#else
int main(int argc, char **argv) { return app_main(argc, argv); }
#endif


#include "serve_ctx.h"

#include "ext.h"
#include "json.h"
#include "llm.h"
#include "net.h"
#include "skills.h"
#include "tools.h"

void api_caps(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "POST") == 0) {
    json_t *body = req->body ? json_parse(req->body) : NULL;
    if (!body) {
      http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}");
      return;
    }
    const char *action = j_s(body, "action", "");
    if (str_ieq(action, "reload")) {
      ext_reload_local();
      json_free(body);
      json_t *o = j_obj();
      j_set_bool(o, "ok", 1);
      j_set_num(o, "tools", tools_count());
      j_set_num(o, "skills", skills_count());
      char *text = json_dump(o);
      http_res_json(res, 200, text);
      free(text);
      json_free(o);
      return;
    } else if (str_ieq(action, "draft")) {

      const char *kind = j_s(body, "kind", "skill");
      const char *brief = j_s(body, "brief", "");
      json_t *draft = j_obj();
      int from_model = 0;

      buf_t prompt;
      buf_init(&prompt);
      if (str_ieq(kind, "mcp")) {
        buf_puts(&prompt,
            "你在写一条 Model Context Protocol(MCP)服务器配置,会被放进 mcp.json 的 mcpServers 里。\n"
            "只输出一个 JSON 对象,不要解释、不要代码块。字段:name(服务器名,小写字母数字连字符)、\n"
            "command(可执行程序,如 npx / uvx / python)、args(字符串数组)、env(可选,字符串到字符串的对象)。\n"
            "只写标准 MCP 服务器的启动方式,不要编造不存在的包。\n用户需求:");
      } else {
        json_free(body);
        http_res_json(res, 400,
                      "{\"ok\":false,\"error\":\"draft 只给 MCP 用;技能与工具请直接编辑定义文件\"}");
        return;
      }
      buf_puts(&prompt, brief);
      buf_t out;
      buf_init(&out);
      int ok = llm_ask(prompt.data, &out);
      buf_free(&prompt);
      if (ok == 0) {
        const char *s = out.data ? strstr(out.data, "{") : NULL;
        json_t *parsed = s ? json_parse(s) : NULL;
        if (parsed && parsed->type == J_OBJ) {
          j_set(draft, "draft", parsed);
          from_model = 1;
        } else {
          json_free(parsed);
          j_set_str(draft, "note", "模型返回的内容不是可用的 JSON,已给出模板");
        }
      } else {
        j_set_str(draft, "note", llm_last_error()[0] ? llm_last_error()
                                                     : "模型当前不可用,已给出模板");
      }
      buf_free(&out);
      if (!from_model) {
        json_t *t = j_obj();
        j_set_str(t, "name", "my-mcp");
        j_set_str(t, "command", "npx");
        json_t *args = j_arr();
        j_add(args, j_str("-y"));
        j_add(args, j_str("@modelcontextprotocol/server-filesystem"));
        j_add(args, j_str("C:\\data"));
        j_set(t, "args", args);
        j_set(draft, "draft", t);
      }
      j_set_bool(draft, "ok", 1);
      j_set_bool(draft, "fromModel", from_model);
      char *text = json_dump(draft);
      http_res_json(res, 200, text);
      free(text);
      json_free(draft);
      json_free(body);
      return;
    } else {
      json_free(body);
      http_res_json(res, 400, "{\"ok\":false,\"error\":\"未知的 action\"}");
      return;
    }

    json_free(body);
    return;
  }

  json_t *inv = ext_inventory_json();
  json_t *extSkills = j_get(inv, "skills");
  json_t *mcp = j_get(inv, "mcp");

  char dirSkills[MAX_PATH * 2], dirTools[MAX_PATH * 2];
  ext_dir(dirSkills, sizeof(dirSkills), "skills");
  ext_dir(dirTools, sizeof(dirTools), "tools");

  json_t *skills = j_arr();
  for (int i = 0; i < skills_count(); i++) {
    skill_t *sk = skills_get(i);
    if (!sk || !sk->name) continue;
    json_t *o = j_obj();
    j_set_str(o, "name", sk->name);
    j_set_str(o, "title", sk->title ? sk->title : "");
    j_set_str(o, "purpose", sk->purpose ? sk->purpose : "");
    j_set_str(o, "when", sk->when ? sk->when : "");
    j_set_str(o, "tools", sk->tools ? sk->tools : "");
    j_set_str(o, "source", "内置");
    char mdPath[MAX_PATH * 4];
    snprintf(mdPath, sizeof(mdPath), "%s\\%s.md", dirSkills, sk->name);
    if (file_size(mdPath) >= 0) j_set_bool(o, "customized", 1);
    for (int k = 0; k < j_len(extSkills); k++) {
      if (strcmp(j_s(j_at(extSkills, k), "name", ""), sk->name) == 0) {
        j_set_str(o, "source", "技能包");
        j_set_str(o, "file", j_s(j_at(extSkills, k), "file", ""));
        j_set_str(o, "body", j_s(j_at(extSkills, k), "body", ""));
        break;
      }
    }
    j_add(skills, o);
  }

  json_t *tools = j_arr();
  for (int i = 0; i < tools_count(); i++) {
    tool_t *t = tools_get(i);
    if (!t || !t->name) continue;
    json_t *o = j_obj();
    j_set_str(o, "name", t->name);
    j_set_str(o, "kind", t->kind ? t->kind : "");
    j_set_str(o, "description", t->description ? t->description : "");
    j_set_str(o, "schema", t->schema ? t->schema : "");

    const char *src = "内置";
    if (str_startswith(t->name, "mcp__")) src = "MCP";
    else if (t->external) src = "外部";
    j_set_str(o, "source", src);
    j_set_str(o, "sourceUrl", t->source_url ? t->source_url : "");
    j_add(tools, o);
  }

  int nTools = 0, nSkills = 0, nMCP = 0, nMCPTools = 0;
  ext_stats(&nTools, &nSkills, &nMCP, &nMCPTools);

  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set(root, "skills", skills);
  j_set(root, "tools", tools);

  {
    char *mcpText = json_dump(mcp);
    json_t *mcpCopy = mcpText ? json_parse(mcpText) : NULL;
    free(mcpText);
    j_set(root, "mcp", mcpCopy ? mcpCopy : j_arr());
  }
  j_set_str(root, "skillsDir", dirSkills);
  j_set_str(root, "toolsDir", dirTools);
  json_t *stats = j_obj();
  j_set_num(stats, "skills", skills_count());
  j_set_num(stats, "tools", tools_count());
  j_set_num(stats, "extSkills", nSkills);
  j_set_num(stats, "extTools", nTools);
  j_set_num(stats, "mcp", nMCP);
  j_set_num(stats, "mcpTools", nMCPTools);
  j_set(root, "stats", stats);
  char *text = json_dump(root);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
  json_free(inv);
}

# 协作说明

这个仓库是一个 C++20 单文件 exe 加内置网页界面的作品，下面是多人一起改时最少要知道的事。

## 一、环境

需要的只有两样：MinGW-w64 的 g++（13 以上，实测 GCC 16.2），以及 Windows 10 或 11，因为用了 WinHTTP、Win32 目录 API 和 Winsock。

```
构建:
  Agent-Zero\build.bat          发布版，产物 Agent-Zero\build\BlueWhiteAgent.exe，单文件，双击即用，不带自检
  Agent-Zero\build.bat debug    调试版，产物 Agent-Zero\build\BlueWhiteAgent-dev.exe，带自检、正则验枪口、网络基准

自检（只有调试版有）:
  Agent-Zero\build\BlueWhiteAgent-dev.exe selftest     118 项，必须全绿
```

`build.bat` 会把 `Agent-Zero\ui\` 和 `Agent-Zero\data\rules\` 编进 exe，见 `Agent-Zero\tools\mkres.cpp`，所以改完界面不用另外分发文件，重新编译即可。

数据目录默认 `C:\Users\<你>\.bw_agent`。想让测试跟仓库无关地跑，把 `BW_AGENT_HOME` 指到别处。

## 二、分支与提交

- `main` 保护，只能通过 PR 合入，CI 必须绿
- 功能分支用 `feat/短描述`，修复用 `fix/短描述`，一次 PR 只做一件事
- 提交信息用 `feat:`、`fix:`、`refactor:`、`docs:`、`test:` 开头，正文说清为什么
- 提交前本地至少跑一遍：`Agent-Zero\build.bat debug && Agent-Zero\build\BlueWhiteAgent-dev.exe selftest`

## 三、必须守住的四条线

这是安全工具，改代码时下面四件事不能破。

1. 边界：所有对外请求只能走 `net.cpp`。授权池 `pool.json` 是唯一边界，池外请求必须被拒并置越权标记 `net_scope_violation`，让决策循环立刻收束。
2. 只读：`net_set_readonly(1)` 下只允许 GET 和 HEAD，不要为了方便加 POST 或 PUT。
3. 留痕：新加的对外动作要 `net_audit(...)`；发现落盘要走 `store_upsert_finding`。
4. 审批：工具执行前会过 `approval_decide`，不要在工具内部绕开这道闸。

## 四、常见改动落点

| 想改什么 | 改哪里 |
|---|---|
| 检测口径（正则、弱口令表、目录清单等） | `data\rules\*.json`，这是数据不是代码 |
| 新增一个原子动作 | `Agent-Zero\src\main\tools.cpp`，并在工具表里登记 schema |
| 新增编排型能力 | `Agent-Zero\src\main\skills.cpp` 是检查类，`skills_closure.cpp` 是收尾类 |
| 界面 | `Agent-Zero\ui\index.html`、`app.css`、`app.js`，只通过 HTTP 和 SSE 与后端说话 |
| 授权池、周期巡检、审批、导出 | `net.cpp`、`automation.cpp`、`approval.cpp`、`export.cpp` |
| 本单位敏感信息定义 | `profile.cpp` 加界面里的敏感信息定义页 |

新增 `.cpp` 不用改构建脚本，`build.bat` 按 `src\main\*.cpp` 通配。

## 五、界面约定

后端只提供数据，前端不复制业务统计逻辑，否则页面上的数字和报告里的数字会变成两套。

可读性底线：正文不小于 13.5px，标签不小于 12px，正文对比度不低于 4.5:1。改样式前先看 `app.css` 顶部那段约束。

## 六、提交 PR 前自查

```
[ ] Agent-Zero\build.bat 通过
[ ] Agent-Zero\build\BlueWhiteAgent-dev.exe selftest 全绿
[ ] 没有把 .env、令牌、真实站点数据提交进来
[ ] 新增的对外请求过了 net.cpp，没有自己开 socket 或 WinHTTP
[ ] 新增的配置项写进了 README 与界面，不只藏在代码里
```

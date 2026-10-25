
r"""
关卡注册表
==================================================================

每个关卡是 `levels/` 下的一个模块，对外只需暴露一个 `LEVEL` 字典：

    LEVEL = {
        "id":         1,
        "key":        "l1",
        "name":       "公开的秘密",
        "difficulty": "★☆☆☆☆",
        "summary":    "一句话说明这一关考什么难度层次",
        "hints":      "给测试者的提示（不剧透具体答案）",
        "tags":       ["敏感信息", ...],
        "banner":     "Apache/2.4.29",
        "headers":    {...},
        "methods":    ("GET", "HEAD"),
        "autoindex":  True,
        "assets":     "l1",
        "routes":     [(方法, 正则, 处理函数), ...],
        "not_found":  函数,
        "dir_locked": 函数,
        "handle":     函数,
    }

核心（`serve.py`）的匹配顺序是：

    方法白名单 → handle() → routes() → 静态文件 → not_found()

所以一个关卡只要不写 `routes`，就退化成一个纯静态站点；
写得越多，行为越"像真的"。
==================================================================
"""

import importlib
import sys

_MODULES = (
    "levels.l0_denied",
    "levels.l1_open",
    "levels.l2_hidden",
    "levels.l3_evasive",
    "levels.l4_logic",
    "levels.l5_forensic",
    "levels.l6_chain",
)

def _build():
    registry = {}
    for name in _MODULES:
        module = importlib.import_module(name)
        level = dict(module.LEVEL)
        level.setdefault("key", name.rsplit(".", 1)[-1])
        level.pop("key_override", None)
        registry[level["key"]] = level
    return dict(sorted(registry.items(), key=lambda kv: kv[1]["id"]))

REGISTRY = _build()

def all_keys():
    """当前已加载的关卡 key（供 --only 报错时提示）。"""
    return list(REGISTRY.keys())

def get(key):
    return REGISTRY.get((key or "").lower())

__all__ = ["REGISTRY", "all_keys", "get"]

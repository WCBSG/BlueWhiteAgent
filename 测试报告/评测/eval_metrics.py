#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按关卡设计表统计巡检结论的召回率与准确率。

用法:
    python eval_metrics.py <数据目录根> [--json 输出文件]

数据目录根下应有 ev-l1 … ev-l6,每个目录里是 findings.jsonl。
"""
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

GT = {
    "l1": [
        ("敏感信息", "/l1/", "首页身份证/手机号/后台口令/内网地址明文", ["敏感信息"], None),
        ("敏感信息", "/l1/files/config.php.bak", "配置备份含数据库与 FTP 口令", ["敏感信息"], None),
        ("敏感信息", "/l1/files/db.sql", "数据库导出可下载", ["敏感信息"], None),
        ("敏感信息", "/l1/files/contact-list.csv", "通讯录导出可下载", ["敏感信息"], None),
        ("挂马", "/l1/", "eval+atob 混淆脚本与隐藏 iframe", ["挂马", "篡改"], None),
        ("篡改", "/l1/", "页脚赌博推广外链", ["篡改", "挂马"], None),
        ("弱配置", "/l1/", "安全响应头缺失与版本泄漏", ["弱配置"], None),
        ("漏洞", "/l1/files/", "目录列表开启、备份文件可遍历", ["漏洞", "弱配置"], "目录索引|目录列表|备份", True),
        ("漏洞", "/l1/admin/", "后台入口无鉴权、表单预填口令", ["漏洞", "敏感信息"], "后台|管理入口", True),
        ("漏洞", "/l1/js/vendor/jquery.min.js", "旧版 jQuery 1.12.4", ["漏洞"], "组件|版本|jQuery"),
        ("漏洞", "/l1/robots.txt", "robots.txt 指路后台", ["漏洞"], "robots"),
        ("漏洞", "/l1/phpinfo.php", "phpinfo 信息泄露", ["漏洞"], "phpinfo"),
        ("漏洞", "/l1/files/download.php", "任意文件读取/目录穿越", ["漏洞"], "穿越|文件读取|包含"),
    ],
    "l2": [
        ("篡改", "/l2/", "标题与页脚被改（需基线比对）", ["篡改"], None),
        ("敏感信息", "/l2/news.html", "身份证前 12 位", ["敏感信息"], None),
        ("敏感信息", "/l2/notice.html", "身份证后 4 位与手机号", ["敏感信息"], None),
        ("敏感信息", "/l2/.env", "数据库/Redis/FTP 口令与云密钥", ["敏感信息"], None),
        ("敏感信息", "/l2/.git/logs/HEAD", "提交者姓名与单位邮箱", ["敏感信息"], None),
        ("漏洞", "/l2/.git/", "Git 元数据残留", ["漏洞", "敏感信息"], "版本库|Git|元数据", True),
        ("漏洞", "/l2/backup/website-backup-20231108.tar.gz", "整站备份归档可下载", ["漏洞", "敏感信息"], "备份|归档"),
        ("漏洞", "/l2/admin-backend/", "后台入口暴露且无鉴权", ["漏洞"], "后台|管理入口"),
        ("漏洞", "/l2/search.html", "反射型 XSS", ["漏洞"], "XSS|跨站"),
        ("漏洞", "/l2/js/vendor/bootstrap.min.js", "旧版 Bootstrap 3.3.7", ["漏洞"], "组件|版本|Bootstrap"),
        ("挂马", "/l2/js/stat.js", "混淆外部 JS 动态注入", ["挂马", "篡改"], None),
        ("弱配置", "/l2/", "响应头值无效与版本泄漏", ["弱配置"], None),
        ("漏洞", "/l2/upload.php", "无限制文件上传", ["漏洞"], "上传"),
        ("漏洞", "/l2/feedback.php", "存储型 XSS", ["漏洞"], "XSS|跨站"),
    ],
    "l3": [
        ("敏感信息", "/l3/notice.html", "手机号 HTML 实体编码", ["敏感信息"], None),
        ("敏感信息", "/l3/staff.html", "Base64 口令与 JS 拼接身份证", ["敏感信息"], None),
        ("敏感信息", "/l3/js/app.js", "接口地址/内部令牌/数据库连接串", ["敏感信息"], None),
        ("漏洞", "/l3/download/2023-archive.dat", "备份包伪装成 .dat（ZIP 魔术字）", ["漏洞", "敏感信息"], "备份|归档|压缩"),
        ("漏洞", "/l3/download/", "目录列表需请求头解锁", ["漏洞", "弱配置"], "目录索引|目录列表", True),
        ("漏洞", "/l3/js/vendor/jquery-3.4.1.min.js", "受影响版本 jQuery", ["漏洞"], "组件|版本|jQuery"),
        ("弱配置", "/l3/", "CSP 值有害、缺 HSTS/Permissions-Policy", ["弱配置"], None),
        ("挂马", "/l3/js/app.js", "无 eval 的动态注入与信标回传", ["挂马", "篡改"], None),
        ("篡改", "/l3/notice.html", "银行账号与值班电话各差 1 位", ["篡改"], None),
        ("篡改", "/l3/staff.html", "同一账号两页不一致", ["篡改"], None),
        ("漏洞", "/l3/includes/cache.php", "混淆 WebShell", ["漏洞"], "WebShell|后门|木马"),
        ("漏洞", "/l3/", "软 404（状态码不可信）", ["漏洞"], "软 ?404"),
    ],
    "l4": [
        ("敏感信息", "/l4/notice.html", "云 AccessKey/数据库口令/内网入口", ["敏感信息"], None),
        ("敏感信息", "/l4/api/v1/export", "全量人员表（参数凑对才返回）", ["敏感信息"], None),
        ("敏感信息", "/l4/download/roster-2024.csv", "人员名单 CSV（Referer 门禁）", ["敏感信息"], None),
        ("漏洞", "/l4/notice.html", "报错信息泄漏（堆栈/SQL/绝对路径）", ["漏洞"], "报错|异常|堆栈"),
        ("漏洞", "/l4/api/v1/export", "API 无鉴权，仅靠参数隐蔽", ["漏洞"], "鉴权|未授权|API"),
        ("漏洞", "/l4/upload/", "PUT/DELETE 方法开放", ["漏洞"], "方法|PUT|DELETE"),
        ("漏洞", "/l4/js/vendor/bootstrap.min.css", "旧版 Bootstrap 3.3.7", ["漏洞"], "组件|版本|Bootstrap"),
        ("弱配置", "/l4/notice.html", "安全响应头只在首页设置", ["弱配置"], None),
        ("挂马", "/l4/", "仅对移动端 UA 注入", ["挂马", "篡改"], None),
        ("篡改", "/l4/notice.html", "HTTPS 降级与电话改 1 位", ["篡改"], None),
        ("漏洞", "/l4/tools/page.php", "include 文件包含", ["漏洞"], "包含|LFI|文件读取"),
    ],
    "l5": [
        ("敏感信息", "/l5/staff.html", "零宽字符/隐藏表单/Set-Cookie 人事数据", ["敏感信息"], None),
        ("敏感信息", "/l5/images/seal.png", "PNG iTXt 元数据中的证件号", ["敏感信息"], None),
        ("敏感信息", "/l5/news.html", "证照号前半段", ["敏感信息"], None),
        ("漏洞", "/l5/_notes/", "仅靠自定义请求头保护的栏目", ["漏洞"], "_notes|内网|请求头", True),
        ("漏洞", "/l5/js/app.js", "解锁暗号写在脚本里", ["漏洞", "敏感信息"], "暗号|令牌|解锁"),
        ("弱配置", "/l5/", "缺全部现代安全响应头", ["弱配置"], None),
        ("挂马", "/l5/css/site.css", "CSS @import 外链与 preload", ["挂马", "篡改"], None),
        ("篡改", "/l5/download/", "公布的 SHA256 与文件实际值不符", ["篡改"], None, True),
        ("篡改", "/l5/images/seal.png", "采集时间晚于改版时间", ["篡改"], None),
        ("漏洞", "/l5/tools/restore.php", "unserialize 反序列化", ["漏洞"], "反序列化|unserialize"),
    ],
    "l6": [
        ("漏洞", "/l6/", "全站软 404，状态码不可信", ["漏洞"], "软 ?404"),
        ("漏洞", "/l6/.git/", "Git 元数据残留（需靠内容特征识别）", ["漏洞", "敏感信息"], "版本库|Git|元数据", True),
        ("漏洞", "/l6/src/site-2024.tar.gz", "源码归档可下载", ["漏洞", "敏感信息"], "源码|归档|备份"),
        ("漏洞", "/l6/api", "内部接口无令牌时拒绝", ["漏洞"], "接口|API|鉴权", True),
        ("敏感信息", "/l6/", "令牌前半与云密钥", ["敏感信息"], None),
        ("篡改", "/l6/", "首页 http 与公告页 https 不一致", ["篡改"], None),
    ],
}

def norm(path):
    path = (path or "").split("?")[0].split("#")[0]
    path = re.sub(r":\d+$", "", path)        
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path

def finding_carriers(f):
    """一条发现覆盖到的路径集合。"""
    out = set()
    t = f.get("target") or ""
    if t.startswith("http"):
        out.add(norm(urlparse(t).path))
    for tok in (f.get("evidence") or "").replace(";", " ").replace(",", " ").split():
        if tok.startswith("http"):
            out.add(norm(urlparse(tok).path))
    return out

def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    report = {}
    for level, units in GT.items():
        fp = root / f"ev-{level}" / "findings.jsonl"
        seen = {}
        if fp.exists():
            for line in fp.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    o = json.loads(line)
                    seen[o.get("id")] = o      
        findings = list(seen.values())

        unit_hits, coverage = [], {}
        for idx, (cat, carrier, title, kinds, title_re, *rest) in enumerate(units):
            is_dir = bool(rest and rest[0])
            base = norm(carrier)
            hits = []
            for f in findings:
                pset = finding_carriers(f)
                covered = any(p == base or (is_dir and p.startswith(base + "/")) for p in pset)
                if not covered:
                    continue
                if f.get("kind") in kinds or (title_re and re.search(title_re, f.get("title", ""))):
                    hits.append(f)
            unit_hits.append(hits)
            for f in hits:
                coverage.setdefault(f["id"], []).append(idx)

        rows, hit = [], 0
        for idx, (cat, carrier, title, _k, _r, *rest) in enumerate(units):
            first = unit_hits[idx][0] if unit_hits[idx] else None
            hit += 1 if first else 0
            rows.append({"category": cat, "carrier": carrier, "title": title,
                         "hit": bool(first),
                         "by": f"{first['id']} {first['kind']}/{first['title']}" if first else ""})

        fp_list = [f"{f['id']} {f['kind']}/{f['title']} @ {f.get('target', '')}"
                   for f in findings if f["id"] not in coverage]
        valid = len(findings) - len(fp_list)
        covered_units = {i for i, h in enumerate(unit_hits) if h}
        first_ids = {unit_hits[i][0]["id"] for i in covered_units}
        tp = valid
        dup_list = [f"{f['id']} {f['kind']}/{f['title']}"
                    for f in findings if f["id"] not in first_ids and f["id"] in coverage]
        report[level] = {
            "gt": len(units), "hit": hit,
            "recall": round(hit / len(units), 4) if units else 0,
            "findings": len(findings), "tp": tp, "dup": len(dup_list),
            "fp": len(fp_list),
            "precision": round(tp / (tp + len(fp_list)), 4) if (tp + len(fp_list)) else 0,
      "rows": rows, "fp_list": fp_list, "dup_list": dup_list,
        }

    total_gt = sum(v["gt"] for v in report.values())
    total_hit = sum(v["hit"] for v in report.values())
    total_fp = sum(v["fp"] for v in report.values())
    total_tp = sum(v["tp"] for v in report.values())
    total_f = sum(v["findings"] for v in report.values())
    summary = {
        "gt": total_gt, "hit": total_hit, "recall": round(total_hit / total_gt, 4),
        "findings": total_f, "tp": total_tp, "fp": total_fp,
        "dup": total_f - total_tp - total_fp,
        "precision": round(total_tp / (total_tp + total_fp), 4) if (total_tp + total_fp) else 0,
        "fp_rate": round(total_fp / total_f, 4) if total_f else 0,
    }

    print(f"{'关卡':<6}{'真值':>5}{'命中':>5}{'召回':>8}{'结论':>6}{'误报':>5}{'准确':>8}")
    for level, v in report.items():
        print(f"{level:<6}{v['gt']:>5}{v['hit']:>5}{v['recall']*100:>7.1f}%"
              f"{v['findings']:>6}{v['fp']:>5}{v['precision']*100:>7.1f}%")
    print(f"{'合计':<6}{summary['gt']:>5}{summary['hit']:>5}{summary['recall']*100:>7.1f}%"
          f"{summary['findings']:>6}{summary['fp']:>5}{summary['precision']*100:>7.1f}%")
    print(f"\n误报率(误报/全部结论): {summary['fp_rate']*100:.1f}%"
          f"   重复结论: {summary['dup']} 条")

    cats = {}
    for v in report.values():
        for r in v["rows"]:
            c = cats.setdefault(r["category"], [0, 0])
            c[0] += 1
            c[1] += 1 if r["hit"] else 0
    print("\n按类别:")
    for c, (n, h) in cats.items():
        print(f"  {c:<6}{h:>3}/{n:<3}{h*100/n:>6.1f}%")

    for level, v in report.items():
        miss = [r["carrier"] + " · " + r["title"] for r in v["rows"] if not r["hit"]]
        if miss:
            print(f"\n[{level}] 漏检 {len(miss)} 项:")
            for m in miss:
                print("  - " + m)
        if v["fp_list"]:
            print(f"[{level}] 误报 {len(v['fp_list'])} 项:")
            for m in v["fp_list"]:
                print("  ! " + m)

    out = Path(sys.argv[sys.argv.index("--json") + 1]) if "--json" in sys.argv else None
    if out:
        out.write_text(json.dumps({"summary": summary, "levels": report},
                                  ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n已写出 {out}")

if __name__ == "__main__":
    main()

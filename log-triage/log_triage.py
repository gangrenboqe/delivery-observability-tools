#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
log_triage —— 把一堆日志变成一份"到底有几种错、什么时候开始、最早出现在哪"的报告

它回答的四个问题（这才是排障真正要花时间的地方）：
    1. 一共多少行、覆盖多长时间？
    2. 有几个级别、各多少条？
    3. 错误**归并**成几类？每类第一次/最后一次出现在什么时候、哪个文件第几行？
    4. 错误什么时候开始密集出现（突增点）？

为什么"归并"是核心：
    timeout after 123ms / timeout after 456ms / timeout after 7890ms
    是**同一类**错。不归并的话 Top N 全是重复行，报告等于没做。

支持两种输入（自动识别）：
    · 行式文本日志（.log / .txt）—— 流式读，100MB 也不会撑爆内存
    · 网关的 JSON 调用日志（.json，一次调用一个文件）—— 取其中的状态与错误字段

隐私：只统计级别、时间、错误类型；**不输出完整日志行**。
    ⚠️ 注意：「错误类型」是去掉 ID/数字/路径后的**消息文本**，正文措辞仍可能保留
    —— 报告要给外人看之前，先人工过目一遍。

用法：
    python log_triage.py --log-dir <目录> --out <输出目录>
    python log_triage.py --log-dir <目录> --top 15

依赖：无（只用 Python 标准库）
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

TEXT_EXT = {".log", ".txt", ".out", ".err"}

# 级别识别：兼容英文与中文；认不出来就归"未知"，**绝不瞎猜**
LEVEL_PATTERNS = [
    (re.compile(r"\b(FATAL|CRITICAL|CRIT|SEVERE)\b|严重|致命"), "FATAL"),
    (re.compile(r"\b(ERROR|ERR|EXCEPTION|TRACEBACK)\b|错误|异常|失败"), "ERROR"),
    (re.compile(r"\b(WARN|WARNING)\b|警告"), "WARN"),
    (re.compile(r"\b(INFO|NOTICE)\b|信息|提示"), "INFO"),
    (re.compile(r"\b(DEBUG|TRACE|VERBOSE)\b|调试"), "DEBUG"),
]

TS_PATTERNS = [
    re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"),
    re.compile(r"(\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2})"),
    re.compile(r"(\d{4}-\d{2}-\d{2})"),
]

# 归并规则。⚠️ 顺序不能改：先掩码 ID，再折叠数字（否则十六进制会先被打成 NbNaNbN）
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
HEX_RE = re.compile(r"\b[0-9a-fA-F]{8,}\b")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
WINPATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"']+")
NUM_RE = re.compile(r"\d+")
# 行首的 [123] / (123) / #123 通常是线程号、错误码或行号，**不带它语义反而更准**
LEAD_NUM_RE = re.compile(r"^(?:\[\d+\]|\(\d+\)|#\d+)\s*")


def normalize(msg: str | None) -> str:
    """把一条消息归一成"错误类型"：同类必须得到同一个字符串。

    🔴🔴 **执行顺序决定成败，这是本项目踩过两次的坑**：
      必须「先剥掉结构性前缀 → 再掩码 ID → 最后才把数字折叠成 N」。
      反过来做的话，`[123] Request aborted` 会先变成 `[N] Request aborted`，
      前缀规则再也匹配不上，同类就被拆成两类。

    🔁 **与 projects/model-call-report 的 normalize_error() 是同一套规则**
    （2026-10-11 第三方复核统一）：同一条错误在两个工具里必须归成同一类，
    空消息兜底同为「（无错误信息）」，截断同为 80 字符 —— **改这里必改那边**。
    """
    if not msg:
        return "（无错误信息）"
    s = LEAD_NUM_RE.sub("", str(msg))   # ① 先剥 [123] / (42) / #7 这类前缀
    s = UUID_RE.sub("<uuid>", s)        # ② 再掩码 ID
    s = HEX_RE.sub("<id>", s)
    s = IP_RE.sub("<ip>", s)
    s = WINPATH_RE.sub("<path>", s)
    s = NUM_RE.sub("N", s)              # ③ 最后才折叠数字
    s = re.sub(r"\s+", " ", s).strip()
    return s[:80]


def detect_level(line: str) -> str:
    for pat, name in LEVEL_PATTERNS:
        if pat.search(line):
            return name
    return "未知"


def extract_ts(line: str) -> str:
    """抽出时间戳并统一成 'YYYY-MM-DD HH:MM:SS'。

    🔴 必须把 ISO 里的 'T' 换成空格：真实日志是 `2026-10-06T02:57:03`，
    直接显示会让"时间跨度"和"按小时分布"两处的格式对不上（实测踩过）。
    """
    for pat in TS_PATTERNS:
        m = pat.search(line)
        if m:
            return m.group(1).replace("/", "-").replace("T", " ")
    return ""


# ---------------------------------------------------------------- 读取

def iter_text_lines(path: Path):
    """流式逐行读，**不做整份载入**，并对无法解码的字节容错。"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            yield i, line.rstrip("\n")


def load_json_calls(path: Path) -> list[dict]:
    """读网关的一次调用日志，取出安全字段。"""
    out = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return out
    s = data.get("summary") or {}
    if not s:
        return out
    err = s.get("error") or data.get("error")
    if isinstance(err, dict):
        err = err.get("message") or err.get("code")
    status = s.get("status")
    if isinstance(status, int) and 200 <= status < 300:
        level = "INFO"
    elif isinstance(status, int):
        level = "ERROR"
    else:
        level = "未知"   # 没有 status 就说认不出来，不猜成 ERROR（2026-10-11 复核修正）
    out.append({
        "ts": extract_ts(str(s.get("timestamp", ""))),
        "level": level,
        "msg": err or ("HTTP %s" % status if status is not None else "（无状态码）"),
        "where": path.name,
    })
    return out


def triage(paths: list[Path]) -> dict:
    """核心：把一堆文件跑成结构化结果。"""
    levels = Counter()
    kinds = defaultdict(lambda: {"count": 0, "first_ts": "", "last_ts": "",
                                 "first_at": "", "last_at": ""})
    total_lines = 0
    total_files = 0
    ts_all = []
    by_hour = Counter()
    err_by_hour = Counter()   # 只数错误行（ERROR/FATAL/未知），突增看这个，不看全部行

    for p in paths:
        if not p.is_file():
            continue
        total_files += 1
        rows = []
        if p.suffix.lower() == ".json":
            rows = [(0, r) for r in load_json_calls(p)]
            total_lines += len(rows)
        else:
            for lineno, line in iter_text_lines(p):
                total_lines += 1
                if not line.strip():
                    continue
                rows.append((lineno, {"ts": extract_ts(line), "level": detect_level(line),
                                      "msg": line, "where": "%s:%d" % (p.name, lineno)}))

        for lineno, r in rows:
            lv = r["level"]
            levels[lv] += 1
            ts = r["ts"]
            if ts:
                ts_all.append(ts)
                by_hour[ts[:13]] += 1
            if lv not in ("ERROR", "FATAL", "未知"):
                continue
            if ts:
                err_by_hour[ts[:13]] += 1
            key = normalize(r["msg"])
            k = kinds[key]
            k["count"] += 1
            where = r["where"]
            if lineno:
                where = "%s:%d" % (p.name, lineno)
            if ts and (not k["first_ts"] or ts < k["first_ts"]):
                k["first_ts"] = ts
                k["first_at"] = where
            if ts and (not k["last_ts"] or ts > k["last_ts"]):
                k["last_ts"] = ts
                k["last_at"] = where

    ts_all.sort()
    top = sorted(kinds.items(), key=lambda kv: kv[1]["count"], reverse=True)

    # 突增检测：哪个小时的**错误行数**明显高于错误的常态（2026-10-11 复核修正：
    # 旧版误用全部行数，INFO 刷屏会被误判成突增；err_hours 死代码已删）
    bursts = []
    if err_by_hour:
        counts = sorted(err_by_hour.values())
        half = len(counts) // 2
        med = counts[half]
        if len(counts) % 2 == 0 and half > 0:
            med = (counts[half - 1] + counts[half]) / 2
        med = med or 1
        for h, n in sorted(err_by_hour.items()):
            if n >= max(med * 3, 3):
                bursts.append((h, n))

    return {
        "total_files": total_files,
        "total_lines": total_lines,
        "span": (ts_all[0] if ts_all else "") + " ~ " + (ts_all[-1] if ts_all else ""),
        "levels": levels.most_common(),
        "kinds": top,
        "by_hour": sorted(by_hour.items()),
        "bursts": bursts,
    }


# ---------------------------------------------------------------- 渲染

def render(r: dict, top_n: int) -> str:
    L = ["# 日志体检报告", ""]
    L.append(f"- 扫描文件：**{r['total_files']}** 个｜总行数：**{r['total_lines']}**")
    L.append(f"- 时间跨度：{r['span'] or '未识别到时间戳'}")
    L.append("")

    L.append("## 一、级别分布")
    L.append("")
    if r["levels"]:
        L.append("| 级别 | 条数 |")
        L.append("|---|---|")
        for k, n in r["levels"]:
            L.append(f"| {k} | {n} |")
    else:
        L.append("没有可识别的日志行。")
    L.append("")

    L.append(f"## 二、错误类型 Top {top_n}（同类已归并）")
    L.append("")
    if not r["kinds"]:
        L.append("未发现 ERROR / FATAL / 未知级别的行。")
    else:
        L.append("| # | 错误类型 | 次数 | 首次出现 | 首次位置 | 末次出现 |")
        L.append("|---|---|---|---|---|---|")
        for i, (k, v) in enumerate(r["kinds"][:top_n], 1):
            L.append(f"| {i} | `{k}` | {v['count']} | {v['first_ts'] or '—'} "
                     f"| {v['first_at'] or '—'} | {v['last_ts'] or '—'} |")
        L.append("")
        L.append(f"> 归并前共 {r['total_lines']} 行，归并后是 **{len(r['kinds'])} 类**。"
                 f"这就是体检的意义——不然你要自己从几千行里数。")
    L.append("")

    L.append("## 三、按小时分布")
    L.append("")
    if r["by_hour"]:
        L.append("| 小时 | 行数 |")
        L.append("|---|---|")
        for h, n in r["by_hour"][:48]:
            L.append(f"| {h} | {n} |")
    else:
        L.append("未识别到时间戳，无法按小时统计。")
    L.append("")

    L.append("## 四、可疑突增点")
    L.append("")
    if r["bursts"]:
        for h, n in r["bursts"]:
            L.append(f"- **{h}**：{n} 条错误（约为错误常态的 3 倍以上）")
    else:
        L.append("没有检测到明显突增。")
    L.append("")
    L.append("---")
    L.append("> 本工具只输出级别、时间与归并后的错误类型，**不输出完整日志行**；"
             "错误类型保留了去 ID/数字后的消息文本，对外分享前请人工过目。")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="把一堆日志变成一份能定位问题的报告")
    ap.add_argument("--log-dir", required=True, help="日志目录")
    ap.add_argument("--out", default=".", help="输出目录")
    ap.add_argument("--top", type=int, default=10, help="错误类型显示条数")
    ap.add_argument("--all-files", action="store_true", help="递归扫描子目录")
    args = ap.parse_args()

    d = Path(args.log_dir)
    if not d.exists():
        print(f"目录不存在：{d}", file=sys.stderr)
        return 1

    if d.is_file():
        paths = [d]
    else:
        it = d.rglob("*") if args.all_files else d.glob("*")
        paths = [p for p in it if p.is_file() and p.suffix.lower() in (TEXT_EXT | {".json"})]

    if not paths:
        print("目录下没有可识别的日志文件。", file=sys.stderr)
        return 1

    res = triage(paths)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "triage-report.md").write_text(render(res, args.top), encoding="utf-8")
    (out_dir / "triage-summary.json").write_text(
        json.dumps({k: v for k, v in res.items()}, ensure_ascii=False, indent=2,
                   default=str), encoding="utf-8")
    print(render(res, args.top))
    print("\n已生成：%s" % (out_dir / "triage-report.md"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
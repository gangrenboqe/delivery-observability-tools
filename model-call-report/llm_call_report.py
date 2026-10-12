#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
llm_call_report —— 把本机 AI 网关留下的调用日志，变成一份能看懂能汇报的报表

它回答四个问题（运维视角）：
    1. 调了多少次？成功率多少？
    2. 慢在哪？（P50 / P95 / 最长 —— 刻意不用平均值）
    3. 花了多少 token？
    4. 失败都是什么原因？

为什么要看 P95 而不是平均值：
    平均值会被大量快速调用拉低，**一次 30 秒的卡顿在平均值里几乎看不出来**；
    而用户感受到的"卡"恰恰来自长尾。P95 才是能报警的线。

隐私：日志文件里含有请求正文（用户问了什么）。
    本工具**只取数字与状态字段**（时间/状态码/耗时/token/错误类型），
    **绝不把请求或响应正文写进报表**，也不打印它们。

用法：
    python llm_call_report.py --log-dir <日志目录> --out <输出目录>
    python llm_call_report.py --since 2026-10-01 --until 2026-10-11
    python llm_call_report.py --json-only

依赖：无（只用 Python 标准库）
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# 默认日志目录：OmniRoute 网关的本机留痕
DEFAULT_LOG_DIR = Path.home() / ".omniroute" / "call_logs"

# 只允许从日志里取这些字段，其余一律不碰（尤其是 requestBody / responseBody）
SAFE_FIELDS = ("timestamp", "status", "model", "provider", "duration",
               "tokens", "error", "path", "method")


# ---------------------------------------------------------------- 解析

def _safe(obj: dict) -> dict:
    """从 summary 里挑出安全字段，丢弃请求/响应正文。"""
    keep = {k: obj.get(k) for k in SAFE_FIELDS if k in obj}
    tok = obj.get("tokens") or {}
    keep["tokens_in"] = _as_int(tok.get("in"))
    keep["tokens_out"] = _as_int(tok.get("out"))
    keep.pop("tokens", None)
    return keep


def _as_int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _parse_ts(s: str) -> str:
    """把日志里的 ISO 时间串转成本地时区的 'YYYY-MM-DD HH:MM:SS'（失败就原样返回）。

    🔴 必须转本地时区：日志是 UTC（结尾Z），直接显示会比本地时间差 8 小时，
    看报表的人会以为"半夜三点有人调了模型"。
    """
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return s or "未知时间"


def load_calls(log_dir: Path) -> list[dict]:
    """读取目录下所有调用日志，返回安全字段列表。"""
    calls = []
    if not log_dir.exists():
        return calls
    for f in sorted(log_dir.rglob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue  # 单个坏文件不该让整份报表失败
        summary = data.get("summary") or {}
        if not summary:
            continue
        row = _safe(summary)
        # 🔴 真实日志实测踩过：error 字段在 JSON 的**顶层**，不在 summary 里。
        # 只读 summary 会让所有失败都变成"（无错误信息）"，等于报表最关键的一节是空的。
        if not row.get("error"):
            top_err = data.get("error")
            if isinstance(top_err, dict):
                top_err = top_err.get("message") or top_err.get("code")
            row["error"] = top_err
        row["date"] = _parse_ts(summary.get("timestamp", ""))[:10]
        row["time"] = _parse_ts(summary.get("timestamp", ""))
        calls.append(row)
    return calls


# ---------------------------------------------------------------- 统计

def percentile(values: list[float], p: float) -> float:
    """线性插值分位数（p 取 0~100）。

    自己实现而不用 statistics，是为了**明确算法**并在测试里锁死它的行为。
    """
    if not values:
        return 0.0
    xs = sorted(values)
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * (p / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    frac = k - lo
    return float(xs[lo] + (xs[hi] - xs[lo]) * frac)


# 🔁 与 projects/log-triage/log_triage.py 的 normalize() 是**同一套规则**
# （2026-10-11 第三方复核统一）：同一条错误在两个工具里必须归成同一类。
# 改这里必改那边。
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
HEX_RE = re.compile(r"\b[0-9a-fA-F]{8,}\b")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
WINPATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"']+")
NUM_RE = re.compile(r"\d+")
LEAD_NUM_RE = re.compile(r"^(?:\[\d+\]|\(\d+\)|#\d+)\s*")


def normalize_error(text: str | None) -> str:
    """把错误信息归一成"错误类型"。

    目的：同类错误要归成一条。
    `timeout after 123ms` 与 `timeout after 456ms` 必须是同一类，
    否则 Top N 里全是重复行，报表就废了。

    🔴🔴 顺序决定成败（两边都踩过）：
      必须先剥行首 [N]/(N)/#N 前缀 → 掩码 UUID → 掩码十六进制 ID →
      掩码 IP → 掩码 Windows 路径 → 最后才把数字折叠成 N。
    反过来做的话，`8b1a01b6` 会先变成 `NbNaNbN`，十六进制正则再也匹配不上；
    `[123] Request aborted` 会先变成 `[N] Request aborted`，前缀规则再也匹配不上。
    空消息兜底「（无错误信息）」，截断 80 字符（与 log-triage 一致）。
    """
    if not text:
        return "（无错误信息）"
    s = LEAD_NUM_RE.sub("", str(text))   # ① 先剥 [123] / (42) / #7 这类前缀
    s = UUID_RE.sub("<uuid>", s)         # ② 再掩码 ID
    s = HEX_RE.sub("<id>", s)
    s = IP_RE.sub("<ip>", s)
    s = WINPATH_RE.sub("<path>", s)
    s = NUM_RE.sub("N", s)               # ③ 最后才折叠数字
    s = re.sub(r"\s+", " ", s).strip()
    return s[:80]


def build_summary(calls: list[dict]) -> dict:
    total = len(calls)
    def _is_ok(c: dict) -> bool:
        return isinstance(c.get("status"), int) and 200 <= c["status"] < 300
    ok = [c for c in calls if _is_ok(c)]
    bad = [c for c in calls if not _is_ok(c)]   # 2026-10-11 复核修正：旧版 c not in ok 是 O(n²)
    durations = [float(c["duration"]) for c in calls
                 if isinstance(c.get("duration"), (int, float))]  # 只收数字，字符串会让排序崩

    err_counter = Counter()
    for c in bad:
        raw = (c.get("error") or "")
        if isinstance(raw, dict):
            raw = raw.get("message") or json.dumps(raw, ensure_ascii=False)
        err_counter[normalize_error(raw)] += 1

    by_day = Counter(c.get("date", "") for c in calls)
    by_model = Counter(c.get("model") or "未知模型" for c in calls)
    top_slow = sorted(calls, key=lambda c: c.get("duration") or 0, reverse=True)[:5]

    return {
        "total": total,
        "success": len(ok),
        "failed": len(bad),
        "success_rate": round(len(ok) / total * 100, 2) if total else 0.0,
        "duration_ms": {
            "p50": round(percentile(durations, 50), 1),
            "p95": round(percentile(durations, 95), 1),
            "max": round(max(durations), 1) if durations else 0,
            "min": round(min(durations), 1) if durations else 0,
            "samples": len(durations),
        },
        "tokens": {
            "in": sum(c.get("tokens_in") or 0 for c in calls),
            "out": sum(c.get("tokens_out") or 0 for c in calls),
        },
        "errors": err_counter.most_common(10),
        "by_day": sorted(by_day.items()),
        "by_model": by_model.most_common(),
        "top_slowest": [
            {"time": c.get("time"), "model": c.get("model"),
             "status": c.get("status"), "duration_ms": c.get("duration")}
            for c in top_slow
        ],
    }


# ---------------------------------------------------------------- 渲染

def render_markdown(s: dict, meta: dict) -> str:
    L = []
    L.append("# 模型调用观测报表")
    L.append("")
    L.append(f"- 日志目录：`{meta['log_dir']}`")
    L.append(f"- 统计范围：{meta['since'] or '最早'} ~ {meta['until'] or '最新'}")
    L.append(f"- 生成时间：{meta['generated_at']}　|　**扫描到 {s['total']} 条调用记录**")
    L.append("")
    L.append("## 一、总览")
    L.append("")
    L.append("| 指标 | 数值 |")
    L.append("|---|---|")
    L.append(f"| 调用总数 | **{s['total']}** |")
    L.append(f"| 成功 / 失败 | {s['success']} / {s['failed']} |")
    L.append(f"| 成功率 | **{s['success_rate']}%** |")
    L.append(f"| token（入 / 出） | {s['tokens']['in']} / {s['tokens']['out']} |")
    L.append("")

    d = s["duration_ms"]
    L.append("## 二、耗时（看分位数，不要只看平均值）")
    L.append("")
    L.append("| 指标 | 毫秒 |")
    L.append("|---|---|")
    L.append(f"| 最快 | {d['min']} |")
    L.append(f"| **P50（一半的调用快于这个）** | {d['p50']} |")
    L.append(f"| **P95（95% 的调用快于这个）** | **{d['p95']}** |")
    L.append(f"| 最长 | **{d['max']}** |")
    L.append(f"| 有效样本 | {d['samples']} |")
    L.append("")
    L.append("> **为什么要分位数**：平均值会被大量快调用拉低，"
             "一次 30 秒的卡顿在平均值里几乎看不见。")
    L.append(">")
    L.append("> ⚠️ 但也别夸大 P95：**只有个别几次特别慢时，P95 仍然是正常值**"
             "（比如 100 次里只有 1 次卡住，P95 什么也看不出来）。")
    L.append("> 所以真正抓长尾要看 **最长耗时**，它是不受样本量影响的硬指标。")
    L.append("")

    L.append("## 三、失败原因 Top 10（同类已归并）")
    L.append("")
    if not s["errors"]:
        L.append("本次统计范围内**没有失败调用**。")
    else:
        L.append("| 错误类型 | 次数 |")
        L.append("|---|---|")
        for e, n in s["errors"]:
            L.append(f"| `{e}` | {n} |")
    L.append("")

    L.append("## 四、按天分布")
    L.append("")
    if s["by_day"]:
        L.append("| 日期 | 调用次数 |")
        L.append("|---|---|")
        for day, n in s["by_day"]:
            L.append(f"| {day} | {n} |")
    else:
        L.append("无数据")
    L.append("")

    L.append("## 五、按模型分布")
    L.append("")
    if s["by_model"]:
        L.append("| 模型 | 调用次数 |")
        L.append("|---|---|")
        for m, n in s["by_model"]:
            L.append(f"| `{m}` | {n} |")
    else:
        L.append("无数据")
    L.append("")

    L.append("## 六、最慢的 5 次调用")
    L.append("")
    if s["top_slowest"]:
        L.append("| 时间 | 模型 | 状态 | 耗时(ms) |")
        L.append("|---|---|---|---|")
        for r in s["top_slowest"]:
            L.append(f"| {r['time']} | `{r['model']}` | {r['status']} | {r['duration_ms']} |")
    else:
        L.append("无数据")
    L.append("")
    L.append("---")
    L.append("> 隐私说明：本报表只读取**时间、状态码、耗时、token、错误类型**；"
             "日志中的请求与响应正文**一律不读入、不输出**。")
    return "\n".join(L)


# ---------------------------------------------------------------- CLI

def main() -> int:
    ap = argparse.ArgumentParser(description="把网关调用日志变成观测报表")
    ap.add_argument("--log-dir", default=str(DEFAULT_LOG_DIR), help="日志目录")
    ap.add_argument("--since", default="", help="起始日期（含），如 2026-10-01")
    ap.add_argument("--until", default="", help="结束日期（含）")
    ap.add_argument("--out", default=".", help="输出目录")
    ap.add_argument("--json-only", action="store_true", help="只输出 JSON，不出 Markdown")
    args = ap.parse_args()

    calls = load_calls(Path(args.log_dir))
    if args.since:
        calls = [c for c in calls if c.get("date", "") >= args.since]
    if args.until:
        calls = [c for c in calls if c.get("date", "") <= args.until]

    if not calls:
        print(f"在 {args.log_dir} 没找到可用的调用记录。", file=sys.stderr)
        print("提示：先跑几次真实调用，让网关留下日志。", file=sys.stderr)
        return 1

    summary = build_summary(calls)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "log_dir": str(args.log_dir),
        "since": args.since,
        "until": args.until,
        "generated_at": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
    }

    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    if not args.json_only:
        md = render_markdown(summary, meta)
        (out_dir / "report.md").write_text(md, encoding="utf-8")
        print(md)
        print("\n已生成：%s" % (out_dir / "report.md"))
    else:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        print("\n已生成：%s" % (out_dir / "summary.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
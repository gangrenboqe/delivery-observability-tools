# 陌生人复验记录（35 号工单 · P4 delivery-observability-tools）

> 复验日期：2026-11-02 · 复验人：技术线（Trae）· 方法：真 clone（SSH）

## 结果

**样例日志生成后，两份报表一次跑通（4 条失败被归并成 3 类）。**

## 工作区实跑（demo 内容本体）

```
cd model-call-report && python llm_call_report.py --log-dir ../samples/logs --out out
→ 扫描到 12 条调用记录；调用总数 12、成功/失败 8/4、成功率 66.67%
cd log-triage && python log_triage.py --log-dir ../samples/logs --all-files --out out
→ 12 个文件；INFO 8 / ERROR 4；归并前 12 行 → 归并后 3 类
   1. HTTP N: upstream timeout after Nms（2 次，首 call_09 末 call_10）
   2. HTTP N: rate limited by upstream（1 次）
   3. HTTP N: bad gateway（1 次）
```

输出快照：[docs/model-call-report_report_snapshot.md](model-call-report_report_snapshot.md) ·
[docs/log-triage_report_snapshot.md](log-triage_report_snapshot.md)（证据快照，进仓）。
样例日志：`samples/logs/*.json`（12 条合成网关调用记录，无真实数据）。

## 真 clone（SSH）原文

```
git clone git@github.com:gangrenboqe/delivery-observability-tools.git
Cloning into 'delivery-observability-tools'...
clone 后目录名: delivery-observability-tools   ✓ 与 README 的 cd 一致
```

## 待推送后复验的部分

`samples/logs/`（内置样例）与 README 顶部「三步跑起来」**尚未推送**——
远端 HEAD 跑 `--log-dir ../samples/logs` 会报"没找到可用的调用记录"（已实测确认，属预期）。
设计者 commit/push 后照 README 三步可完整复验；三条命令与两份快照的生成方式均在上文，可复算。

## 说明

- `windows-inspector`（PowerShell 巡检）**没有做离线 demo**：它巡检的是运行者自己的电脑（只读），
  输出天然随机器不同——硬造样例输出反而失真；README「怎么跑」第 3 条已有可用命令，保持原样。
- .gitignore 未改：`out/` 本就被忽略（运行产物），docs/ 快照进仓。
- 复验环境：Windows 11，Python 3.11，SSH 认证，未配 key，未联网。

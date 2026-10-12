# 交付质量与可观测工具集（delivery-observability-tools）

> 一条方法，三个工具：**东西交出去之前，先证明它能被验证；出了问题，先看清有几类错。**

---

## 这是什么

三个**零第三方依赖**的小工具，都在我真实遇到故障之后做的：

| 工具 | 解决什么 | 谁用得上 |
|---|---|---|
| [model-call-report/](model-call-report/) | 把大模型网关的调用日志变成一份能看懂的报表：成功率、耗时分位数、token、失败原因归并 | AI Infra / AI 平台 / 数据运维 |
| [log-triage/](log-triage/) | 把一堆日志变成一份"到底有几种错、什么时候开始、最早出现在哪"的报告 | 系统运维 / 应用实施 / IT 支持 |
| [windows-inspector/](windows-inspector/) | 给一台 Windows 电脑做体检，出一份别人看得懂的报告，**只读不改** | IT 支持 / 桌面运维 / 数字化专员 |

同系列的第四个工具 **[PDF 交付体检器](https://github.com/gangrenboqe/pdf-delivery-audit)**
（人眼看着对 ≠ 机器能读）已单独发布，在 [ai-daily-collector](https://github.com/gangrenboqe/ai-daily-collector) 之前完成。

---

## 怎么跑（每个工具都是独立可运行的）

```bash
# 1. 模型调用观测报表
cd model-call-report && python llm_call_report.py --log-dir <日志目录>

# 2. 日志体检器
cd log-triage && python log_triage.py --log-dir <日志目录> --all-files

# 3. Windows 巡检（PowerShell 5.1+）
cd windows-inspector && powershell -ExecutionPolicy Bypass -File Inspect-Windows.ps1
```

**测试**（纯标准库，毫秒级，不起服务、不联网）：

```bash
cd model-call-report && python -m unittest discover -s tests   # 22 项
cd log-triage       && python -m unittest discover -s tests   # 33 项
powershell -ExecutionPolicy Bypass -File windows-inspector/Test-Inspect.ps1  # 58 项断言
```

**依赖：无。**三个工具都只用 Python 标准库 / Windows 自带 cmdlet。

---

## 实测结果（真实数据，不是造出来的样例）

| 工具 | 实测 |
|---|---|
| 模型调用观测 | 真实 50 条调用记录：成功率 64%、最慢一次 150 秒、18 条失败**归并成 4 类** |
| 日志体检 | 同一批日志：18 条失败**归并成 4 类**，并给出首末时间与文件位置 |
| Windows 巡检 | 真机查出 **7 个上次运行失败的计划任务**、**2 项指向不存在路径的残留自启** |

每个工具目录下都有 `SAMPLE_REPORT.md`（脱敏后的真实输出样例）。

---

## 三个工具共同的方法

**① 错误必须归并，否则报表是废的。**
`timeout after 123ms` 和 `timeout after 456ms` 是同一类错。不归并的话 Top N 里全是重复行。
🔴 归并的**执行顺序决定成败**——这个坑我踩了两次：
必须「先剥 `[123]` 前缀 → 再掩码 ID → 最后才把数字折叠成 N」，
反过来做会让 `[123] X` 变成 `[N] X`，前缀规则永远匹配不上。**两次都是被单元测试当场打回才发现的。**

**② 噪声必须为零。**
按需启动的服务（`Stopped / Manual`）平时就是停的，判成"异常"是噪声。
所以规则是：**自动启动却没运行 = 异常；按需启动且停止 = 正常。**

**③ 认不出来就说认不出来。**
日志级别识别不出来就归「未知」，**不瞎猜成 INFO**；JSON 缺状态码就归「未知」，
**不猜成 ERROR**。每一条都有测试守着。

---

## 一个反复出现的教训

这三个工具里，我犯过三次同类错误，**全部是测试发现的，不是看代码看出来的**：
三档判断整体颠倒、改了参数名没改调用处、归并顺序搞反。

> **测了函数 ≠ 测对了。测了函数 ≠ 测全了。**
> 这是这个工具集里最值钱的一句，比代码本身更能说明我怎么做工程。

---

## 说明

- 源目录：本仓库是**发布副本**；开发源在 `../../projects/<工具名>/`
- 许可证：MIT
- 三个工具之间**互不依赖**，可以单独取用

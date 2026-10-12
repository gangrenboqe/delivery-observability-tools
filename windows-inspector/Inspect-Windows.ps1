<#
.SYNOPSIS
    Windows 机器巡检工具（只读体检）—— 给一台 Windows 电脑做体检，出一份别人看得懂的报告。

.DESCRIPTION
    覆盖六类检查，每一类都给出三档判断（正常 / 警告 / 异常），而不是只把数值打印出来：
      1. 磁盘空间      2. 端口占用      3. 关键服务
      4. 计划任务      5. 开机自启      6. 最近的系统严重错误

    🔴 本脚本**只读**：只用 Get-* 查询，不启停服务、不删除自启项、不清日志、不改任何配置。
       体检和动手改是两件事——后者需要单独确认。

    🔴 导出的报告会**自动脱敏**：计算机名、用户名、IP、磁盘卷标一律替换为占位符。

.NOTES
    依赖：无。全部使用 Windows 自带 cmdlet。
    自测：powershell -ExecutionPolicy Bypass -File Test-Inspect.ps1
#>

param(
    # 非交互模式：执行一次体检、打印结果后退出，不进入菜单。
    # 自动化脚本与 CI 用这个；日常使用直接运行不带参数即可。
    [switch]$Once,
    # 配合 -Once 使用：把脱敏后的报告写到指定路径。
    [string]$ExportPath = ""
)

# ============================ 基础函数 ============================

function Get-StatusLevel {
    <#
    三档判断。

    🔴 这里踩过一次极危险的 bug：原本同时有 -HigherIsWorse 和 -Invert 两个开关，
       但函数体里只判断了 -Invert，导致"已用 95%"被判成"正常"、"已用 50%"被判成"异常"
       —— **整个判断颠倒**。自测脚本当场抓到。
       现在只保留一个开关，且参数名与判断处严格对应。
    #>
    param(
        [double]$Value,
        [double]$WarnAt,
        [double]$ErrorAt,
        [switch]$HigherIsWorse
    )
    if ($HigherIsWorse) {
        # 数值越大越糟（例如"已用空间百分比"）
        if ($Value -ge $ErrorAt) { return "异常" }
        if ($Value -ge $WarnAt)  { return "警告" }
        return "正常"
    }
    # 数值越小越糟（例如"剩余 GB"）
    if ($Value -le $ErrorAt) { return "异常" }
    if ($Value -le $WarnAt)  { return "警告" }
    return "正常"
}

function Get-PortLevel {
    <#
    端口三档判断（SPEC：关键端口被非预期占用要能亮出来，不能全绿）。
    - 数据库/网关类端口（3306/5432/6379/20128/8787）绑定在非回环地址
      （0.0.0.0 / :: / 局域网 IP）= 对局域网暴露 → 异常
    - 3389 远程桌面在监听 = 常见攻击面 → 警告（不用就该关）
    - 其余（含对外的 80/443）→ 正常
    #>
    param([int]$Port, [string]$LocalAddress = "127.0.0.1")
    $loopbackOnly = $LocalAddress -in @("127.0.0.1", "::1")
    $dbLike = $Port -in @(3306, 5432, 6379, 20128, 8787)
    if ($dbLike -and -not $loopbackOnly) { return "异常" }
    if ($Port -eq 3389) { return "警告" }
    return "正常"
}

function Get-EventLevel {
    <#
    系统错误三档判断（SPEC 异常示例：磁盘错误、蓝屏、服务崩溃）。
    - 命中 7/51/153（磁盘）、1001（蓝屏）、7031/7034（服务崩溃）→ 异常
    - 条数 ≥ 10，或含 41/6008（异常断电/异常关机）→ 警告
    - 其余 → 正常
    #>
    param([int[]]$EventIds, [int]$Count)
    $errorIds = @(7, 51, 153, 1001, 7031, 7034)
    $warnIds = @(41, 6008)
    foreach ($id in $EventIds) {
        if ($errorIds -contains $id) { return "异常" }
    }
    foreach ($id in $EventIds) {
        if ($warnIds -contains $id) { return "警告" }
    }
    if ($Count -ge 10) { return "警告" }
    return "正常"
}

function Protect-Text {
    <#
    脱敏：把机器名、用户名、IP、卷标、用户目录全部替换成占位符。
    导出的报告要能给别人看，所以这一步是硬要求，不是可选装饰。
    #>
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text
    $t = $t -replace [regex]::Escape($env:COMPUTERNAME), "<计算机名>"
    if ($env:USERNAME) {
        $t = $t -replace [regex]::Escape($env:USERNAME), "<用户名>"
    }
    $t = $t -replace '\b\d{1,3}(\.\d{1,3}){3}\b', "<IP>"
    $t = $t -replace '([A-Za-z]:\\Users\\)[^\\"]+', '$1<用户名>'
    $t = $t -replace '([A-Za-z]:\\)[^\\"]*?(Documents and Settings|Users)', '$1<用户目录>'
    return $t
}

function Add-Finding {
    <# 把一条检查结果收集起来 #>
    param(
        [string]$Category,
        [string]$Item,
        [string]$Value,
        [string]$Level,
        [string]$Advice = ""
    )
    $script:Findings += [pscustomobject]@{
        Category = $Category
        Item     = $Item
        Value    = (Protect-Text $Value)
        Level    = $Level
        Advice   = (Protect-Text $Advice)
    }
}

# ============================ 各项检查 ============================

function Check-Disk {
    $cats = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
    foreach ($c in $cats) {
        $sizeGB = [math]::Round($c.Size / 1GB, 1)
        $freeGB = [math]::Round($c.FreeSpace / 1GB, 1)
        $usedPct = if ($sizeGB -gt 0) { [math]::Round((1 - $c.FreeSpace / $c.Size) * 100, 1) } else { 0 }
        $level = Get-StatusLevel -Value $usedPct -WarnAt 80 -ErrorAt 90 -HigherIsWorse
        $advice = if ($level -eq "正常") { "" }
                  elseif ($level -eq "警告") { "剩余偏少，建议清理" }
                  else { "空间紧张，建议立即清理（< 10%）" }
        Add-Finding -Category "磁盘" -Item "$($c.DeviceID) 总 $sizeGB GB" `
                    -Value "已用 $usedPct%，剩 $freeGB GB" -Level $level -Advice $advice
    }
}

function Check-Ports {
    $watch = @{
        80 = "HTTP"; 443 = "HTTPS"; 3389 = "远程桌面"; 3306 = "MySQL"; 5432 = "PostgreSQL"
        6379 = "Redis"; 20128 = "本机 AI 网关"; 8787 = "Personal AI"
    }
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    foreach ($l in $listeners) {
        $port = $l.LocalPort
        if ($watch.ContainsKey($port)) {
            $procName = "未知"
            try { $procName = (Get-Process -Id $l.OwningProcess -ErrorAction Stop).ProcessName } catch {}
            $level = Get-PortLevel -Port $port -LocalAddress $l.LocalAddress
            $advice = switch ($level) {
                "异常" { "数据库/网关端口绑定在非本机地址（$($l.LocalAddress)），对局域网暴露，建议改为只听 127.0.0.1 或加防火墙" }
                "警告" { "远程桌面端口在监听：不用远程桌面建议关闭" }
                default { "被占用属正常" }
            }
            Add-Finding -Category "端口" -Item "$port（$($watch[$port])）" `
                        -Value "正在监听，进程 $procName（绑定 $($l.LocalAddress)）" -Level $level -Advice $advice
        }
    }
    $missing = @()
    foreach ($p in 3306, 6379) {
        if (-not ($listeners | Where-Object { $_.LocalPort -eq $p })) { $missing += $p }
    }
    if ($missing.Count -gt 0) {
        Add-Finding -Category "端口" -Item "常用服务端口" `
                    -Value "未占用：$($missing -join ', ')" -Level "正常" -Advice "未部署该服务属正常"
    }
}

function Check-Services {
    $critical = @("Spooler", "w32time", "WinDefend", "BITS", "Schedule")
    foreach ($name in $critical) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) {
            Add-Finding -Category "服务" -Item $name -Value "未安装" -Level "警告" -Advice "该服务在本机不存在"
            continue
        }
        # ⚠️ 判断要区分"该跑却没跑"和"按需启动"：
        #    Automatic + 停止 = 异常（本该自动跑却没跑）
        #    Manual + 停止    = 正常（按需启动的服务平时就是停的）
        # 把所有停止的服务都判成异常是**噪声**，噪声多了等于没检查。
        $level = "正常"
        $advice = ""
        if ($svc.Status -ne "Running" -and $svc.StartType -eq "Automatic") {
            $level = "异常"
            $advice = "设为自动启动但未运行"
        } elseif ($svc.Status -ne "Running") {
            $level = "正常"
            $advice = "按需启动，平时不运行属正常"
        }
        Add-Finding -Category "服务" -Item "$($svc.DisplayName)" `
                    -Value "$($svc.Status) / 启动类型: $($svc.StartType)" -Level $level -Advice $advice
    }
}

function Check-ScheduledTasks {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
             Where-Object { $_.State -ne "Disabled" -and $_.TaskPath -notlike "\Microsoft\*" }
    $failed = @()
    foreach ($t in $tasks) {
        $info = $null
        try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch {}
        if ($info -and $info.LastTaskResult -ne 0 -and $info.LastTaskResult -ne 267009) {
            $failed += "$($t.TaskPath)$($t.TaskName)（结果码 $($info.LastTaskResult)）"
        }
    }
    if ($failed.Count -gt 0) {
        Add-Finding -Category "计划任务" -Item "上次运行失败的任务" `
                    -Value "$($failed.Count) 个" -Level "警告" `
                    -Advice ($failed -join "; ")
    } else {
        Add-Finding -Category "计划任务" -Item "第三方计划任务" `
                    -Value "$($tasks.Count) 个，均无失败记录" -Level "正常" -Advice ""
    }
}

function Check-Startup {
    $items = @()
    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($k in $runKeys) {
        if (Test-Path $k) {
            $props = Get-ItemProperty $k -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -notlike "PS*") { $items += [pscustomobject]@{ Name = $p.Name; Cmd = $p.Value } }
            }
        }
    }
    $broken = @()
    foreach ($i in $items) {
        $path = ($i.Cmd -split '"')[1]
        if (-not $path) { $path = ($i.Cmd -split ' ')[0] }
        if ($path -match '^[A-Za-z]:\\' -and -not (Test-Path $path)) { $broken += $i.Name }
    }
    if ($broken.Count -gt 0) {
        Add-Finding -Category "开机自启" -Item "指向不存在路径" `
                    -Value "$($broken.Count) 项" -Level "警告" `
                    -Advice ($broken -join "; ")
    } else {
        Add-Finding -Category "开机自启" -Item "注册表启动项" `
                    -Value "$($items.Count) 项，路径均存在" -Level "正常" -Advice ""
    }
}

function Check-SystemErrors {
    $since = (Get-Date).AddHours(-24)
    $events = Get-WinEvent -FilterHashtable @{ LogName = "System"; Level = 1, 2; StartTime = $since } `
               -ErrorAction SilentlyContinue | Select-Object -First 20
    if (-not $events) {
        Add-Finding -Category "系统错误" -Item "最近 24 小时严重/错误事件" `
                    -Value "0 条" -Level "正常" -Advice "很干净"
        return
    }
    $ids = $events | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5
    $desc = ($ids | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ", "
    $allIds = @($events | ForEach-Object { [int]$_.Id })
    $level = Get-EventLevel -EventIds $allIds -Count @($events).Count
    $advice = switch ($level) {
        "异常" { "发现磁盘错误/蓝屏/服务崩溃类事件（7/51/153=磁盘，1001=蓝屏，7031/7034=服务崩溃），建议尽快排查" }
        "警告" { "事件偏多或含异常关机（41/6008），建议打开事件查看器看一眼" }
        default { "ID 含义：7/51=磁盘 41=异常断电 6008=异常关机 1001=蓝屏 7031/7034=服务崩溃" }
    }
    Add-Finding -Category "系统错误" -Item "最近 24 小时严重/错误事件" `
                -Value "$(@($events).Count) 条（事件ID: $desc）" -Level $level -Advice $advice
}

# ============================ 主流程 ============================

function Invoke-Inspection {
    $script:Findings = @()
    Check-Disk
    Check-Ports
    Check-Services
    Check-ScheduledTasks
    Check-Startup
    Check-SystemErrors
    return $script:Findings
}

function Format-ConsolReport {
    param($Findings)
    $icon = @{ "正常" = "[正常]"; "警告" = "[警告]"; "异常" = "[异常]" }
    Write-Host ""
    Write-Host "================ 体检结果 ================" -ForegroundColor Cyan
    $last = ""
    foreach ($f in $Findings) {
        if ($f.Category -ne $last) {
            Write-Host ""
            Write-Host "--- $($f.Category) ---" -ForegroundColor White
            $last = $f.Category
        }
        $color = switch ($f.Level) { "异常" { "Red" } "警告" { "Yellow" } default { "Green" } }
        Write-Host ("  {0} {1}: {2}" -f $icon[$f.Level], $f.Item, $f.Value) -ForegroundColor $color
        if ($f.Advice) { Write-Host ("         建议: {0}" -f $f.Advice) -ForegroundColor DarkGray }
    }
    Write-Host ""
    $bad = ($Findings | Where-Object { $_.Level -eq "异常" }).Count
    $warn = ($Findings | Where-Object { $_.Level -eq "警告" }).Count
    if ($bad -gt 0)      { Write-Host "结论: 发现 $bad 项异常、$warn 项警告" -ForegroundColor Red }
    elseif ($warn -gt 0) { Write-Host "结论: 无异常，$warn 项警告" -ForegroundColor Yellow }
    else                 { Write-Host "结论: 全部正常" -ForegroundColor Green }
}

function Export-Report {
    param($Findings, $Path)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("# Windows 机器巡检报告")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("- 生成时间：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("- 计算机名：<计算机名>　用户：<用户名>")
    [void]$sb.AppendLine("- 本报告已脱敏：计算机名 / 用户名 / IP / 用户目录均已替换为占位符")
    [void]$sb.AppendLine("")
    foreach ($cat in ($Findings.Category | Select-Object -Unique)) {
        [void]$sb.AppendLine("## $cat")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("| 项目 | 实测值 | 判断 | 建议 |")
        [void]$sb.AppendLine("|---|---|---|---|")
        foreach ($f in $Findings | Where-Object { $_.Category -eq $cat }) {
            [void]$sb.AppendLine("| $($f.Item) | $($f.Value) | **$($f.Level)** | $($f.Advice) |")
        }
        [void]$sb.AppendLine("")
    }
    [void]$sb.AppendLine("---")
    [void]$sb.AppendLine("> 本工具**只读**，不做任何修改；报告已脱敏，可直接交付他人。")
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object Text.UTF8Encoding($true)))
    return $Path
}

# ============================ 菜单 ============================

# 单项检查映射（SPEC 菜单第 2 项「只看某个项目」）：六类检查的入口表
$script:CheckMap = [ordered]@{
    "磁盘"     = "Check-Disk"
    "端口"     = "Check-Ports"
    "服务"     = "Check-Services"
    "计划任务" = "Check-ScheduledTasks"
    "开机自启" = "Check-Startup"
    "系统错误" = "Check-SystemErrors"
}

function Invoke-SingleCheck {
    <# 只体检某一类：别人有时只想看磁盘，不想等全部跑完。 #>
    Write-Host ""
    Write-Host "要体检哪一项？" -ForegroundColor Cyan
    $keys = @($script:CheckMap.Keys)
    for ($i = 0; $i -lt $keys.Count; $i++) { Write-Host "$($i + 1). $($keys[$i])" }
    $sel = Read-Host "请选择 1-$($keys.Count)"
    $idx = 0
    if (-not [int]::TryParse($sel, [ref]$idx) -or $idx -lt 1 -or $idx -gt $keys.Count) {
        Write-Host "无效选择。" -ForegroundColor Red
        return
    }
    $script:Findings = @()
    & $script:CheckMap[$keys[$idx - 1]]
    Format-ConsolReport $script:Findings
}

function Show-Menu {
    Write-Host ""
    Write-Host "=== Windows 机器巡检（只读） ===" -ForegroundColor Cyan
    Write-Host "1. 立即体检并显示"
    Write-Host "2. 只看某个项目（如磁盘）"
    Write-Host "3. 体检并导出报告到文件"
    Write-Host "4. 查看最近一次导出的报告"
    Write-Host "q. 退出"
    $choice = Read-Host "请选择"
    switch ($choice) {
        "1" { $r = Invoke-Inspection; Format-ConsolReport $r }
        "2" { Invoke-SingleCheck }
        "3" {
            $r = Invoke-Inspection
            Format-ConsolReport $r
            $p = Join-Path (Get-Location) ("巡检报告-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".md")
            $saved = Export-Report -Findings $r -Path $p
            Write-Host "`n报告已导出：$saved（已脱敏）" -ForegroundColor Green
        }
        "4" {
            $last = Get-ChildItem -Path (Get-Location) -Filter "巡检报告-*.md" -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($last) { Invoke-Item $last.FullName } else { Write-Host "还没有导出过报告。" -ForegroundColor Yellow }
        }
        "q" { return }
        default { Write-Host "无效选择。" -ForegroundColor Red }
    }
}

# 判断"是否被直接运行"的正确写法：
#   dot-source 时 $MyInvocation.InvocationName 等于 "."
# 🔴 曾写成 `InvocationName -eq MyCommand.Name` —— 用 `powershell -File` 跑时
#    两者不相等（一个是完整路径、一个是文件名），整个入口块被跳过，
#    脚本**静默什么都不做**。CI 第一次跑就撞上了这个问题。
if ($MyInvocation.InvocationName -ne '.') {
    if ($Once) {
        # 非交互模式：跑一次体检、打印结果、退出。
        # 用途 = 自动化脚本与 CI —— 交互菜单在无人值守环境里会一直等输入。
        $result = Invoke-Inspection
        Format-ConsolReport $result
        if ($ExportPath) {
            $saved = Export-Report -Findings $result -Path $ExportPath
            Write-Host ""
            Write-Host "Report exported: $saved" -ForegroundColor Green
        }
        exit 0
    }
    Write-Host "提示：部分检查（系统错误事件）在非管理员 PowerShell 下可能读不到。" -ForegroundColor DarkGray
    while ($true) { Show-Menu; if ($null -eq (Read-Host "按回车继续，或输入 q 退出")) { break } }
}
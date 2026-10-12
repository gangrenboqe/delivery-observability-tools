<#
.SYNOPSIS
    Inspect-Windows.ps1 的自测脚本（不依赖 Pester，纯标准库 Assert 风格）。

    为什么必须有：脱敏是本工具的**硬要求**——
    报告要能给别人看，里面不能出现计算机名、用户名、IP。
    没有断言守着，这个要求迟早会被改坏。

运行：powershell -ExecutionPolicy Bypass -File Test-Inspect.ps1
#>

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Inspect-Windows.ps1")

$script:Pass = 0
$script:Fail = 0

function Assert-Equal {
    param($Actual, $Expected, [string]$Name)
    if ($Actual -eq $Expected) {
        $script:Pass++
        Write-Host ("  [PASS] {0}" -f $Name) -ForegroundColor Green
    } else {
        $script:Fail++
        Write-Host ("  [FAIL] {0}`n         期望: {1}`n         实际: {2}" -f $Name, $Expected, $Actual) -ForegroundColor Red
    }
}

Write-Host "`n=== 1. 三档判断（正常 / 警告 / 异常）===" -ForegroundColor Cyan
Assert-Equal (Get-StatusLevel -Value 50 -WarnAt 80 -ErrorAt 90 -HigherIsWorse) "正常" "已用 50% → 正常"
Assert-Equal (Get-StatusLevel -Value 85 -WarnAt 80 -ErrorAt 90 -HigherIsWorse) "警告" "已用 85% → 警告"
Assert-Equal (Get-StatusLevel -Value 95 -WarnAt 80 -ErrorAt 90 -HigherIsWorse) "异常" "已用 95% → 异常"
Assert-Equal (Get-StatusLevel -Value 500 -WarnAt 20 -ErrorAt 10) "正常" "剩余 500GB → 正常"
Assert-Equal (Get-StatusLevel -Value 15 -WarnAt 20 -ErrorAt 10) "警告" "剩余 15GB → 警告"
Assert-Equal (Get-StatusLevel -Value 5 -WarnAt 20 -ErrorAt 10) "异常" "剩余 5GB → 异常"
Assert-Equal (Get-StatusLevel -Value 80 -WarnAt 80 -ErrorAt 90 -HigherIsWorse) "警告" "边界值 80 → 警告（不含异常）"
Assert-Equal (Get-StatusLevel -Value 90 -WarnAt 80 -ErrorAt 90 -HigherIsWorse) "异常" "边界值 90 → 异常"

Write-Host "`n=== 2. 脱敏（本工具的硬要求）===" -ForegroundColor Cyan
Assert-Equal ((Protect-Text "路径 C:\Users\Someone\secret.txt").Contains("Someone")) $false "用户目录里的用户名被替换"
Assert-Equal ((Protect-Text "访问 192.168.1.77 失败").Contains("192.168")) $false "IPv4 被替换"
Assert-Equal ((Protect-Text "机器 $env:COMPUTERNAME 上的错误").Contains($env:COMPUTERNAME)) $false "计算机名被替换（用真实机器名测）"
Assert-Equal ((Protect-Text "登录用户 $env:USERNAME 失败").Contains($env:USERNAME)) $false "当前用户名被替换"
Assert-Equal (Protect-Text "普通文本没有敏感信息") "普通文本没有敏感信息" "无敏感信息时原样返回"
Assert-Equal (Protect-Text "") "" "空输入不炸"

Write-Host "`n=== 3. 只读红线（源码里不许出现修改类命令）===" -ForegroundColor Cyan
$src = Get-Content (Join-Path $PSScriptRoot "Inspect-Windows.ps1") -Raw
foreach ($forbidden in @("Set-Service", "Stop-Process", "Start-Process", "Remove-Item",
                         "Set-ItemProperty", "New-ItemProperty", "Stop-Service", "Restart-Computer")) {
    Assert-Equal ($src -match [regex]::Escape($forbidden)) $false "源码不含修改类命令：$forbidden"
}

Write-Host "`n=== 4. 检查项齐全（六类都在）===" -ForegroundColor Cyan
foreach ($fn in @("Check-Disk", "Check-Ports", "Check-Services",
                  "Check-ScheduledTasks", "Check-Startup", "Check-SystemErrors")) {
    Assert-Equal ([bool](Get-Command $fn -ErrorAction SilentlyContinue)) $true "存在函数 $fn"
}

Write-Host "`n=== 4b. 单项检查映射（SPEC 菜单第 2 项「只看某个项目」）===" -ForegroundColor Cyan
Assert-Equal ($CheckMap.Count) 6 "单项检查映射包含 6 类"
foreach ($k in $CheckMap.Keys) {
    Assert-Equal ([bool](Get-Command $CheckMap[$k] -ErrorAction SilentlyContinue)) $true "映射 $k → $($CheckMap[$k]) 存在"
}
Assert-Equal ($src -match [regex]::Escape("只看某个项目")) $true "菜单含「只看某个项目」"

Write-Host "`n=== 4c. 端口与系统错误的三档判断（不能全绿）===" -ForegroundColor Cyan
Assert-Equal (Get-PortLevel -Port 3306 -LocalAddress "127.0.0.1") "正常" "MySQL 只听本机 → 正常"
Assert-Equal (Get-PortLevel -Port 3306 -LocalAddress "0.0.0.0") "异常" "MySQL 绑定所有网卡 → 异常"
Assert-Equal (Get-PortLevel -Port 6379 -LocalAddress "::") "异常" "Redis 绑定 :: → 异常"
Assert-Equal (Get-PortLevel -Port 20128 -LocalAddress "192.168.1.5") "异常" "AI 网关绑定局域网地址 → 异常"
Assert-Equal (Get-PortLevel -Port 3389 -LocalAddress "127.0.0.1") "警告" "远程桌面监听 → 警告"
Assert-Equal (Get-PortLevel -Port 80 -LocalAddress "0.0.0.0") "正常" "HTTP 对外属正常"
Assert-Equal (Get-EventLevel -EventIds @(7) -Count 1) "异常" "磁盘错误(7) → 异常"
Assert-Equal (Get-EventLevel -EventIds @(1001) -Count 1) "异常" "蓝屏(1001) → 异常"
Assert-Equal (Get-EventLevel -EventIds @(7034) -Count 1) "异常" "服务崩溃(7034) → 异常"
Assert-Equal (Get-EventLevel -EventIds @(41) -Count 1) "警告" "异常断电(41) → 警告"
Assert-Equal (Get-EventLevel -EventIds @(9999) -Count 12) "警告" "12 条普通错误 → 警告"
Assert-Equal (Get-EventLevel -EventIds @(9999) -Count 2) "正常" "2 条普通错误 → 正常"

Write-Host "`n=== 5. 体检能真跑出结果 ===" -ForegroundColor Cyan
$r = Invoke-Inspection
Assert-Equal ($r.Count -gt 0) $true "体检返回了条目（实际 $($r.Count) 条）"
Assert-Equal (($r | Where-Object { $_.Level -notin @("正常", "警告", "异常") }).Count -eq 0) $true "每一项都有三档判断"
Assert-Equal (($r | Where-Object { $_.Item -and $_.Item.Contains($env:USERNAME) }).Count -eq 0) $true "结果里不含用户名"

Write-Host "`n=== 6. 集成一致性（这一层曾漏过，必须守住）===" -ForegroundColor Cyan
# 上一轮自测只测了 Get-StatusLevel 本身，**没测Check-Disk 的调用处**，
# 结果参数名改了没同步，真跑时磁盘 72% 全被判成"异常"。这条断言就是补这个洞。
$r2 = Invoke-Inspection
$diskMismatch = 0
foreach ($f in $r2 | Where-Object { $_.Category -eq "磁盘" }) {
    # 🔴 必须在循环体内重新匹配：$Matches 是全局自动变量，
    #    放在 Where-Object 里会被后续项覆盖，导致读到别的磁盘的百分比。
    if ($f.Value -notmatch "已用 ([0-9.]+)%") { continue }
    $pct = [double]$Matches[1]
    $expected = Get-StatusLevel -Value $pct -WarnAt 80 -ErrorAt 90 -HigherIsWorse
    if ($expected -ne $f.Level) {
        $script:Fail++
        Write-Host ("  [FAIL] 磁盘 {0}% 期望[{1}] 实际[{2}]" -f $pct, $expected, $f.Level) -ForegroundColor Red
    } else { $script:Pass++ }
}
Assert-Equal ($diskMismatch -eq 0) $true "磁盘判断与阈值一致"

# 按需启动的服务不该被判成异常（噪声必须为零）
$falseAlarm = @($r2 | Where-Object {
    $_.Category -eq "服务" -and $_.Value -match "^Stopped" -and $_.Value -match "Manual" -and $_.Level -eq "异常"
})
Assert-Equal $falseAlarm.Count 0 "按需启动且停止的服务未被误报为异常"

Write-Host "`n=== 7. 入口集成（脚本必须真能跑起来）===" -ForegroundColor Cyan
# 这组是被一个真 bug 逼出来的：
#   主脚本判断"是否被直接运行"时写成了 `InvocationName -eq MyCommand.Name`，
#   用 `powershell -File` 跑时两者不相等 → 整个入口被跳过 → **脚本静默什么都不做**。
#   而自测是 dot-source 调函数的，**永远走不到这个分支**，所以 58 项断言全绿也照样漏。
#   → 必须起一个真子进程跑一遍，才测得到入口。
$scriptPath = Join-Path $PSScriptRoot "Inspect-Windows.ps1"
$tmpOut = Join-Path $env:TEMP ("inspect_once_" + [guid]::NewGuid().ToString("N") + ".txt")
# ⚠️ 这里**不能用 Start-Process**：本机环境变量里同时存在 http_proxy 与 HTTP_PROXY，
#    PowerShell 5.1 的 Start-Process 会因"重复键"直接抛 ArgumentException。
#    改用调用运算符 + 重定向，效果一样且不会踩这个坑。
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath -Once *>&1 |
    Out-File -FilePath $tmpOut -Encoding UTF8
Assert-Equal $LASTEXITCODE 0 "以 -Once 非交互模式运行时退出码为 0"
$onceOut = if (Test-Path $tmpOut) { Get-Content $tmpOut -Raw } else { "" }
Assert-Equal ($onceOut.Length -gt 200) $true "非交互模式确实输出了内容（实际 $([math]::Round($onceOut.Length)) 字符）"
Assert-Equal ($onceOut.Contains("体检结果")) $true "输出里含体检结果小标题"
Remove-Item $tmpOut -ErrorAction SilentlyContinue

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host ("通过 {0} 项，失败 {1} 项" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { exit 1 }
<#
.SYNOPSIS
  NIKKE 런처 점검/정리 도구 - GUI 버전 (NikkeLauncherCleanup.ps1 을 불러와 사용)
.DESCRIPTION
  같은 폴더에 NikkeLauncherCleanup.ps1 (와 ioc.json) 이 있어야 합니다.
  네트워크 접속/외부 전송 없음. 삭제는 항목마다 확인창을 띄웁니다.
#>
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $PSCommandPath
$core = Join-Path $here 'NikkeLauncherCleanup.ps1'
if (-not (Test-Path -LiteralPath $core)) {
    Add-Type -AssemblyName System.Windows.Forms
    [void][Windows.Forms.MessageBox]::Show("NikkeLauncherCleanup.ps1 을 같은 폴더에 두세요.", 'NIKKE 점검/정리', 'OK', 'Error')
    return
}

# 핵심 로직 불러오기 (함수만 정의되고 종료됨)
. $core

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

# 콘솔용 확인 프롬프트를 확인창으로 대체
function Confirm-Step([string]$Question) {
    $r = [Windows.Forms.MessageBox]::Show($Question.Trim(), 'NIKKE 정리 - 확인', 'YesNo', 'Question', 'Button2')
    return ($r -eq 'Yes')
}

$isAdmin = Test-IsAdmin

$form = New-Object Windows.Forms.Form
$form.Text = 'NIKKE 런처 점검/정리 도구 (비공식)'
$form.Size = New-Object Drawing.Size(820, 640)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object Drawing.Font('Malgun Gothic', 9)

$lblInfo = New-Object Windows.Forms.Label
$lblInfo.Location = New-Object Drawing.Point(12, 10)
$lblInfo.Size = New-Object Drawing.Size(780, 36)
$lblInfo.Text = "네트워크 접속 없음 / 외부 전송 없음 / 삭제는 항목별 확인 후 수행`r`n" + $(if ($isAdmin) { '관리자 권한: 예 (hosts/방화벽 차단 가능)' } else { '관리자 권한: 아니오 (hosts/방화벽 차단은 건너뜀)' })
$form.Controls.Add($lblInfo)

$lblPath = New-Object Windows.Forms.Label
$lblPath.Location = New-Object Drawing.Point(12, 54)
$lblPath.Size = New-Object Drawing.Size(150, 20)
$lblPath.Text = 'NIKKE 폴더(선택, 자동탐색 실패 시):'
$lblPath.AutoSize = $true
$form.Controls.Add($lblPath)

$tbPath = New-Object Windows.Forms.TextBox
$tbPath.Location = New-Object Drawing.Point(12, 76)
$tbPath.Size = New-Object Drawing.Size(640, 24)
$form.Controls.Add($tbPath)

$btnBrowse = New-Object Windows.Forms.Button
$btnBrowse.Location = New-Object Drawing.Point(660, 74)
$btnBrowse.Size = New-Object Drawing.Size(80, 27)
$btnBrowse.Text = '찾아보기'
$btnBrowse.Add_Click({
    $fd = New-Object Windows.Forms.FolderBrowserDialog
    if ($fd.ShowDialog() -eq 'OK') { $tbPath.Text = $fd.SelectedPath }
})
$form.Controls.Add($btnBrowse)

$btnScan = New-Object Windows.Forms.Button
$btnScan.Location = New-Object Drawing.Point(12, 110)
$btnScan.Size = New-Object Drawing.Size(150, 34)
$btnScan.Text = '점검만 (읽기 전용)'
$form.Controls.Add($btnScan)

$btnClean = New-Object Windows.Forms.Button
$btnClean.Location = New-Object Drawing.Point(172, 110)
$btnClean.Size = New-Object Drawing.Size(150, 34)
$btnClean.Text = '점검 + 정리'
$form.Controls.Add($btnClean)

$btnAdmin = New-Object Windows.Forms.Button
$btnAdmin.Location = New-Object Drawing.Point(332, 110)
$btnAdmin.Size = New-Object Drawing.Size(170, 34)
$btnAdmin.Text = '관리자 권한으로 다시 실행'
$btnAdmin.Enabled = (-not $isAdmin)
$form.Controls.Add($btnAdmin)

$tb = New-Object Windows.Forms.TextBox
$tb.Location = New-Object Drawing.Point(12, 154)
$tb.Size = New-Object Drawing.Size(780, 436)
$tb.Multiline = $true
$tb.ReadOnly = $true
$tb.ScrollBars = 'Vertical'
$tb.Font = New-Object Drawing.Font('Consolas', 9)
$tb.Anchor = 'Top,Bottom,Left,Right'
$form.Controls.Add($tb)

$buttons = @($btnScan, $btnClean, $btnBrowse)

function Invoke-GuiAction([scriptblock]$Action) {
    foreach ($b in $buttons) { $b.Enabled = $false }
    $tb.Clear()
    $script:NikkePath = @(if ($tbPath.Text.Trim()) { $tbPath.Text.Trim() })
    try {
        & $Action *>&1 | ForEach-Object {
            if ($_ -is [int]) { return }
            $tb.AppendText(($_.ToString() + "`r`n"))
            [Windows.Forms.Application]::DoEvents()
        }
    } catch {
        $tb.AppendText("오류: $($_.Exception.Message)`r`n")
    } finally {
        foreach ($b in $buttons) { $b.Enabled = $true }
        $tb.AppendText("`r`n--- 완료 ---`r`n")
    }
}

$btnScan.Add_Click({ Invoke-GuiAction { [void](Invoke-Scan) } })
$btnClean.Add_Click({
    $msg = "점검 후 정리를 진행합니다.`r`n삭제는 항목마다 다시 확인하며, 정리 전에 증거를 바탕화면에 백업합니다.`r`n계속할까요?"
    if ([Windows.Forms.MessageBox]::Show($msg, 'NIKKE 정리', 'YesNo', 'Warning') -eq 'Yes') {
        Invoke-GuiAction { [void](Invoke-Scan); Invoke-Clean }
    }
})
$btnAdmin.Add_Click({
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', ('"{0}"' -f $PSCommandPath))
        $form.Close()
    } catch { [void][Windows.Forms.MessageBox]::Show('관리자 권한 실행이 취소되었습니다.', 'NIKKE 점검/정리', 'OK', 'Information') }
})

[void]$form.ShowDialog()

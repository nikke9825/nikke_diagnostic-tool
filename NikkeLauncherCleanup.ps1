<#
.SYNOPSIS
  NIKKE PC 런처 공급망 공격(2026-11) 점검 및 정리 도구 (Windows)

.DESCRIPTION
  - 기본은 읽기 전용 점검입니다. 삭제/변경은 항목마다 사용자 확인 후에만 수행합니다.
  - 네트워크 접속을 하지 않습니다. 악성 파일을 실행하지 않습니다. 어떤 데이터도 외부로 보내지 않습니다.
  - 정리 전에 증거(로그 등)를 바탕화면에 복사해 둡니다.

  참고 보고서: https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5
  이 도구는 위 보고서와 댓글 제보를 근거로 만든 비공식 도구입니다. 보증하지 않습니다.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\NikkeLauncherCleanup.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Scan', 'Clean', 'PostReboot')]
    [string]$Mode = 'Menu',
    [string[]]$NikkePath
)

$ErrorActionPreference = 'Continue'
$script:Findings = New-Object System.Collections.ArrayList
$script:LogFiles = @()

# ---------------------------------------------------------------- IOC 데이터
$Ioc = @{
    ClsidPath   = 'HKCU:\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
    Domains     = @('insightjs.com', 'analytics.insightjs.com', 'insightjs.org')
    BlockIPs    = @('89.127.233.127', '89.126.250.172')
    LogNeedles  = @('k2f_chan', 'agent started as', 'k2f.lua')
    StateNeedle = 'k2f.agent'
    LoaderKey   = 'insightjs.com/l.js'
    # 변조된 공식 파일의 ETag (HTTP 캐시에 남아 있을 수 있음)
    BadEtags    = @(
        '50d1861152ea7f6875ffceb7d08445b5',  # aegis-fix.min.js
        '481e9b5ab8fb93406bf31980b53e0578',  # images.7fec4c32.js
        'b7d842200372ad0d9a84ef4cc8511311',  # FeedList.feb647c9.js
        'dd06875637a29cddd3bae2ba84142c78'   # vue-bucket.min.js
    )
}
# 스크립트 자신의 경로 (dot-source 되어도 이 파일 경로를 유지)
$SelfPath = $PSCommandPath

# ioc.json 이 같은 폴더에 있으면 내장 기본값을 덮어씀 (IOC 갱신을 코드 수정 없이 하기 위함)
if ($SelfPath) {
    $IocFile = Join-Path (Split-Path -Parent $SelfPath) 'ioc.json'
    if (Test-Path -LiteralPath $IocFile) {
        try {
            $j = Get-Content -LiteralPath $IocFile -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($k in @($Ioc.Keys)) {
                if ($null -ne $j.$k) {
                    if ($Ioc[$k] -is [array]) { $Ioc[$k] = @($j.$k) } else { $Ioc[$k] = [string]$j.$k }
                }
            }
            Write-Host ("IOC 로드: ioc.json (version {0})" -f $j.version) -ForegroundColor DarkGray
        } catch { Write-Warning "ioc.json 을 읽지 못해 내장 기본값을 사용합니다: $($_.Exception.Message)" }
    }
}
$LauncherData = Join-Path $env:APPDATA 'nikke_launcher'
$TbsCache     = Join-Path $LauncherData 'tbs_cache'
$ChromeHelper = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\PlatformExperienceHelper'
$HostsFile    = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$HostsMarker  = '# NIKKE-launcher-IOC-block'

# ---------------------------------------------------------------- 유틸
function Write-Info($m) { Write-Host $m -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "  [정상] $m" -ForegroundColor Green }
function Write-Bad($m)  { Write-Host "  [위험] $m" -ForegroundColor Red }
function Write-Warn2($m){ Write-Host "  [주의] $m" -ForegroundColor Yellow }

function Add-Finding([string]$Level, [string]$Name, [string]$Detail) {
    [void]$script:Findings.Add([pscustomobject]@{ Level = $Level; Name = $Name; Detail = $Detail })
    switch ($Level) {
        'INFECTED' { Write-Bad  "$Name : $Detail" }
        'EXPOSED'  { Write-Warn2 "$Name : $Detail" }
        default    { Write-Ok   "$Name : $Detail" }
    }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Confirm-Step([string]$Question) {
    $a = Read-Host "$Question (y/N)"
    return ($a -match '^(y|yes|예|ㅇ)$')
}

# 파일(잠겨 있어도 읽기 공유로)을 바이트로 읽어 문자열 포함 여부 검사
function Test-FileContains([string]$Path, [string[]]$Needles) {
    $hits = @()
    try {
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($fi.Length -eq 0 -or $fi.Length -gt 200MB) { return $hits }
        $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $br = New-Object IO.BinaryReader($fs)
            $buf = $br.ReadBytes([int]$fs.Length)
        } finally { $fs.Close() }
        $text = [Text.Encoding]::GetEncoding(28591).GetString($buf)
        foreach ($n in $Needles) {
            if ($text.IndexOf($n, [StringComparison]::Ordinal) -ge 0) { $hits += $n }
        }
    } catch { }
    return $hits
}

function Get-LauncherProcs {
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match 'nikke|tbs_browser' }
}

function Get-MaliciousDllDirs {
    if (-not (Test-Path -LiteralPath $ChromeHelper)) { return @() }
    Get-ChildItem -LiteralPath $ChromeHelper -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '^[0-9a-fA-F]{64}$' -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'platform_experience_helper.dll'))
        }
}

# ---------------------------------------------------------------- NIKKE 설치 위치 탐색
function Find-NikkeLogs {
    Write-Info '[탐색] NIKKE 설치 폴더를 찾는 중입니다 (드라이브 크기에 따라 시간이 걸립니다)...'
    $roots = New-Object System.Collections.ArrayList
    foreach ($p in $NikkePath) { if ($p) { [void]$roots.Add($p) } }
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Za-z]:\\$' }
    foreach ($d in $drives) {
        Get-ChildItem -LiteralPath $d.Root -Directory -Recurse -Depth 3 -Filter '*nikke*' -ErrorAction SilentlyContinue |
            ForEach-Object { [void]$roots.Add($_.FullName) }
    }
    $logs = @()
    foreach ($r in ($roots | Select-Object -Unique)) {
        $logs += Get-ChildItem -LiteralPath $r -Recurse -Depth 5 -Filter 'debug.log' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like '*intl_service*' } | ForEach-Object FullName
    }
    $script:LogFiles = @($logs | Select-Object -Unique)
    if ($script:LogFiles.Count -eq 0) {
        Write-Warn2 'debug.log를 찾지 못했습니다 (NIKKE 폴더를 삭제/재설치했거나 위치가 다를 수 있음). -NikkePath 로 폴더를 지정할 수 있습니다.'
    } else {
        $script:LogFiles | ForEach-Object { Write-Host "  발견: $_" }
    }
}

# ---------------------------------------------------------------- 점검
function Invoke-Scan {
    $script:Findings.Clear()
    Write-Host ''
    Write-Info '=== 점검 시작 (읽기 전용) ==='

    # 1) debug.log
    Find-NikkeLogs
    foreach ($log in $script:LogFiles) {
        $h = Test-FileContains $log $Ioc.LogNeedles
        if ($h.Count -gt 0) { Add-Finding 'INFECTED' 'debug.log' ("에이전트 실행 흔적: " + ($h -join ', ') + "  [$log]") }
        else { Add-Finding 'OK' 'debug.log' "에이전트 흔적 없음 [$log]" }
    }

    # 2) 에이전트 상태 (Local Storage) - NIKKE 폴더를 지웠어도 남음
    $ldb = Join-Path $TbsCache 'Local Storage\leveldb'
    if (Test-Path -LiteralPath $ldb) {
        $stateHit = $false
        Get-ChildItem -LiteralPath $ldb -File -ErrorAction SilentlyContinue | ForEach-Object {
            if ((Test-FileContains $_.FullName @($Ioc.StateNeedle)).Count -gt 0) {
                $stateHit = $true
                Add-Finding 'INFECTED' 'Local Storage' "k2f.agent 상태 발견: $($_.Name)"
            }
        }
        if (-not $stateHit) { Add-Finding 'OK' 'Local Storage' 'k2f.agent 상태 없음 (압축된 .ldb 안은 확인 불가)' }
    } else { Add-Finding 'OK' 'Local Storage' 'leveldb 폴더 없음' }

    # 3) 크롬 persistence: 레지스트리
    $inproc = Join-Path $Ioc.ClsidPath 'InprocServer32'
    if (Test-Path -LiteralPath $Ioc.ClsidPath) {
        $val = $null
        try { $val = (Get-ItemProperty -LiteralPath $inproc -ErrorAction Stop).'(default)' } catch { }
        Add-Finding 'INFECTED' 'HKCU CLSID' "악성 COM 등록 존재 -> $val"
    } else { Add-Finding 'OK' 'HKCU CLSID' '없음' }

    # 4) 크롬 persistence: DLL 폴더
    $dirs = @(Get-MaliciousDllDirs)
    if ($dirs.Count -gt 0) { foreach ($d in $dirs) { Add-Finding 'INFECTED' 'Chrome DLL' $d.FullName } }
    else { Add-Finding 'OK' 'Chrome DLL' '해시 이름 하위 폴더 없음' }

    # 5) 로더 실행 여부 (Code Cache)
    $cc = Join-Path $TbsCache 'Code Cache\js'
    $loaderFiles = 0
    if (Test-Path -LiteralPath $cc) {
        Get-ChildItem -LiteralPath $cc -File -ErrorAction SilentlyContinue | ForEach-Object {
            if ((Test-FileContains $_.FullName @($Ioc.LoaderKey)).Count -gt 0) { $loaderFiles++ }
        }
    }
    if ($loaderFiles -gt 0) { Add-Finding 'EXPOSED' 'Code Cache' "로더 실행 흔적 $loaderFiles 건 (페이로드를 받았다는 뜻은 아님)" }
    else { Add-Finding 'OK' 'Code Cache' '로더 흔적 없음' }

    # 6) HTTP 캐시에 변조 파일 잔존
    $hc = Join-Path $TbsCache 'Cache'
    $etagHit = $false
    if (Test-Path -LiteralPath $hc) {
        Get-ChildItem -LiteralPath $hc -File -ErrorAction SilentlyContinue | ForEach-Object {
            $h = Test-FileContains $_.FullName ($Ioc.BadEtags + @('insightjs'))
            if ($h.Count -gt 0) { $etagHit = $true; Add-Finding 'EXPOSED' 'HTTP 캐시' "변조 파일 흔적($($h -join ',')): $($_.Name)" }
        }
    }
    if (-not $etagHit) { Add-Finding 'OK' 'HTTP 캐시' '변조 파일 흔적 없음' }

    # 7) 임시 파일
    $tmp = @(Get-ChildItem -LiteralPath $env:TEMP -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'k2f*' })
    if ($tmp.Count -gt 0) { $tmp | ForEach-Object { Add-Finding 'INFECTED' 'TEMP' $_.FullName } }
    else { Add-Finding 'OK' 'TEMP' 'k2f* 임시 파일 없음' }

    # 8) DNS 캐시
    $dns = @()
    try { $dns = @(Get-DnsClientCache -ErrorAction Stop | Where-Object { $_.Entry -like '*insightjs*' }) } catch { }
    if ($dns.Count -gt 0) { Add-Finding 'EXPOSED' 'DNS 캐시' (($dns | ForEach-Object Entry | Select-Object -Unique) -join ', ') }
    else { Add-Finding 'OK' 'DNS 캐시' 'insightjs 조회 기록 없음 (캐시는 금방 사라지므로 참고용)' }

    # 9) 차단 상태
    $blocked = (Test-Path -LiteralPath $HostsFile) -and ((Get-Content -LiteralPath $HostsFile -ErrorAction SilentlyContinue) -contains $HostsMarker)
    if ($blocked) { Write-Ok 'hosts 차단: 적용됨' } else { Write-Warn2 'hosts 차단: 미적용' }

    # 결론
    Write-Host ''
    $inf = @($script:Findings | Where-Object Level -eq 'INFECTED').Count
    $exp = @($script:Findings | Where-Object Level -eq 'EXPOSED').Count
    if ($inf -gt 0) {
        Write-Host '결론: 감염 흔적이 발견되었습니다. 정리와 자격증명 교체가 필요합니다.' -ForegroundColor Red
    } elseif ($exp -gt 0) {
        Write-Host '결론: 악성 로더에 노출된 흔적은 있으나 에이전트 실행 흔적은 없습니다. 캐시 삭제와 차단을 권장합니다.' -ForegroundColor Yellow
    } else {
        Write-Host '결론: 알려진 흔적이 발견되지 않았습니다.' -ForegroundColor Green
    }
    Write-Host '※ 흔적 없음은 "감염되지 않음"의 증명이 아닙니다. 폴더 삭제/재설치로 로그가 사라졌을 수 있고,' -ForegroundColor DarkGray
    Write-Host '   Defender가 해당 DLL을 탐지하지 못했다는 제보가 있습니다.' -ForegroundColor DarkGray

    Save-Report
    return $inf
}

function Save-Report {
    $desk = [Environment]::GetFolderPath('Desktop')
    $path = Join-Path $desk ("NIKKE_scan_report_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $lines = @("NIKKE launcher scan report  $(Get-Date -Format s)", '')
    $lines += $script:Findings | ForEach-Object { "[{0}] {1}: {2}" -f $_.Level, $_.Name, $_.Detail }
    try { $lines | Out-File -LiteralPath $path -Encoding UTF8; Write-Host "리포트 저장: $path" } catch { }
}

# ---------------------------------------------------------------- 증거 보존
function Backup-Evidence {
    $desk = [Environment]::GetFolderPath('Desktop')
    $dest = Join-Path $desk ("NIKKE_evidence_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Write-Info "[증거 보존] $dest"
    $i = 0
    foreach ($log in $script:LogFiles) {
        $i++
        $sub = Join-Path $dest "install$i"
        New-Item -ItemType Directory -Path $sub -Force | Out-Null
        Copy-Item -LiteralPath $log -Destination $sub -ErrorAction SilentlyContinue
        $launcher = Split-Path (Split-Path $log -Parent) -Parent
        $tg = Join-Path $launcher 'log\tinyget'
        if (Test-Path -LiteralPath $tg) { Copy-Item -LiteralPath $tg -Destination $sub -Recurse -ErrorAction SilentlyContinue }
    }
    $ldb = Join-Path $TbsCache 'Local Storage\leveldb'
    if (Test-Path -LiteralPath $ldb) { Copy-Item -LiteralPath $ldb -Destination (Join-Path $dest 'leveldb') -Recurse -ErrorAction SilentlyContinue }
    $dirs = @(Get-MaliciousDllDirs)
    foreach ($d in $dirs) {
        $f = Join-Path $d.FullName 'platform_experience_helper.dll'
        try {
            $hash = (Get-FileHash -LiteralPath $f -Algorithm SHA256 -ErrorAction Stop).Hash
            "$hash  $f" | Out-File -LiteralPath (Join-Path $dest 'dll_hashes.txt') -Append -Encoding UTF8
        } catch { }
    }
    Write-Host '  (DLL 자체는 복사하지 않고 경로/해시만 기록합니다. 복사본에는 공격자 에이전트 정보가 들어 있으니 외부에 올리지 마세요.)' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------- 정리
function Remove-DllDirs {
    $left = 0
    foreach ($d in @(Get-MaliciousDllDirs)) {
        try {
            Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction Stop
            Write-Ok "삭제됨: $($d.FullName)"
        } catch {
            Write-Warn2 "삭제 실패(잠김): $($d.FullName)"
            $left++
        }
    }
    return $left
}

function Invoke-Clean {
    if (-not (Test-IsAdmin)) {
        Write-Warn2 '관리자 권한이 아닙니다. hosts/방화벽 차단 단계는 건너뜁니다. (전체 정리는 관리자 PowerShell 권장)'
    }

    # 실행 중 프로세스
    $procs = @(Get-LauncherProcs)
    if ($procs.Count -gt 0) {
        Write-Warn2 ('실행 중인 관련 프로세스: ' + (($procs | ForEach-Object ProcessName | Select-Object -Unique) -join ', '))
        Write-Host '  (tbs_browser 는 다른 Tencent 계열 런처도 쓸 수 있습니다.)' -ForegroundColor DarkGray
        if (Confirm-Step '  이 프로세스들을 종료할까요?') {
            $procs | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        } else { Write-Warn2 '종료하지 않으면 일부 삭제가 실패할 수 있습니다.' }
    }

    Backup-Evidence

    # 1단계: 레지스트리 (반드시 DLL 삭제보다 먼저)
    Write-Host ''
    Write-Info '[1] 크롬 persistence 레지스트리 제거'
    if (Test-Path -LiteralPath $Ioc.ClsidPath) {
        Write-Host "  대상: $($Ioc.ClsidPath)  (HKCU 만. HKLM 의 동일 CLSID 는 정상이므로 건드리지 않습니다)"
        if (Confirm-Step '  삭제할까요?') {
            try { Remove-Item -LiteralPath $Ioc.ClsidPath -Recurse -Force -ErrorAction Stop; Write-Ok '삭제됨' }
            catch { Write-Bad "삭제 실패: $($_.Exception.Message)" }
        }
    } else { Write-Ok '해당 없음' }

    # 2단계: DLL 폴더
    Write-Host ''
    Write-Info '[2] 크롬 악성 DLL 폴더 제거'
    $dirs = @(Get-MaliciousDllDirs)
    if ($dirs.Count -eq 0) { Write-Ok '해당 없음' }
    else {
        $dirs | ForEach-Object { Write-Host "  대상: $($_.FullName)" }
        Write-Host '  (PlatformExperienceHelper 폴더 자체와 LoadFeatures 파일은 정상이라 삭제하지 않습니다)' -ForegroundColor DarkGray
        if (Confirm-Step '  삭제를 시도할까요?') {
            $chrome = @(Get-Process -Name chrome -ErrorAction SilentlyContinue)
            if ($chrome.Count -gt 0 -and (Confirm-Step '  크롬을 종료해야 합니다. 크롬을 모두 닫을까요? (저장 안 된 작업 주의)')) {
                $chrome | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2
            }
            $left = Remove-DllDirs
            if ($left -gt 0) {
                Write-Warn2 'DLL이 로드되어 잠겨 있습니다. 재부팅 후 자동으로 마저 삭제하도록 예약합니다.'
                if ($SelfPath) {
                    $cmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode PostReboot' -f $SelfPath
                    try {
                        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'NikkeCleanupPost' -Value $cmd
                        Write-Host '  예약됨. 이 스크립트 파일을 이동/삭제하지 마세요.' -ForegroundColor Yellow
                    } catch { Write-Bad '예약 실패. 재부팅 후 -Mode PostReboot 로 직접 실행하세요.' }
                }
                $script:NeedReboot = $true
            }
        }
    }

    # 3단계: 임시 파일
    Write-Host ''
    Write-Info '[3] TEMP 의 k2f* 임시 파일'
    $tmp = @(Get-ChildItem -LiteralPath $env:TEMP -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'k2f*' })
    if ($tmp.Count -eq 0) { Write-Ok '해당 없음' }
    elseif (Confirm-Step "  $($tmp.Count)개 삭제할까요?") {
        $tmp | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue; Write-Ok '삭제됨'
    }

    # 4단계: 런처 캐시
    Write-Host ''
    Write-Info '[4] 런처 캐시 삭제 (변조 파일/에이전트 상태 제거)'
    if (Test-Path -LiteralPath $TbsCache) {
        Write-Host "  대상: $TbsCache  (증거는 위에서 백업했습니다)"
        if (Confirm-Step '  삭제할까요?') {
            try { Remove-Item -LiteralPath $TbsCache -Recurse -Force -ErrorAction Stop; Write-Ok '삭제됨' }
            catch { Write-Bad "삭제 실패: $($_.Exception.Message)" }
        }
    } else { Write-Ok '해당 없음' }

    # 5단계: 차단 (관리자)
    Write-Host ''
    Write-Info '[5] 공격 인프라 차단 (관리자 필요)'
    if (Test-IsAdmin) {
        if (Confirm-Step '  hosts 파일에 공격 도메인 차단을 추가할까요?') {
            $cur = @(Get-Content -LiteralPath $HostsFile -ErrorAction SilentlyContinue)
            if ($cur -contains $HostsMarker) { Write-Ok '이미 적용됨' }
            else {
                $add = @('', $HostsMarker) + ($Ioc.Domains | ForEach-Object { "0.0.0.0 $_" })
                Add-Content -LiteralPath $HostsFile -Value $add -Encoding ASCII
                Write-Ok 'hosts 차단 추가됨'
            }
        }
        if (Confirm-Step '  방화벽에서 공격 서버 IP 아웃바운드를 차단할까요?') {
            try {
                if (-not (Get-NetFirewallRule -DisplayName 'NIKKE-IOC-Block' -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName 'NIKKE-IOC-Block' -Direction Outbound -Action Block -RemoteAddress $Ioc.BlockIPs | Out-Null
                }
                Write-Ok '방화벽 규칙 적용됨'
            } catch { Write-Bad "실패: $($_.Exception.Message)" }
        }
    } else { Write-Warn2 '관리자 권한이 아니어서 건너뜁니다.' }

    Show-Checklist
    if ($script:NeedReboot) {
        Write-Host ''
        Write-Host '재부팅이 필요합니다. 재부팅하면 남은 DLL 폴더가 자동 삭제됩니다.' -ForegroundColor Yellow
        if (Confirm-Step '지금 재부팅할까요?') { Restart-Computer -Force }
    }
}

function Show-Checklist {
    Write-Host ''
    Write-Host '================ 수동으로 해야 할 일 (도구가 대신할 수 없음) ================' -ForegroundColor Magenta
    @(
        '1. 깨끗한 다른 기기(휴대폰 등)에서 비밀번호 변경: NIKKE/Level Infinite -> 이메일 -> 디스코드 -> 은행 -> 브라우저 저장 비밀번호',
        '2. 모든 기기/서비스에서 세션 로그아웃 (쿠키는 비밀번호 없이도 악용됨) + 2단계 인증 활성화',
        '3. GitHub, npm, AWS, AI 서비스 API 키, SSH 키 등 개발자 자격증명 폐기 후 재발급',
        '4. 크롬에 암호화폐 지갑 확장이 있었다면 새 지갑/새 시드 문구로 자산 이전',
        '5. 에이전트 실행 흔적이 있었다면 Windows 재설치가 가장 확실 (원격 명령 실행이 가능했음)',
        '6. 공식 수정 발표 전까지 NIKKE PC 런처 실행 금지'
    ) | ForEach-Object { Write-Host "  $_" }
}

# ---------------------------------------------------------------- 재부팅 후
function Invoke-PostReboot {
    Write-Info '[재부팅 후 정리] 남은 악성 DLL 폴더를 삭제합니다.'
    if (Test-Path -LiteralPath $Ioc.ClsidPath) {
        Write-Warn2 'HKCU CLSID 가 다시 존재합니다. 먼저 정리(Clean) 모드를 다시 실행하세요.'
    } else {
        $left = Remove-DllDirs
        if ($left -eq 0) { Write-Ok '완료' } else { Write-Bad '일부 삭제 실패. 안전 모드/다른 OS에서 삭제하거나 Windows 재설치를 고려하세요.' }
    }
    Show-Checklist
    Read-Host 'Enter 를 누르면 종료합니다'
}

# ---------------------------------------------------------------- 진입점
$script:NeedReboot = $false
# GUI 등에서 dot-source 로 불러온 경우 함수만 정의하고 종료
if ($MyInvocation.InvocationName -eq '.') { return }
Write-Host ''
Write-Host 'NIKKE PC 런처 점검/정리 도구 (비공식)' -ForegroundColor White
Write-Host '네트워크 접속 없음 / 외부 전송 없음 / 삭제는 항목별 확인 후 수행' -ForegroundColor DarkGray

switch ($Mode) {
    'Scan'       { [void](Invoke-Scan) }
    'Clean'      { [void](Invoke-Scan); Invoke-Clean }
    'PostReboot' { Invoke-PostReboot }
    default {
        Write-Host ''
        Write-Host '  1) 점검만 (읽기 전용)'
        Write-Host '  2) 점검 + 정리'
        Write-Host '  3) 종료'
        switch (Read-Host '선택') {
            '1' { [void](Invoke-Scan) }
            '2' { [void](Invoke-Scan); Invoke-Clean }
            default { return }
        }
    }
}

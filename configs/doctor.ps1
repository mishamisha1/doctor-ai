<#
  AI-Doctor for Windows (terminal-only)
  Safe "doctor": scan -> plan -> fix -> rollback -> avscan -> update
#>

param(
  [ValidateSet("scan","plan","fix","rollback","avscan","update","driver-install","drivers","power","driver-update","driver-auto")]
  [string]$cmd = "scan",
  [switch]$Auto,            # fix without prompt (only low-risk actions)
  [string]$PolicyPath = ".\policy.json"
)

# ---- console defaults (UTF-8, quiet progress) ----
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

# ---- paths & logging ----
$ErrorActionPreference = "Stop"
$global:BaseDir = (Resolve-Path ".").Path
$global:LogDir  = Join-Path $BaseDir "logs"
$global:QDir    = Join-Path $BaseDir "quarantine"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path $QDir | Out-Null

function Write-Log($msg) {
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "[$ts] $msg"
  $line | Tee-Object -FilePath (Join-Path $LogDir ("doctor_" + (Get-Date -Format "yyyyMMdd") + ".log")) -Append
}

function Load-Policy {
  if (!(Test-Path $PolicyPath)) { throw "Policy file not found: $PolicyPath" }
  (Get-Content $PolicyPath -Raw | ConvertFrom-Json)
}

function New-RestorePoint {
  Write-Log "creating system restore point"
  try { Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue | Out-Null } catch {}
  try {
    Checkpoint-Computer -Description "AI_Doctor_BeforeFix" -RestorePointType 'MODIFY_SETTINGS' | Out-Null
    Write-Log "restore point created"
  } catch {
    Write-Log "restore point failed: $_"
    $ans = Read-Host "System restore point failed. Continue without it? (yes/no)"
    if ($ans -ne 'yes') { throw "aborted: no restore point" }
  }
}

function Is-UnsignedFile([string]$path) {
  try {
    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
    return ($null -eq $sig) -or ($sig.Status -ne 'Valid')
  } catch { return $true }
}

function Path-MatchAny($path, [string[]]$patterns) {
  foreach ($p in $patterns) {
    try {
      $probe = $p.Replace("*","")
      if ($probe.Length -ge 3) { [void](Test-Path $probe) } # warm fs
    } catch {}
    if ($path -like $p) { return $true }
  }
  return $false
}

# -------- telemetry --------
function Collect-Telemetry {
  Write-Log "collect telemetry"

  $procs = Get-CimInstance Win32_Process | ForEach-Object {
    [PSCustomObject]@{
      Name = $_.Name
      PID = $_.ProcessId
      Path = $_.ExecutablePath
      CommandLine = $_.CommandLine
      User = (Get-CimAssociatedInstance -InputObject $_ -Association Win32_ProcessOwner -ErrorAction SilentlyContinue | ForEach-Object { $_.User }) -join '\'
    }
  }

  $net = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
         Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess

  $autoruns = @()
  foreach ($hive in @("HKCU","HKLM")) {
    foreach ($key in @(
      "Software\Microsoft\Windows\CurrentVersion\Run",
      "Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )) {
      try {
        $path = "Registry::$hive\$key"
        $vals = Get-ItemProperty $path
        $vals.PSObject.Properties |
          Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' } |
          ForEach-Object {
            $autoruns += [PSCustomObject]@{
              Hive=$hive; Key=$key; Name=$_.Name; Data=$_.Value
            }
          }
      } catch {}
    }
  }

  # defender metadata only (no UI)
  $defStatus = $null
  $lastThreats = $null
  try { $defStatus = Get-MpComputerStatus } catch {}
  try { $lastThreats = Get-MpThreatDetection -ErrorAction SilentlyContinue } catch {}

  $out = [PSCustomObject]@{
    Hostname = $env:COMPUTERNAME
    Time = (Get-Date).ToString("s")
    Processes = $procs
    Net = $net
    Autoruns = $autoruns
    DefenderStatus = $defStatus
    Threats = $lastThreats
  }
  $json = $out | ConvertTo-Json -Depth 6
  $path = Join-Path $LogDir ("scan_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".json")
  $json | Out-File -Encoding utf8 $path
  Write-Log "telemetry saved: $path"
  return $out
}

# -------- heuristics --------
function Analyze-Heuristics($tele, $policy) {
  Write-Log "heuristic analysis"
  $sus = @()

  # 1) processes: only unsigned AND from user profile or temp; ignore UWP apps
  foreach ($p in $tele.Processes) {
    $exe = $p.Path
    if ([string]::IsNullOrEmpty($exe)) { continue }
    if ($exe -like "C:\Program Files\WindowsApps\*") { continue }

    $isTemp = Path-MatchAny $exe $policy.quarantinePaths
    $inUserProfile = $exe -like "$env:USERPROFILE\*" -or $exe -like "C:\Users\*\AppData\*"
    $isUnsigned = Is-UnsignedFile $exe

    if (($isTemp -or $inUserProfile) -and $isUnsigned) {
      $sus += [PSCustomObject]@{
        Type="process"; PID=$p.PID; Name=$p.Name; Path=$exe; Reason="unsigned+user-temp"
      }
    }
  }

  # 2) autoruns: only from temp or user profile
  foreach ($a in $tele.Autoruns) {
    $data = [string]$a.Data
    if ($data -and ((Path-MatchAny $data $policy.quarantinePaths) -or
                    $data -like "$env:USERPROFILE\*" -or $data -like "C:\Users\*\AppData\*")) {
      $sus += [PSCustomObject]@{
        Type="autorun"; Hive=$a.Hive; Key=$a.Key; Name=$a.Name; Data=$data; Reason="autorun-from-user-temp"
      }
    }
  }

  # 3) network flags (info only)
  $flags = @()
  foreach ($c in $tele.Net) {
    if ($c.RemoteAddress -and ($c.RemoteAddress -match "^\d+\.\d+\.\d+\.\d+$")) {
      $flags += [PSCustomObject]@{
        Type="net"; PID=$c.OwningProcess; Remote=$c.RemoteAddress; Port=$c.RemotePort; Reason="ip-without-dns"
      }
    }
  }

  return [PSCustomObject]@{ Suspicious=$sus; Flags=$flags }
}

# -------- plan --------
function Build-Plan($analysis, $policy) {
  $plan = @()
  foreach ($i in $analysis.Suspicious) {
    if ($i.Type -eq "process") {
      $plan += [PSCustomObject]@{ Action="KillProcess"; Detail=$i }
      if ($policy.autoFix.quarantineNewBinariesFromTemp -and $i.Path) {
        $plan += [PSCustomObject]@{ Action="QuarantineFile"; Detail=$i }
      }
    } elseif ($i.Type -eq "autorun") {
      if ($policy.autoFix.disableAutorun) {
        $plan += [PSCustomObject]@{ Action="DisableAutorun"; Detail=$i }
      }
    }
  }
  return $plan
}

# -------- apply plan --------
function Apply-Plan($plan, $policy, [switch]$auto) {
  if (-not $plan -or $plan.Count -eq 0) { Write-Log "nothing to fix"; Write-Host "nothing to fix"; return }

  if (-not $auto) {
    Write-Host "Plan:" -ForegroundColor Cyan
    $plan | Select-Object Action,
      @{n='Name';e={$_.Detail.Name}},
      @{n='PID';e={$_.Detail.PID}},
      @{n='Path';e={ if ($_.Detail.Path) { ($_.Detail.Path -replace '^(.{80}).+$','$1…') } else { $_.Detail.Data } }},
      @{n='Reason';e={$_.Detail.Reason}} | Format-Table -AutoSize
    $ok = Read-Host "Apply these actions? (yes/no)"
    if ($ok -ne "yes") { Write-Log "user declined fix"; return }
  }

  New-RestorePoint

  foreach ($step in $plan) {
    switch ($step.Action) {
      "KillProcess" {
        $pid = $step.Detail.PID
        Write-Log "kill process PID=$pid"
        try { Stop-Process -Id $pid -Force -ErrorAction Stop } catch { Write-Log "kill failed: $_" }
      }
      "QuarantineFile" {
        $src = $step.Detail.Path
        if (-not (Test-Path $src)) { continue }
        $dst = Join-Path $QDir ((Split-Path $src -Leaf) + "." + (Get-Date -Format "yyyyMMddHHmmss"))
        Write-Log "quarantine file $src -> $dst"
        try {
          Copy-Item $src $dst -ErrorAction Stop
          Set-ItemProperty -Path $src -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue
        } catch { Write-Log "quarantine failed: $_" }
      }
      "DisableAutorun" {
        $hive = $step.Detail.Hive; $key=$step.Detail.Key; $name=$step.Detail.Name
        $regPath = "Registry::$hive\$key"
        Write-Log "disable autorun $regPath :: $name"
        try { Remove-ItemProperty -Path $regPath -Name $name -ErrorAction Stop } catch { Write-Log "autorun remove failed: $_" }
      }
      default { Write-Log "unknown action $($step.Action)" }
    }
  }
}

# -------- winget updates --------
function Update-AllowedPackages($policy) {
  Write-Log "winget updating allowed packages"
  foreach ($pkg in $policy.allowedPackages) {
    try {
      & winget upgrade --id $pkg --accept-source-agreements --accept-package-agreements | Out-Null
      & winget upgrade --id $pkg --accept-source-agreements --accept-package-agreements --silent | Out-Null
      Write-Log "updated $pkg (if available)"
    } catch { Write-Log "winget issue on ${pkg}: $_" }
  }
  try { Update-MpSignature | Out-Null; Write-Log "defender signatures updated" }
  catch { Write-Log "defender update failed: $_" }
}
# -------- drivers: detect, install from folder, vendor tools (PS 5.1 safe) --------

function Get-DriverInventory {
  $drv = Get-CimInstance Win32_PnPSignedDriver | Select-Object FriendlyName, DeviceClass, DriverProviderName, DriverVersion, DriverDate, InfName, DeviceID, IsSigned
  $devs = Get-CimInstance Win32_PnPEntity | Select-Object Name, DeviceID, ConfigManagerErrorCode, PNPClass
  [PSCustomObject]@{ Drivers=$drv; Devices=$devs }
}

function Guess-DeviceVendor([string]$deviceId) {
  if ($deviceId -match 'VEN_8086' -or $deviceId -match 'VID_8086') { return 'Intel' }
  if ($deviceId -match 'VEN_10DE' -or $deviceId -match 'VID_10DE') { return 'NVIDIA' }
  if ($deviceId -match 'VEN_1002' -or $deviceId -match 'VID_1002' -or $deviceId -match 'VEN_1022') { return 'AMD' }
  if ($deviceId -match 'VEN_10EC' -or $deviceId -match 'VID_10EC') { return 'Realtek' }
  if ($deviceId -match 'VEN_14E4' -or $deviceId -match 'VID_14E4') { return 'Broadcom' }
  if ($deviceId -match 'VEN_8087' -or $deviceId -match 'VID_8087') { return 'Intel' }
  return ''
}

function Get-MissingDrivers($inv) {
  $byDevice = @{}
  foreach ($r in $inv.Drivers) { $byDevice[$r.DeviceID] = $r }

  $missing = @()
  foreach ($d in $inv.Devices) {
    $err = [int]$d.ConfigManagerErrorCode
    $hasRec = $byDevice.ContainsKey($d.DeviceID)
    $rec = $null
    if ($hasRec) { $rec = $byDevice[$d.DeviceID] }

    $noSigned = $false
    if ($hasRec -and $rec.DriverProviderName -ne 'Microsoft' -and $rec.IsSigned -ne $true) { $noSigned = $true }

    $unknownClass = (-not $d.PNPClass) -or ($d.PNPClass -eq 'Unknown')
    $errNoDriver = ($err -eq 28)

    if ($errNoDriver -or $unknownClass -or $noSigned -or (-not $hasRec)) {
      $name = if ($d.Name) { $d.Name } elseif ($rec) { $rec.FriendlyName } else { '' }
      $pnp  = if ($d.PNPClass) { $d.PNPClass } elseif ($rec) { $rec.DeviceClass } else { '' }
      $inf  = if ($rec) { $rec.InfName } else { '' }
      $prov = if ($rec) { $rec.DriverProviderName } else { '' }
      $sgn  = if ($rec) { $rec.IsSigned } else { $false }

      $missing += [PSCustomObject]@{
        Name      = $name
        DeviceID  = $d.DeviceID
        PNPClass  = $pnp
        ErrorCode = $err
        CurrentInf= $inf
        Provider  = $prov
        Signed    = $sgn
        Vendor    = (Guess-DeviceVendor $d.DeviceID)
      }
    }
  }
  $missing
}

function Install-DriversFromFolder([string]$folder) {
  if (-not (Test-Path $folder)) { throw "drivers folder not found: $folder" }
  $infGlob = Join-Path $folder '*.inf'
  Write-Log "pnputil add-driver $infGlob /subdirs /install"
  New-RestorePoint
  try {
    pnputil /add-driver $infGlob /subdirs /install | Tee-Object -FilePath (Join-Path $LogDir ("driver_install_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log"))
    pnputil /scan-devices | Out-Null
    Write-Host "drivers from folder installed (see logs)" -ForegroundColor Green
  } catch {
    Write-Log "driver install failed: $_"
    throw
  }
}

function Offer-VendorTools($vendors) {
  $map = @{
    'Intel'  = 'Intel.DriverAndSupportAssistant'
    'NVIDIA' = 'NVIDIA.GeForceExperience'
    'AMD'    = 'AMD.Software'
    'Realtek'= ''
  }
  $todo = @()
  foreach ($v in ($vendors | Sort-Object -Unique)) {
    if ($v -and $map.ContainsKey($v) -and $map[$v]) { $todo += $v }
  }
  if ($todo.Count -eq 0) {
    Write-Host "no vendor tools to offer" -ForegroundColor DarkYellow
    return
  }
  Write-Host "`nVendor tools to install (official):" -ForegroundColor Cyan
  foreach ($v in $todo) { Write-Host ("  - {0} -> winget install {1}" -f $v, $map[$v]) }
  $ok = Read-Host "install these vendor tools now? (yes/no)"
  if ($ok -ne 'yes') { return }
  foreach ($v in $todo) {
    $id = $map[$v]
    try {
      Write-Log "winget install $id"
      winget install --id $id --accept-source-agreements --accept-package-agreements --silent | Out-Null
      Write-Host ("{0} tool installed (if available)" -f $v) -ForegroundColor Green
    } catch { Write-Log "winget vendor tool failed: $_" }
  }
}

function Driver-PlanPretty($list) {
  $list | Select-Object @{n='Name';e={$_.Name}},
                       @{n='Vendor';e={$_.Vendor}},
                       @{n='Class';e={$_.PNPClass}},
                       @{n='Err';e={$_.ErrorCode}},
                       @{n='Inf';e={$_.CurrentInf}},
                       @{n='Signed';e={$_.Signed}},
                       @{n='DeviceID';e={($_.DeviceID -replace '^(.{60}).+$','$1…')}}
}
# -------- driver-auto via Microsoft Update Catalog (by HWID), with provenance logging --------

function Get-ProblemDevices {
  $drv = Get-CimInstance Win32_PnPSignedDriver | Select-Object FriendlyName, DeviceClass, DriverProviderName, IsSigned, InfName, DeviceID
  $byDev = @{}; foreach($r in $drv){ $byDev[$r.DeviceID] = $r }
  $devs = Get-CimInstance Win32_PnPEntity | Select-Object Name, DeviceID, PNPClass, ConfigManagerErrorCode, HardwareID
  $out = @()
  foreach($d in $devs){
    $err = [int]$d.ConfigManagerErrorCode
    $rec = if($byDev.ContainsKey($d.DeviceID)){ $byDev[$d.DeviceID] } else { $null }
    $noSigned = $false
    if($rec -and $rec.DriverProviderName -ne 'Microsoft' -and $rec.IsSigned -ne $true){ $noSigned = $true }
    $unknown = (-not $d.PNPClass) -or $d.PNPClass -eq 'Unknown'
    if($err -ne 0 -or $unknown -or -not $rec -or $noSigned){
      $hwids = @()
      if ($d.HardwareID) { $hwids = @($d.HardwareID) } else { $hwids = @() }
      $out += [PSCustomObject]@{
        Name=$d.Name; DeviceID=$d.DeviceID; PNPClass=$d.PNPClass; Err=$err;
        HWIDs=$hwids
      }
    }
  }
  $out
}

function Get-PrimaryHWID($hwids){
  # берём самый «общий» HWID: PCI/USB с VEN/DEV/VID/PID, без REV/Subsystem
  foreach($h in $hwids){
    if ($h -match '^PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}') { return ($h -replace '&SUBSYS_[0-9A-F]{8}','' -replace '&REV_[0-9A-F]{2}','') }
    if ($h -match '^USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}') { return ($h -replace '&REV_[0-9A-F]{2}','') }
    if ($h -match '^ACPI\\') { return $h }
    if ($h -match '^HDAUDIO\\') { return $h }
    if ($h -match '^BTHE?NUM\\') { return $h }
  }
  if ($hwids -and $hwids.Count -gt 0) { return $hwids[0] }
  return $null
}

function Invoke-CatalogSearch([string]$query){
  # шаг 1: Search.aspx?q=... -> найдём download.aspx?...
  $u = "https://www.catalog.update.microsoft.com/Search.aspx?q=$([uri]::EscapeDataString($query))"
  $resp = Invoke-WebRequest -Uri $u -UseBasicParsing -Headers @{ 'User-Agent'='Mozilla/5.0' }
  $dlLinks = $resp.Links | Where-Object { $_.href -like "DownloadDialog.aspx*" -or $_.href -like "download.aspx*" }
  if (-not $dlLinks -or $dlLinks.Count -eq 0) { return @() }

  $items = @()
  foreach ($lnk in $dlLinks) {
    # открыть download.aspx, вытащить embedded JSON with "downloadInformation"
    $href = if ($lnk.href -like "http*") { $lnk.href } else { "https://www.catalog.update.microsoft.com/" + $lnk.href.TrimStart('/') }
    $page = Invoke-WebRequest -Uri $href -UseBasicParsing -Headers @{ 'User-Agent'='Mozilla/5.0' }
    $m = [regex]::Match($page.Content, 'var\s+downloadInformation\s*=\s*(\[[\s\S]+?\]);')
    if ($m.Success) {
      $json = $m.Groups[1].Value
      try {
        $arr = $json | ConvertFrom-Json
        foreach($it in $arr){
          # $it.files[*].url, $it.title, $it.updateId
          $file = $it.files[0]
          $items += [PSCustomObject]@{
            Title = $it.title
            Url   = $file.url
          }
        }
      } catch {}
    }
  }
  # отфильтруем мусор не .cab
  $items | Where-Object { $_.Url -like "*.cab*" } 
}

function Select-BestDriver($items){
  if (-not $items) { return $null }
  # эвристика: выбирать по дате/версии в Title: Windows 10/11, x64
  $pref = @('Windows 11','Windows 10','x64','AMD64','64-bit')
  $scored = @()
  foreach($it in $items){
    $score = 0
    foreach($p in $pref){ if ($it.Title -match [Regex]::Escape($p)) { $score += 1 } }
    # чем новее по числам в названии версии — тем лучше (очень грубо)
    $vernums = ([regex]::Matches($it.Title, '\d+')) | ForEach-Object { [int]$_.Value }
    if ($vernums.Count -gt 0) { $score += ([Enumerable]::Max([int[]]$vernums) / 100000) }
    $scored += [PSCustomObject]@{ Item=$it; Score=$score }
  }
  ($scored | Sort-Object Score -Descending | Select-Object -First 1).Item
}

function Get-SHA256([string]$path){
  try { (Get-FileHash -Path $path -Algorithm SHA256).Hash } catch { "" }
}

function Install-DriverCab([string]$cabUrl, [string]$deviceName, [string]$hwid){
  $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
  $devSafe = ($deviceName -replace '[^\w\.-]+','_')
  if (-not $devSafe) { $devSafe = "device" }
  $work = Join-Path $LogDir ("driver_auto_" + $devSafe + "_" + $stamp)
  New-Item -ItemType Directory -Force -Path $work | Out-Null

  $cabPath = Join-Path $work "driver.cab"
  $logPath = Join-Path $work "install.log"
  $provLog = Join-Path $work "provenance.txt"

  Write-Log ("download cab: {0}" -f $cabUrl)
  try {
    Invoke-WebRequest -Uri $cabUrl -OutFile $cabPath -UseBasicParsing -Headers @{ 'User-Agent'='Mozilla/5.0' }
  } catch { Write-Log "cab download failed: $_"; return $false }

  $hash = Get-SHA256 $cabPath

  # распакуем (в Win10+ есть expand.exe)
  $extDir = Join-Path $work "cab"
  New-Item -ItemType Directory -Force -Path $extDir | Out-Null
  & expand.exe -F:* $cabPath $extDir | Out-Null

  # quick signature sanity: есть ли .cat и .inf
  $inf = Get-ChildItem $extDir -Filter *.inf -Recurse -ErrorAction SilentlyContinue
  $cat = Get-ChildItem $extDir -Filter *.cat -Recurse -ErrorAction SilentlyContinue
  if (-not $inf) { Write-Log "no INF in cab -> skip"; return $false }

  # точка восстановления + установка
  New-RestorePoint
  try {
    $glob = Join-Path $extDir "*.inf"
    pnputil /add-driver $glob /subdirs /install | Tee-Object -FilePath $logPath | Out-Null
    pnputil /scan-devices | Out-Null
  } catch { Write-Log "pnputil failed: $_"; return $false }

  # provenance
  $prov = @()
  $prov += "SourceURL: $cabUrl"
  $prov += "Device: $deviceName"
  $prov += "PrimaryHWID: $hwid"
  $prov += "Downloaded: $cabPath"
  $prov += "SHA256: $hash"
  $prov += "INFs:"
  foreach($i in $inf){ $prov += "  - " + $i.FullName }
  if ($cat){ $prov += "CATs:"; foreach($c in $cat){ $prov += "  - " + $c.FullName } }
  $prov -join "`r`n" | Out-File -FilePath $provLog -Encoding utf8

  Write-Host ("installed from: {0}" -f $cabUrl) -ForegroundColor Green
  return $true
}

function VendorFromHWID([string]$hwid){
  if ($hwid -match 'VEN_8086|VID_8086') { return 'Intel' }
  if ($hwid -match 'VEN_10DE|VID_10DE') { return 'NVIDIA' }
  if ($hwid -match 'VEN_1002|VID_1002|VEN_1022') { return 'AMD' }
  if ($hwid -match 'VEN_10EC|VID_10EC') { return 'Realtek' }
  if ($hwid -match 'VEN_14E4|VID_14E4') { return 'Broadcom' }
  return ''
}

function Open-VendorSearchPages($devName, $hwid){
  $ven = VendorFromHWID $hwid
  $q = [uri]::EscapeDataString($hwid)
  if ($ven -eq 'Intel')  { Start-Process "https://www.intel.com/content/www/us/en/search.html?ws=text#q=$q&t=Downloads" }
  elseif ($ven -eq 'NVIDIA') { Start-Process "https://www.nvidia.com/Download/index.aspx" }
  elseif ($ven -eq 'AMD') { Start-Process "https://www.amd.com/en/support" }
  elseif ($ven -eq 'Realtek') { Start-Process "https://www.realtek.com/en/component/zoo/category/network-interface-controllers-10-100-1000m-gigabit-ethernet-pci-express-software" }
  elseif ($ven -eq 'Broadcom') { Start-Process "https://www.broadcom.com/support/download-search" }
  # всегда открываем Microsoft Update Catalog как fallback
  Start-Process ("https://www.catalog.update.microsoft.com/Search.aspx?q=" + $q)
}

# -------- commands --------
$policy = Load-Policy

switch ($cmd) {
  "scan" {
    $tele = Collect-Telemetry
    $analysis = Analyze-Heuristics $tele $policy
    $plan = Build-Plan $analysis $policy

    Write-Host "`n--- HEURISTICS PLAN ---" -ForegroundColor Cyan
    if ($plan -and $plan.Count) {
      $plan | Select-Object Action,
        @{n='Name';e={$_.Detail.Name}},
        @{n='PID';e={$_.Detail.PID}},
        @{n='Path';e={ if ($_.Detail.Path) { ($_.Detail.Path -replace '^(.{80}).+$','$1…') } else { $_.Detail.Data } }},
        @{n='Reason';e={$_.Detail.Reason}} | Format-Table -AutoSize
      Write-Host "`nyou can apply: .\doctor.ps1 fix  (or: .\doctor.ps1 fix -Auto)" -ForegroundColor Green
    } else {
      Write-Host "no suspicious low-risk items" -ForegroundColor Green
    }
    Write-Host "json saved to logs/" -ForegroundColor DarkGray
  }

  "plan" {
    $lastScan = Get-ChildItem $LogDir -Filter "scan_*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $lastScan) { throw "no scan data. run: .\doctor.ps1 scan" }
    $tele = Get-Content $lastScan.FullName -Raw | ConvertFrom-Json
    $analysis = Analyze-Heuristics $tele $policy
    $plan = Build-Plan $analysis $policy
    Write-Host "`n--- HEURISTICS PLAN ---" -ForegroundColor Cyan
    $plan | Select-Object Action,
      @{n='Name';e={$_.Detail.Name}},
      @{n='PID';e={$_.Detail.PID}},
      @{n='Path';e={ if ($_.Detail.Path) { ($_.Detail.Path -replace '^(.{80}).+$','$1…') } else { $_.Detail.Data } }},
      @{n='Reason';e={$_.Detail.Reason}} | Format-Table -AutoSize
    Write-Host "`nready. run: .\doctor.ps1 fix" -ForegroundColor Green
  }

  "fix" {
    $lastScan = Get-ChildItem $LogDir -Filter "scan_*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $lastScan) { throw "no scan data. run: .\doctor.ps1 scan" }
    $tele = Get-Content $lastScan.FullName -Raw | ConvertFrom-Json
    $analysis = Analyze-Heuristics $tele $policy
    $plan = Build-Plan $analysis $policy
    Apply-Plan $plan $policy $Auto
    Write-Host "fix complete. see logs." -ForegroundColor Green
  }

  "rollback" {
    Write-Log "user requested rollback (launching rstrui)"
    Start-Process "rstrui.exe"
  }

  "avscan" {
    $mp = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
    if (-not (Test-Path $mp)) { $mp = "$env:ProgramFiles\Microsoft Defender\MpCmdRun.exe" }
    if (Test-Path $mp) {
      Write-Log "defender quick scan via MpCmdRun"
      & $mp -Scan -ScanType 1 -DisableRemediation 2>&1 |
        Tee-Object -FilePath (Join-Path $LogDir ("defender_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log"))
      Write-Host "defender quick scan finished (log in logs)" -ForegroundColor Green
    } else {
      Write-Host "MpCmdRun.exe not found - skipping AV scan" -ForegroundColor Yellow
    }
  }
     "driver-install" {
    $inv = Get-DriverInventory
    $missing = Get-MissingDrivers $inv

    if (-not $missing -or $missing.Count -eq 0) {
      Write-Host "drivers: nothing missing/problematic detected" -ForegroundColor Green
      break
    }

    Write-Host "`n--- MISSING / PROBLEMATIC DRIVERS ---" -ForegroundColor Cyan
    Driver-PlanPretty $missing | Format-Table -AutoSize

    # choose folder with INF
    $defaultFolder = if ($policy.drivers -and $policy.drivers.folder) { Join-Path $BaseDir $policy.drivers.folder } else { Join-Path $BaseDir "drivers" }
    $folder = Read-Host ("Path to drivers (INF) folder? [Enter for default: {0}]" -f $defaultFolder)
    if ([string]::IsNullOrWhiteSpace($folder)) { $folder = $defaultFolder }

    if (Test-Path $folder) {
      Write-Host ("Will install INF from: {0}" -f $folder) -ForegroundColor Yellow
      $ok = Read-Host "Proceed with installing drivers from this folder? (yes/no)"
      if ($ok -eq 'yes') { Install-DriversFromFolder $folder }
    } else {
      Write-Host ("Folder not found: {0}" -f $folder) -ForegroundColor DarkYellow
    }

    # offer vendor tools
    $vendors = @()
    foreach ($m in $missing) { if ($m.Vendor) { $vendors += $m.Vendor } }
    Offer-VendorTools $vendors

    # final rescan
    Write-Host "`nRe-scan devices..." -ForegroundColor DarkGray
    try { pnputil /scan-devices | Out-Null } catch {}
    $inv2 = Get-DriverInventory
    $missing2 = Get-MissingDrivers $inv2
    if ($missing2.Count -gt 0) {
      Write-Host "`nStill have issues:" -ForegroundColor Yellow
      Driver-PlanPretty $missing2 | Format-Table -AutoSize
      Write-Host "You may need OEM support page or exact INF package by HWID." -ForegroundColor DarkYellow
    } else {
      Write-Host "`nAll problematic devices resolved." -ForegroundColor Green
    }
  }
  "driver-auto" {
    $problems = Get-ProblemDevices
    if (-not $problems -or $problems.Count -eq 0) {
      Write-Host "no problematic devices detected" -ForegroundColor Green
      break
    }

    Write-Host "`n--- PROBLEM DEVICES (by HWID) ---" -ForegroundColor Cyan
    $problems | Select-Object Name,
      @{n='Err';e={$_.Err}},
      @{n='HWIDs';e={ (@($_.HWIDs) -join '; ') }},
      @{n='DeviceID';e={ ($_.DeviceID -replace '^(.{60}).+$','$1…') }} | Format-Table -AutoSize

    foreach($d in $problems){
      $hwid = Get-PrimaryHWID $d.HWIDs
      if (-not $hwid) { continue }

      Write-Host ("`nSearching Microsoft Update Catalog for: {0}" -f $hwid) -ForegroundColor Yellow
      $items = Invoke-CatalogSearch $hwid
      $best  = Select-BestDriver $items

      if ($best) {
        Write-Host ("Candidate: {0}" -f $best.Title) -ForegroundColor DarkCyan
        $ok = Read-Host "Download and install this driver automatically? (yes/no)"
        if ($ok -eq 'yes') {
          $ok2 = Install-DriverCab -cabUrl $best.Url -deviceName $d.Name -hwid $hwid
          if (-not $ok2) {
            Write-Host "install failed; opening vendor/search pages..." -ForegroundColor Yellow
            Open-VendorSearchPages $d.Name $hwid
          }
        } else {
          Open-VendorSearchPages $d.Name $hwid
        }
      } else {
        Write-Host "no catalog entry found; opening vendor/search pages..." -ForegroundColor Yellow
        Open-VendorSearchPages $d.Name $hwid
      }
    }

    Write-Host "`nRe-scan devices..." -ForegroundColor DarkGray
    try { pnputil /scan-devices | Out-Null } catch {}
    $left = Get-ProblemDevices
    if ($left -and $left.Count -gt 0) {
      Write-Host "`nStill have issues:" -ForegroundColor Yellow
      $left | Select-Object Name, @{n='Err';e={$_.Err}}, @{n='HWIDs';e={($_.HWIDs -join '; ')}} | Format-Table -AutoSize
      Write-Host "Check logs/driver_auto_* folders for provenance. You may need exact OEM package by HWID." -ForegroundColor DarkYellow
    } else {
      Write-Host "`nAll problematic devices resolved or improved." -ForegroundColor Green
    }
  }



  "update" {
    Update-AllowedPackages $policy
    Write-Host "updates done." -ForegroundColor Green
  }
}

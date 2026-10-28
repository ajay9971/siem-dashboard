<#
SecureWatch Windows agent
Reads the real Windows Event Log and sends events to your SIEM. Needs PowerShell run AS ADMINISTRATOR.

  Set-ExecutionPolicy -Scope Process Bypass
  .\agent.ps1 -Url https://YOUR-APP.onrender.com -Key YOUR_INGEST_KEY

Optional - Windows Firewall dropped connections (for port scan detection):
  netsh advfirewall set allprofiles logging droppedconnections enable
  .\agent.ps1 -Url ... -Key ... -FirewallLog "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

What it watches:
  4625  failed logon              -> Brute force rule
  4624  successful logon (2, 10)  -> normal log line
  4732  user added to Administrators -> Privilege escalation rule
  1102  security audit log cleared   -> Critical alert
  Defender 1116 malware detected     -> Malware rule
#>
param(
  [Parameter(Mandatory = $true)][string]$Url,
  [Parameter(Mandatory = $true)][string]$Key,
  [string]$FirewallLog = "",
  [int]$Interval = 5
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Url = $Url.TrimEnd("/")

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "Please run PowerShell as Administrator (needed to read the Security log)."; exit 1 }

function Get-Ip($addr, $ws) {
  if ($addr -and $addr -ne "-" -and $addr -ne "::1" -and $addr -ne "127.0.0.1") { return $addr }
  if ($ws -and $ws -ne "-") { return $ws }
  return "local"
}

function Send-Events($list) {
  $json = ConvertTo-Json -InputObject @($list) -Compress -Depth 4
  try {
    Invoke-RestMethod -Uri "$Url/api/ingest" -Method Post -Headers @{ "x-api-key" = $Key } `
      -ContentType "application/json" -Body ([Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec 60 | Out-Null
    Write-Host ("{0} sent {1} events" -f (Get-Date -Format "HH:mm:ss"), @($list).Count)
  } catch {
    Write-Host ("send failed: " + $_.Exception.Message)
  }
}

function Convert-SecurityEvent($e) {
  $x = [xml]$e.ToXml()
  $d = @{}
  foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }
  switch ($e.Id) {
    4625 {
      $ip = Get-Ip $d.IpAddress $d.WorkstationName
      return @{ source = "AUTH"; level = "warn"; ip = $ip; message = "Failed password for $($d.TargetUserName) from $ip port 0 (Windows logon failed, type $($d.LogonType))" }
    }
    4624 {
      $u = $d.TargetUserName
      if (@("2", "10") -notcontains [string]$d.LogonType) { return $null }
      if ($u -match '\$$' -or $u -match '^(DWM|UMFD)-\d+$') { return $null }
      $ip = Get-Ip $d.IpAddress $d.WorkstationName
      return @{ source = "AUTH"; level = "info"; ip = $ip; message = "Accepted logon for $u from $ip (type $($d.LogonType))" }
    }
    4732 {
      if ($d.TargetUserName -notmatch "Administrators|Admins") { return $null }
      return @{ source = "AUTH"; level = "crit"; ip = "local"; message = "gained root-equivalent rights: $($d.MemberSid) added to group $($d.TargetUserName) by $($d.SubjectUserName)" }
    }
    1102 {
      $u = $x.Event.UserData.LogFileCleared.SubjectUserName
      return @{ source = "ENDPOINT"; level = "crit"; ip = "local"; message = "Security audit log cleared by $u - possible malware activity cover-up" }
    }
  }
  return $null
}

$sr = $null
if ($FirewallLog) {
  $fs = [IO.File]::Open($FirewallLog, "Open", "Read", "ReadWrite")
  $fs.Seek(0, "End") | Out-Null
  $sr = New-Object IO.StreamReader($fs)
  Write-Host "Watching firewall log: $FirewallLog"
}

Write-Host "SecureWatch Windows agent running. Sending to $Url  (Ctrl+C to stop)"
$last = Get-Date
$seen = @{}

while ($true) {
  $out = @()
  $now = Get-Date

  $sec = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4624, 4625, 4732, 1102; StartTime = $last } -ErrorAction SilentlyContinue | Sort-Object TimeCreated
  foreach ($e in $sec) {
    $key = "S" + $e.RecordId
    if ($seen[$key]) { continue }
    $seen[$key] = 1
    $ev = Convert-SecurityEvent $e
    if ($ev) { $out += $ev }
  }

  $def = Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-Windows Defender/Operational"; Id = 1116; StartTime = $last } -ErrorAction SilentlyContinue
  foreach ($e in $def) {
    $key = "D" + $e.RecordId
    if ($seen[$key]) { continue }
    $seen[$key] = 1
    $name = "unknown threat"
    if ($e.Message -match "Name:\s*(.+)") { $name = $Matches[1].Trim() }
    $out += @{ source = "ENDPOINT"; level = "crit"; ip = "local"; message = "Windows Defender detected malware: $name" }
  }

  if ($sr) {
    while (($line = $sr.ReadLine()) -ne $null) {
      if ($line.StartsWith("#") -or -not $line.Trim()) { continue }
      $f = $line -split " "
      if ($f.Count -ge 8 -and $f[2] -eq "DROP") {
        $out += @{ source = "FIREWALL"; level = "warn"; ip = $f[4]; message = "DROP $($f[3].ToLower()) SRC=$($f[4]) DPT=$($f[7])" }
      }
    }
  }

  $last = $now.AddSeconds(-2)
  if ($seen.Count -gt 5000) { $seen.Clear() }

  for ($i = 0; $i -lt $out.Count; $i += 50) {
    $j = [Math]::Min($i + 49, $out.Count - 1)
    Send-Events $out[$i..$j]
  }
  Start-Sleep -Seconds $Interval
}

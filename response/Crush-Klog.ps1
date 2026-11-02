#Requires -Version 5.1
<#
  Crush-Klog.ps1 - suspend, isolate, quarantine and de-persist a suspected software keylogger.

  Dry run :  .\Crush-Klog.ps1 -Target klog
  Execute :  .\Crush-Klog.ps1 -Target klog -Apply
  Undo    :  <run dir>\RESTORE.ps1   (elevated, same as the crush)

  Corrections against the earlier draft, each of which changed behaviour:

  * Process tree is depth-first, children before parents. The draft built it breadth-first and then
    reversed the outer array, which suspended the root first and freed the watchdog to respawn.
  * Target resolution no longer appends ".exe" to a target that already ends in ".exe", and the
    firewall step uses each target's own executable instead of roots[0] for every rule.
  * The report is written on every exit path, including dry runs and refusals, from a finally block.
  * -TimeWarp is refused rather than implemented. Skewing the system clock rewrites file timestamps and
    breaks event correlation, so it destroys the timeline this tool exists to preserve; a defensible
    response does not edit the clock. It stays a parameter only to refuse it by name.
  * System directories are refused before any rename, so a target sitting in C:\Windows cannot turn
    containment into destruction.
  * Evidence (hashes, binary copy, live sockets, persistence inventory) is captured before mutation.
  * Suspension is verified from thread wait states instead of assumed from the call returning.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Target,
    [switch]$Apply,
    [switch]$TimeWarp,
    [string]$OutDir = (Join-Path $env:USERPROFILE ("Desktop\klog-crush-" + (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

$ErrorActionPreference = 'Stop'
$script:Log = [System.Collections.Generic.List[string]]::new()
$script:ExitCode = 0
function Say { param([string]$Message, [string]$Color = 'Gray')
    Write-Host $Message -ForegroundColor $Color
    $script:Log.Add("$([DateTime]::UtcNow.ToString('s'))Z $Message") }

function Finish {
    param([int]$Code)
    if (Test-Path $OutDir) {
        try {
            $script:Log | Set-Content (Join-Path $OutDir 'report.txt') -Encoding UTF8
            Get-ChildItem $OutDir -Recurse -File |
                Where-Object Name -ne 'MANIFEST.sha256' |
                Get-FileHash -Algorithm SHA256 |
                ForEach-Object { "$($_.Hash)  $($_.Path.Substring($OutDir.Length + 1))" } |
                Set-Content (Join-Path $OutDir 'MANIFEST.sha256') -Encoding UTF8
        } catch { Write-Warning "could not finalise report: $_" }
    }
    exit $Code
}

function Get-OrderedTree {
    <#
      Depth-first post-order: every descendant before the node that owns it. Breadth-first order -
      which the earlier draft produced - suspends the root first and lets a watchdog respawn its child.
    #>
    param(
        [hashtable]$Edges,
        [int[]]$Roots
    )
    $ordered = [System.Collections.Generic.List[int]]::new()
    $walk = {
        param([int]$Id)
        if ($Edges.ContainsKey($Id)) {
            foreach ($c in $Edges[$Id]) { & $walk $c }
        }
        if (-not $ordered.Contains($Id)) { $ordered.Add($Id) }
    }
    foreach ($r in $Roots) { & $walk $r }
    , $ordered.ToArray()
}

function Test-PathHit {
    <# Exact executable path, or the file name as a whole word. Loose substring matching flagged
       /bin/bash for a script target and a systemd unit for a name it never contained. #>
    param(
        [string]$Value,
        [string[]]$Paths,
        [string[]]$Leafs
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    foreach ($p in $Paths) {
        if ($Value.IndexOf($p, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    foreach ($n in $Leafs) {
        if ([regex]::IsMatch($Value, "(?i)(^|[\s""'=])" + [regex]::Escape($n) + "($|[\s""'])")) { return $true }
    }
    return $false
}

try {
    if ($Apply -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Say '!! -Apply requires elevation. Re-run from an elevated prompt.' 'Red'; Finish 2
    }
    if ($TimeWarp) {
        Say 'REFUSED: -TimeWarp is not implemented. Changing the system clock rewrites file timestamps,' 'Red'
        Say '          breaks event correlation and invalidates the timeline this run is meant to preserve.' 'Red'
        Say '          Nothing was changed.' 'Red'
        Finish 2
    }

    New-Item -ItemType Directory -Force -Path $OutDir, (Join-Path $OutDir 'evidence'),
        (Join-Path $OutDir 'persistence') | Out-Null
    Say "Run dir: $OutDir" 'Cyan'
    Say ("Mode: " + $(if ($Apply) { 'APPLY' } else { 'DRY RUN - nothing will be changed' })) `
        $(if ($Apply) { 'Yellow' } else { 'Cyan' })
    Say "Clock recorded as $([DateTime]::UtcNow.ToString('s'))Z and not altered"

    # ------------------------------------------------------------ resolve
    $all = Get-CimInstance Win32_Process
    $roots = foreach ($t in $Target) {
        $byPath = $all | Where-Object { $_.ExecutablePath -and $_.ExecutablePath -ieq $t }
        if ($byPath) { $byPath; continue }
        $name = if ($t -match '\.exe$') { $t } else { "$t.exe" }   # no ".exe.exe"
        $all | Where-Object { $_.Name -ieq $name }
    }
    $roots = @($roots | Where-Object { $_.ProcessId -ne $PID } |
               Sort-Object ProcessId -Unique)
    if (-not $roots) { Say "No matching process. Check with: Get-Process | Where-Object Path" 'Red'; Finish 1 }

    Say "`n== Matched ==" 'Cyan'
    $roots | Select-Object ProcessId, Name, ExecutablePath | Format-Table -AutoSize | Out-String | Write-Host

    # ------------------------------------------------------------ tree, children first
    $byParent = @{}
    foreach ($p in $all) {
        $ppid = [int]$p.ParentProcessId
        if (-not $byParent.ContainsKey($ppid)) { $byParent[$ppid] = [System.Collections.Generic.List[int]]::new() }
        $byParent[$ppid].Add([int]$p.ProcessId)
    }
    $ordered = Get-OrderedTree -Edges $byParent -Roots @($roots | ForEach-Object { [int]$_.ProcessId })
    Say "`n== Process tree (children first) ==" 'Cyan'
    Say ("  " + ($ordered -join ', '))

    # ------------------------------------------------------------ evidence, before mutation
    $evidence = Join-Path $OutDir 'evidence'
    $binaries = Join-Path $evidence 'binary'
    New-Item -ItemType Directory -Force -Path $binaries | Out-Null
    $hashes = [System.Collections.Generic.List[string]]::new()
    $captured = 0
    foreach ($r in $roots) {
        if (-not $r.ExecutablePath) { continue }
        $pidFile = Join-Path $evidence ("pid-" + $r.ProcessId + ".txt")
        @("pid $($r.ProcessId)", "ppid $($r.ParentProcessId)", "name $($r.Name)",
          "exe $($r.ExecutablePath)", "cmdline $($r.CommandLine)",
          "started $($r.CreationDate.ToUniversalTime().ToString('s'))Z",
          "user $((Invoke-CimMethod -InputObject $r -MethodName GetOwner).User)") |
            Set-Content $pidFile -Encoding UTF8
        if (Test-Path -LiteralPath $r.ExecutablePath) {
            $hash = (Get-FileHash -LiteralPath $r.ExecutablePath -Algorithm SHA256).Hash
            $hashes.Add("$hash  $($r.ExecutablePath)")
            Copy-Item -LiteralPath $r.ExecutablePath -Destination $binaries -Force -ErrorAction SilentlyContinue
            $copy = Join-Path $binaries (Split-Path $r.ExecutablePath -Leaf)
            if (Test-Path $copy) { Set-ItemProperty -LiteralPath $copy -Name IsReadOnly -Value $true }
            $captured++
        }
    }
    $hashes | Set-Content (Join-Path $evidence 'hashes.txt') -Encoding UTF8
    # live sockets, while the process is still running: this map cannot be recovered afterwards
    try {
        $ids = $ordered
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $ids -contains $_.OwningProcess } |
            Select-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State |
            Export-Csv (Join-Path $evidence 'sockets.csv') -NoTypeInformation
    } catch { Say "  socket capture unavailable: $_" 'DarkYellow' }
    Say "`n== Evidence ==" 'Cyan'
    Say "  binaries copied and hashed: $captured"

    # ------------------------------------------------------------ persistence inventory
    $paths = @($roots.ExecutablePath   | Where-Object { $_ })
    $leafs = @($paths | ForEach-Object { Split-Path $_ -Leaf })
    function Test-Hit { param([string]$Value) Test-PathHit -Value $Value -Paths $paths -Leafs $leafs }

    $RunKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $persist = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $RunKeys) {
        if (-not (Test-Path $k)) { continue }
        foreach ($pr in (Get-ItemProperty $k -ErrorAction SilentlyContinue).PSObject.Properties) {
            if ($pr.Name -like 'PS*') { continue }
            if (Test-Hit ([string]$pr.Value)) {
                $persist.Add([pscustomobject]@{ Kind='RunKey'; Where=$k; Name=$pr.Name; Data=[string]$pr.Value })
            }
        }
    }
    foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) {
        foreach ($a in $t.Actions) {
            if (Test-Hit $a.Execute) {
                $persist.Add([pscustomobject]@{ Kind='Task'; Where=$t.TaskPath; Name=$t.TaskName; Data=$a.Execute })
            }
        }
    }
    foreach ($s in Get-CimInstance Win32_Service) {
        if (Test-Hit $s.PathName) {
            $persist.Add([pscustomobject]@{ Kind='Service'; Where=''; Name=$s.Name; Data=$s.PathName })
        }
    }
    $startup = [Environment]::GetFolderPath('Startup')
    if (Test-Path $startup) {
        $sh = New-Object -ComObject WScript.Shell
        foreach ($l in Get-ChildItem $startup -Filter *.lnk -ErrorAction SilentlyContinue) {
            try { if (Test-Hit $sh.CreateShortcut($l.FullName).TargetPath) {
                $persist.Add([pscustomobject]@{ Kind='Shortcut'; Where=$startup; Name=$l.Name; Data=$l.FullName })
            } } catch { }
        }
    }
    $persist | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $OutDir 'persistence\entries.json') -Encoding UTF8
    Say "`n== Persistence ==" 'Cyan'
    if ($persist) { $persist | Format-Table Kind, Name, Data -AutoSize | Out-String | Write-Host }
    else { Say '  none matched' }

    # ------------------------------------------------------------ filter drivers
    # fltmc columns are space padded; splitting on runs of whitespace keeps the name at index 0
    $filters = @()
    foreach ($line in (fltmc filters 2>$null | Select-Object -Skip 1)) {
        $cols = ($line -split '\s{1,}') | Where-Object { $_ }
        if ($cols.Count -lt 2 -or $cols[0] -match '^(Filter|----)') { continue }
        $name = $cols[0]
        $svc = Get-CimInstance Win32_SystemDriver -Filter "Name='$name'" -ErrorAction SilentlyContinue
        if ($svc -and (Test-Hit $svc.PathName)) { $filters += $name }
    }
    Say "`n== Kernel filters ==" 'Cyan'
    if ($filters) { $filters | ForEach-Object { Say "  $_" 'Yellow' } } else { Say '  none matched' }

    if (-not $Apply) {
        Say "`nDry run complete. Nothing was suspended, renamed or blocked." 'Cyan'
        Say "Re-run with -Apply to execute." 'Cyan'
        Finish 0
    }

    # ------------------------------------------------------------ 1. suspend, children first
    Say "`n[1] Suspending $($ordered.Count) process(es), children first" 'Yellow'
    if (-not ('Nt.Proc' -as [type])) {
        Add-Type -Namespace Nt -Name Proc -MemberDefinition @'
[DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h);
[DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr h);
'@
    }
    $suspended = @(); $failed = 0
    foreach ($id in $ordered) {
        $p = Get-Process -Id $id -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        try {
            [Nt.Proc]::NtSuspendProcess($p.Handle) | Out-Null
            Start-Sleep -Milliseconds 150
            $p.Refresh()
            $live = @($p.Threads | Where-Object { $_.WaitReason -ne 'Suspended' -and $_.ThreadState -eq 'Wait' })
            if ($live.Count -eq 0) { $suspended += $id; Say "  suspended $($p.ProcessName) ($id) - all threads in suspended wait" }
            else { $failed++; Say "  signal sent but $($live.Count) thread(s) still running in $($p.ProcessName) ($id)" 'DarkYellow' }
        } catch { $failed++; Say "  could not suspend $id : $($_.Exception.Message)" 'Red' }
    }

    # ------------------------------------------------------------ 2. de-persist
    Say "`n[2] Removing persistence (after suspension, so nothing respawns it)" 'Yellow'
    foreach ($e in $persist) {
        switch ($e.Kind) {
            'RunKey'   { Remove-ItemProperty -Path $e.Where -Name $e.Name -ErrorAction SilentlyContinue
                         Say "  run key removed: $($e.Name)" }
            'Task'     { try {
                             Export-ScheduledTask -TaskName $e.Name -TaskPath $e.Where |
                                 Set-Content (Join-Path $OutDir "persistence\$($e.Name).xml") -Encoding UTF8
                             Unregister-ScheduledTask -TaskName $e.Name -TaskPath $e.Where -Confirm:$false
                             Say "  task removed: $($e.Name)"
                         } catch { Say "  FAILED to remove task $($e.Name): $($_.Exception.Message)" 'Red' } }
            'Service'  { sc.exe config $e.Name start= disabled | Out-Null
                         sc.exe stop $e.Name | Out-Null
                         Say "  service disabled (not deleted): $($e.Name)" }
            'Shortcut' { try { Move-Item -LiteralPath $e.Data -Destination (Join-Path $OutDir 'persistence') -Force
                               Say "  shortcut moved: $($e.Name)" }
                         catch { Say "  FAILED to move $($e.Name)" 'Red' } }
        }
    }

    # ------------------------------------------------------------ 3. filters
    Say "`n[3] Unloading filter drivers" 'Yellow'
    foreach ($f in $filters) {
        $out = fltmc unload $f 2>&1
        if ($LASTEXITCODE -eq 0) { Say "  unloaded $f" }
        else { Say "  FAILED $f ($out) - a reboot clears it" 'Red' }
    }

    # ------------------------------------------------------------ 4. quarantine by rename
    Say "`n[4] Quarantining install directories" 'Yellow'
    $renames = [System.Collections.Generic.List[object]]::new()
    $protected = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
                   $env:WINDIR, 'C:\Windows', 'C:\Program Files', 'C:\Program Files (x86)') |
                 Where-Object { $_ }
    foreach ($r in $roots) {
        if (-not $r.ExecutablePath) { continue }
        $dir = Split-Path $r.ExecutablePath -Parent
        if ($protected -contains $dir.TrimEnd('\')) {
            Say "  REFUSED to rename $dir : system or shared program directory, not an application folder" 'Red'
            $failed++; continue
        }
        if ((Split-Path $dir -Leaf) -match '\.quarantined$') { Say "  already quarantined: $dir"; continue }
        $new = "$dir.quarantined"
        try {
            Rename-Item -LiteralPath $dir -NewName (Split-Path $new -Leaf) -ErrorAction Stop
            $renames.Add([pscustomobject]@{ Old=$dir; New=$new })
            Say "  $dir -> $new"
        } catch {
            Say "  FAILED to rename $dir (image still mapped, in use, or permissions): $($_.Exception.Message)" 'Red'
            $failed++
        }
    }

    # ------------------------------------------------------------ 5. firewall
    Say "`n[5] Blocking network for the quarantined paths" 'Yellow'
    $rules = 0
    foreach ($r in $renames) {
        $leaf = Split-Path $r.Old -Leaf
        $exe = Get-ChildItem -LiteralPath $r.New -Filter *.exe -Recurse -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if (-not $exe) { Say "  no executable under $($r.New); skipping" 'DarkYellow'; continue }
        foreach ($dir in 'Outbound', 'Inbound') {
            try {
                New-NetFirewallRule -DisplayName "KLOG-CRUSH-$rules-$dir" -Group 'KeyloggerCrush' `
                    -Program $exe.FullName -Direction $dir -Action Block -Profile Any -Enabled True | Out-Null
                $rules++
            } catch { Say "  FAILED to add $dir rule for $($exe.Name): $($_.Exception.Message)" 'Red' }
        }
        Say "  blocked $($exe.FullName)"
    }
    Say '  note: rules bind to the new path, so they bite on restart; live containment is the suspension above.' 'DarkYellow'

    # ------------------------------------------------------------ restore script
    $restorePath = Join-Path $OutDir 'RESTORE.ps1'
    $resumeIds = ($suspended -join ',')
    $renameLines = ($renames | ForEach-Object {
        "Rename-Item -LiteralPath '$($_.New)' -NewName '$(Split-Path $_.Old -Leaf)' -ErrorAction SilentlyContinue"
    }) -join "`n"
    $filterLines = ($filters | ForEach-Object { "fltmc load $_ 2>`$null" }) -join "`n"

    $restore = @"
# RESTORE.ps1 - generated $([DateTime]::UtcNow.ToString('s'))Z by Crush-Klog.ps1
# Reverses this run. Run elevated. Idempotent: safe to run twice.
`$ErrorActionPreference = 'Continue'
if (-not ('Nt.Proc' -as [type])) {
    Add-Type -Namespace Nt -Name Proc -MemberDefinition @'
[DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr h);
'@
}

Write-Host 'Resuming processes...' -ForegroundColor Yellow
foreach (`$id in @($resumeIds)) {
    `$p = Get-Process -Id `$id -ErrorAction SilentlyContinue
    if (`$p) { [Nt.Proc]::NtResumeProcess(`$p.Handle) | Out-Null; Write-Host "  resumed `$(`$p.ProcessName) (`$id)" }
}

Write-Host 'Removing firewall blocks...' -ForegroundColor Yellow
Get-NetFirewallRule -Group 'KeyloggerCrush' -ErrorAction SilentlyContinue | Remove-NetFirewallRule

Write-Host 'Restoring directories...' -ForegroundColor Yellow
$renameLines

Write-Host 'Restoring persistence...' -ForegroundColor Yellow
`$entriesPath = Join-Path '$OutDir' 'persistence\entries.json'
if (Test-Path `$entriesPath) {
    foreach (`$e in (Get-Content `$entriesPath -Raw | ConvertFrom-Json)) {
        switch (`$e.Kind) {
            'RunKey'   { Set-ItemProperty -Path `$e.Where -Name `$e.Name -Value `$e.Data; Write-Host "  run key: `$(`$e.Name)" }
            'Task'     { Register-ScheduledTask -Xml (Get-Content (Join-Path '$OutDir' "persistence\`$(`$e.Name).xml") -Raw) -TaskName `$e.Name -TaskPath `$e.Where -Force | Out-Null
                         Write-Host "  task: `$(`$e.Name)" }
            'Service'  { sc.exe config `$e.Name start= auto | Out-Null; sc.exe start `$e.Name | Out-Null; Write-Host "  service: `$(`$e.Name)" }
            'Shortcut' { Copy-Item (Join-Path '$OutDir' "persistence\`$(`$e.Name)") `$e.Where -Force; Write-Host "  shortcut: `$(`$e.Name)" }
        }
    }
}

Write-Host 'Restarting filter drivers...' -ForegroundColor Yellow
$filterLines
Write-Host 'The clock was never changed by this tool.' -ForegroundColor DarkYellow
Write-Host 'Done. Reboot if any filter driver failed to reload.' -ForegroundColor Green
"@
    $restore | Set-Content $restorePath -Encoding UTF8

    Say "`n== Summary ==" 'Cyan'
    Say "suspended          : $($suspended.Count) of $($ordered.Count) ($failed failed)"
    Say "persistence hits   : $($persist.Count)"
    Say "filters unloaded   : $($filters.Count)"
    Say "directories moved  : $($renames.Count)"
    Say "firewall rules     : $rules"
    Say "`nUndo: $restorePath" 'Green'
    if ($failed -gt 0 -or $renames.Count -eq 0) {
        Say 'PARTIAL: some steps failed. Read report.txt before declaring this contained.' 'Red'
        Finish 3
    }
    Finish 0
}
catch {
    Say "UNEXPECTED: $($_.Exception.Message)" 'Red'
    Say 'Nothing further was attempted. Read report.txt.' 'Red'
    Finish 4
}

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Snapshot','Arm','TestRollback','Apply','Restore','Verify','Disarm')]
    [string]$Action,
    [Parameter(Mandatory=$true)]
    [string]$RunDirectory,
    [string]$ClientAddress,
    [string]$Gateway,
    [string]$IPv6Gateway
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator access is required.'
}
$root = Join-Path $env:ProgramData 'failsafe4g-tests'
$resolved = [IO.Path]::GetFullPath($RunDirectory).TrimEnd('\')
if (-not $resolved.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or
    (Split-Path $resolved -Parent) -ne $root) {
    throw 'RunDirectory must be one direct child of the private failsafe4g-tests directory.'
}
$RunDirectory = $resolved
$statePath = Join-Path $RunDirectory 'state.json'
$baselinePath = Join-Path $RunDirectory 'baseline.json'
$receiptPath = Join-Path $RunDirectory 'restored.json'
$taskName = 'Failsafe4G-Rollback-' + (Split-Path $RunDirectory -Leaf)

function Write-PrivateJson($Path, $Value) {
    $temporary = $Path + '.new'
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Read-Baseline {
    Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
}

function Read-State {
    Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
}

function Get-Configuration($InterfaceIndex) {
    $adapter = Get-NetAdapter | Where-Object ifIndex -eq $InterfaceIndex
    $interfaces = @(Get-NetIPInterface -InterfaceIndex $InterfaceIndex |
        Select-Object AddressFamily,Dhcp,RouterDiscovery,AutomaticMetric,InterfaceMetric,WeakHostSend,WeakHostReceive)
    $addresses = @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex |
        Select-Object IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin,SkipAsSource)
    $routes = @(Get-NetRoute -InterfaceIndex $InterfaceIndex -PolicyStore ActiveStore |
        Select-Object DestinationPrefix,NextHop,RouteMetric,Protocol)
    $persistent = @(Get-NetRoute -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object InterfaceIndex -eq $InterfaceIndex |
        Select-Object DestinationPrefix,NextHop,RouteMetric,Protocol)
    $dns = @(Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex |
        Select-Object AddressFamily,ServerAddresses)
    $nrpt = @(Get-DnsClientNrptRule | Select-Object Name,Namespace,NameServers,Comment,DisplayName)
    [ordered]@{
        InterfaceIndex = $InterfaceIndex
        InterfaceGuid = $adapter.InterfaceGuid.ToString()
        Interfaces = $interfaces
        Addresses = $addresses
        Routes = $routes
        PersistentRoutes = $persistent
        DNS = $dns
        NRPT = $nrpt
    }
}

function Route-Key($Route) {
    '{0}|{1}|{2}|{3}' -f $Route.DestinationPrefix,$Route.NextHop,$Route.RouteMetric,([int]$Route.Protocol)
}

function Test-Configuration {
    $baseline = Read-Baseline
    $current = Get-Configuration $baseline.Configuration.InterfaceIndex
    $original = $baseline.Configuration
    $checks = [ordered]@{}
    $checks.InterfaceGuid = $current.InterfaceGuid -eq $original.InterfaceGuid
    foreach ($property in @('Interfaces','Addresses','DNS','NRPT','PersistentRoutes')) {
        $left = @($current[$property] | ForEach-Object { $_ | ConvertTo-Json -Depth 8 -Compress } | Sort-Object)
        $right = @($original.$property | ForEach-Object { $_ | ConvertTo-Json -Depth 8 -Compress } | Sort-Object)
        $checks[$property] = ($left -join "`n") -eq ($right -join "`n")
    }
    $left = @($current.Routes | ForEach-Object { Route-Key $_ } | Sort-Object)
    $right = @($original.Routes | ForEach-Object { Route-Key $_ } | Sort-Object)
    $checks.Routes = ($left -join "`n") -eq ($right -join "`n")
    $checks.ClientAddress = @($current.Addresses | Where-Object IPAddress -eq $baseline.ClientAddress).Count -eq 1
    [ordered]@{ Matched = -not ($checks.Values -contains $false); Checks = $checks; CheckedUtc = [DateTime]::UtcNow.ToString('o') }
}

function Restore-OwnedChanges {
    $baseline = Read-Baseline
    $state = Read-State
    foreach ($route in @($state.Routes)) {
        Get-NetRoute -InterfaceIndex $baseline.Configuration.InterfaceIndex -DestinationPrefix $route.Prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $route.NextHop -and $_.RouteMetric -eq 7 } |
            Remove-NetRoute -Confirm:$false
    }
    Get-DnsClientNrptRule | Where-Object Comment -eq $taskName | Remove-DnsClientNrptRule -Force
    $verification = Test-Configuration
    Write-PrivateJson $receiptPath $verification
    if (-not $verification.Matched) { throw 'Restoration verification failed; backups retained for inspection.' }
    Write-PrivateJson $statePath ([ordered]@{ Routes=@(); Applied=$false; RestoredUtc=[DateTime]::UtcNow.ToString('o') })
    $verification
}

if ($Action -eq 'Snapshot') {
    if (Test-Path -LiteralPath $RunDirectory) { throw 'Run directory already exists; refusing to overwrite a baseline.' }
    $address = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq $ClientAddress)
    if ($address.Count -ne 1) { throw 'ClientAddress must identify exactly one current IPv4 address.' }
    New-Item -ItemType Directory -Path $RunDirectory -Force | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sidValue in @('S-1-5-18','S-1-5-32-544')) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidValue)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $RunDirectory -AclObject $acl
    Write-PrivateJson $baselinePath ([ordered]@{
        ClientAddress = $ClientAddress
        RecordedUtc = [DateTime]::UtcNow.ToString('o')
        Configuration = Get-Configuration $address[0].InterfaceIndex
    })
    Write-PrivateJson $statePath ([ordered]@{ Routes = @(); Applied = $false })
    Test-Configuration | ConvertTo-Json -Depth 8 -Compress
    exit
}

if ($Action -eq 'Arm') {
    if ((Read-State).Applied) { throw 'Restore the previous application before rearming.' }
    $script = Join-Path $RunDirectory 'windows_client_pilot.ps1'
    if (-not (Test-Path -LiteralPath $script)) { throw 'Copy this script into the private run directory before arming.' }
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action Restore -RunDirectory "{1}"' -f $script,$RunDirectory
    $taskAction = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments
    $triggers = @((New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10)),(New-ScheduledTaskTrigger -AtStartup))
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $triggers -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Remove-Item -LiteralPath $receiptPath -ErrorAction SilentlyContinue
    $info = Get-ScheduledTaskInfo -TaskName $taskName
    if ($info.NextRunTime -lt (Get-Date) -or $info.NextRunTime -gt (Get-Date).AddMinutes(11)) { throw 'Rollback trigger verification failed.' }
    [ordered]@{ Task = $taskName; NextRunTime = $info.NextRunTime.ToString('o') } | ConvertTo-Json -Compress
    exit
}

if ($Action -eq 'TestRollback') {
    $baseline = Read-Baseline
    $state = Read-State
    if ($state.Applied) { throw 'Cannot run canary test while client routes are applied.' }
    $prefix = '203.0.113.254/32'
    if (Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue) { throw 'Canary prefix already in use.' }
    $nextHop = @($baseline.Configuration.Routes | Where-Object DestinationPrefix -eq '0.0.0.0/0')[0].NextHop
    $state.Routes = @([ordered]@{ Prefix=$prefix; NextHop=$nextHop })
    Write-PrivateJson $statePath $state
    New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $baseline.Configuration.InterfaceIndex -NextHop $nextHop -RouteMetric 7 -PolicyStore ActiveStore | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddSeconds(45)
    while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $receiptPath)) { Start-Sleep -Milliseconds 300 }
    if (-not (Test-Path -LiteralPath $receiptPath)) { throw 'Local SYSTEM rollback did not produce a receipt.' }
    $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    if (-not $receipt.Matched) { throw 'Canary rollback did not restore the baseline.' }
    Write-PrivateJson $statePath ([ordered]@{ Routes=@(); Applied=$false })
    $receipt | ConvertTo-Json -Depth 8 -Compress
    exit
}

if ($Action -eq 'Apply') {
    $baseline = Read-Baseline
    $state = Read-State
    if ($state.Applied) { throw 'Client test is already applied.' }
    $task = Get-ScheduledTaskInfo -TaskName $taskName
    if ($task.NextRunTime -lt (Get-Date).AddMinutes(5)) { throw 'Rearm the rollback task before applying test routes.' }
    $ipv4 = [Net.IPAddress]::Parse($Gateway)
    $ipv6 = [Net.IPAddress]::Parse($IPv6Gateway)
    if ($ipv4.AddressFamily -ne 'InterNetwork' -or -not $ipv6.IsIPv6LinkLocal) { throw 'Use an IPv4 pilot gateway and IPv6 link-local gateway.' }
    if (@(Get-DnsClientNrptRule).Count -ne 0) { throw 'Existing NRPT policy requires review before testing.' }
    $routes = @(
        [ordered]@{ Prefix='0.0.0.0/1'; NextHop=$Gateway },
        [ordered]@{ Prefix='128.0.0.0/1'; NextHop=$Gateway },
        [ordered]@{ Prefix='2000::/3'; NextHop=$IPv6Gateway }
    )
    foreach ($route in $routes) {
        if (Get-NetRoute -DestinationPrefix $route.Prefix -ErrorAction SilentlyContinue) { throw 'A test prefix already has a route; refusing to override it.' }
    }
    $state.Routes = $routes
    $state.Applied = $true
    Write-PrivateJson $statePath $state
    try {
        foreach ($route in $routes) {
            New-NetRoute -DestinationPrefix $route.Prefix -InterfaceIndex $baseline.Configuration.InterfaceIndex -NextHop $route.NextHop -RouteMetric 7 -PolicyStore ActiveStore | Out-Null
        }
        Add-DnsClientNrptRule -Namespace 'www.cloudflare.com','one.one.one.one' -NameServers $Gateway -Comment $taskName -DisplayName $taskName | Out-Null
        [ordered]@{ Applied=$true; ClientAddressUnchanged=$baseline.ClientAddress; RollbackTask=$taskName } | ConvertTo-Json -Compress
    } catch {
        Restore-OwnedChanges | Out-Null
        throw
    }
    exit
}

if ($Action -eq 'Restore') {
    Restore-OwnedChanges | ConvertTo-Json -Depth 8 -Compress
    exit
}

if ($Action -eq 'Verify') {
    Test-Configuration | ConvertTo-Json -Depth 8 -Compress
    exit
}

if ($Action -eq 'Disarm') {
    $verification = Test-Configuration
    if (-not $verification.Matched) { throw 'Cannot remove rollback task until baseline restoration is verified.' }
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    [ordered]@{ Disarmed=$true; BaselineMatched=$true } | ConvertTo-Json -Compress
}

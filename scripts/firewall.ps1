# Native Windows firewall adapter. Values arrive as JSON over stdin, never as commands.
# Only rules with this fixed Group AND generated name prefix are owned by this project.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$ManagedGroup = 'DPIEngine.ManagedBlocking.v1'
$NamePrefix = 'DPIEngine-Managed-'
$rollbackSucceeded = $null
$mutationStarted = $false
$mutex = $null
$mutexHeld = $false

function Get-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ManagedRules([string]$PolicyStore = 'PersistentStore') {
    return @(Get-NetFirewallRule -PolicyStore $PolicyStore -ErrorAction Stop | Where-Object {
        $_.Group -eq $ManagedGroup -and $_.Name.StartsWith($NamePrefix, [StringComparison]::Ordinal)
    })
}

function Get-NativeStatus {
    $owned = @(Get-ManagedRules)
    $active = @(Get-ManagedRules 'ActiveStore' | Where-Object { $_.Enabled -eq 'True' })
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
        @{ name = [string]$_.Name; enabled = ($_.Enabled -eq 'True') }
    })
    return @{
        supported = $true
        available = $true
        statusKnown = $true
        elevated = (Get-IsAdministrator)
        group = $ManagedGroup
        installedCount = $owned.Count
        enabledCount = @($owned | Where-Object { $_.Enabled -eq 'True' }).Count
        activeCount = $active.Count
        firewallEnabled = (@($profiles | Where-Object { -not $_.enabled }).Count -eq 0)
        profiles = $profiles
        rules = @($owned | ForEach-Object {
            @{ name = [string]$_.Name; displayName = [string]$_.DisplayName; direction = [string]$_.Direction; enabled = ($_.Enabled -eq 'True') }
        })
    }
}

function Backup-ManagedRules($Rules) {
    return @($Rules | ForEach-Object {
        $port = $_ | Get-NetFirewallPortFilter
        $address = $_ | Get-NetFirewallAddressFilter
        $backup = @{
            Name = [string]$_.Name
            DisplayName = [string]$_.DisplayName
            Description = [string]$_.Description
            Group = $ManagedGroup
            Direction = [string]$_.Direction
            Enabled = [string]$_.Enabled
            Action = [string]$_.Action
            Profile = $_.Profile
            PolicyStore = 'PersistentStore'
            Protocol = [string]$port.Protocol
            LocalAddress = @($address.LocalAddress)
            RemoteAddress = @($address.RemoteAddress)
        }
        if ([string]$port.Protocol -in @('TCP', 'UDP', '6', '17')) {
            $backup.LocalPort = @($port.LocalPort)
            $backup.RemotePort = @($port.RemotePort)
        }
        $backup
    })
}

function Restore-ManagedRules($Backups) {
    $existing = @{}
    @(Get-ManagedRules) | ForEach-Object { $existing[$_.Name] = $_ }
    foreach ($backup in $Backups) {
        if ($existing.ContainsKey($backup.Name)) {
            $existing[$backup.Name] | Set-NetFirewallRule -Enabled $backup.Enabled -ErrorAction Stop | Out-Null
        } else {
            New-NetFirewallRule @backup -ErrorAction Stop | Out-Null
        }
    }
}

function New-RuleParameters($Entry, [string]$Name) {
    if ($Entry.direction -notin @('Inbound', 'Outbound')) { throw 'Invalid traffic direction.' }
    if ($Entry.kind -notin @('ip', 'port', 'protocol')) { throw 'Invalid native rule type.' }
    if ($Entry.protocol -notin @('Any', 'TCP', 'UDP', 'ICMPv4', 'ICMPv6')) { throw 'Invalid native protocol.' }
    $parameters = @{
        Name = $Name
        DisplayName = ('DPI Engine: ' + [string]$Entry.label + ' (' + [string]$Entry.direction + ')')
        Description = 'Created by DPI Engine live enforcement. Managed independently from capture filtering.'
        Group = $ManagedGroup
        Direction = [string]$Entry.direction
        Action = 'Block'
        Enabled = 'False'
        Profile = 'Any'
        PolicyStore = 'PersistentStore'
        Protocol = [string]$Entry.protocol
    }
    if ($Entry.kind -eq 'ip') {
        $value = [string]$Entry.remoteAddress
        $parts = $value.Split('/')
        $parsedAddress = $null
        if ($value -notmatch '^[0-9a-fA-F:./]+$' -or $parts.Length -gt 2 -or -not [Net.IPAddress]::TryParse($parts[0], [ref]$parsedAddress)) { throw 'Invalid remote IP address.' }
        if ($parts.Length -eq 2) {
            $maximum = 32
            if ($parsedAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $maximum = 128 }
            if ($parts[1] -notmatch '^\d{1,3}$' -or [int]$parts[1] -gt $maximum) { throw 'Invalid IP network prefix.' }
        }
        if ($Entry.protocol -ne 'Any') { throw 'IP rules must apply to all protocols.' }
        $parameters.RemoteAddress = $value
    } elseif ($Entry.kind -eq 'port') {
        if ($Entry.protocol -notin @('TCP', 'UDP')) { throw 'Port rules require TCP or UDP.' }
        $port = if ($Entry.direction -eq 'Inbound') { [string]$Entry.localPort } else { [string]$Entry.remotePort }
        if ($port -notmatch '^(\d{1,5})(?:-(\d{1,5}))?$') { throw 'Invalid port range.' }
        $first = [int]$Matches[1]
        $last = $first
        if ($Matches[2]) { $last = [int]$Matches[2] }
        if ($first -lt 1 -or $last -gt 65535 -or $first -gt $last) { throw 'Invalid port bounds.' }
        if ($Entry.direction -eq 'Inbound') { $parameters.LocalPort = $port } else { $parameters.RemotePort = $port }
    } elseif ($Entry.protocol -eq 'Any') {
        throw 'A protocol rule cannot block every protocol.'
    }
    return $parameters
}

try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    if ($request.action -notin @('status', 'apply', 'remove')) { throw 'Unknown firewall operation.' }
    try {
        Import-Module NetSecurity -ErrorAction Stop
    } catch {
        if ($request.action -eq 'status') {
            @{ ok = $true; status = @{ supported = $true; available = $false; statusKnown = $false; elevated = (Get-IsAdministrator); installedCount = $null; enabledCount = $null; activeCount = $null; rules = @(); profiles = @(); group = $ManagedGroup; message = 'Windows Defender Firewall management is unavailable.' } } | ConvertTo-Json -Depth 8 -Compress
            exit 0
        }
        throw 'Windows Defender Firewall management is unavailable.'
    }

    if ($request.action -eq 'status') {
        try {
            $status = Get-NativeStatus
        } catch {
            $isAdmin = Get-IsAdministrator
            $message = 'Native firewall status could not be read. Check Windows Defender Firewall services.'
            if (-not $isAdmin) { $message = 'Restart the server as Administrator to inspect and change Windows Defender Firewall.' }
            $status = @{ supported = $true; available = $true; statusKnown = $false; elevated = $isAdmin; installedCount = $null; enabledCount = $null; activeCount = $null; rules = @(); profiles = @(); group = $ManagedGroup; message = $message }
        }
        @{ ok = $true; status = $status } | ConvertTo-Json -Depth 8 -Compress
        exit 0
    }
    if (-not (Get-IsAdministrator)) {
        @{ ok = $false; code = 'NOT_ADMIN'; error = 'Restart the server as Administrator to change Windows Defender Firewall.' } | ConvertTo-Json -Compress
        exit 1
    }

    # Serialize changes across Node processes as well as within a single server.
    $mutex = New-Object Threading.Mutex($false, 'Global\DPIEngineManagedFirewallV1')
    try { $mutexHeld = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $mutexHeld = $true }
    if (-not $mutexHeld) { throw 'Another DPI Engine firewall change is in progress.' }

    $oldRules = @(Get-ManagedRules)
    $backups = @(Backup-ManagedRules $oldRules)
    $createdNames = New-Object 'System.Collections.Generic.List[string]'
    $parametersToCreate = @()
    if ($request.action -eq 'apply') {
        $entries = @($request.plan.entries)
        if ($entries.Count -lt 1 -or $entries.Count -gt 256) { throw 'A policy must contain between 1 and 256 native rules.' }
        $batch = [Guid]::NewGuid().ToString('N')
        for ($index = 0; $index -lt $entries.Count; $index++) {
            $name = $NamePrefix + $batch + '-' + $index
            # Validate the complete policy before making the first native change.
            $parametersToCreate += (New-RuleParameters $entries[$index] $name)
        }
    }

    try {
        $mutationStarted = $true
        foreach ($parameters in $parametersToCreate) {
            $createdNames.Add($parameters.Name)
            New-NetFirewallRule @parameters -ErrorAction Stop | Out-Null
        }
        # Stage disabled rules first. Enable the full replacement before removing the old policy.
        if ($createdNames.Count -gt 0) {
            $newRules = @(Get-ManagedRules | Where-Object { $createdNames.Contains($_.Name) })
            if ($newRules.Count -ne $createdNames.Count) { throw 'Not all staged native rules were created.' }
            $newRules | Set-NetFirewallRule -Enabled True -ErrorAction Stop | Out-Null
        }
        foreach ($old in $oldRules) {
            $old | Remove-NetFirewallRule -ErrorAction Stop | Out-Null
        }
        $remaining = @(Get-ManagedRules)
        if ($request.action -eq 'apply' -and ($remaining.Count -ne $createdNames.Count -or @($remaining | Where-Object { $_.Enabled -ne 'True' }).Count -gt 0)) { throw 'The native policy did not match the requested replacement.' }
        if ($request.action -eq 'remove' -and $remaining.Count -gt 0) { throw 'Some managed firewall rules could not be removed.' }
    } catch {
        $originalError = $_.Exception.Message
        $rollbackSucceeded = $true
        try { Restore-ManagedRules $backups } catch { $rollbackSucceeded = $false }
        try {
            @(Get-ManagedRules | Where-Object { $createdNames.Contains($_.Name) }) | Remove-NetFirewallRule -ErrorAction Stop | Out-Null
        } catch { $rollbackSucceeded = $false }
        if ($rollbackSucceeded) { throw ($originalError + ' The previous managed policy was restored.') }
        throw ($originalError + ' Rollback was incomplete. Refresh status and inspect the managed rules in Windows Firewall.')
    }

    @{ ok = $true; status = (Get-NativeStatus) } | ConvertTo-Json -Depth 8 -Compress
} catch {
    $result = @{ ok = $false; error = $_.Exception.Message }
    if ($null -ne $rollbackSucceeded) { $result.rollbackSucceeded = $rollbackSucceeded }
    if ($mutationStarted -and $rollbackSucceeded -ne $true) { $result.stateUnconfirmed = $true }
    $result | ConvertTo-Json -Depth 8 -Compress
    exit 1
} finally {
    if ($mutexHeld) { $mutex.ReleaseMutex() }
    if ($null -ne $mutex) { $mutex.Dispose() }
}

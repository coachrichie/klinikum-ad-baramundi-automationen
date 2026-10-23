<#
.SYNOPSIS
Read-only reconciliation of AD computers and a baramundi inventory CSV.
.DESCRIPTION
Returns review candidates, never changes source systems. Only an explicitly
requested ReportPath writes a local file; WhatIf suppresses that write.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$BaramundiCsvPath,
    [AllowEmptyCollection()][object[]]$ADComputers,
    [ValidateRange(1, 36500)][int]$StaleDays = 90,
    [datetime]$Now = (Get-Date),
    [string]$SearchBase,
    [string]$ReportPath
)

$auditCmdlet = $PSCmdlet
function Stop-Audit {
    param([string]$Id, [string]$Message, [object]$Target)
    $record = [System.Management.Automation.ErrorRecord]::new(
        [System.InvalidOperationException]::new($Message), $Id,
        [System.Management.Automation.ErrorCategory]::InvalidData, $Target)
    $auditCmdlet.ThrowTerminatingError($record)
}

function ConvertTo-DeviceKey {
    param([string]$Name)
    $key = ($Name.Trim() -replace '\$$', '').ToUpperInvariant()
    if ($key -notmatch '^[A-Z0-9][A-Z0-9_.-]*$') {
        Stop-Audit 'InvalidDeviceName' 'Device names must be nonempty host names, optionally ending in $.' $Name
    }
    $key
}

try {
    $inventory = @(Import-Csv -LiteralPath $BaramundiCsvPath -Encoding UTF8 -ErrorAction Stop)
} catch {
    Stop-Audit 'CsvReadFailed' ('Cannot read inventory CSV: ' + $_.Exception.Message) $BaramundiCsvPath
}
if ($inventory.Count -eq 0) {
    Stop-Audit 'EmptyInventory' 'Inventory CSV contains no device rows; verify the export before auditing.' $BaramundiCsvPath
}
if ('DeviceName' -notin $inventory[0].PSObject.Properties.Name -or 'LastSeen' -notin $inventory[0].PSObject.Properties.Name) {
    Stop-Audit 'InvalidCsvSchema' 'Inventory CSV requires columns DeviceName and LastSeen (comma-separated UTF-8).' $BaramundiCsvPath
}

$baramundiByName = @{}
foreach ($device in $inventory) {
    $key = ConvertTo-DeviceKey $device.DeviceName
    if ($baramundiByName.ContainsKey($key)) {
        Stop-Audit 'DuplicateDeviceName' 'Duplicate normalized DeviceName in inventory; resolve ambiguity first.' $key
    }
    $lastSeen = $null
    if (-not [string]::IsNullOrWhiteSpace($device.LastSeen)) {
        $parsed = [datetimeoffset]::MinValue
        if ($device.LastSeen -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$' -or
            -not [datetimeoffset]::TryParse($device.LastSeen, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {
            Stop-Audit 'InvalidLastSeen' 'LastSeen must be empty or an ISO 8601 timestamp with Z or an explicit UTC offset.' $key
        }
        $lastSeen = $parsed.UtcDateTime
    }
    $baramundiByName[$key] = $lastSeen
}

# An explicitly supplied empty array is an empty source, not a live-query request.
if (-not $PSBoundParameters.ContainsKey('ADComputers')) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $query = @{ Filter = '*'; Properties = @('LastLogonDate'); ErrorAction = 'Stop' }
        if ($SearchBase) { $query.SearchBase = $SearchBase }
        $ADComputers = @(Get-ADComputer @query)
    } catch {
        Stop-Audit 'ADReadFailed' ('Cannot read AD computers: ' + $_.Exception.Message) $SearchBase
    }
}

$adByName = @{}
foreach ($computer in $ADComputers) {
    $key = ConvertTo-DeviceKey $computer.Name
    if ($adByName.ContainsKey($key)) {
        Stop-Audit 'DuplicateDeviceName' 'Duplicate normalized AD name; resolve ambiguity or narrow SearchBase.' $key
    }
    $adByName[$key] = $computer
}

$cutoff = $Now.ToUniversalTime().AddDays(-$StaleDays)
$names = @(@($adByName.Keys) + @($baramundiByName.Keys) | Sort-Object -Unique)
$results = @(foreach ($name in $names) {
    $inAD = $adByName.ContainsKey($name)
    $inBaramundi = $baramundiByName.ContainsKey($name)
    $logon = $null
    if ($inAD -and $null -ne $adByName[$name].LastLogonDate) {
        $logon = ([datetime]$adByName[$name].LastLogonDate).ToUniversalTime()
    }
    $stale = $null -ne $logon -and $logon -lt $cutoff
    $status = if ($stale) { 'StaleInAD' } elseif ($inAD -and $inBaramundi) { 'Matched' } elseif ($inAD) { 'OnlyInAD' } else { 'OnlyInBaramundi' }
    [pscustomobject]@{
        DeviceName = $name
        Status = $status
        InAD = $inAD
        InBaramundi = $inBaramundi
        ADLastLogonDate = if ($null -ne $logon) { $logon.ToString('o') } else { $null }
        ADLogonState = if (-not $inAD) { 'NotInSource' } elseif ($null -eq $logon) { 'Unknown' } elseif ($stale) { 'Stale' } else { 'WithinThreshold' }
        BaramundiLastSeen = if ($null -ne $baramundiByName[$name]) { $baramundiByName[$name].ToString('o') } else { $null }
        BaramundiSeenState = if (-not $inBaramundi) { 'NotInSource' } elseif ($null -eq $baramundiByName[$name]) { 'Unknown' } else { 'Recorded' }
        AuditTimeUtc = $Now.ToUniversalTime().ToString('o')
        StaleDays = $StaleDays
    }
})

if ($ReportPath -and $PSCmdlet.ShouldProcess($ReportPath, 'Create inventory audit CSV (no overwrite)')) {
    try {
        $results | Export-Csv -LiteralPath $ReportPath -NoTypeInformation -NoClobber -Encoding UTF8 -ErrorAction Stop
    } catch {
        Stop-Audit 'ReportWriteFailed' ('Cannot create report CSV: ' + $_.Exception.Message) $ReportPath
    }
}
$results

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $ADComputerCsv,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $BaramundiAuditCsv,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $ConfigPath,

    [string] $OutputDirectory,

    [datetime] $ReferenceTimeUtc = [datetime]::UtcNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-CsvSchema {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Label,
        [Parameter(Mandatory)] [string[]] $RequiredColumns
    )

    $header = Get-Content -LiteralPath $Path -TotalCount 1
    if ([string]::IsNullOrWhiteSpace($header)) {
        throw "$Label is empty."
    }

    $columns = @($header.Split(',') | ForEach-Object { $_.Trim().Trim('"') })
    foreach ($column in $RequiredColumns) {
        if ($columns -notcontains $column) {
            throw "$Label is missing required column '$column'."
        }
    }
}

function ConvertTo-StrictBoolean {
    param(
        [Parameter(Mandatory)] [string] $Value,
        [Parameter(Mandatory)] [string] $FieldName
    )

    $parsed = $false
    if (-not [bool]::TryParse($Value, [ref] $parsed)) {
        throw "Field '$FieldName' must contain true or false."
    }
    $parsed
}

function ConvertTo-NonNegativeInteger {
    param(
        [Parameter(Mandatory)] [string] $Value,
        [Parameter(Mandatory)] [string] $FieldName
    )

    $parsed = 0
    if (-not [int]::TryParse($Value, [ref] $parsed) -or $parsed -lt 0) {
        throw "Field '$FieldName' must contain a non-negative integer."
    }
    $parsed
}

function New-AuditFinding {
    param(
        [string] $ComputerName,
        [string] $OperatingSystem,
        [string] $Status,
        [string] $Severity,
        [string] $Control,
        [string] $ObservedValue,
        [string] $Finding,
        [string] $Recommendation,
        [string] $AuditTimeUtc
    )

    [pscustomobject][ordered]@{
        ComputerName    = $ComputerName
        OperatingSystem = $OperatingSystem
        Status          = $Status
        Severity        = $Severity
        Control         = $Control
        ObservedValue   = $ObservedValue
        Finding         = $Finding
        Recommendation  = $Recommendation
        AuditTimeUtc    = $AuditTimeUtc
    }
}

Assert-CsvSchema -Path $ADComputerCsv -Label 'AD computer export' -RequiredColumns @(
    'ComputerName', 'Enabled', 'OperatingSystem', 'IsDomainController'
)
Assert-CsvSchema -Path $BaramundiAuditCsv -Label 'Baramundi LDAP audit' -RequiredColumns @(
    'DeviceName', 'AuditTimeUtc', 'LdapSigningRequired', 'ChannelBindingMode',
    'UnsignedBindEvents24h', 'ChannelBindingEvents7d'
)

$config = Import-PowerShellDataFile -LiteralPath $ConfigPath
$requiredConfigKeys = @(
    'MaxAuditAgeDays', 'RequireLdapSigning', 'TargetChannelBindingMode',
    'MaxUnsignedBindEvents24h', 'MaxChannelBindingEvents7d'
)
foreach ($key in $requiredConfigKeys) {
    if (-not $config.ContainsKey($key)) {
        throw "Configuration is missing required key '$key'."
    }
}

if ([int] $config.MaxAuditAgeDays -lt 1) {
    throw 'MaxAuditAgeDays must be a positive integer.'
}
if ([int] $config.MaxUnsignedBindEvents24h -lt 0 -or [int] $config.MaxChannelBindingEvents7d -lt 0) {
    throw 'Event thresholds must be non-negative integers.'
}
$validModes = @('Never', 'WhenSupported', 'Always')
if ($validModes -notcontains [string] $config.TargetChannelBindingMode) {
    throw 'TargetChannelBindingMode must be Never, WhenSupported, or Always.'
}

$adRows = @(Import-Csv -LiteralPath $ADComputerCsv)
$auditRows = @(Import-Csv -LiteralPath $BaramundiAuditCsv)
$auditIndex = @{}

foreach ($row in $auditRows) {
    $deviceName = $row.DeviceName.Trim()
    if ([string]::IsNullOrWhiteSpace($deviceName)) {
        throw 'Baramundi LDAP audit contains an empty DeviceName.'
    }

    $key = $deviceName.ToLowerInvariant()
    if ($auditIndex.ContainsKey($key)) {
        throw "Baramundi LDAP audit contains duplicate DeviceName '$($row.DeviceName)'."
    }
    $auditIndex[$key] = $row
}

$referenceUtc = $ReferenceTimeUtc.ToUniversalTime()
$findings = [System.Collections.Generic.List[object]]::new()

foreach ($computer in $adRows) {
    $enabled = ConvertTo-StrictBoolean -Value $computer.Enabled -FieldName 'Enabled'
    $isDomainController = ConvertTo-StrictBoolean -Value $computer.IsDomainController -FieldName 'IsDomainController'
    if (-not $enabled -or -not $isDomainController) {
        continue
    }

    $computerName = $computer.ComputerName.Trim()
    if ([string]::IsNullOrWhiteSpace($computerName)) {
        throw 'AD computer export contains an empty ComputerName for an in-scope domain controller.'
    }
    $operatingSystem = $computer.OperatingSystem.Trim()
    $key = $computerName.ToLowerInvariant()

    if (-not $auditIndex.ContainsKey($key)) {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Failed' -Severity 'High' -Control 'AuditCoverage' -ObservedValue 'Missing' `
            -Finding 'Für den aktivierten Domain Controller liegt kein aktueller Baramundi-LDAP-Auditdatensatz vor.' `
            -Recommendation 'Datenerfassung ausführen, Export aktualisieren und den Audit erneut starten.' `
            -AuditTimeUtc ''))
        continue
    }

    $audit = $auditIndex[$key]
    $auditTime = [datetime]::MinValue
    if (-not [datetime]::TryParse($audit.AuditTimeUtc, [ref] $auditTime)) {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Review' -Severity 'Medium' -Control 'AuditFreshness' -ObservedValue $audit.AuditTimeUtc `
            -Finding 'Der Auditzeitpunkt ist nicht auswertbar.' `
            -Recommendation 'Zeitformat der Datenerfassung korrigieren und erneut inventarisieren.' `
            -AuditTimeUtc $audit.AuditTimeUtc))
        continue
    }

    $auditUtc = $auditTime.ToUniversalTime()
    if (($referenceUtc - $auditUtc).TotalDays -gt [int] $config.MaxAuditAgeDays) {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Review' -Severity 'Medium' -Control 'AuditFreshness' -ObservedValue $auditUtc.ToString('o') `
            -Finding 'Der LDAP-Härtungsstatus ist älter als der konfigurierte Grenzwert.' `
            -Recommendation 'Status und Ereigniszähler neu erfassen; veraltete Werte nicht für eine Erzwingung verwenden.' `
            -AuditTimeUtc $auditUtc.ToString('o')))
        continue
    }

    $signingRequired = ConvertTo-StrictBoolean -Value $audit.LdapSigningRequired -FieldName 'LdapSigningRequired'
    $channelBindingMode = $audit.ChannelBindingMode.Trim()
    if ($validModes -notcontains $channelBindingMode) {
        throw 'Field ChannelBindingMode must contain Never, WhenSupported, or Always.'
    }
    $unsignedBindEvents = ConvertTo-NonNegativeInteger -Value $audit.UnsignedBindEvents24h -FieldName 'UnsignedBindEvents24h'
    $channelBindingEvents = ConvertTo-NonNegativeInteger -Value $audit.ChannelBindingEvents7d -FieldName 'ChannelBindingEvents7d'
    $auditStamp = $auditUtc.ToString('o')

    if ([bool] $config.RequireLdapSigning -and -not $signingRequired) {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Failed' -Severity 'High' -Control 'LdapSigning' -ObservedValue 'NotRequired' `
            -Finding 'Der Domain Controller erzwingt keine LDAP-Signierung.' `
            -Recommendation 'Unsichere Clients zuerst ermitteln und migrieren; Signaturpflicht danach kontrolliert per Gruppenrichtlinie aktivieren.' `
            -AuditTimeUtc $auditStamp))
    }
    else {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Passed' -Severity 'Info' -Control 'LdapSigning' -ObservedValue ([string] $signingRequired) `
            -Finding 'Die konfigurierte Vorgabe zur LDAP-Signierung ist erfüllt.' `
            -Recommendation 'Konfiguration und Ereignisse turnusmäßig erneut prüfen.' `
            -AuditTimeUtc $auditStamp))
    }

    if ($channelBindingMode -eq 'Never') {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Failed' -Severity 'High' -Control 'ChannelBinding' -ObservedValue $channelBindingMode `
            -Finding 'LDAP Channel Binding ist deaktiviert.' `
            -Recommendation 'Zunächst WhenSupported aktivieren, Auditereignisse auswerten und Always erst nach Clientbereinigung pilotieren.' `
            -AuditTimeUtc $auditStamp))
    }
    elseif ($channelBindingMode -eq 'WhenSupported' -and [string] $config.TargetChannelBindingMode -eq 'Always') {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Review' -Severity 'Low' -Control 'ChannelBinding' -ObservedValue $channelBindingMode `
            -Finding 'Channel Binding wird unterstützt, aber noch nicht für alle anwendbaren Clients erzwungen.' `
            -Recommendation 'Auditereignisse und Anwendungstests auswerten; anschließend eine kontrollierte Pilotgruppe für Always planen.' `
            -AuditTimeUtc $auditStamp))
    }
    else {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Passed' -Severity 'Info' -Control 'ChannelBinding' -ObservedValue $channelBindingMode `
            -Finding 'Die konfigurierte Vorgabe zu LDAP Channel Binding ist erfüllt.' `
            -Recommendation 'Kompatibilität und Auditereignisse weiterhin überwachen.' `
            -AuditTimeUtc $auditStamp))
    }

    if ($unsignedBindEvents -gt [int] $config.MaxUnsignedBindEvents24h) {
        $activitySeverity = if ($signingRequired) { 'Medium' } else { 'Critical' }
        $activityStatus = if ($signingRequired) { 'Review' } else { 'Failed' }
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status $activityStatus -Severity $activitySeverity -Control 'UnsignedBindActivity' -ObservedValue ([string] $unsignedBindEvents) `
            -Finding 'Es wurden LDAP-Bind-Versuche ohne ausreichende Signierung beziehungsweise Absicherung beobachtet.' `
            -Recommendation 'Verursachende Clients anhand der Directory-Service-Ereignisse identifizieren und vor einer Erzwingung aktualisieren.' `
            -AuditTimeUtc $auditStamp))
    }
    else {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Passed' -Severity 'Info' -Control 'UnsignedBindActivity' -ObservedValue ([string] $unsignedBindEvents) `
            -Finding 'Der Ereigniszähler für unsichere LDAP-Binds liegt innerhalb des Grenzwerts.' `
            -Recommendation 'Ereigniszähler über ein repräsentatives Beobachtungsfenster weiter überwachen.' `
            -AuditTimeUtc $auditStamp))
    }

    if ($channelBindingEvents -gt [int] $config.MaxChannelBindingEvents7d) {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Review' -Severity 'Medium' -Control 'ChannelBindingActivity' -ObservedValue ([string] $channelBindingEvents) `
            -Finding 'Channel-Binding-Auditereignisse weisen auf nicht kompatible oder fehlerhaft konfigurierte Clients hin.' `
            -Recommendation 'Betroffene Anwendungen und Geräte identifizieren; Clientkompatibilität vor Always-Erzwingung herstellen.' `
            -AuditTimeUtc $auditStamp))
    }
    else {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Passed' -Severity 'Info' -Control 'ChannelBindingActivity' -ObservedValue ([string] $channelBindingEvents) `
            -Finding 'Der Channel-Binding-Ereigniszähler liegt innerhalb des Grenzwerts.' `
            -Recommendation 'Ein repräsentatives Beobachtungsfenster und Anwendungstests beibehalten.' `
            -AuditTimeUtc $auditStamp))
    }
}

$result = @($findings)
if (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
    $result | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'ldap-hardening-readiness-findings.csv') -NoTypeInformation -Encoding utf8

    [ordered]@{
        GeneratedAtUtc = $referenceUtc.ToString('o')
        Total           = $result.Count
        Passed          = @($result | Where-Object Status -eq 'Passed').Count
        Failed          = @($result | Where-Object Status -eq 'Failed').Count
        Review          = @($result | Where-Object Status -eq 'Review').Count
        Critical        = @($result | Where-Object Severity -eq 'Critical').Count
        High            = @($result | Where-Object Severity -eq 'High').Count
        Medium          = @($result | Where-Object Severity -eq 'Medium').Count
        Low             = @($result | Where-Object Severity -eq 'Low').Count
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'ldap-hardening-readiness-summary.json') -Encoding utf8
}

$result

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $ADServerCsv,

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
        ComputerName   = $ComputerName
        OperatingSystem = $OperatingSystem
        Status         = $Status
        Severity       = $Severity
        Control        = $Control
        ObservedValue  = $ObservedValue
        Finding        = $Finding
        Recommendation = $Recommendation
        AuditTimeUtc   = $AuditTimeUtc
    }
}

Assert-CsvSchema -Path $ADServerCsv -Label 'AD server export' -RequiredColumns @(
    'ComputerName', 'Enabled', 'OperatingSystem'
)
Assert-CsvSchema -Path $BaramundiAuditCsv -Label 'Baramundi SMB audit' -RequiredColumns @(
    'DeviceName', 'AuditTimeUtc', 'LegacyProtocolEnabled', 'InboundSigningRequired',
    'OutboundSigningRequired', 'GuestAccessEnabled'
)

$config = Import-PowerShellDataFile -LiteralPath $ConfigPath
foreach ($key in 'MaxAuditAgeDays', 'DisallowLegacyProtocol', 'RequireInboundSigning', 'RequireOutboundSigning', 'DisallowGuestAccess') {
    if (-not $config.ContainsKey($key)) {
        throw "Configuration is missing required key '$key'."
    }
}
if ([int] $config.MaxAuditAgeDays -lt 1) {
    throw 'MaxAuditAgeDays must be a positive integer.'
}

$adRows = @(Import-Csv -LiteralPath $ADServerCsv)
$auditRows = @(Import-Csv -LiteralPath $BaramundiAuditCsv)

$auditIndex = @{}
foreach ($row in $auditRows) {
    $key = $row.DeviceName.Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($key)) {
        throw 'Baramundi SMB audit contains an empty DeviceName.'
    }
    if ($auditIndex.ContainsKey($key)) {
        throw "Baramundi SMB audit contains duplicate DeviceName '$($row.DeviceName)'."
    }
    $auditIndex[$key] = $row
}

$referenceUtc = $ReferenceTimeUtc.ToUniversalTime()
$findings = [System.Collections.Generic.List[object]]::new()

foreach ($server in $adRows) {
    $enabled = ConvertTo-StrictBoolean -Value $server.Enabled -FieldName 'Enabled'
    if (-not $enabled) {
        continue
    }

    $computerName = $server.ComputerName.Trim()
    $operatingSystem = $server.OperatingSystem.Trim()
    $key = $computerName.ToLowerInvariant()

    if (-not $auditIndex.ContainsKey($key)) {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Failed' -Severity 'High' -Control 'AuditCoverage' -ObservedValue 'Missing' `
            -Finding 'Für den aktivierten AD-Server liegt kein Baramundi-Sicherheitsaudit vor.' `
            -Recommendation 'Datenerfassung auf dem Server ausführen und den Audit anschließend wiederholen.' `
            -AuditTimeUtc ''))
        continue
    }

    $audit = $auditIndex[$key]
    $auditTime = [datetime]::MinValue
    if (-not [datetime]::TryParse($audit.AuditTimeUtc, [ref] $auditTime)) {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Review' -Severity 'Medium' -Control 'AuditFreshness' -ObservedValue $audit.AuditTimeUtc `
            -Finding 'Der Auditzeitpunkt ist nicht auswertbar.' `
            -Recommendation 'Zeitformat der Datenerfassung korrigieren und den Audit erneut ausführen.' `
            -AuditTimeUtc $audit.AuditTimeUtc))
        continue
    }

    $auditUtc = $auditTime.ToUniversalTime()
    if (($referenceUtc - $auditUtc).TotalDays -gt [int] $config.MaxAuditAgeDays) {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Review' -Severity 'Medium' -Control 'AuditFreshness' -ObservedValue $auditUtc.ToString('o') `
            -Finding 'Der Baramundi-Sicherheitsstatus ist älter als der zulässige Grenzwert.' `
            -Recommendation 'Status neu erfassen; veraltete Werte nicht als Entscheidungsgrundlage für eine Härtung verwenden.' `
            -AuditTimeUtc $auditUtc.ToString('o')))
        continue
    }

    $legacyEnabled = ConvertTo-StrictBoolean -Value $audit.LegacyProtocolEnabled -FieldName 'LegacyProtocolEnabled'
    $inboundSigning = ConvertTo-StrictBoolean -Value $audit.InboundSigningRequired -FieldName 'InboundSigningRequired'
    $outboundSigning = ConvertTo-StrictBoolean -Value $audit.OutboundSigningRequired -FieldName 'OutboundSigningRequired'
    $guestAccess = ConvertTo-StrictBoolean -Value $audit.GuestAccessEnabled -FieldName 'GuestAccessEnabled'
    $auditStamp = $auditUtc.ToString('o')

    if ([bool] $config.DisallowLegacyProtocol -and $legacyEnabled) {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Failed' -Severity 'Critical' -Control 'LegacyProtocol' -ObservedValue 'Enabled' `
            -Finding 'Das veraltete Dateifreigabeprotokoll ist aktiviert.' `
            -Recommendation 'Abhängige Systeme identifizieren, Ersatzpfad testen und das Protokoll kontrolliert deaktivieren.' `
            -AuditTimeUtc $auditStamp))
    }
    else {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Passed' -Severity 'Info' -Control 'LegacyProtocol' -ObservedValue ([string] $legacyEnabled) `
            -Finding 'Die Vorgabe zum veralteten Protokoll ist erfüllt.' `
            -Recommendation 'Status turnusmäßig überwachen.' -AuditTimeUtc $auditStamp))
    }

    if ([bool] $config.RequireInboundSigning -and -not $inboundSigning) {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Failed' -Severity 'High' -Control 'InboundSigning' -ObservedValue 'NotRequired' `
            -Finding 'Eingehende Dateifreigabeverbindungen müssen nicht signiert sein.' `
            -Recommendation 'Kompatibilität prüfen und serverseitige Signaturpflicht über den freigegebenen Härtungsprozess aktivieren.' `
            -AuditTimeUtc $auditStamp))
    }
    else {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Passed' -Severity 'Info' -Control 'InboundSigning' -ObservedValue ([string] $inboundSigning) `
            -Finding 'Die Vorgabe zur eingehenden Signaturpflicht ist erfüllt.' `
            -Recommendation 'Status turnusmäßig überwachen.' -AuditTimeUtc $auditStamp))
    }

    if ([bool] $config.RequireOutboundSigning -and -not $outboundSigning) {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Failed' -Severity 'High' -Control 'OutboundSigning' -ObservedValue 'NotRequired' `
            -Finding 'Ausgehende Dateifreigabeverbindungen müssen nicht signiert sein.' `
            -Recommendation 'Zielsysteme prüfen und clientseitige Signaturpflicht nach Kompatibilitätstest aktivieren.' `
            -AuditTimeUtc $auditStamp))
    }
    else {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Passed' -Severity 'Info' -Control 'OutboundSigning' -ObservedValue ([string] $outboundSigning) `
            -Finding 'Die Vorgabe zur ausgehenden Signaturpflicht ist erfüllt.' `
            -Recommendation 'Status turnusmäßig überwachen.' -AuditTimeUtc $auditStamp))
    }

    if ([bool] $config.DisallowGuestAccess -and $guestAccess) {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Failed' -Severity 'High' -Control 'GuestAccess' -ObservedValue 'Enabled' `
            -Finding 'Nicht authentifizierter Gastzugriff ist zugelassen.' `
            -Recommendation 'Abhängige Geräte identifizieren und auf authentifizierten Zugriff umstellen; Gastzugriff anschließend deaktivieren.' `
            -AuditTimeUtc $auditStamp))
    }
    else {
        $findings.Add((New-AuditFinding -ComputerName $computerName -OperatingSystem $operatingSystem `
            -Status 'Passed' -Severity 'Info' -Control 'GuestAccess' -ObservedValue ([string] $guestAccess) `
            -Finding 'Die Vorgabe zum Gastzugriff ist erfüllt.' `
            -Recommendation 'Status turnusmäßig überwachen.' -AuditTimeUtc $auditStamp))
    }
}

$result = @($findings)
if (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
    $result | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'smb-hardening-readiness-findings.csv') -NoTypeInformation -Encoding utf8

    [ordered]@{
        GeneratedAtUtc = $referenceUtc.ToString('o')
        Total = $result.Count
        Passed = @($result | Where-Object Status -eq 'Passed').Count
        Failed = @($result | Where-Object Status -eq 'Failed').Count
        Review = @($result | Where-Object Status -eq 'Review').Count
        Critical = @($result | Where-Object Severity -eq 'Critical').Count
        High = @($result | Where-Object Severity -eq 'High').Count
        Medium = @($result | Where-Object Severity -eq 'Medium').Count
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'smb-hardening-readiness-summary.json') -Encoding utf8
}

$result

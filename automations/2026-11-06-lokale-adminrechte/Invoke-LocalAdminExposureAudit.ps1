[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $ADPrincipalCsv,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $BaramundiLocalAdminCsv,

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
    foreach ($required in $RequiredColumns) {
        if ($columns -notcontains $required) {
            throw "$Label is missing required column '$required'."
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
    return $parsed
}

function New-Finding {
    param(
        [string] $ComputerName,
        [string] $Principal,
        [string] $PrincipalType,
        [string] $Status,
        [string] $Severity,
        [string] $Control,
        [string] $Finding,
        [string] $Recommendation,
        [string] $LastInventoryUtc,
        [int] $DeviceCount = 1
    )

    [pscustomobject][ordered]@{
        ComputerName    = $ComputerName
        Principal       = $Principal
        PrincipalType   = $PrincipalType
        Status          = $Status
        Severity        = $Severity
        Control         = $Control
        Finding         = $Finding
        Recommendation  = $Recommendation
        LastInventoryUtc = $LastInventoryUtc
        DeviceCount     = $DeviceCount
    }
}

Assert-CsvSchema -Path $ADPrincipalCsv -Label 'AD principal export' -RequiredColumns @(
    'Principal', 'Enabled', 'ApprovedForLocalAdmin'
)
Assert-CsvSchema -Path $BaramundiLocalAdminCsv -Label 'Baramundi local-admin export' -RequiredColumns @(
    'DeviceName', 'Principal', 'PrincipalType', 'LastInventoryUtc'
)

$config = Import-PowerShellDataFile -LiteralPath $ConfigPath
foreach ($key in 'MaxInventoryAgeDays', 'MaxDevicesPerPrincipal', 'ApprovedLocalAccounts') {
    if (-not $config.ContainsKey($key)) {
        throw "Configuration is missing required key '$key'."
    }
}
if ([int] $config.MaxInventoryAgeDays -lt 1 -or [int] $config.MaxDevicesPerPrincipal -lt 1) {
    throw 'Configuration thresholds must be positive integers.'
}

$adRows = @(Import-Csv -LiteralPath $ADPrincipalCsv)
$inventoryRows = @(Import-Csv -LiteralPath $BaramundiLocalAdminCsv)

$adIndex = @{}
foreach ($row in $adRows) {
    $key = $row.Principal.Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($key)) {
        throw 'AD principal export contains an empty Principal value.'
    }
    if ($adIndex.ContainsKey($key)) {
        throw "AD principal export contains duplicate Principal '$($row.Principal)'."
    }
    $adIndex[$key] = [pscustomobject]@{
        Principal = $row.Principal.Trim()
        Enabled = ConvertTo-StrictBoolean -Value $row.Enabled -FieldName 'Enabled'
        Approved = ConvertTo-StrictBoolean -Value $row.ApprovedForLocalAdmin -FieldName 'ApprovedForLocalAdmin'
    }
}

$approvedLocalAccounts = @{}
foreach ($account in @($config.ApprovedLocalAccounts)) {
    if (-not [string]::IsNullOrWhiteSpace([string] $account)) {
        $approvedLocalAccounts[[string]$account.ToLowerInvariant()] = $true
    }
}

$membershipKeys = @{}
foreach ($row in $inventoryRows) {
    $membershipKey = '{0}|{1}' -f $row.DeviceName.Trim().ToLowerInvariant(), $row.Principal.Trim().ToLowerInvariant()
    if ($membershipKeys.ContainsKey($membershipKey)) {
        throw "Baramundi local-admin export contains duplicate membership '$($row.DeviceName) / $($row.Principal)'."
    }
    $membershipKeys[$membershipKey] = $true
}

$referenceUtc = $ReferenceTimeUtc.ToUniversalTime()
$findings = [System.Collections.Generic.List[object]]::new()

foreach ($row in $inventoryRows) {
    $device = $row.DeviceName.Trim()
    $principal = $row.Principal.Trim()
    $principalType = $row.PrincipalType.Trim()
    $inventoryTimestamp = [datetime]::MinValue

    if (-not [datetime]::TryParse($row.LastInventoryUtc, [ref] $inventoryTimestamp)) {
        $findings.Add((New-Finding -ComputerName $device -Principal $principal -PrincipalType $principalType `
            -Status 'Review' -Severity 'Medium' -Control 'InventoryFreshness' `
            -Finding 'Der Inventurzeitpunkt ist nicht auswertbar.' `
            -Recommendation 'Baramundi-Export und Zeitformat prüfen; danach Audit erneut ausführen.' `
            -LastInventoryUtc $row.LastInventoryUtc))
        continue
    }

    $inventoryUtc = $inventoryTimestamp.ToUniversalTime()
    if (($referenceUtc - $inventoryUtc).TotalDays -gt [int] $config.MaxInventoryAgeDays) {
        $findings.Add((New-Finding -ComputerName $device -Principal $principal -PrincipalType $principalType `
            -Status 'Failed' -Severity 'Medium' -Control 'InventoryFreshness' `
            -Finding 'Die Baramundi-Inventur ist älter als der zulässige Grenzwert.' `
            -Recommendation 'Inventur aktualisieren und den Befund vor einer Rechteänderung erneut bewerten.' `
            -LastInventoryUtc $inventoryUtc.ToString('o')))
        continue
    }

    if ($principalType -ieq 'Domain') {
        $adKey = $principal.ToLowerInvariant()
        if (-not $adIndex.ContainsKey($adKey)) {
            $findings.Add((New-Finding -ComputerName $device -Principal $principal -PrincipalType $principalType `
                -Status 'Failed' -Severity 'High' -Control 'ADPrincipalResolution' `
                -Finding 'Das Domänenkonto ist im geprüften AD-Export nicht auflösbar.' `
                -Recommendation 'Kontoherkunft, SID-Auflösung und Notwendigkeit der lokalen Mitgliedschaft prüfen.' `
                -LastInventoryUtc $inventoryUtc.ToString('o')))
            continue
        }

        $adPrincipal = $adIndex[$adKey]
        if (-not $adPrincipal.Enabled) {
            $findings.Add((New-Finding -ComputerName $device -Principal $principal -PrincipalType $principalType `
                -Status 'Failed' -Severity 'Critical' -Control 'ADAccountState' `
                -Finding 'Ein deaktiviertes AD-Konto ist weiterhin lokaler Administrator.' `
                -Recommendation 'Mitgliedschaft fachlich prüfen und über den freigegebenen Änderungsprozess entfernen.' `
                -LastInventoryUtc $inventoryUtc.ToString('o')))
            continue
        }

        if (-not $adPrincipal.Approved) {
            $findings.Add((New-Finding -ComputerName $device -Principal $principal -PrincipalType $principalType `
                -Status 'Failed' -Severity 'High' -Control 'ApprovedPrincipal' `
                -Finding 'Das AD-Konto ist nicht ausdrücklich für lokale Administratorrechte freigegeben.' `
                -Recommendation 'Geschäftliche Notwendigkeit bestätigen oder Mitgliedschaft kontrolliert entfernen.' `
                -LastInventoryUtc $inventoryUtc.ToString('o')))
            continue
        }
    }
    elseif ($principalType -ieq 'Local') {
        $accountName = ($principal -split '\\')[-1].ToLowerInvariant()
        if (-not $approvedLocalAccounts.ContainsKey($accountName)) {
            $findings.Add((New-Finding -ComputerName $device -Principal $principal -PrincipalType $principalType `
                -Status 'Failed' -Severity 'High' -Control 'ApprovedLocalAccount' `
                -Finding 'Das lokale Administratorkonto steht nicht auf der expliziten Freigabeliste.' `
                -Recommendation 'Kontozweck, LAPS-Abdeckung und notwendige Mitgliedschaft prüfen.' `
                -LastInventoryUtc $inventoryUtc.ToString('o')))
            continue
        }
    }
    else {
        $findings.Add((New-Finding -ComputerName $device -Principal $principal -PrincipalType $principalType `
            -Status 'Review' -Severity 'Medium' -Control 'PrincipalType' `
            -Finding 'Der Prinzipaltyp ist weder Domain noch Local.' `
            -Recommendation 'Export-Mapping prüfen und den Datensatz korrekt klassifizieren.' `
            -LastInventoryUtc $inventoryUtc.ToString('o')))
        continue
    }

    $findings.Add((New-Finding -ComputerName $device -Principal $principal -PrincipalType $principalType `
        -Status 'Passed' -Severity 'Info' -Control 'LocalAdminMembership' `
        -Finding 'Die Mitgliedschaft entspricht der geprüften Freigabe.' `
        -Recommendation 'Freigabe und Inventur turnusmäßig erneut prüfen.' `
        -LastInventoryUtc $inventoryUtc.ToString('o')))
}

$approvedDomainPrincipals = @($inventoryRows | Where-Object { $_.PrincipalType -ieq 'Domain' } | Group-Object { $_.Principal.ToLowerInvariant() })
foreach ($group in $approvedDomainPrincipals) {
    if ($group.Count -le [int] $config.MaxDevicesPerPrincipal) {
        continue
    }
    if (-not $adIndex.ContainsKey($group.Name) -or -not $adIndex[$group.Name].Enabled -or -not $adIndex[$group.Name].Approved) {
        continue
    }

    $displayPrincipal = $group.Group[0].Principal.Trim()
    $findings.Add((New-Finding -ComputerName '*' -Principal $displayPrincipal -PrincipalType 'Domain' `
        -Status 'Review' -Severity 'Medium' -Control 'PrivilegeSpread' `
        -Finding "Das freigegebene Konto besitzt lokale Administratorrechte auf $($group.Count) Geräten." `
        -Recommendation 'Reichweite gegen Rollenmodell und Minimalprinzip prüfen; gerätespezifische Gruppen bevorzugen.' `
        -LastInventoryUtc '' -DeviceCount $group.Count))
}

$result = @($findings)

if (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
    $result | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'local-admin-exposure-findings.csv') -NoTypeInformation -Encoding utf8

    $summary = [ordered]@{
        GeneratedAtUtc = $referenceUtc.ToString('o')
        Total = $result.Count
        Passed = @($result | Where-Object Status -eq 'Passed').Count
        Failed = @($result | Where-Object Status -eq 'Failed').Count
        Review = @($result | Where-Object Status -eq 'Review').Count
        Critical = @($result | Where-Object Severity -eq 'Critical').Count
        High = @($result | Where-Object Severity -eq 'High').Count
        Medium = @($result | Where-Object Severity -eq 'Medium').Count
    }
    $summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'local-admin-exposure-summary.json') -Encoding utf8
}

$result

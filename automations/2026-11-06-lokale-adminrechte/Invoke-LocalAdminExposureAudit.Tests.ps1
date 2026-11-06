BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-LocalAdminExposureAudit.ps1'

    function New-TestCsv {
        param(
            [Parameter(Mandatory)] [string] $Path,
            [Parameter(Mandatory)] [string[]] $Lines
        )
        Set-Content -LiteralPath $Path -Value $Lines -Encoding utf8
        return $Path
    }

    function New-Config {
        param(
            [Parameter(Mandatory)] [string] $Path,
            [int] $MaxInventoryAgeDays = 7,
            [int] $MaxDevicesPerPrincipal = 5,
            [string[]] $ApprovedLocalAccounts = @()
        )
        $approved = ($ApprovedLocalAccounts | ForEach-Object { "        '$_'" }) -join ",`n"
        $content = @"
@{
    MaxInventoryAgeDays = $MaxInventoryAgeDays
    MaxDevicesPerPrincipal = $MaxDevicesPerPrincipal
    ApprovedLocalAccounts = @(
$approved
    )
}
"@
        Set-Content -LiteralPath $Path -Value $content -Encoding utf8
        return $Path
    }
}

Describe 'Invoke-LocalAdminExposureAudit' {
    BeforeEach {
        $adCsv = Join-Path $TestDrive 'ad.csv'
        $baramundiCsv = Join-Path $TestDrive 'baramundi.csv'
        $config = New-Config -Path (Join-Path $TestDrive 'config.psd1')
    }

    It 'passes an enabled and explicitly approved domain principal' {
        New-TestCsv $adCsv @(
            'Principal,Enabled,ApprovedForLocalAdmin',
            'EXAMPLE\svc-support,true,true'
        ) | Out-Null
        New-TestCsv $baramundiCsv @(
            'DeviceName,Principal,PrincipalType,LastInventoryUtc',
            'MED-WS-001,EXAMPLE\svc-support,Domain,2026-11-06T08:00:00Z'
        ) | Out-Null

        $result = & $scriptPath -ADPrincipalCsv $adCsv -BaramundiLocalAdminCsv $baramundiCsv -ConfigPath $config -ReferenceTimeUtc ([datetime]'2026-11-06T12:00:00Z')

        @($result).Count | Should -Be 1
        $result.Status | Should -Be 'Passed'
        $result.Severity | Should -Be 'Info'
        $result.Control | Should -Be 'LocalAdminMembership'
    }

    It 'flags an unapproved domain principal as high risk' {
        New-TestCsv $adCsv @('Principal,Enabled,ApprovedForLocalAdmin', 'EXAMPLE\user-a,true,false') | Out-Null
        New-TestCsv $baramundiCsv @('DeviceName,Principal,PrincipalType,LastInventoryUtc', 'MED-WS-001,EXAMPLE\user-a,Domain,2026-11-06T08:00:00Z') | Out-Null

        $result = & $scriptPath -ADPrincipalCsv $adCsv -BaramundiLocalAdminCsv $baramundiCsv -ConfigPath $config -ReferenceTimeUtc ([datetime]'2026-11-06T12:00:00Z')

        $result.Status | Should -Be 'Failed'
        $result.Severity | Should -Be 'High'
        $result.Control | Should -Be 'ApprovedPrincipal'
    }

    It 'flags a disabled domain principal as critical' {
        New-TestCsv $adCsv @('Principal,Enabled,ApprovedForLocalAdmin', 'EXAMPLE\former-admin,false,true') | Out-Null
        New-TestCsv $baramundiCsv @('DeviceName,Principal,PrincipalType,LastInventoryUtc', 'MED-WS-001,EXAMPLE\former-admin,Domain,2026-11-06T08:00:00Z') | Out-Null

        $result = & $scriptPath -ADPrincipalCsv $adCsv -BaramundiLocalAdminCsv $baramundiCsv -ConfigPath $config -ReferenceTimeUtc ([datetime]'2026-11-06T12:00:00Z')

        $result.Status | Should -Be 'Failed'
        $result.Severity | Should -Be 'Critical'
        $result.Control | Should -Be 'ADAccountState'
    }

    It 'flags a domain principal missing from the AD export' {
        New-TestCsv $adCsv @('Principal,Enabled,ApprovedForLocalAdmin', 'EXAMPLE\svc-support,true,true') | Out-Null
        New-TestCsv $baramundiCsv @('DeviceName,Principal,PrincipalType,LastInventoryUtc', 'MED-WS-001,EXAMPLE\unknown,Domain,2026-11-06T08:00:00Z') | Out-Null

        $result = & $scriptPath -ADPrincipalCsv $adCsv -BaramundiLocalAdminCsv $baramundiCsv -ConfigPath $config -ReferenceTimeUtc ([datetime]'2026-11-06T12:00:00Z')

        $result.Severity | Should -Be 'High'
        $result.Control | Should -Be 'ADPrincipalResolution'
    }

    It 'flags a local account that is not on the explicit allowlist' {
        New-TestCsv $adCsv @('Principal,Enabled,ApprovedForLocalAdmin') | Out-Null
        New-TestCsv $baramundiCsv @('DeviceName,Principal,PrincipalType,LastInventoryUtc', 'MED-WS-001,MED-WS-001\LocalSupport,Local,2026-11-06T08:00:00Z') | Out-Null

        $result = & $scriptPath -ADPrincipalCsv $adCsv -BaramundiLocalAdminCsv $baramundiCsv -ConfigPath $config -ReferenceTimeUtc ([datetime]'2026-11-06T12:00:00Z')

        $result.Severity | Should -Be 'High'
        $result.Control | Should -Be 'ApprovedLocalAccount'
    }

    It 'accepts a local account only when explicitly allowed' {
        $config = New-Config -Path (Join-Path $TestDrive 'config.psd1') -ApprovedLocalAccounts 'BreakGlassAdmin'
        New-TestCsv $adCsv @('Principal,Enabled,ApprovedForLocalAdmin') | Out-Null
        New-TestCsv $baramundiCsv @('DeviceName,Principal,PrincipalType,LastInventoryUtc', 'MED-WS-001,MED-WS-001\BreakGlassAdmin,Local,2026-11-06T08:00:00Z') | Out-Null

        $result = & $scriptPath -ADPrincipalCsv $adCsv -BaramundiLocalAdminCsv $baramundiCsv -ConfigPath $config -ReferenceTimeUtc ([datetime]'2026-11-06T12:00:00Z')

        $result.Status | Should -Be 'Passed'
    }

    It 'flags stale Baramundi inventory using the configured threshold' {
        New-TestCsv $adCsv @('Principal,Enabled,ApprovedForLocalAdmin', 'EXAMPLE\svc-support,true,true') | Out-Null
        New-TestCsv $baramundiCsv @('DeviceName,Principal,PrincipalType,LastInventoryUtc', 'MED-WS-001,EXAMPLE\svc-support,Domain,2026-10-01T08:00:00Z') | Out-Null

        $result = & $scriptPath -ADPrincipalCsv $adCsv -BaramundiLocalAdminCsv $baramundiCsv -ConfigPath $config -ReferenceTimeUtc ([datetime]'2026-11-06T12:00:00Z')

        $result.Severity | Should -Be 'Medium'
        $result.Control | Should -Be 'InventoryFreshness'
    }

    It 'flags an approved principal spread across too many devices' {
        $config = New-Config -Path (Join-Path $TestDrive 'config.psd1') -MaxDevicesPerPrincipal 2
        New-TestCsv $adCsv @('Principal,Enabled,ApprovedForLocalAdmin', 'EXAMPLE\svc-support,true,true') | Out-Null
        New-TestCsv $baramundiCsv @(
            'DeviceName,Principal,PrincipalType,LastInventoryUtc',
            'MED-WS-001,EXAMPLE\svc-support,Domain,2026-11-06T08:00:00Z',
            'MED-WS-002,EXAMPLE\svc-support,Domain,2026-11-06T08:00:00Z',
            'MED-WS-003,EXAMPLE\svc-support,Domain,2026-11-06T08:00:00Z'
        ) | Out-Null

        $result = & $scriptPath -ADPrincipalCsv $adCsv -BaramundiLocalAdminCsv $baramundiCsv -ConfigPath $config -ReferenceTimeUtc ([datetime]'2026-11-06T12:00:00Z')

        $spread = $result | Where-Object Control -eq 'PrivilegeSpread'
        @($spread).Count | Should -Be 1
        $spread.Severity | Should -Be 'Medium'
        $spread.DeviceCount | Should -Be 3
    }

    It 'rejects an AD export with missing required columns' {
        New-TestCsv $adCsv @('Name,Enabled', 'EXAMPLE\svc-support,true') | Out-Null
        New-TestCsv $baramundiCsv @('DeviceName,Principal,PrincipalType,LastInventoryUtc', 'MED-WS-001,EXAMPLE\svc-support,Domain,2026-11-06T08:00:00Z') | Out-Null

        { & $scriptPath -ADPrincipalCsv $adCsv -BaramundiLocalAdminCsv $baramundiCsv -ConfigPath $config } |
            Should -Throw '*AD principal export*missing required column*'
    }

    It 'rejects duplicate device and principal memberships' {
        New-TestCsv $adCsv @('Principal,Enabled,ApprovedForLocalAdmin', 'EXAMPLE\svc-support,true,true') | Out-Null
        New-TestCsv $baramundiCsv @(
            'DeviceName,Principal,PrincipalType,LastInventoryUtc',
            'MED-WS-001,EXAMPLE\svc-support,Domain,2026-11-06T08:00:00Z',
            'med-ws-001,example\SVC-SUPPORT,Domain,2026-11-06T08:00:00Z'
        ) | Out-Null

        { & $scriptPath -ADPrincipalCsv $adCsv -BaramundiLocalAdminCsv $baramundiCsv -ConfigPath $config } |
            Should -Throw '*duplicate membership*'
    }

    It 'writes structured CSV and JSON reports without secret fields' {
        New-TestCsv $adCsv @('Principal,Enabled,ApprovedForLocalAdmin', 'EXAMPLE\svc-support,true,true') | Out-Null
        New-TestCsv $baramundiCsv @('DeviceName,Principal,PrincipalType,LastInventoryUtc', 'MED-WS-001,EXAMPLE\svc-support,Domain,2026-11-06T08:00:00Z') | Out-Null
        $output = Join-Path $TestDrive 'reports'

        $null = & $scriptPath -ADPrincipalCsv $adCsv -BaramundiLocalAdminCsv $baramundiCsv -ConfigPath $config -OutputDirectory $output -ReferenceTimeUtc ([datetime]'2026-11-06T12:00:00Z')

        $csv = Join-Path $output 'local-admin-exposure-findings.csv'
        $json = Join-Path $output 'local-admin-exposure-summary.json'
        $csv | Should -Exist
        $json | Should -Exist
        (Get-Content -Raw $csv) | Should -Not -Match '(?i)password|secret|token'
        $summary = Get-Content -Raw $json | ConvertFrom-Json
        $summary.Total | Should -Be 1
        $summary.Passed | Should -Be 1
    }
}

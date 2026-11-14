BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-FileShareHardeningAudit.ps1'
    $fixturePath = Join-Path $PSScriptRoot 'testdata'
    $configPath = Join-Path $PSScriptRoot 'config.example.psd1'
}

Describe 'Invoke-FileShareHardeningAudit' {
    It 'passes all four controls for a current hardened server' {
        $result = & $scriptPath `
            -ADServerCsv (Join-Path $fixturePath 'ad-enabled.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-healthy.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc ([datetime]'2026-11-14T15:00:00Z')

        @($result).Count | Should -Be 4
        @($result | Where-Object Status -eq 'Passed').Count | Should -Be 4
        @($result | Where-Object Status -eq 'Failed').Count | Should -Be 0
    }

    It 'flags the legacy protocol as critical when it is enabled' {
        $result = & $scriptPath `
            -ADServerCsv (Join-Path $fixturePath 'ad-enabled.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-legacy.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc ([datetime]'2026-11-14T15:00:00Z')

        $finding = $result | Where-Object Control -eq 'LegacyProtocol'
        $finding.Status | Should -Be 'Failed'
        $finding.Severity | Should -Be 'Critical'
    }

    It 'flags missing inbound SMB signing as high risk' {
        $result = & $scriptPath `
            -ADServerCsv (Join-Path $fixturePath 'ad-enabled.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-no-server-signing.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc ([datetime]'2026-11-14T15:00:00Z')

        $finding = $result | Where-Object Control -eq 'InboundSigning'
        $finding.Status | Should -Be 'Failed'
        $finding.Severity | Should -Be 'High'
    }

    It 'flags missing outbound SMB signing as high risk' {
        $result = & $scriptPath `
            -ADServerCsv (Join-Path $fixturePath 'ad-enabled.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-no-client-signing.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc ([datetime]'2026-11-14T15:00:00Z')

        $finding = $result | Where-Object Control -eq 'OutboundSigning'
        $finding.Status | Should -Be 'Failed'
        $finding.Severity | Should -Be 'High'
    }

    It 'flags insecure guest logons as high risk' {
        $result = & $scriptPath `
            -ADServerCsv (Join-Path $fixturePath 'ad-enabled.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-guest.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc ([datetime]'2026-11-14T15:00:00Z')

        $finding = $result | Where-Object Control -eq 'GuestAccess'
        $finding.Status | Should -Be 'Failed'
        $finding.Severity | Should -Be 'High'
    }

    It 'flags an enabled AD server missing from the Baramundi audit' {
        $result = & $scriptPath `
            -ADServerCsv (Join-Path $fixturePath 'ad-enabled.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-empty.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc ([datetime]'2026-11-14T15:00:00Z')

        @($result).Count | Should -Be 1
        $result.Control | Should -Be 'AuditCoverage'
        $result.Severity | Should -Be 'High'
    }

    It 'uses a stale audit only to report inventory freshness' {
        $result = & $scriptPath `
            -ADServerCsv (Join-Path $fixturePath 'ad-enabled.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-stale.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc ([datetime]'2026-11-14T15:00:00Z')

        @($result).Count | Should -Be 1
        $result.Control | Should -Be 'AuditFreshness'
        $result.Severity | Should -Be 'Medium'
    }

    It 'ignores disabled AD server objects' {
        $result = & $scriptPath `
            -ADServerCsv (Join-Path $fixturePath 'ad-disabled.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-empty.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc ([datetime]'2026-11-14T15:00:00Z')

        @($result).Count | Should -Be 0
    }

    It 'rejects a Baramundi audit with missing required columns' {
        { & $scriptPath `
            -ADServerCsv (Join-Path $fixturePath 'ad-enabled.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-invalid-schema.txt') `
            -ConfigPath $configPath } |
            Should -Throw '*Baramundi SMB audit*missing required column*'
    }

    It 'rejects duplicate audit rows for the same device' {
        { & $scriptPath `
            -ADServerCsv (Join-Path $fixturePath 'ad-enabled.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-duplicate.txt') `
            -ConfigPath $configPath } |
            Should -Throw '*duplicate DeviceName*'
    }

    It 'writes structured CSV and JSON reports without secret fields' {
        $output = Join-Path $TestDrive 'reports'
        $null = & $scriptPath `
            -ADServerCsv (Join-Path $fixturePath 'ad-enabled.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-healthy.txt') `
            -ConfigPath $configPath `
            -OutputDirectory $output `
            -ReferenceTimeUtc ([datetime]'2026-11-14T15:00:00Z')

        $csv = Join-Path $output 'smb-hardening-readiness-findings.csv'
        $json = Join-Path $output 'smb-hardening-readiness-summary.json'
        $csv | Should -Exist
        $json | Should -Exist
        (Get-Content -Raw $csv) | Should -Not -Match '(?i)password|secret|token'
        $summary = Get-Content -Raw $json | ConvertFrom-Json
        $summary.Total | Should -Be 4
        $summary.Passed | Should -Be 4
    }
}

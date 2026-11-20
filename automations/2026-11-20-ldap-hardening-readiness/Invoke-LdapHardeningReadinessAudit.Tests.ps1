BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-LdapHardeningReadinessAudit.ps1'
    $fixturePath = Join-Path $PSScriptRoot 'testdata'
    $configPath = Join-Path $PSScriptRoot 'config.example.psd1'
    $referenceTime = [datetime]'2026-11-20T12:00:00Z'
}

Describe 'Invoke-LdapHardeningReadinessAudit' {
    It 'passes all controls for a current hardened domain controller without compatibility events' {
        $result = & $scriptPath `
            -ADComputerCsv (Join-Path $fixturePath 'ad-enabled-dc.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-hardened.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc $referenceTime

        @($result).Count | Should -Be 4
        @($result | Where-Object Status -eq 'Passed').Count | Should -Be 4
        @($result | Where-Object Status -eq 'Failed').Count | Should -Be 0
    }

    It 'flags disabled signing with observed unsigned binds as critical activity' {
        $result = & $scriptPath `
            -ADComputerCsv (Join-Path $fixturePath 'ad-enabled-dc.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-signing-disabled.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc $referenceTime

        ($result | Where-Object Control -eq 'LdapSigning').Status | Should -Be 'Failed'
        ($result | Where-Object Control -eq 'LdapSigning').Severity | Should -Be 'High'
        ($result | Where-Object Control -eq 'UnsignedBindActivity').Severity | Should -Be 'Critical'
    }

    It 'flags channel binding mode Never as high risk' {
        $result = & $scriptPath `
            -ADComputerCsv (Join-Path $fixturePath 'ad-enabled-dc.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-channel-never.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc $referenceTime

        $finding = $result | Where-Object Control -eq 'ChannelBinding'
        $finding.Status | Should -Be 'Failed'
        $finding.Severity | Should -Be 'High'
    }

    It 'marks WhenSupported without compatibility events as a staged enforcement review' {
        $result = & $scriptPath `
            -ADComputerCsv (Join-Path $fixturePath 'ad-enabled-dc.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-channel-supported.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc $referenceTime

        $finding = $result | Where-Object Control -eq 'ChannelBinding'
        $finding.Status | Should -Be 'Review'
        $finding.Severity | Should -Be 'Low'
    }

    It 'reports channel binding compatibility events for client remediation' {
        $result = & $scriptPath `
            -ADComputerCsv (Join-Path $fixturePath 'ad-enabled-dc.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-channel-events.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc $referenceTime

        $finding = $result | Where-Object Control -eq 'ChannelBindingActivity'
        $finding.Status | Should -Be 'Review'
        $finding.Severity | Should -Be 'Medium'
        $finding.ObservedValue | Should -Be '4'
    }

    It 'flags an enabled domain controller missing from the Baramundi audit' {
        $result = & $scriptPath `
            -ADComputerCsv (Join-Path $fixturePath 'ad-enabled-dc.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-empty.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc $referenceTime

        @($result).Count | Should -Be 1
        $result.Control | Should -Be 'AuditCoverage'
        $result.Severity | Should -Be 'High'
    }

    It 'uses stale evidence only to report audit freshness' {
        $result = & $scriptPath `
            -ADComputerCsv (Join-Path $fixturePath 'ad-enabled-dc.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-stale.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc $referenceTime

        @($result).Count | Should -Be 1
        $result.Control | Should -Be 'AuditFreshness'
        $result.Status | Should -Be 'Review'
    }

    It 'ignores disabled domain controllers and non-domain-controller objects' {
        $result = & $scriptPath `
            -ADComputerCsv (Join-Path $fixturePath 'ad-out-of-scope.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-empty.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc $referenceTime

        @($result).Count | Should -Be 0
    }

    It 'rejects an audit export with missing required columns' {
        { & $scriptPath `
            -ADComputerCsv (Join-Path $fixturePath 'ad-enabled-dc.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-invalid-schema.txt') `
            -ConfigPath $configPath } |
            Should -Throw '*Baramundi LDAP audit*missing required column*'
    }

    It 'rejects duplicate audit rows for the same device case-insensitively' {
        { & $scriptPath `
            -ADComputerCsv (Join-Path $fixturePath 'ad-enabled-dc.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-duplicate.txt') `
            -ConfigPath $configPath } |
            Should -Throw '*duplicate DeviceName*'
    }

    It 'rejects invalid channel binding modes' {
        { & $scriptPath `
            -ADComputerCsv (Join-Path $fixturePath 'ad-enabled-dc.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-invalid-mode.txt') `
            -ConfigPath $configPath `
            -ReferenceTimeUtc $referenceTime } |
            Should -Throw '*ChannelBindingMode*Never, WhenSupported, or Always*'
    }

    It 'writes structured CSV and JSON reports without secret fields' {
        $output = Join-Path $TestDrive 'reports'
        $null = & $scriptPath `
            -ADComputerCsv (Join-Path $fixturePath 'ad-enabled-dc.txt') `
            -BaramundiAuditCsv (Join-Path $fixturePath 'audit-hardened.txt') `
            -ConfigPath $configPath `
            -OutputDirectory $output `
            -ReferenceTimeUtc $referenceTime

        $csv = Join-Path $output 'ldap-hardening-readiness-findings.csv'
        $json = Join-Path $output 'ldap-hardening-readiness-summary.json'
        $csv | Should -Exist
        $json | Should -Exist
        (Get-Content -Raw $csv) | Should -Not -Match '(?i)password|secret|token|patient'
        $summary = Get-Content -Raw $json | ConvertFrom-Json
        $summary.Total | Should -Be 4
        $summary.Passed | Should -Be 4
    }
}

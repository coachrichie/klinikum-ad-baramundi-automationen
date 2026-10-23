BeforeAll {
    $audit = Join-Path $PSScriptRoot 'Invoke-ADBaramundiInventoryAudit.ps1'
    $now = [datetime]'2026-10-23T12:00:00Z'
}

Describe 'AD and baramundi inventory audit' {
    BeforeEach {
        $csv = Join-Path $TestDrive 'inventory.csv'
        'DeviceName,LastSeen', 'LAB-PC01,2026-10-22T12:00:00Z' | Set-Content $csv
        $ad = @([pscustomobject]@{ Name = 'LAB-PC01'; LastLogonDate = $now })
    }
    It 'matches names ignoring case and a trailing dollar sign' {
        # Removing normalization must turn this match into two separate candidates.
        Test-Path -LiteralPath $audit | Should -BeTrue -Because 'the audit implementation must exist'
        $csv = Join-Path $TestDrive 'inventory.csv'
        'DeviceName,LastSeen', 'lab-pc01,2026-10-22T12:00:00Z' | Set-Content $csv
        $ad = @([pscustomobject]@{ Name = 'LAB-PC01$'; LastLogonDate = $now })
        $rows = @(& $audit -BaramundiCsvPath $csv -ADComputers $ad -Now $now)
        $rows.Count | Should -Be 1
        $rows[0].Status | Should -Be 'Matched'
        $rows[0].DeviceName | Should -Be 'LAB-PC01'
    }

    It 'returns an AD-only device with its source membership' {
        $ad = @([pscustomobject]@{ Name = 'LAB-AD'; LastLogonDate = $now })
        $row = & $audit -BaramundiCsvPath $csv -ADComputers $ad -Now $now | Where-Object DeviceName -EQ 'LAB-AD'
        $row.Status | Should -Be 'OnlyInAD'
        $row.InAD | Should -BeTrue
        $row.InBaramundi | Should -BeFalse
    }

    It 'returns a baramundi-only device when AD is explicitly empty' {
        $row = & $audit -BaramundiCsvPath $csv -ADComputers @() -Now $now
        $row.Status | Should -Be 'OnlyInBaramundi'
        $row.InAD | Should -BeFalse
        $row.InBaramundi | Should -BeTrue
    }

    It 'marks an AD device stale only beyond the configured age' {
        $ad[0].LastLogonDate = $now.AddDays(-31)
        (& $audit -BaramundiCsvPath $csv -ADComputers $ad -Now $now -StaleDays 30).Status | Should -Be 'StaleInAD'
        (& $audit -BaramundiCsvPath $csv -ADComputers $ad -Now $now -StaleDays 60).Status | Should -Be 'Matched'
    }

    It 'keeps a device exactly on the cutoff current' {
        $ad[0].LastLogonDate = $now.AddDays(-30)
        (& $audit -BaramundiCsvPath $csv -ADComputers $ad -Now $now -StaleDays 30).Status | Should -Be 'Matched'
    }

    It 'preserves missing AD logon as unknown rather than stale' {
        $ad[0].LastLogonDate = $null
        $row = & $audit -BaramundiCsvPath $csv -ADComputers $ad -Now $now
        $row.Status | Should -Be 'Matched'
        $row.ADLogonState | Should -Be 'Unknown'
    }

    It 'retains source membership when staleness takes precedence' {
        $ad = @([pscustomobject]@{ Name = 'LAB-OLD'; LastLogonDate = $now.AddDays(-100) })
        $row = & $audit -BaramundiCsvPath $csv -ADComputers $ad -Now $now | Where-Object DeviceName -EQ 'LAB-OLD'
        $row.Status | Should -Be 'StaleInAD'
        $row.InBaramundi | Should -BeFalse
    }

    It 'rejects a missing DeviceName column with a structured error' {
        'WrongName,LastSeen', 'LAB-PC01,2026-10-22T12:00:00Z' | Set-Content $csv
        { & $audit -BaramundiCsvPath $csv -ADComputers $ad } | Should -Throw -ErrorId 'InvalidCsvSchema*' -ExpectedMessage '*DeviceName*LastSeen*'
    }

    It 'rejects a missing LastSeen column' {
        'DeviceName', 'LAB-PC01' | Set-Content $csv
        { & $audit -BaramundiCsvPath $csv -ADComputers $ad } | Should -Throw -ErrorId 'InvalidCsvSchema*'
    }

    It 'rejects nonpositive StaleDays <days>' -ForEach @(@{days=0}, @{days=-1}) {
        { & $audit -BaramundiCsvPath $csv -ADComputers $ad -StaleDays $days } | Should -Throw
    }

    It 'does not modify AD inputs or filesystem contents by default' {
        $beforeAD = $ad | ConvertTo-Json -Depth 5
        $beforeHash = (Get-FileHash $csv).Hash
        $beforeFiles = @(Get-ChildItem $TestDrive -Recurse -File).Count
        $rows = @(& $audit -BaramundiCsvPath $csv -ADComputers $ad -Now $now)
        $rows.Count | Should -Be 1
        ($ad | ConvertTo-Json -Depth 5) | Should -Be $beforeAD
        (Get-FileHash $csv).Hash | Should -Be $beforeHash
        @(Get-ChildItem $TestDrive -Recurse -File).Count | Should -Be $beforeFiles
    }

    It 'writes an explicitly requested CSV report and returns objects' {
        $report = Join-Path $TestDrive 'audit.csv'
        $rows = @(& $audit -BaramundiCsvPath $csv -ADComputers $ad -ReportPath $report -Now $now)
        $rows[0].Status | Should -Be 'Matched'
        Test-Path $report | Should -BeTrue
        (Import-Csv $report).Status | Should -Be 'Matched'
    }

    It 'suppresses report creation with WhatIf while returning audit results' {
        $report = Join-Path $TestDrive 'whatif.csv'
        $row = & $audit -BaramundiCsvPath $csv -ADComputers $ad -ReportPath $report -WhatIf -Now $now
        $row.Status | Should -Be 'Matched'
        Test-Path $report | Should -BeFalse
    }

    It 'never overwrites an existing report' {
        $report = Join-Path $TestDrive 'existing.csv'
        'keep this content' | Set-Content $report
        { & $audit -BaramundiCsvPath $csv -ADComputers $ad -ReportPath $report } | Should -Throw -ErrorId 'ReportWriteFailed*'
        Get-Content $report | Should -Be 'keep this content'
    }

    It 'rejects duplicate normalized inventory names' {
        'DeviceName,LastSeen', 'LAB-PC01,2026-10-22T12:00:00Z', 'lab-pc01$,2026-10-20T12:00:00Z' | Set-Content $csv
        { & $audit -BaramundiCsvPath $csv -ADComputers $ad } | Should -Throw -ErrorId 'DuplicateDeviceName*'
    }

    It 'rejects duplicate normalized AD names' {
        $ad = @($ad[0], [pscustomobject]@{ Name='lab-pc01$'; LastLogonDate=$now })
        { & $audit -BaramundiCsvPath $csv -ADComputers $ad } | Should -Throw -ErrorId 'DuplicateDeviceName*'
    }

    It 'rejects malformed inventory dates instead of implying freshness' {
        'DeviceName,LastSeen', 'LAB-PC01,not-a-date' | Set-Content $csv
        { & $audit -BaramundiCsvPath $csv -ADComputers $ad } | Should -Throw -ErrorId 'InvalidLastSeen*'
    }

    It 'retains an empty inventory timestamp as unknown' {
        'DeviceName,LastSeen', 'LAB-PC01,' | Set-Content $csv
        $row = & $audit -BaramundiCsvPath $csv -ADComputers $ad
        $row.BaramundiLastSeen | Should -BeNullOrEmpty
        $row.BaramundiSeenState | Should -Be 'Unknown'
    }

    It 'rejects a header-only inventory to prevent misleading AD-only results' {
        'DeviceName,LastSeen' | Set-Content $csv
        { & $audit -BaramundiCsvPath $csv -ADComputers $ad } | Should -Throw -ErrorId 'EmptyInventory*'
    }

    It 'rejects blank device names' {
        'DeviceName,LastSeen', ',2026-10-22T12:00:00Z' | Set-Content $csv
        { & $audit -BaramundiCsvPath $csv -ADComputers $ad } | Should -Throw -ErrorId 'InvalidDeviceName*'
    }

    It 'reports unreadable CSV input with a structured error' {
        { & $audit -BaramundiCsvPath (Join-Path $TestDrive 'missing.csv') -ADComputers $ad } | Should -Throw -ErrorId 'CsvReadFailed*'
    }
}

Describe 'Live AD boundary without contacting a domain' {
    BeforeAll {
        # The real dependency reads a remote directory; replace only this boundary.
        function Get-ADComputer { param($Filter, $Properties, $SearchBase, $ErrorAction) }
    }
    BeforeEach {
        $csv = Join-Path $TestDrive 'live.csv'
        'DeviceName,LastSeen', 'LAB-PC01,2026-10-22T12:00:00Z' | Set-Content $csv
        Mock Import-Module {} -ParameterFilter { $Name -eq 'ActiveDirectory' }
        Mock Get-ADComputer { [pscustomobject]@{Name='LAB-PC01'; LastLogonDate=[datetime]'2026-10-22T12:00:00Z'} }
    }
    It 'reads AD with only LastLogonDate and passes the requested SearchBase' {
        $row = & $audit -BaramundiCsvPath $csv -SearchBase 'OU=Lab,DC=example,DC=test' -Now $now
        $row.Status | Should -Be 'Matched'
        Should -Invoke Get-ADComputer -Times 1 -Exactly -ParameterFilter {
            $Filter -eq '*' -and @($Properties).Count -eq 1 -and $Properties[0] -eq 'LastLogonDate' -and $SearchBase -eq 'OU=Lab,DC=example,DC=test'
        }
    }
    It 'wraps AD access failures without returning a partial audit' {
        Mock Get-ADComputer { throw 'Directory unavailable' }
        { & $audit -BaramundiCsvPath $csv } | Should -Throw -ErrorId 'ADReadFailed*'
    }
}

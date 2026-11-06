# Audit lokaler Administratorrechte mit AD- und Baramundi-Daten

Dieses Wochenpaket gleicht den dokumentierten AD-Freigabestand mit einer neutralen Inventardatei lokaler Administrator-Mitgliedschaften ab. Es erkennt:

- deaktivierte AD-Konten mit fortbestehenden lokalen Administratorrechten,
- nicht ausdrücklich freigegebene Domänen- und lokale Konten,
- im AD-Export nicht auflösbare Domänenprinzipale,
- veraltete Baramundi-Inventurdaten sowie
- freigegebene Konten mit auffällig großer Geräte-Reichweite.

Das Skript arbeitet ausschließlich lesend. Es entfernt keine Gruppenmitgliedschaften und verändert weder Active Directory noch Endgeräte oder Baramundi.

## Voraussetzungen

- PowerShell 7 oder Windows PowerShell 5.1
- Pester 5 für die Tests
- zwei kontrollierte CSV-Exporte ohne Kennwörter, Tokens oder Patientendaten
- eine geprüfte Kopie von `config.example.psd1`

Es wird bewusst keine undokumentierte Baramundi-API verwendet. Die Inventardaten können aus einer freigegebenen Exportfunktion, einem Report oder einer kontrollierten Inventardaten-Schnittstelle stammen. Die Feldzuordnung wird vor dem Audit auf das neutrale Schema dieses Pakets normalisiert.

## Eingabeschema

### AD-Freigabestand

```text
Principal,Enabled,ApprovedForLocalAdmin
EXAMPLE\svc-support,true,true
EXAMPLE\former-admin,false,false
```

`ApprovedForLocalAdmin` darf nicht automatisch aus einer vorhandenen Gruppenmitgliedschaft abgeleitet werden. Der Wert muss aus einem dokumentierten Rollen-, Ausnahme- oder Freigabeprozess stammen.

### Baramundi-Inventar lokaler Administratoren

```text
DeviceName,Principal,PrincipalType,LastInventoryUtc
MED-WS-001,EXAMPLE\svc-support,Domain,2026-11-06T08:00:00Z
MED-WS-002,MED-WS-002\BreakGlassAdmin,Local,2026-11-06T08:05:00Z
```

Zulässige Werte für `PrincipalType` sind `Domain` und `Local`. Zeitangaben sollten als UTC-Zeitstempel im ISO-8601-Format vorliegen.

## Konfiguration

Kopieren Sie `config.example.psd1` und passen Sie ausschließlich geprüfte Werte an:

- `MaxInventoryAgeDays`: maximale Inventuralterung
- `MaxDevicesPerPrincipal`: Schwelle für die Reichweitenprüfung
- `ApprovedLocalAccounts`: explizite Allowlist lokaler Kontonamen

Die Allowlist ist standardmäßig leer. Ein lokales Konto gilt somit nicht allein wegen seines Namens als zulässig.

## Ausführung

```powershell
./Invoke-LocalAdminExposureAudit.ps1 `
    -ADPrincipalCsv ./input/ad-principals.csv `
    -BaramundiLocalAdminCsv ./input/baramundi-local-admins.csv `
    -ConfigPath ./config.psd1 `
    -OutputDirectory ./reports
```

Das Skript gibt strukturierte Objekte an die Pipeline zurück und schreibt optional:

- `local-admin-exposure-findings.csv`
- `local-admin-exposure-summary.json`

## Sichere Auswertung

1. Inventurfrische prüfen, bevor Rechtebefunde bewertet werden.
2. Kritische Befunde zu deaktivierten Konten priorisieren.
3. Fachliche Notwendigkeit und Systemabhängigkeiten bestätigen.
4. Änderungen nur über einen freigegebenen Prozess mit Rollback und Wartungsfenster umsetzen.
5. Nach einer Änderung erneut inventarisieren und den Audit wiederholen.

Die Automation selbst führt absichtlich keine Zustandsänderung aus. Deshalb sind `SupportsShouldProcess` und `-WhatIf` nicht erforderlich.

## Tests

```powershell
Invoke-Pester ./Invoke-LocalAdminExposureAudit.Tests.ps1 -Output Detailed
```

Die Tests verwenden ausschließlich synthetische Daten unter `TestDrive`.

## Grenzen

- Der Audit beweist nicht, dass jede Inventurquelle vollständig ist.
- Verschachtelte AD-Gruppen müssen vor dem Export fachlich korrekt aufgelöst werden.
- Dienstkonten, Cluster, Altverfahren und Medizinprodukte können begründete Ausnahmen benötigen.
- Ein Befund ist eine Prüfspur, keine automatische Löschfreigabe.

## Quellen

- [baramundi – Guardian Mode und Asset Management im Release 2026](https://www.baramundi.com/de-de/pressemitteilung/guardian-mode-und-asset-management-im-release-der-baramundi-management-suite/)
- [Microsoft – Local accounts](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts)
- [Microsoft – Implementing least-privilege administrative models](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models)
- [EUR-Lex – Richtlinie (EU) 2022/2555, Artikel 21](https://eur-lex.europa.eu/eli/dir/2022/2555/oj/deu)

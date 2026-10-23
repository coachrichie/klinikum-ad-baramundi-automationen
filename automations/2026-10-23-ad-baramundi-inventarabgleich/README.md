# AD × baramundi: Inventarabgleich (2026-10-23)

Dieses reine Audit gleicht AD-Computerobjekte mit einem vorbereiteten baramundi-CSV-Export ab. Die Ausgabe enthält Prüfkandidaten; sie belegt weder Patchstand noch aktuelle Verwaltung. Keine AD-Objekte werden verändert, keine baramundi-Jobs ausgelöst. Standardmäßig entstehen auch keine Dateien.

## Voraussetzungen und Berechtigungen

Windows PowerShell 5.1 oder PowerShell 7; offline getestet mit PowerShell 7.6.5, Windows PowerShell 5.1 und Pester 5.7.1. Für den Live-Abruf sind Windows, RSAT/ActiveDirectory-Modul, Domänenverbindung und Leserechte auf Computerobjekte einschließlich `LastLogonDate` erforderlich. Domain-Admin-Rechte sind nicht erforderlich. Ohne `SearchBase` wird der Standardbereich der AD-Verbindung abgefragt; für den Einstieg eine kleine freigegebene OU angeben. Der baramundi-Export benötigt ausschließlich Inventar-Leserechte, der Audit selbst keinen API-Zugang und keine Zugangsdaten.

CSV-Vertrag: UTF-8, Komma als Trennzeichen, Spalten `DeviceName` und `LastSeen`. Dies ist ein bewusst festgelegtes Eingabeschema, kein garantiertes baramundi-Standardschema. Spalten aus dem lokalen Export gegebenenfalls gezielt umbenennen und das Trennzeichen konvertieren. Zeitstempel: ISO 8601 mit `Z` oder Offset, beispielsweise `2026-10-22T12:00:00Z`; leer bedeutet unbekannt. CSV muss mindestens eine Zeile enthalten. Doppelte normalisierte Namen, leere/ungültige Namen und ungültige Zeitstempel stoppen den Lauf. Namen dürfen Buchstaben, Ziffern, Punkt, Unterstrich und Bindestrich enthalten, beginnen mit Buchstabe/Ziffer und dürfen ein abschließendes `$` haben.

## Aufruf

```powershell
# Im Paketordner; ausschließlich Lesen, Ausgabe als PowerShell-Objekte
.\Invoke-ADBaramundiInventoryAudit.ps1 -BaramundiCsvPath .\Lab.csv `
    -SearchBase 'OU=Lab,DC=example,DC=test' -StaleDays 90

# Konfiguration wird explizit geladen und per Splatting übergeben
$config = Import-PowerShellDataFile .\config.example.psd1
.\Invoke-ADBaramundiInventoryAudit.ps1 @config

# Optionaler Bericht; Elternordner muss existieren, Ziel darf nicht existieren
.\Invoke-ADBaramundiInventoryAudit.ps1 -BaramundiCsvPath .\Lab.csv `
    -ReportPath .\reports\audit-2026-10-23.csv -WhatIf
# Nach Prüfung denselben Aufruf ohne -WhatIf bewusst ausführen.
```

`-WhatIf` unterdrückt ausschließlich das Schreiben des Berichts. Abfragen und Objekt-Ausgabe finden weiter statt. `-Confirm` fragt vor dem Berichtsschreiben nach. Vorhandene Dateien werden auch bei direkter Nutzung von `ReportPath` niemals überschrieben. Strukturierte terminierende Fehler enthalten eine auswertbare `FullyQualifiedErrorId`, zum Beispiel `InvalidCsvSchema`, `DuplicateDeviceName`, `ADReadFailed` oder `ReportWriteFailed`; nach einem Fehler Ergebnisse verwerfen und Ursache prüfen.

## Ergebnisinterpretation

| Status | Bedeutung |
| --- | --- |
| `Matched` | Name in beiden Quellen, kein bekanntes AD-Logon außerhalb der Schwelle. Kein Gesundheits- oder Patchnachweis. |
| `OnlyInAD` | AD-Name fehlt im bereitgestellten Export. Exportfilter und Gerätezuständigkeit prüfen. |
| `OnlyInBaramundi` | Exportname fehlt im gewählten AD-Bereich. Andere OU, Domäne oder Arbeitsgruppe prüfen. |
| `StaleInAD` | Bekannter AD-Logon ist älter als `Now - StaleDays`. Hat Vorrang vor den anderen Statuswerten. |

`InAD` und `InBaramundi` erhalten die Quellenzugehörigkeit auch bei `StaleInAD`. `ADLogonState=Unknown` kennzeichnet fehlende Logonwerte; sie werden nicht automatisch als veraltet eingestuft. `BaramundiSeenState=Unknown` kennzeichnet fehlende Inventarzeit. Inventarzeit wird als `BaramundiLastSeen` ausgegeben, aber bewusst nicht als Patchnachweis oder separater Stale-Status bewertet. Alle Ausgabezeitpunkte verwenden UTC/ISO 8601. `StaleDays` ist ganzzahlig, Standard 90, Bereich 1–36500; der exakte Grenzzeitpunkt gilt noch nicht als veraltet.

## Offline-Labor und Tests

```powershell
$ad = @(
    [pscustomobject]@{ Name='LAB-PC01$'; LastLogonDate=[datetime]'2026-10-22T12:00:00Z' }
    [pscustomobject]@{ Name='LAB-OLD'; LastLogonDate=[datetime]'2026-01-01T12:00:00Z' }
)
.\Invoke-ADBaramundiInventoryAudit.ps1 -BaramundiCsvPath .\Lab.csv `
    -ADComputers $ad -Now ([datetime]'2026-10-23T12:00:00Z')
Invoke-Pester -Path . -Output Detailed
```

`Lab.csv` mit synthetischen Daten vorbereiten:

```csv
DeviceName,LastSeen
lab-pc01,2026-10-22T12:00:00Z
LAB-EXPORT,2026-10-21T12:00:00+00:00
```

Explizites `-ADComputers @()` bedeutet eine leere AD-Quelle und löst keinen Live-Abruf aus. Injizierte Objekte benötigen `Name` und `LastLogonDate` (DateTime oder null). Tests nutzen synthetische Daten im Pester-TestDrive und ersetzen ausschließlich die externe AD-Grenze. Die vollständige Suite vom Repository-Wurzelordner: `Invoke-Pester -Path ./automations -Output Detailed`. Vor Nutzung auch [Laborprüfung](../../docs/lab-validation.md) beachten.

## Grenzen, Datenschutz und Rollback

`LastLogonDate` ist eine lesbare Darstellung von `lastLogonTimestamp`; dessen Aktualisierung ist intervallgesteuert und nicht für Echtzeit-Aktivitätsnachweise geeignet. Replikation, Uhren, Wartungs-/Reservegeräte und fehlende Werte berücksichtigen. Ein aktuelles Inventardatum sagt nichts über erfolgreiche Patches aus. AD-OU und Export müssen denselben gewollten Gerätebestand abdecken. Es erfolgt kein DNS-/FQDN-Abgleich, keine Domänenkürzung und kein Abgleich über Seriennummer oder Hardware-ID; wiederverwendete Namen bleiben eine Grenze. Nicht-domänengebundene Geräte und medizinische Systeme können außerhalb dieser Quellen liegen. Zukünftige Zeitstempel müssen separat auf Uhrfehler geprüft werden.

Gerätenamen und Zeitpunkte sind interne Betriebsdaten, können Personenbezug haben und gehören nicht in das öffentliche Repository. Exporte/Berichte auf freigegebenen lokalen Speicherorten mit beschränkten ACLs halten; Aufbewahrung und Löschung betrieblich festlegen. Keine Patienten- oder Zugangsdaten verwenden. Audit-Dateien sind per `.gitignore` ausgeschlossen; vor jedem Commit trotzdem den Inhalt kontrollieren.

Rollback: Das Audit erzeugt keine Änderungen an Quellsystemen. Ein optionaler Bericht kann nach den lokalen Aufbewahrungsvorgaben entfernt werden. Eine Bereinigung von AD oder Endpoints ist ein eigener, manuell freizugebender Prozess.

## Quellen

- [Microsoft: Get-ADComputer](https://learn.microsoft.com/powershell/module/activedirectory/get-adcomputer?view=windowsserver2025-ps)
- [Microsoft: lastLogonTimestamp](https://learn.microsoft.com/windows/win32/adschema/a-lastlogontimestamp)
- [Microsoft Directory Services: Zweck und Aktualisierung](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/8220-the-lastlogontimestamp-attribute-8221-8211-8220-what-it-was/bc-p/4158907/highlight/true)
- [baramundi Inventory](https://www.baramundi.com/en/products/inventory), [baramundi Connect](https://www.baramundi.com/en/products/interfaces)

# SMB-Hardening-Readiness für lokale AD-Server

Diese audit-only PowerShell-Automation gleicht aktivierte Windows-Server aus einem neutralen AD-Export mit einem über baramundi Inventory einsammelbaren Sicherheitsstatus ab. Sie bewertet Datenabdeckung, Aktualität, ein veraltetes Dateifreigabeprotokoll, eingehende und ausgehende Signaturpflicht sowie nicht authentifizierten Gastzugriff.

Die Automation ändert keine Systeme. Sie nutzt keine undokumentierte baramundi-API und benötigt keine Zugangsdaten. Der Standardbetrieb ist ein reiner Reportlauf.

## Sicherheitsmodell

- Aktivierte AD-Server ohne Inventardatensatz werden als Abdeckungslücke mit hoher Priorität gemeldet.
- Veraltete oder nicht auswertbare Erhebungen werden nur als Aktualitätsproblem bewertet; ihre Kontrollwerte werden nicht für Härtungsentscheidungen verwendet.
- Ein aktiviertes Altprotokoll wird als kritisch eingestuft.
- Fehlende Signaturpflicht und zugelassener Gastzugriff werden als hohe Risiken eingestuft.
- Die Ausgabe enthält nur technische Metadaten und keine Kennwörter, Tokens oder Patientendaten.

Die Befunde sind eine Entscheidungsgrundlage, kein Freibrief für eine sofortige flächendeckende Richtlinienänderung. Vor einer Härtung müssen insbesondere Abhängigkeiten von Medizingeräten, PACS-/Labor-Systemen, NAS-Systemen und Altanwendungen in einer repräsentativen Testgruppe geprüft werden.

## Eingaben

### AD-Server-Export

CSV-Spalten:

```text
ComputerName,Enabled,OperatingSystem
```

Der Export kann beispielsweise aus einer administrativ freigegebenen Abfrage von Computerobjekten erstellt werden. Nur Zeilen mit `Enabled=true` werden bewertet.

### baramundi-Audit-Export

CSV-Spalten:

```text
DeviceName,AuditTimeUtc,LegacyProtocolEnabled,InboundSigningRequired,OutboundSigningRequired,GuestAccessEnabled
```

Die Werte können mit einem freigegebenen PowerShell-Erfassungsskript in baramundi Inventory erhoben und anschließend exportiert werden. Die Feldzuordnung lautet:

- `LegacyProtocolEnabled`: Status der SMBv1-Serverkomponente.
- `InboundSigningRequired`: `Get-SmbServerConfiguration().RequireSecuritySignature`.
- `OutboundSigningRequired`: `Get-SmbClientConfiguration().RequireSecuritySignature`.
- `GuestAccessEnabled`: freigegebene Richtlinie beziehungsweise Clientkonfiguration für unsichere Gastanmeldungen.

Das Repository enthält bewusst kein Remote-Ausführungsskript und keine organisationsspezifische baramundi-Konfiguration.

## Verwendung

```powershell
.\Invoke-FileShareHardeningAudit.ps1 `
    -ADServerCsv .\ad-servers.csv `
    -BaramundiAuditCsv .\baramundi-file-share-audit.csv `
    -ConfigPath .\config.example.psd1 `
    -OutputDirectory .\reports
```

Erzeugte Dateien:

- `smb-hardening-readiness-findings.csv`: Befund je Server und Kontrolle.
- `smb-hardening-readiness-summary.json`: aggregierte Zählwerte für Dashboard oder Pipeline.

## Tests

Voraussetzung: Pester 5.x.

```powershell
Invoke-Pester -Path . -Output Detailed
```

Die Tests decken den sicheren Sollzustand, jede einzelne Abweichung, fehlende und veraltete Inventardaten, deaktivierte AD-Objekte, Schemafehler, Duplikate und die Reportausgabe ab.

## Empfohlener Betriebsablauf

1. AD- und baramundi-Daten in einem administrativ geschützten Arbeitsverzeichnis exportieren.
2. Audit ausführen und zuerst Abdeckungs- sowie Aktualitätslücken schließen.
3. Abhängige Systeme und verantwortliche Anwendungen je Befund zuordnen.
4. Änderungen in einer repräsentativen Pilotgruppe testen und überwachen.
5. Erst danach freigegebene Gruppenrichtlinien oder Konfigurationsjobs stufenweise ausrollen.
6. Wiederanlauf- und Rückfallweg dokumentieren; Audit nach jeder Welle erneut ausführen.

## Primärquellen

- [Microsoft: SMB signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- [Microsoft: SMB security hardening](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening)
- [Microsoft: Detect, enable, and disable SMBv1, SMBv2, and SMBv3](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- [Microsoft: Control SMB client behavior for insecure guest logons](https://learn.microsoft.com/en-us/windows-server/storage/file-server/enable-insecure-guest-logons-smb2-and-smb3)
- [baramundi: Inventory](https://www.baramundi.com/de-de/produkte/inventory/)

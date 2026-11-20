# LDAP-Hardening-Readiness für lokale Active-Directory-Umgebungen

Diese audit-only PowerShell-Automation gleicht aktivierte Domain Controller aus einem neutralen AD-Export mit einem über baramundi Inventory erfassbaren LDAP-Sicherheitsstatus ab. Sie bewertet Datenabdeckung, Aktualität, LDAP-Signaturpflicht, Channel-Binding-Modus und beobachtete Kompatibilitätsereignisse.

Die Automation verändert keine Richtlinien, Registry-Werte oder Domain Controller. Sie nutzt keine undokumentierte baramundi-API und benötigt keine Zugangsdaten. Der Standardbetrieb ist ausschließlich ein Reportlauf.

## Warum Readiness statt sofortiger Erzwingung?

LDAP-Signierung schützt die Integrität von LDAP-Kommunikation. Channel Binding bindet die Authentisierung an den TLS-Kanal und erschwert Relay-Angriffe. Eine ungeprüfte Erzwingung kann jedoch ältere Fachanwendungen, Medizingeräte, Laboranbindungen oder Appliances aussperren.

Das Audit trennt deshalb vier Fragen:

- Wird LDAP-Signierung auf jedem aktivierten Domain Controller erzwungen?
- Ist Channel Binding deaktiviert, im Kompatibilitätsmodus oder vollständig erzwungen?
- Wurden unsichere LDAP-Binds beobachtet?
- Weisen Channel-Binding-Ereignisse auf noch nicht kompatible Clients hin?

## Sicherheitsmodell

- Nur aktivierte Objekte mit `IsDomainController=true` werden bewertet.
- Fehlende Inventardaten werden als Abdeckungslücke mit hoher Priorität gemeldet.
- Veraltete oder nicht auswertbare Erhebungen werden nur als Aktualitätsproblem bewertet; ihre Kontrollwerte fließen nicht in eine Härtungsentscheidung ein.
- `Never` für Channel Binding ist ein fehlgeschlagener Kontrollwert.
- `WhenSupported` wird bei einem Zielwert `Always` bewusst als Review und nicht als sofortiger Fehler behandelt: Erst Ereignisse und Anwendungsabhängigkeiten prüfen, dann pilotieren.
- Beobachtete unsichere Binds werden bei fehlender Signaturpflicht als kritisch eingestuft.
- Die Ausgabe enthält nur technische Metadaten und keine Kennwörter, Tokens oder Patientendaten.

## Eingaben

### AD-Computerexport

Erforderliche CSV-Spalten:

```text
ComputerName,Enabled,OperatingSystem,IsDomainController
```

Der Export kann mit einer administrativ freigegebenen Abfrage der AD-Computerobjekte erzeugt werden. Das Beispiel enthält ausschließlich neutrale Testnamen.

### baramundi-LDAP-Auditexport

Erforderliche CSV-Spalten:

```text
DeviceName,AuditTimeUtc,LdapSigningRequired,ChannelBindingMode,UnsignedBindEvents24h,ChannelBindingEvents7d
```

Die Werte können über eine freigegebene PowerShell-Erkennungsregel in baramundi Inventory erhoben und anschließend exportiert werden. baramundi dokumentiert benutzerdefinierte Erkennungsregeln und die Erfassung spezifischer Werte per PowerShell; dieses Paket verwendet deshalb bewusst einen Export statt einer nicht verifizierten API.

Empfohlene Feldzuordnung:

- `LdapSigningRequired`: effektiver Zustand der serverseitigen LDAP-Signaturpflicht, nicht lediglich das Vorhandensein eines einzelnen Registry-Werts.
- `ChannelBindingMode`: normalisierter effektiver Wert `Never`, `WhenSupported` oder `Always`.
- `UnsignedBindEvents24h`: aggregierter Wert aus dem 24-Stunden-Hinweis zu unsicheren Binds, insbesondere Ereignis 2887. Ereignis 2889 kann zeitlich begrenzt zur Clientidentifikation aktiviert werden.
- `ChannelBindingEvents7d`: aggregierte Channel-Binding-Auditereignisse aus einem dokumentierten Beobachtungsfenster, insbesondere 3039 bis 3041.

Die organisationsspezifische Erfassungsregel gehört in den administrativ kontrollierten baramundi-Prozess und ist nicht Teil dieses öffentlichen Portfolios.

## Verwendung

```powershell
.\Invoke-LdapHardeningReadinessAudit.ps1 `
    -ADComputerCsv .\ad-domain-controllers.csv `
    -BaramundiAuditCsv .\baramundi-ldap-audit.csv `
    -ConfigPath .\config.example.psd1 `
    -OutputDirectory .\reports
```

Erzeugte Dateien:

- `ldap-hardening-readiness-findings.csv`: Befund je Domain Controller und Kontrolle.
- `ldap-hardening-readiness-summary.json`: aggregierte Zählwerte für Review, Dashboard oder Pipeline.

## Konfiguration

`config.example.psd1` enthält sichere, neutrale Standardwerte:

- maximale Inventaralterung von sieben Tagen,
- erforderliche LDAP-Signaturpflicht,
- Zielmodus `Always` für Channel Binding,
- keine tolerierten Ereignisse für unsichere Binds oder Channel-Binding-Kompatibilitätsprobleme.

Der Zielmodus löst keine Änderung aus. `WhenSupported` wird als geplanter Review-Schritt sichtbar gemacht, damit eine Erzwingung erst nach Kompatibilitätsprüfung erfolgt.

## Tests

Voraussetzung: Pester 5.x.

```powershell
Invoke-Pester -Path . -Output Detailed
```

Die Tests decken Sollzustand, fehlende Signaturpflicht, jeden Channel-Binding-Modus, Kompatibilitätsereignisse, fehlende und veraltete Inventardaten, Out-of-Scope-Objekte, Schemafehler, Duplikate, ungültige Werte und strukturierte Reportausgaben ab.

## Empfohlener klinischer Einführungsweg

1. Domain Controller und baramundi-Datensätze vollständig abgleichen.
2. Ereignisse über ein repräsentatives Fenster sammeln; Detailprotokollierung nur zielgerichtet und zeitlich begrenzt aktivieren.
3. Client-IP, Gerät, Anwendung, Hersteller und fachliche Verantwortung zuordnen.
4. Unsichere Bind-Verfahren migrieren und Zertifikats-, Namens- sowie Vertrauensketten für TLS prüfen.
5. LDAP-Signierung und zunächst `WhenSupported` kontrolliert ausrollen.
6. `Always` erst in einer repräsentativen Pilotgruppe testen; Rückfallweg und klinische Funktionsprüfung dokumentieren.
7. Audit nach jeder Welle wiederholen und Ausnahmen mit Eigentümer sowie Ablaufdatum führen.

## Primärquellen

- [Microsoft: LDAP signing overview for Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing)
- [Microsoft: Configure LDAP signing by using Group Policy](https://learn.microsoft.com/en-us/windows-server/identity/manage-ldap-signing-group-policy)
- [Microsoft: LDAP channel binding in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
- [Microsoft: How to enable LDAP signing](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)
- [BSI: APP.2.2 Active Directory Domain Services](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-GS-Kompendium_Einzel_PDFs_2023/06_APP_Anwendungen/APP_2_2_Active_Directory_Domain_Services_Edition_2023.pdf?__blob=publicationFile&v=4)
- [baramundi: Inventory](https://www.baramundi.com/de-de/produkte/inventory/)

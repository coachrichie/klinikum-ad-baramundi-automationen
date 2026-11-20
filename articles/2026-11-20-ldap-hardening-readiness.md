# LDAP absichern, ohne Kliniksysteme auszusperren

**LDAP-Signierung und Channel Binding einfach einzuschalten, ist technisch schnell erledigt. Herauszufinden, welche klinischen Systeme danach nicht mehr authentisieren können, ist die eigentliche Arbeit.**

In gewachsenen Krankenhausumgebungen greifen nicht nur moderne Windows-Clients auf das lokale Active Directory zu. Auch Labor- und PACS-Anbindungen, Appliances, Medizintechnik, Druckdienste und ältere Fachanwendungen können LDAP verwenden. Unsichere oder unverschlüsselte Bind-Verfahren erhöhen das Risiko von Manipulations-, Man-in-the-Middle- und Relay-Angriffen. Eine ungeprüfte Erzwingung kann gleichzeitig einen Versorgungsprozess unterbrechen.

Microsoft verlangt LDAP-Signierung bei neuen Active-Directory-Bereitstellungen ab Windows Server 2025 standardmäßig. Bei Upgrades bleiben vorhandene Richtlinien jedoch erhalten, um Störungen zu vermeiden. Für Channel Binding ist bei neuen Server-2025-Bereitstellungen zunächst `When supported` der Standard; `Always` lehnt nicht kompatible anwendbare Clients ab. Genau deshalb braucht Härtung zuerst Transparenz.

Das BSI formuliert im IT-Grundschutz-Baustein APP.2.2 ebenfalls das Ziel, LDAP-Sitzungen signiert und mit Channel Binding abzusichern.

## Vier Datenpunkte statt eines riskanten Schalters

Für diese Woche habe ich eine audit-only PowerShell-Automation entwickelt. Sie gleicht aktivierte Domain Controller aus einem neutralen AD-Export mit einem über baramundi Inventory erfassbaren Sicherheitsstatus ab:

- Wird LDAP-Signierung effektiv erzwungen?
- Steht Channel Binding auf `Never`, `WhenSupported` oder `Always`?
- Gibt es Ereignisse zu unsicheren LDAP-Binds?
- Gibt es Channel-Binding-Auditereignisse, die auf inkompatible Clients hindeuten?

Die Automation verändert keine Gruppenrichtlinie und keinen Registry-Wert. Sie erzeugt CSV- und JSON-Ergebnisse für technische Reviews, Maßnahmenlisten oder Dashboards.

## Ein sicherer Weg zur Erzwingung

**1. Domain Controller vollständig erfassen**
Jeder aktivierte DC benötigt einen aktuellen Auditdatensatz. Fehlende oder veraltete Daten sind selbst ein Risiko und dürfen nicht als „kein Befund“ gelten.

**2. Ereignisse vor Richtlinienänderungen auswerten**
Ereignis 2887 liefert einen regelmäßigen Hinweis auf zugelassene unsichere Binds. Mit 2889 lassen sich verursachende Clients detaillierter identifizieren; diese Diagnose sollte zielgerichtet und zeitlich begrenzt erfolgen. Channel-Binding-Ereignisse wie 3039 bis 3041 helfen, Kompatibilitätsprobleme vor der Erzwingung sichtbar zu machen.

**3. Technik mit fachlicher Verantwortung verbinden**
Eine IP-Adresse ist noch kein Ansprechpartner. Baramundi-Inventardaten helfen bei der Zuordnung zu Gerät, Betriebssystem und Verwaltungskontext. Ergänzt werden müssen Anwendung, Hersteller, klinischer Prozess und fachlich verantwortliche Stelle.

**4. Client zuerst, Domain Controller danach härten**
Unsichere Simple Binds und nicht signierende Clients werden migriert. Bei TLS gehören Zertifikatsnamen, Vertrauenskette und Sperrprüfung in den Test. Erst wenn die Clients kompatibel sind, wird die serverseitige Signaturpflicht kontrolliert erzwungen.

**5. Channel Binding stufenweise anheben**
Von `Never` führt der sichere Weg zunächst über `WhenSupported`. `Always` gehört in eine repräsentative Pilotgruppe mit Monitoring, klinischer Funktionsprüfung und dokumentiertem Rückfallweg.

**6. Nach jeder Welle erneut messen**
Ein geschlossenes Change-Ticket beweist noch keine Kompatibilität. Konfiguration, Ereigniszähler und klinische Funktion müssen nach jeder Änderung erneut geprüft werden. Verbleibende Ausnahmen brauchen Eigentümer, Begründung und Ablaufdatum.

So wird aus einer riskanten Richtlinienänderung ein kontrollierter Härtungsprozess: messen, zuordnen, migrieren, pilotieren und erneut nachweisen.

**Welche Anwendung oder welches Medizingerät würde in Ihrer Klinik auffallen, wenn unsichere LDAP-Binds morgen konsequent abgelehnt würden?**

#KrankenhausIT #ActiveDirectory #LDAP #WindowsServer #Baramundi #Hardening #Cybersecurity #KRITIS #NIS2 #PowerShell

## Quellen

- [Microsoft: LDAP signing overview for Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing)
- [Microsoft: Configure LDAP signing by using Group Policy](https://learn.microsoft.com/en-us/windows-server/identity/manage-ldap-signing-group-policy)
- [Microsoft: LDAP channel binding in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
- [Microsoft: How to enable LDAP signing](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)
- [BSI: APP.2.2 Active Directory Domain Services](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-GS-Kompendium_Einzel_PDFs_2023/06_APP_Anwendungen/APP_2_2_Active_Directory_Domain_Services_Edition_2023.pdf?__blob=publicationFile&v=4)
- [baramundi: Inventory](https://www.baramundi.com/de-de/produkte/inventory/)

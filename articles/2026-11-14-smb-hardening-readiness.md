# SMB-Hardening: Erst messen, dann erzwingen

Ein Klinikserver kann vollständig gepatcht sein – und trotzdem Dateifreigaben akzeptieren, die nicht zu Ihrem heutigen Schutzbedarf passen.

Gerade in gewachsenen Krankenhausnetzen treffen moderne Windows-Server auf ältere NAS-Systeme, Medizingeräte, Laboranbindungen und Anwendungen mit langen Lebenszyklen. SMB-Signierung einfach flächendeckend zu erzwingen oder SMBv1 spontan abzuschalten, kann deshalb die Sicherheit erhöhen – oder einen bisher unbekannten Versorgungsprozess unterbrechen.

Die richtige Reihenfolge lautet: **Bestand erfassen, Risiken priorisieren, Abhängigkeiten testen, kontrolliert härten.**

Für diese Woche habe ich deshalb eine audit-only PowerShell-Automation entwickelt. Sie gleicht aktivierte Serverobjekte aus dem lokalen Active Directory mit einem über baramundi Inventory einsammelbaren Sicherheitsstatus ab. Bewertet werden:

- Fehlt für einen aktivierten AD-Server ein aktueller Inventardatensatz?
- Ist ein veraltetes Dateifreigabeprotokoll noch aktiv?
- Wird für eingehende SMB-Verbindungen eine Signatur verlangt?
- Wird für ausgehende SMB-Verbindungen eine Signatur verlangt?
- Ist nicht authentifizierter Gastzugriff zugelassen?

Warum diese Kontrollen wichtig sind:

SMB-Signierung schützt die Integrität der Kommunikation und erschwert Manipulations- sowie Relay-Szenarien. SMBv1 ist seit Jahren veraltet und auf modernen Windows-Versionen nicht standardmäßig installiert. Unsichere Gastanmeldungen verzichten auf zentrale Schutzmechanismen wie Authentifizierung und SMB-Signierung. Windows Server 2025 hebt die Standardabsicherung weiter an – gemischte Kliniklandschaften und ältere Systeme brauchen trotzdem eine gemessene Ausgangslage.

Mein Vorgehen für Kliniken:

1. **Abdeckung vor Bewertung:** Erst sicherstellen, dass jeder aktivierte AD-Server einen aktuellen Auditdatensatz besitzt.
2. **Altprotokolle priorisieren:** SMBv1-Funde als kritische technische Schuld behandeln und die konkrete Abhängigkeit benennen.
3. **Signierung getrennt betrachten:** Eingehende und ausgehende Anforderungen separat erfassen; beide Seiten einer Verbindung müssen in die Kompatibilitätsprüfung.
4. **Gastzugriff sichtbar machen:** Geräte ohne authentifizierten Zugriff identifizieren und einen belastbaren Migrationspfad schaffen.
5. **Pilot statt Big Bang:** Repräsentative Server und klinische Workflows testen, Monitoring aktivieren und den Rückfallweg festlegen.
6. **Ergebnis erneut messen:** Nach jeder Härtungswelle denselben Audit ausführen und verbleibende Ausnahmen mit Eigentümer und Frist dokumentieren.

Die Automation ist bewusst defensiv: keine Zugangsdaten, keine Patientendaten, keine undokumentierte baramundi-API und keine Zustandsänderung. Sie erzeugt CSV- und JSON-Ergebnisse, die sich für technische Reviews, Maßnahmenlisten oder ein Dashboard weiterverwenden lassen.

Wie erfassen Sie heute in Ihrer Klinik die tatsächlichen SMB-Abhängigkeiten, bevor Sie strengere Richtlinien ausrollen?

#KrankenhausIT #Cybersecurity #ActiveDirectory #WindowsServer #Baramundi #SMB #Hardening #KRITIS #NIS2 #PowerShell

## Quellen

- [Microsoft: SMB signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- [Microsoft: SMB security hardening](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening)
- [Microsoft: Detect, enable, and disable SMBv1, SMBv2, and SMBv3](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- [Microsoft: Control SMB client behavior for insecure guest logons](https://learn.microsoft.com/en-us/windows-server/storage/file-server/enable-insecure-guest-logons-smb2-and-smb3)
- [baramundi: Inventory](https://www.baramundi.com/de-de/produkte/inventory/)

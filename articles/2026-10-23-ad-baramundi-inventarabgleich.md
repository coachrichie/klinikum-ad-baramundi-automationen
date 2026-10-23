# Im AD vorhanden. Aber wird das Gerät noch verwaltet?

Ein Computerobjekt im Active Directory ist kein Beweis dafür, dass ein Endpunkt aktuell inventarisiert, verwaltet oder gepatcht ist. Genau hier können in der Krankenhaus-IT Blindstellen entstehen.

Mein erster Freitagsbaustein verbindet deshalb zwei Perspektiven: lokale AD-Computerobjekte und einen baramundi-Inventarexport.

Der Abgleich liefert konkrete Prüfkandidaten:

- Nur im AD: Fehlt das Gerät im Endpoint-Management – oder im gewählten Export?
- Nur in baramundi: Gehört es zu einer anderen OU, Domäne oder Arbeitsgruppe?
- Alter AD-Logon: Ist das Gerät Reserve, länger offline oder bereits ausgemustert?
- In beiden Quellen: Zuordnung vorhanden; Patchstand anschließend gesondert prüfen.

So würde ich starten: denselben Geltungsbereich wählen, Exportspalten und Zeitstempel prüfen, Gerätenamen vereinheitlichen und eine fachlich passende Altersschwelle setzen. Anschließend Kandidaten mit den Verantwortlichen klären und Ergebnisse nachvollziehbar dokumentieren.

Das BSI beschreibt im Asset-Inventar-Baustein AM-01 die Anforderungen an Vollständigkeit, Richtigkeit, Aktualität und Konsistenz. Ein Quellenabgleich kann dazu beitragen; er deckt allein nicht alle Assets ab. [BSI, AM-01](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/KRITIS/run_anhang.pdf?__blob=publicationFile&v=6)

Die PowerShell-Automatisierung liest AD und eine CSV. Sie liefert Objekte und auf Wunsch einen lokalen Bericht. Sie deaktiviert, verschiebt oder löscht keine Systeme. Auffälligkeiten sind Kandidaten für eine Prüfung, keine automatische Stilllegung.

Auch die Zeitwerte brauchen Kontext: `LastLogonDate` ist kein Echtzeit-Nachweis; ein Inventarzeitpunkt belegt keinen erfolgreichen Patch. Interne Gerätenamen und Berichte bleiben in geschützten Ablagen.

Das Paket mit Tests und Laboranleitung: [GitHub](https://github.com/coachrichie/klinikum-ad-baramundi-automationen/tree/weekly/2026-10-23-ad-baramundi-inventarabgleich/automations/2026-10-23-ad-baramundi-inventarabgleich).

Welche Blindstellen findet ihr häufiger: Geräte ohne Management oder Inventareinträge ohne klaren Besitzer?

#KrankenhausIT #ActiveDirectory #baramundi #ITInventar #PowerShell #ITSecurity

Weitere Primärquellen: [Microsoft Get-ADComputer](https://learn.microsoft.com/powershell/module/activedirectory/get-adcomputer?view=windowsserver2025-ps), [Microsoft Zeitstempel](https://learn.microsoft.com/windows/win32/adschema/a-lastlogontimestamp), [baramundi Inventory](https://www.baramundi.com/en/products/inventory), [baramundi Connect und Schnittstellen](https://www.baramundi.com/en/products/interfaces).

# Lokale Adminrechte: Wer darf wirklich?

**Ein deaktiviertes AD-Konto ist nicht automatisch von allen Servern und Arbeitsplatzsystemen verschwunden.**

Bleibt es Mitglied einer lokalen Administratorgruppe, existiert die privilegierte Berechtigung auf dem Endgerät weiter – auch wenn das Konto im Active Directory bereits gesperrt wurde. Ebenso kritisch sind lokale Supportkonten, alte Projektgruppen oder Domänenkonten, deren administrative Reichweite niemand mehr belastbar erklären kann.

Gerade in Kliniken ist das mehr als ein Bereinigungsthema. Ein kompromittiertes Administratorkonto kann den Zugriff auf viele Systeme erleichtern und laterale Bewegung begünstigen. Microsoft empfiehlt deshalb, die Zahl der Mitglieder lokaler Administratorgruppen zu begrenzen, administrative Modelle nach dem Minimalprinzip aufzubauen und lokale Konten mit individuellen Kennwörtern abzusichern.

Mit der baramundi Management Suite 2026 adressiert der Hersteller dieses Problem über den Guardian Mode: Lokale Administratorkonten können inventarisiert und unerwünschte Konten verwaltet werden. Der entscheidende Schritt bleibt jedoch der Abgleich mit dem AD und dem eigenen Rollenmodell.

## Drei Datenbestände, eine belastbare Aussage

**1. Ist-Zustand vom Endgerät**

Welche lokalen und Domänenkonten sind tatsächlich Mitglied der lokalen Administratorgruppe? Wie aktuell ist die Inventur?

**2. Kontostatus aus dem lokalen AD**

Existiert das Domänenkonto noch, ist es aktiviert und lässt es sich eindeutig auflösen?

**3. Dokumentierte Freigabe**

Ist genau dieses Konto für genau diese administrative Rolle vorgesehen? Eine vorhandene Mitgliedschaft ist noch keine Genehmigung.

Erst der Abgleich macht Schattenadministratoren sichtbar:

- deaktivierte AD-Konten mit fortbestehender lokaler Berechtigung,
- nicht freigegebene Domänen- oder lokale Konten,
- nicht auflösbare Prinzipale,
- veraltete Inventurdaten und
- Supportkonten mit ungewöhnlich großer Geräte-Reichweite.

## Automatisieren – aber zunächst nur lesen

Die zugehörige PowerShell-Automation verarbeitet einen neutralen AD-Freigabeexport und einen normalisierten Baramundi-Inventarexport. Sie verändert keine Gruppenmitgliedschaften, sondern erzeugt strukturierte Befunde mit Schweregrad, Kontrollziel und Handlungsempfehlung.

Das ist in einer Klinikumgebung der sichere Standard: Erst Datenqualität und Ausnahmen klären, dann Änderungen über einen freigegebenen Prozess mit Wartungsfenster, Rollback und erneuter Inventur umsetzen. Ein automatisch erkannter Befund darf nie allein eine Löschung auslösen – insbesondere nicht bei Diensten, Clustern, Altverfahren oder Medizinprodukten.

## Ein pragmatischer Start

1. Lokale Administrator-Mitgliedschaften über Baramundi inventarisieren.
2. Den AD-Kontostatus und eine explizite Freigabeliste exportieren.
3. Inventurfrische, deaktivierte Konten und unbekannte Prinzipale zuerst prüfen.
4. Reichweite privilegierter Konten gegen Rollenmodell und Systemzonen bewerten.
5. Bereinigungen kontrolliert durchführen und anschließend erneut inventarisieren.

Die wichtigste Frage lautet nicht: **„Wer steht heute in der Gruppe?“**

Sondern: **„Wer benötigt dieses Recht noch – auf genau diesem System und für genau diese Aufgabe?“**

Könnte Ihre Klinik heute für jedes lokale Administratorkonto innerhalb einer Stunde Kontostatus, fachliche Freigabe und betroffene Systeme belegen?

#KrankenhausIT #ActiveDirectory #Baramundi #WindowsServer #Hardening #LeastPrivilege #Cybersecurity #KRITIS #NIS2 #PowerShell

## Quellen

- [baramundi – Guardian Mode und Asset Management im Release 2026](https://www.baramundi.com/de-de/pressemitteilung/guardian-mode-und-asset-management-im-release-der-baramundi-management-suite/)
- [Microsoft – Local accounts](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts)
- [Microsoft – Implementing least-privilege administrative models](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models)
- [EUR-Lex – Richtlinie (EU) 2022/2555, Artikel 21](https://eur-lex.europa.eu/eli/dir/2022/2555/oj/deu)

*Fachbeitrag, keine Rechtsberatung. Maßnahmen müssen anhand der konkreten Schutzbedarfe, Betriebsabhängigkeiten und Freigabeprozesse der jeweiligen Einrichtung validiert werden.*

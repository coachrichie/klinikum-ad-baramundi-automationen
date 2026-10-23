# Sicherheitsmodell

Audit-Pakete lesen ausschließlich freigegebene Datenquellen. Sie deaktivieren, verschieben oder löschen keine AD-Objekte und starten keine Endpoint-Jobs. Ein optionaler lokaler Bericht ist die einzige ausdrücklich angeforderte Ausgabe auf dem Dateisystem; vorhandene Dateien dürfen nicht überschrieben werden.

Ein Treffer ist ein Prüfkandidat, kein Nachweis eines Sicherheitsvorfalls, eines aktuellen Patchstands oder einer Stilllegungsfreigabe. Namensabgleich ist keine stabile Geräteidentität. Veraltete, unvollständige oder unterschiedlich abgegrenzte Quellen können Fehlalarme erzeugen.

Ausführen mit minimalen Leserechten auf die relevanten AD-Attribute und den Export. Keine Domain-Admin-Rechte erforderlich. Daten lokal mit passenden ACLs und Aufbewahrungsfristen schützen; Berichte enthalten interne Gerätenamen. Niemals reale Daten in dieses öffentliche Repository übertragen.

Rollback: Ein reines Audit verändert keine Quellsysteme. Nur selbst erzeugte Berichte können nach den lokalen Vorgaben entfernt werden.

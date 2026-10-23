# Laborprüfung

1. Skript und Dokumentation prüfen; ausschließlich synthetische Daten oder ein freigegebenes isoliertes AD-Labor verwenden.
2. Pester 5 im aktuellen Benutzerprofil bereitstellen und `Invoke-Pester -Path ./automations -Output Detailed` ausführen.
3. Alle PowerShell-Dateien mit `System.Management.Automation.Language.Parser.ParseFile` auf Syntaxfehler prüfen.
4. Zunächst injizierte AD-Daten, anschließend bei Bedarf eine kleine Labor-OU mit RSAT/ActiveDirectory-Modul und reinen Leserechten verwenden.
5. Export-Schema, identischen Geltungsbereich, Zeitstempel, Zeitzonen, fehlende Werte und doppelte Namen prüfen.
6. Optionalen Bericht mit `-WhatIf` prüfen; dann bewusst einen neuen Zielpfad auswählen. Keine realen Exporte oder Berichte committen.

Offline-Tests ersetzen keine Integration mit einer realen AD-Domäne und einem versionsspezifischen baramundi-Export. Labornachweise und betriebliche Freigaben sind vor einem produktiven Einsatz separat erforderlich.

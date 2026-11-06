@{
    # Inventurdaten, die älter sind, werden nicht als belastbarer Ist-Zustand gewertet.
    MaxInventoryAgeDays = 7

    # Auffälligkeitsschwelle für ein freigegebenes AD-Konto mit lokaler Adminrolle.
    MaxDevicesPerPrincipal = 5

    # Keine impliziten Freigaben: lokale Konten müssen hier ausdrücklich benannt werden.
    ApprovedLocalAccounts = @(
        'BreakGlassAdmin'
    )
}

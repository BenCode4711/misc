# FocusSpy

Kleines Windows-Tool, das live protokolliert, welcher Prozess bzw. welches Fenster den Vordergrund-Fokus übernimmt.
Gedacht zur Fehlersuche, wenn das aktive Programm immer wieder kurz den Fokus verliert (Flackern, „Fokus-Diebe“).

## Start

1. `FocusSpy.ps1` und `FocusSpy.bat` in denselben Ordner legen.
2. Doppelklick auf `FocusSpy.bat` (startet mit Administratorrechten für vollständige Prozessinfos).

Alternativ direkt in PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\FocusSpy.ps1 -SchwelleMs 3000
```

## Funktionen

- Jede Fokusänderung mit Zeit (ms), Prozess, PID, Fenstertitel und Fensterklasse
- **VERDACHT** (rot): Muster A → B (kurz) → A; B wird mit Pfad und Elternprozess gezählt
- Gelb = unsichtbares Fenster / ohne Titel, Lila = gar kein Fenster im Vordergrund
- Tasten: `M` Markierung setzen, `S` Zusammenfassung, `Q`/`ESC` beenden
- Vollständiges Protokoll als CSV (Excel-tauglich) neben dem Skript

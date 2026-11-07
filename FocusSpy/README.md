# FocusSpy 2

Windows-Tool zur Fehlersuche bei Fokusverlust, Hängern und Flackern, speziell auf Laptops mit Hybrid-Grafik
(z. B. AMD-iGPU + NVIDIA-dGPU). Es misst live, welches Programm den Fokus übernimmt, ob das Programm im
Vordergrund hängt, und was die Grafikkarten in diesem Moment tun.

## Start

1. `FocusSpy.ps1` und `FocusSpy.bat` in denselben Ordner legen.
2. Doppelklick auf `FocusSpy.bat` (startet mit Administratorrechten).

Alternativ direkt in PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\FocusSpy.ps1 -SchwelleMs 3000 -StockenMs 200
```

## Was gemessen wird

| Ereignis | Bedeutung |
|---|---|
| `FOKUS` | Wechsel des Vordergrundfensters (Prozess, Titel, Klasse, Sichtbarkeit) |
| `GHOST(x.exe)` | Windows hat das Fenster von x.exe durch ein Ghost-Fenster von dwm.exe ersetzt, weil x.exe nicht reagiert |
| `VERDACHT` | Fokus-Dieb: A → kurz B → A |
| `STOCKEN` / `HÄNGER` | Das Vordergrundfenster antwortet langsamer als `-StockenMs` (Hänger: ≥ 1 s oder von Windows als „reagiert nicht“ erkannt) |
| `FLACKERN` | ≥ 6 Fokuswechsel innerhalb von 1 s; am Ende gibt es eine Auswertung mit Beteiligten, Hängern und GPU-Zustand |
| `GPU_ZUSTAND` | Energiezustand einer Grafikkarte wechselt (D0 = aktiv, D3 = schlafend) |
| `GPU_NUTZUNG` | Auf welcher Grafikkarte das Vordergrundprogramm rendert (3D) bzw. Daten kopiert (Copy); wird bei Änderung gemeldet |

Bei jedem Hänger und jeder Flacker-Phase wird automatisch geprüft, ob innerhalb von ±2 s ein GPU-Zustandswechsel stattfand.

## Tasten

`M` Markierung setzen · `S` Zusammenfassung · `G` aktueller GPU-Status · `Q`/`ESC` Beenden

## Ausgabe

- `FocusSpy_<Datum>.csv`: alle Ereignisse
- `FocusSpy_<Datum>_GPU.csv`: einmal pro Sekunde je Grafikkarte die Werte Zustand, Last (3D/Copy/Video/Compute) und Last des Vordergrundprogramms; gut für Diagramme in Excel

## Hinweise zur Auswertung

- Viel **Copy**-Last auf der iGPU, während das Programm auf der dGPU rendert, bedeutet, dass jedes Bild von der dGPU zum internen Display
  (das an der iGPU hängt) kopiert wird. Das ist eine typische Quelle für Stocken bei Hybrid-Grafik.
- Häufige Wechsel **D3 → D0** der dGPU kurz vor einem Hänger deuten auf Probleme beim Aufwecken der dGPU hin.

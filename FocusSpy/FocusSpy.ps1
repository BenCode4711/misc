<#
  FocusSpy - protokolliert live, welcher Prozess/welches Fenster den Vordergrund-Fokus übernimmt.

  Erkennt automatisch "Fokus-Diebe": Fenster A -> kurz Fenster B -> wieder A.
  B wird dann rot als VERDACHT markiert und gezählt.

  Tasten während der Laufzeit:
    M  = Markierung setzen ("jetzt hat es geflackert")
    S  = Zusammenfassung der bisherigen Verdächtigen anzeigen
    Q / ESC = Beenden (mit Zusammenfassung)

  Alles wird zusätzlich in eine CSV-Datei neben dem Skript geschrieben (Excel-tauglich).

  Parameter:
    -SchwelleMs  Wie kurz (ms) ein Fensterwechsel sein darf, um als "Fokus-Diebstahl" zu gelten. Standard 3000.
    -LogDatei    Pfad der CSV-Datei. Standard: FocusSpy_<Datum>.csv im Skriptordner.
#>
param(
    [int]$SchwelleMs = 3000,
    [string]$LogDatei = ""
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

if (-not $LogDatei) {
    $LogDatei = Join-Path $PSScriptRoot ("FocusSpy_{0:yyyy-MM-dd_HH-mm-ss}.csv" -f (Get-Date))
}

$code = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public class FsProcInfo {
    public string Name = "?";
    public string Path = "";
    public uint ParentPid = 0;
    public string ParentName = "";
    public string CmdLine = "";
}

public static class FocusSpy {
    delegate void WinEventDelegate(IntPtr hHook, uint ev, IntPtr hwnd, int idObject, int idChild, uint thread, uint time);

    [StructLayout(LayoutKind.Sequential)]
    struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public int x; public int y; public uint priv; }
    [StructLayout(LayoutKind.Sequential)]
    struct RECT { public int L, T, R, B; }

    [DllImport("user32.dll")] static extern IntPtr SetWinEventHook(uint min, uint max, IntPtr hmod, WinEventDelegate cb, uint pid, uint tid, uint flags);
    [DllImport("user32.dll")] static extern bool UnhookWinEvent(IntPtr h);
    [DllImport("user32.dll")] static extern bool PeekMessage(out MSG m, IntPtr h, uint a, uint b, uint remove);
    [DllImport("user32.dll")] static extern bool TranslateMessage(ref MSG m);
    [DllImport("user32.dll")] static extern IntPtr DispatchMessage(ref MSG m);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder sb, ref int size);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    const uint EVENT_SYSTEM_FOREGROUND = 0x0003;
    const uint EVENT_SYSTEM_MINIMIZESTART = 0x0016;
    const uint EVENT_SYSTEM_MINIMIZEEND = 0x0017;
    const uint WINEVENT_OUTOFCONTEXT = 0x0000;
    const uint WINEVENT_SKIPOWNPROCESS = 0x0002;
    const uint PM_REMOVE = 0x0001;

    class Entry {
        public IntPtr Hwnd; public uint Pid; public FsProcInfo Proc;
        public string Title; public string Cls; public bool Visible; public string Size;
        public DateTime Start;
    }

    static WinEventDelegate _cb = new WinEventDelegate(OnEvent); // muss am Leben bleiben (GC)
    static Dictionary<uint, FsProcInfo> _cache = new Dictionary<uint, FsProcInfo>();
    static List<Entry> _hist = new List<Entry>();
    static Dictionary<string, int> _thiefCount = new Dictionary<string, int>();
    static Dictionary<string, string> _thiefDetail = new Dictionary<string, string>();
    static StreamWriter _csv;
    static int _thresholdMs = 3000;
    static int _focusEvents = 0, _suspects = 0, _markers = 0;
    static DateTime _startTime;

    public static void Run(string csvPath, int thresholdMs) {
        _thresholdMs = thresholdMs;
        _startTime = DateTime.Now;
        _csv = new StreamWriter(csvPath, false, new UTF8Encoding(true));
        _csv.AutoFlush = true;
        _csv.WriteLine("Zeit;Ereignis;Dauer_vorher_ms;PID;Prozess;Pfad;Parent_PID;Parent;Fenstertitel;Fensterklasse;Sichtbar;Fenstergroesse;Verdacht;Kommandozeile");

        uint flags = WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS;
        IntPtr h1 = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, IntPtr.Zero, _cb, 0, 0, flags);
        IntPtr h2 = SetWinEventHook(EVENT_SYSTEM_MINIMIZESTART, EVENT_SYSTEM_MINIMIZEEND, IntPtr.Zero, _cb, 0, 0, flags);
        if (h1 == IntPtr.Zero) { Console.WriteLine("FEHLER: SetWinEventHook fehlgeschlagen."); return; }

        HandleForeground(GetForegroundWindow(), DateTime.Now, "START");

        bool quit = false;
        while (!quit) {
            MSG msg;
            while (PeekMessage(out msg, IntPtr.Zero, 0, 0, PM_REMOVE)) { TranslateMessage(ref msg); DispatchMessage(ref msg); }
            try {
                while (Console.KeyAvailable) {
                    ConsoleKeyInfo k = Console.ReadKey(true);
                    if (k.Key == ConsoleKey.Q || k.Key == ConsoleKey.Escape) quit = true;
                    else if (k.Key == ConsoleKey.S) PrintSummary();
                    else if (k.Key == ConsoleKey.M) Marker();
                }
            } catch (InvalidOperationException) { }
            Thread.Sleep(10);
        }

        UnhookWinEvent(h1);
        if (h2 != IntPtr.Zero) UnhookWinEvent(h2);
        PrintSummary();
        _csv.Close();
    }

    static void OnEvent(IntPtr hHook, uint ev, IntPtr hwnd, int idObject, int idChild, uint thread, uint time) {
        try {
            if (idObject != 0) return; // nur OBJID_WINDOW
            // exakter Zeitpunkt aus dem Event-Zeitstempel (GetTickCount-Basis)
            uint now = (uint)Environment.TickCount;
            long ago = (long)(uint)(now - time);
            if (ago < 0 || ago > 60000) ago = 0;
            DateTime t = DateTime.Now.AddMilliseconds(-ago);

            if (ev == EVENT_SYSTEM_FOREGROUND) HandleForeground(hwnd, t, "FOKUS");
            else if (ev == EVENT_SYSTEM_MINIMIZESTART) HandleSimple(hwnd, t, "MINIMIERT");
            else if (ev == EVENT_SYSTEM_MINIMIZEEND) HandleSimple(hwnd, t, "WIEDERHERGESTELLT");
        } catch (Exception ex) {
            Console.WriteLine("  (Fehler im Event-Handler: " + ex.Message + ")");
        }
    }

    static Entry Describe(IntPtr hwnd, DateTime t) {
        Entry e = new Entry();
        e.Hwnd = hwnd; e.Start = t; e.Title = ""; e.Cls = ""; e.Size = "";
        uint pid = 0;
        if (hwnd != IntPtr.Zero) {
            GetWindowThreadProcessId(hwnd, out pid);
            StringBuilder sb = new StringBuilder(512);
            GetWindowText(hwnd, sb, sb.Capacity); e.Title = sb.ToString();
            sb.Clear();
            GetClassName(hwnd, sb, sb.Capacity); e.Cls = sb.ToString();
            e.Visible = IsWindowVisible(hwnd);
            RECT r;
            if (GetWindowRect(hwnd, out r)) e.Size = string.Format("{0}x{1}@{2},{3}", r.R - r.L, r.B - r.T, r.L, r.T);
        }
        e.Pid = pid;
        e.Proc = GetProc(pid);
        return e;
    }

    static void HandleSimple(IntPtr hwnd, DateTime t, string kind) {
        Entry e = Describe(hwnd, t);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("{0:HH:mm:ss.fff}  {1,-17} {2} ({3})  \"{4}\"", t, kind, e.Proc.Name, e.Pid, Trunc(e.Title, 50));
        Console.ResetColor();
        WriteCsv(t, kind, "", e, "");
    }

    static void HandleForeground(IntPtr hwnd, DateTime t, string kind) {
        if (_hist.Count > 0 && _hist[_hist.Count - 1].Hwnd == hwnd) return; // keine echte Änderung
        Entry e = Describe(hwnd, t);
        _focusEvents++;

        string durStr = "";
        string suspect = "";
        Entry prev = _hist.Count > 0 ? _hist[_hist.Count - 1] : null;
        if (prev != null) {
            double dur = (t - prev.Start).TotalMilliseconds;
            if (dur < 0) dur = 0;
            durStr = ((long)dur).ToString();

            // Muster: A -> B (kurz) -> A  => B ist Verdächtiger
            if (_hist.Count >= 2) {
                Entry a = _hist[_hist.Count - 2];
                if (a.Pid == e.Pid && prev.Pid != e.Pid && dur < _thresholdMs) {
                    suspect = prev.Proc.Name;
                    _suspects++;
                    int c; _thiefCount.TryGetValue(suspect, out c); _thiefCount[suspect] = c + 1;
                    _thiefDetail[suspect] = string.Format("PID {0}, Klasse '{1}', Titel '{2}', sichtbar={3}, {4}, Pfad {5}, Parent {6} ({7})",
                        prev.Pid, prev.Cls, Trunc(prev.Title, 40), prev.Visible, prev.Size, prev.Proc.Path, prev.Proc.ParentName, prev.Proc.ParentPid);
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("  >>> VERDACHT #{0}: {1} (PID {2}) hatte den Fokus nur {3} ms  [Klasse '{4}', sichtbar={5}, {6}]  -> bisher {7}x",
                        _suspects, prev.Proc.Name, prev.Pid, (long)dur, prev.Cls, prev.Visible, prev.Size, _thiefCount[suspect]);
                    if (prev.Proc.Path != "") Console.WriteLine("      Pfad:   " + prev.Proc.Path);
                    if (prev.Proc.ParentName != "") Console.WriteLine("      Parent: " + prev.Proc.ParentName + " (PID " + prev.Proc.ParentPid + ")");
                    Console.ResetColor();
                    WriteCsv(t, "VERDACHT", durStr, prev, suspect);
                }
            }
        }

        // Ausgabe der Fokusänderung
        bool odd = hwnd == IntPtr.Zero || !e.Visible || e.Title == "";
        Console.ForegroundColor = hwnd == IntPtr.Zero ? ConsoleColor.Magenta : (odd ? ConsoleColor.Yellow : ConsoleColor.Gray);
        string flags = "";
        if (hwnd == IntPtr.Zero) flags = " [KEIN FENSTER]";
        else {
            if (!e.Visible) flags += " [UNSICHTBAR]";
            if (e.Title == "") flags += " [OHNE TITEL]";
        }
        Console.WriteLine("{0:HH:mm:ss.fff}  {1,-6} vorher {2,7} ms -> {3} ({4})  \"{5}\"  [{6}]{7}",
            t, kind, durStr == "" ? "-" : durStr, e.Proc.Name, e.Pid, Trunc(e.Title, 45), e.Cls, flags);
        Console.ResetColor();
        WriteCsv(t, kind, durStr, e, "");

        _hist.Add(e);
        if (_hist.Count > 20) _hist.RemoveAt(0);
    }

    static void Marker() {
        _markers++;
        DateTime t = DateTime.Now;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("{0:HH:mm:ss.fff}  ======== MARKIERUNG #{1} (Glitch gesehen) ========", t, _markers);
        Console.ResetColor();
        _csv.WriteLine(Q(t.ToString("yyyy-MM-dd HH:mm:ss.fff")) + ";" + Q("MARKIERUNG #" + _markers) + ";;;;;;;;;;;;");
    }

    static void PrintSummary() {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine("================ ZUSAMMENFASSUNG ================");
        Console.WriteLine("Laufzeit: {0:hh\\:mm\\:ss}   Fokuswechsel: {1}   Verdachtsfälle: {2}   Markierungen: {3}",
            DateTime.Now - _startTime, _focusEvents, _suspects, _markers);
        if (_thiefCount.Count == 0) {
            Console.WriteLine("Noch keine Fokus-Diebe erkannt.");
        } else {
            List<KeyValuePair<string, int>> list = new List<KeyValuePair<string, int>>(_thiefCount);
            list.Sort(delegate (KeyValuePair<string, int> x, KeyValuePair<string, int> y) { return y.Value.CompareTo(x.Value); });
            foreach (KeyValuePair<string, int> kv in list) {
                Console.WriteLine("  {0,4}x  {1}", kv.Value, kv.Key);
                Console.WriteLine("         zuletzt: " + _thiefDetail[kv.Key]);
            }
        }
        Console.WriteLine("=================================================");
        Console.WriteLine();
        Console.ResetColor();
    }

    static FsProcInfo GetProc(uint pid) {
        FsProcInfo pi;
        if (_cache.TryGetValue(pid, out pi)) return pi;
        pi = new FsProcInfo();
        if (pid == 0) { pi.Name = "<kein Fenster>"; return pi; }

        try { pi.Name = Process.GetProcessById((int)pid).ProcessName + ".exe"; }
        catch { pi.Name = "<Prozess bereits beendet>"; }

        IntPtr h = OpenProcess(0x1000 /* QUERY_LIMITED_INFORMATION */, false, pid);
        if (h != IntPtr.Zero) {
            StringBuilder sb = new StringBuilder(1024);
            int size = sb.Capacity;
            if (QueryFullProcessImageName(h, 0, sb, ref size)) pi.Path = sb.ToString();
            CloseHandle(h);
        }

        try {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                "SELECT ParentProcessId, CommandLine FROM Win32_Process WHERE ProcessId=" + pid)) {
                foreach (ManagementObject o in s.Get()) {
                    if (o["ParentProcessId"] != null) pi.ParentPid = Convert.ToUInt32(o["ParentProcessId"]);
                    if (o["CommandLine"] != null) pi.CmdLine = o["CommandLine"].ToString();
                }
            }
            if (pi.ParentPid != 0) {
                try { pi.ParentName = Process.GetProcessById((int)pi.ParentPid).ProcessName + ".exe"; }
                catch { pi.ParentName = "<beendet>"; }
            }
        } catch { }

        // beendete Prozesse nicht cachen (PID könnte wiederverwendet werden)
        if (pi.Name != "<Prozess bereits beendet>") _cache[pid] = pi;
        return pi;
    }

    static void WriteCsv(DateTime t, string kind, string dur, Entry e, string suspect) {
        string[] f = new string[] {
            t.ToString("yyyy-MM-dd HH:mm:ss.fff"), kind, dur, e.Pid.ToString(), e.Proc.Name, e.Proc.Path,
            e.Proc.ParentPid.ToString(), e.Proc.ParentName, e.Title, e.Cls, e.Visible ? "ja" : "nein", e.Size, suspect, e.Proc.CmdLine
        };
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < f.Length; i++) { if (i > 0) sb.Append(';'); sb.Append(Q(f[i])); }
        _csv.WriteLine(sb.ToString());
    }

    static string Q(string s) {
        if (s == null) s = "";
        return "\"" + s.Replace("\"", "\"\"").Replace("\r", " ").Replace("\n", " ") + "\"";
    }

    static string Trunc(string s, int n) {
        if (s == null) return "";
        return s.Length <= n ? s : s.Substring(0, n - 1) + "…";
    }
}
'@

if (-not ('FocusSpy' -as [type])) {
    Add-Type -TypeDefinition $code -ReferencedAssemblies System.Management
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host ""
Write-Host "  FocusSpy - Live-Überwachung des Vordergrund-Fokus" -ForegroundColor Cyan
Write-Host "  -------------------------------------------------"
Write-Host "  Log:       $LogDatei"
Write-Host "  Schwelle:  Fokuswechsel A -> B -> A mit B < $SchwelleMs ms = VERDACHT"
Write-Host "  Tasten:    [M] Markierung   [S] Zusammenfassung   [Q]/[ESC] Beenden"
if (-not $isAdmin) {
    Write-Host "  Hinweis:   Nicht als Administrator gestartet - Pfad/Kommandozeile von Systemprozessen evtl. unvollständig." -ForegroundColor Yellow
}
Write-Host "  Farben:    grau = normal, gelb = unsichtbar/ohne Titel, lila = kein Fenster, rot = Verdacht"
Write-Host ""

[FocusSpy]::Run($LogDatei, $SchwelleMs)

Write-Host "Log gespeichert: $LogDatei" -ForegroundColor Green

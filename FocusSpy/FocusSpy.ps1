﻿<#
  FocusSpy 2 - Fokus-, Hänger- und GPU-Überwachung für Hybrid-Grafik-Laptops

  Protokolliert live:
    * jeden Wechsel des Vordergrundfensters (inkl. Ghost-Fenster von dwm.exe -> echter Besitzer)
    * Fokus-Diebe (A -> kurz B -> A)
    * UI-Hänger/Stocken des Vordergrundprogramms (gemessen per Ping an das Fenster)
    * Flacker-Phasen (viele Fokuswechsel in kurzer Zeit)
    * Energiezustand jeder Grafikkarte (D0 = aktiv, D3 = schlafend) und jeden Wechsel
    * GPU-Last pro Grafikkarte und pro Prozess (3D, Copy, Video, Compute)
  und setzt Hänger/Flackern automatisch in Bezug zu GPU-Zustandswechseln.

  Tasten:  M = Markierung   S = Zusammenfassung   G = GPU-Status   Q/ESC = Beenden

  Parameter:
    -SchwelleMs  Max. Dauer (ms) eines Fokuswechsels A->B->A, damit B als Verdacht gilt. Standard 3000.
    -StockenMs   Ab welcher Antwortzeit (ms) des Vordergrundfensters ein "Stocken" protokolliert wird. Standard 200.
    -LogDatei    Pfad der CSV-Datei. Standard: FocusSpy_<Datum>.csv im Skriptordner.
                 GPU-Messwerte (1x pro Sekunde) landen in <LogDatei>_GPU.csv.
#>
param(
    [int]$SchwelleMs = 3000,
    [int]$StockenMs = 200,
    [string]$LogDatei = ""
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

if (-not $LogDatei) {
    $LogDatei = Join-Path $PSScriptRoot ("FocusSpy_{0:yyyy-MM-dd_HH-mm-ss}.csv" -f (Get-Date))
}
$GpuLogDatei = [System.IO.Path]::ChangeExtension($LogDatei, $null).TrimEnd('.') + "_GPU.csv"

$code = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

public class FsProcInfo {
    public string Name = "?";
    public string Path = "";
    public uint ParentPid = 0;
    public string ParentName = "";
    public string CmdLine = "";
}

public class FsAdapter {
    public string Name = "";
    public string Short = "";
    public uint VendorId = 0;
    public string Luid = "";      // Format wie in den Leistungsindikatoren: 0X00000000_0X0000D1A2
    public int DevIndex = -1;     // Index in der SetupAPI-Geräteliste
    public volatile int Power = 0;   // 1=D0 ... 4=D3, 0=unbekannt
    public int Transitions = 0;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct FsDxgiAdapterDesc1 {
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Description;
    public uint VendorId;
    public uint DeviceId;
    public uint SubSysId;
    public uint Revision;
    public UIntPtr DedicatedVideoMemory;
    public UIntPtr DedicatedSystemMemory;
    public UIntPtr SharedSystemMemory;
    public uint LuidLow;
    public int LuidHigh;
    public uint Flags;
}

[ComImport, Guid("29038f61-3839-4626-91fd-086879011a05"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IFsDxgiAdapter1 {
    void _SetPrivateData(); void _SetPrivateDataInterface(); void _GetPrivateData(); void _GetParent();
    void _EnumOutputs(); void _GetDesc(); void _CheckInterfaceSupport();
    [PreserveSig] int GetDesc1(out FsDxgiAdapterDesc1 desc);
}

[ComImport, Guid("770aae78-f26f-4dba-a829-253c83d1b387"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IFsDxgiFactory1 {
    void _SetPrivateData(); void _SetPrivateDataInterface(); void _GetPrivateData(); void _GetParent();
    void _EnumAdapters(); void _MakeWindowAssociation(); void _GetWindowAssociation(); void _CreateSwapChain(); void _CreateSoftwareAdapter();
    [PreserveSig] int EnumAdapters1(uint index, out IFsDxgiAdapter1 adapter);
}

public static class FocusSpy {
    // ------------------------------------------------------------------ Win32
    delegate void WinEventDelegate(IntPtr hHook, uint ev, IntPtr hwnd, int idObject, int idChild, uint thread, uint time);

    [StructLayout(LayoutKind.Sequential)]
    struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public int x; public int y; public uint priv; }
    [StructLayout(LayoutKind.Sequential)]
    struct RECT { public int L, T, R, B; }
    [StructLayout(LayoutKind.Sequential)]
    struct SP_DEVINFO_DATA { public uint cbSize; public Guid ClassGuid; public uint DevInst; public IntPtr Reserved; }
    [StructLayout(LayoutKind.Sequential)]
    struct DEVPROPKEY { public Guid fmtid; public uint pid; }

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
    [DllImport("user32.dll")] static extern bool IsHungAppWindow(IntPtr h);
    [DllImport("user32.dll")] static extern IntPtr HungWindowFromGhostWindow(IntPtr h);
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr SendMessageTimeout(IntPtr h, uint msg, UIntPtr wp, IntPtr lp, uint flags, uint timeout, out UIntPtr result);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder sb, ref int size);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("dxgi.dll")] static extern int CreateDXGIFactory1(ref Guid riid, out IFsDxgiFactory1 factory);
    [DllImport("setupapi.dll", SetLastError = true)] static extern IntPtr SetupDiGetClassDevs(ref Guid cls, IntPtr enumerator, IntPtr hwnd, uint flags);
    [DllImport("setupapi.dll", SetLastError = true)] static extern bool SetupDiEnumDeviceInfo(IntPtr set, uint index, ref SP_DEVINFO_DATA data);
    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SetupDiGetDeviceRegistryPropertyW")]
    static extern bool SetupDiGetDeviceRegistryProperty(IntPtr set, ref SP_DEVINFO_DATA data, uint prop, out uint regType, byte[] buf, uint size, out uint required);
    [DllImport("setupapi.dll", SetLastError = true, EntryPoint = "SetupDiGetDevicePropertyW")]
    static extern bool SetupDiGetDeviceProperty(IntPtr set, ref SP_DEVINFO_DATA data, ref DEVPROPKEY key, out uint propType, byte[] buf, uint size, out uint required, uint flags);
    [DllImport("setupapi.dll")] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);

    const uint EVENT_SYSTEM_FOREGROUND = 0x0003;
    const uint EVENT_SYSTEM_MINIMIZESTART = 0x0016;
    const uint EVENT_SYSTEM_MINIMIZEEND = 0x0017;
    const uint WINEVENT_OUTOFCONTEXT = 0x0000;
    const uint WINEVENT_SKIPOWNPROCESS = 0x0002;
    const uint PM_REMOVE = 0x0001;
    const uint WM_NULL = 0x0000;
    const uint SMTO_ABORTIFHUNG = 0x0002;
    const uint DIGCF_PRESENT = 0x0002;
    const uint SPDRP_DEVICEDESC = 0x0000;
    const uint SPDRP_HARDWAREID = 0x0001;
    const int FLICKER_EVENTS = 6;          // so viele Fokuswechsel ...
    const int FLICKER_WINDOW_MS = 1000;    // ... innerhalb dieser Zeit = Flackern

    // ------------------------------------------------------------------ Zustand
    class Entry {
        public IntPtr Hwnd; public uint Pid; public FsProcInfo Proc; public string Name;
        public string Title; public string Cls; public bool Visible; public string Size;
        public bool IsGhost; public DateTime Start;
    }
    class HangStat { public int Count; public double TotalMs; public double MaxMs; public int WithPower; public string Render = ""; }
    class Interval { public DateTime Start; public DateTime End; public string Proc; }

    static readonly object _out = new object();
    static readonly object _gpuLock = new object();
    static readonly object _cacheLock = new object();
    static readonly object _statLock = new object();
    static volatile bool _quit = false;
    static uint _myPid;

    static WinEventDelegate _cb = new WinEventDelegate(OnEvent); // muss am Leben bleiben (GC)
    static Dictionary<uint, FsProcInfo> _cache = new Dictionary<uint, FsProcInfo>();
    static List<Entry> _hist = new List<Entry>();
    static Dictionary<string, int> _thiefCount = new Dictionary<string, int>();
    static Dictionary<string, string> _thiefDetail = new Dictionary<string, string>();
    static StreamWriter _csv, _gpuCsv;
    static int _thresholdMs = 3000, _stockenMs = 200;
    static int _focusEvents = 0, _suspects = 0, _markers = 0;
    static DateTime _startTime;
    static volatile uint _fgPid = 0;

    // Flackern (nur Hauptthread)
    static Queue<DateTime> _recent = new Queue<DateTime>();
    static bool _flickerActive = false;
    static DateTime _flickerStart, _flickerLast;
    static int _flickerCount = 0, _flickerTotal = 0;
    static double _flickerTotalMs = 0;
    static Dictionary<string, int> _flickerProcs = new Dictionary<string, int>();

    // Hänger (Hänger-Thread; Statistik unter _statLock)
    static volatile bool _hangActive = false;
    static DateTime _hangStart;
    static IntPtr _hangHwnd;
    static string _hangProc = "", _hangTitle = "", _hangGpuAtStart = "";
    static long _hangMaxLat = 0;
    static bool _hangHard = false, _hangAnnounced = false;
    static Dictionary<string, HangStat> _hangStats = new Dictionary<string, HangStat>();
    static List<Interval> _hangIntervals = new List<Interval>();
    static int _hangCount = 0, _hangWithPower = 0;

    // GPU
    static List<FsAdapter> _adapters = new List<FsAdapter>();
    static IntPtr _devSet = IntPtr.Zero;
    static List<SP_DEVINFO_DATA> _devs = new List<SP_DEVINFO_DATA>();
    static PerformanceCounterCategory _gpuCat = null;
    static Dictionary<string, CounterSample> _prevSamples = null;
    static Dictionary<string, double> _adapterUse = new Dictionary<string, double>();               // LUID|Gruppe -> %
    static Dictionary<uint, Dictionary<string, double>> _pidUse = new Dictionary<uint, Dictionary<string, double>>();
    static List<KeyValuePair<DateTime, string>> _powerEvents = new List<KeyValuePair<DateTime, string>>();
    static Regex _instRx = new Regex(@"pid_(\d+)_luid_(0x[0-9a-fA-F]+_0x[0-9a-fA-F]+)_phys_\d+_eng_(\d+)_engtype_(.*)$", RegexOptions.IgnoreCase);
    static uint _sigPid = 0;
    static string _sigLast = null;
    static HashSet<uint> _sigSeen = new HashSet<uint>();
    static bool _gpuCountersOk = false;

    // ------------------------------------------------------------------ Hauptprogramm
    public static void Run(string csvPath, string gpuCsvPath, int thresholdMs, int stockenMs) {
        _thresholdMs = thresholdMs;
        _stockenMs = stockenMs;
        _startTime = DateTime.Now;
        _myPid = (uint)Process.GetCurrentProcess().Id;

        _csv = new StreamWriter(csvPath, false, new UTF8Encoding(true));
        _csv.AutoFlush = true;
        _csv.WriteLine("Zeit;Ereignis;Dauer_ms;PID;Prozess;Pfad;Parent_PID;Parent;Fenstertitel;Fensterklasse;Sichtbar;Fenstergroesse;Verdacht;Details;Kommandozeile");

        InitAdapters();
        InitCounters();

        _gpuCsv = new StreamWriter(gpuCsvPath, false, new UTF8Encoding(true));
        _gpuCsv.AutoFlush = true;
        _gpuCsv.WriteLine("Zeit;Adapter;Zustand;3D_%;Copy_%;Video_%;Compute_%;Sonst_%;Vordergrund_PID;Vordergrund_Prozess;VG_3D_%;VG_Copy_%;VG_Video_%;VG_Compute_%");

        PrintAdapters();

        uint flags = WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS;
        IntPtr h1 = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, IntPtr.Zero, _cb, 0, 0, flags);
        IntPtr h2 = SetWinEventHook(EVENT_SYSTEM_MINIMIZESTART, EVENT_SYSTEM_MINIMIZEEND, IntPtr.Zero, _cb, 0, 0, flags);
        if (h1 == IntPtr.Zero) { Console.WriteLine("FEHLER: SetWinEventHook fehlgeschlagen."); return; }

        HandleForeground(GetForegroundWindow(), DateTime.Now, "START");

        Thread gpuThread = new Thread(GpuLoop); gpuThread.IsBackground = true; gpuThread.Start();
        Thread hangThread = new Thread(HangLoop); hangThread.IsBackground = true; hangThread.Start();

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
                    else if (k.Key == ConsoleKey.G) PrintGpuStatus();
                }
            } catch (InvalidOperationException) { }
            if (_flickerActive && (DateTime.Now - _flickerLast).TotalMilliseconds > 1500) EndFlicker();
            Thread.Sleep(10);
        }

        _quit = true;
        hangThread.Join(3000);
        gpuThread.Join(3000);
        UnhookWinEvent(h1);
        if (h2 != IntPtr.Zero) UnhookWinEvent(h2);
        if (_flickerActive) EndFlicker();
        PrintSummary();
        lock (_out) { _csv.Close(); _csv = null; _gpuCsv.Close(); _gpuCsv = null; }
        if (_devSet != IntPtr.Zero) SetupDiDestroyDeviceInfoList(_devSet);
    }

    // ------------------------------------------------------------------ Fokus-Ereignisse
    static void OnEvent(IntPtr hHook, uint ev, IntPtr hwnd, int idObject, int idChild, uint thread, uint time) {
        try {
            if (idObject != 0) return; // nur OBJID_WINDOW
            uint now = (uint)Environment.TickCount;
            long ago = (long)(uint)(now - time);
            if (ago < 0 || ago > 60000) ago = 0;
            DateTime t = DateTime.Now.AddMilliseconds(-ago);

            if (ev == EVENT_SYSTEM_FOREGROUND) HandleForeground(hwnd, t, "FOKUS");
            else if (ev == EVENT_SYSTEM_MINIMIZESTART) HandleSimple(hwnd, t, "MINIMIERT");
            else if (ev == EVENT_SYSTEM_MINIMIZEEND) HandleSimple(hwnd, t, "WIEDERHERGESTELLT");
        } catch (Exception ex) {
            Out(ConsoleColor.DarkRed, "  (Fehler im Event-Handler: " + ex.Message + ")");
        }
    }

    static string ClassOf(IntPtr hwnd) {
        StringBuilder sb = new StringBuilder(256);
        GetClassName(hwnd, sb, sb.Capacity);
        return sb.ToString();
    }

    static string TitleOf(IntPtr hwnd) {
        StringBuilder sb = new StringBuilder(512);
        GetWindowText(hwnd, sb, sb.Capacity);
        return sb.ToString();
    }

    static Entry Describe(IntPtr hwnd, DateTime t) {
        Entry e = new Entry();
        e.Hwnd = hwnd; e.Start = t; e.Title = ""; e.Cls = ""; e.Size = "";
        uint pid = 0;
        if (hwnd != IntPtr.Zero) {
            GetWindowThreadProcessId(hwnd, out pid);
            e.Title = TitleOf(hwnd);
            e.Cls = ClassOf(hwnd);
            e.Visible = IsWindowVisible(hwnd);
            RECT r;
            if (GetWindowRect(hwnd, out r)) e.Size = string.Format("{0}x{1}@{2},{3}", r.R - r.L, r.B - r.T, r.L, r.T);
        }
        e.Pid = pid;
        e.Proc = GetProc(pid);
        e.Name = e.Proc.Name;
        if (e.Cls == "Ghost") {
            // Ghost-Fenster gehört technisch dwm.exe - wir ordnen es dem hängenden Besitzer zu
            IntPtr owner = HungWindowFromGhostWindow(hwnd);
            if (owner != IntPtr.Zero) {
                uint opid;
                GetWindowThreadProcessId(owner, out opid);
                e.IsGhost = true;
                e.Pid = opid;
                e.Proc = GetProc(opid);
                e.Name = "GHOST(" + e.Proc.Name + ")";
            } else {
                e.IsGhost = true;
                e.Name = "GHOST(?)";
            }
        }
        return e;
    }

    static void HandleSimple(IntPtr hwnd, DateTime t, string kind) {
        Entry e = Describe(hwnd, t);
        if (!_flickerActive)
            Out(ConsoleColor.DarkGray, string.Format("{0:HH:mm:ss.fff}  {1,-17} {2} ({3})  \"{4}\"", t, kind, e.Name, e.Pid, Trunc(e.Title, 50)));
        Row(t, kind, "", e, "", "");
    }

    static void HandleForeground(IntPtr hwnd, DateTime t, string kind) {
        if (_hist.Count > 0 && _hist[_hist.Count - 1].Hwnd == hwnd) return; // keine echte Änderung
        Entry e = Describe(hwnd, t);
        _focusEvents++;
        if (hwnd != IntPtr.Zero) _fgPid = e.Pid;

        // ---- Flacker-Erkennung
        _recent.Enqueue(t);
        while (_recent.Count > 0 && (t - _recent.Peek()).TotalMilliseconds > FLICKER_WINDOW_MS) _recent.Dequeue();
        if (_flickerActive) {
            _flickerCount++;
            _flickerLast = t;
            AddCount(_flickerProcs, e.Name);
        } else if (_recent.Count >= FLICKER_EVENTS) {
            _flickerActive = true;
            _flickerStart = _recent.Peek();
            _flickerLast = t;
            _flickerCount = _recent.Count;
            _flickerProcs = new Dictionary<string, int>();
            AddCount(_flickerProcs, e.Name);
            Out(ConsoleColor.Magenta, string.Format("{0:HH:mm:ss.fff}  ######## FLACKERN beginnt ({1} Fokuswechsel in < {2} ms) - Einzelzeilen pausiert ########",
                _flickerStart, _recent.Count, FLICKER_WINDOW_MS));
            Row(_flickerStart, "FLACKERN_START", "", null, "", "GPU: " + PowerStates());
        }
        bool quiet = _flickerActive;

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
                    suspect = prev.Name;
                    _suspects++;
                    AddCount(_thiefCount, suspect);
                    _thiefDetail[suspect] = string.Format("PID {0}, Klasse '{1}', Titel '{2}', sichtbar={3}, {4}, Pfad {5}, Parent {6} ({7})",
                        prev.Pid, prev.Cls, Trunc(prev.Title, 40), prev.Visible, prev.Size, prev.Proc.Path, prev.Proc.ParentName, prev.Proc.ParentPid);
                    if (!quiet) {
                        lock (_out) {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("  >>> VERDACHT #{0}: {1} (PID {2}) hatte den Fokus nur {3} ms  [Klasse '{4}', sichtbar={5}, {6}]  -> bisher {7}x",
                                _suspects, prev.Name, prev.Pid, (long)dur, prev.Cls, prev.Visible, prev.Size, _thiefCount[suspect]);
                            if (prev.Proc.Path != "") Console.WriteLine("      Pfad:   " + prev.Proc.Path);
                            if (prev.Proc.ParentName != "") Console.WriteLine("      Parent: " + prev.Proc.ParentName + " (PID " + prev.Proc.ParentPid + ")");
                            Console.ResetColor();
                        }
                    }
                    Row(t, "VERDACHT", durStr, prev, suspect, "");
                }
            }
        }

        if (!quiet) {
            ConsoleColor col = ConsoleColor.Gray;
            string fl = "";
            if (hwnd == IntPtr.Zero) { col = ConsoleColor.Magenta; fl = " [KEIN FENSTER]"; }
            else if (e.IsGhost) { col = ConsoleColor.Red; fl = " [GHOST - Programm reagiert nicht]"; }
            else {
                if (!e.Visible) fl += " [UNSICHTBAR]";
                if (e.Title == "") fl += " [OHNE TITEL]";
                if (fl != "") col = ConsoleColor.Yellow;
            }
            Out(col, string.Format("{0:HH:mm:ss.fff}  {1,-6} vorher {2,7} ms -> {3} ({4})  \"{5}\"  [{6}]{7}",
                t, kind, durStr == "" ? "-" : durStr, e.Name, e.Pid, Trunc(e.Title, 45), e.Cls, fl));
        }
        Row(t, kind, durStr, e, "", e.IsGhost ? "Ghost-Fenster (dwm.exe) fuer haengendes Programm" : "");

        _hist.Add(e);
        if (_hist.Count > 20) _hist.RemoveAt(0);
    }

    static void EndFlicker() {
        _flickerActive = false;
        double dur = (_flickerLast - _flickerStart).TotalMilliseconds;
        _flickerTotal++;
        _flickerTotalMs += dur;

        List<KeyValuePair<string, int>> list = new List<KeyValuePair<string, int>>(_flickerProcs);
        list.Sort(delegate (KeyValuePair<string, int> x, KeyValuePair<string, int> y) { return y.Value.CompareTo(x.Value); });
        StringBuilder sb = new StringBuilder();
        foreach (KeyValuePair<string, int> kv in list) { if (sb.Length > 0) sb.Append(", "); sb.Append(kv.Key + " " + kv.Value + "x"); }

        string hangs = HangsBetween(_flickerStart.AddSeconds(-1), _flickerLast.AddSeconds(1));
        string pw = PowerEventsBetween(_flickerStart.AddSeconds(-2), _flickerLast.AddSeconds(1), _flickerStart);
        string render = UsageString(_fgPid);
        string details = string.Format("{0} Fokuswechsel | beteiligt: {1} | UI-Haenger: {2} | GPU-Zustandswechsel (+-2s): {3} | GPU jetzt: {4} | Rendering Vordergrund: {5}",
            _flickerCount, sb, hangs, pw, PowerStates(), render);
        lock (_out) {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("{0:HH:mm:ss.fff}  ######## FLACKERN beendet nach {1} ms, {2} Fokuswechsel ########", _flickerLast, (long)dur, _flickerCount);
            Console.WriteLine("      beteiligt:            " + sb);
            Console.WriteLine("      UI-Hänger:            " + hangs);
            Console.WriteLine("      GPU-Zustandswechsel:  " + pw);
            Console.WriteLine("      GPU jetzt:            " + PowerStates());
            Console.WriteLine("      Rendering Vordergrund:" + " " + render);
            Console.ResetColor();
        }
        Row(_flickerLast, "FLACKERN_ENDE", ((long)dur).ToString(), null, "", details);
    }

    static void Marker() {
        _markers++;
        DateTime t = DateTime.Now;
        string ctx = "GPU: " + PowerStates() + " | Vordergrund-Rendering: " + UsageString(_fgPid);
        Out(ConsoleColor.Cyan, string.Format("{0:HH:mm:ss.fff}  ======== MARKIERUNG #{1} (Glitch gesehen) ========  {2}", t, _markers, ctx));
        Row(t, "MARKIERUNG #" + _markers, "", null, "", ctx);
    }

    // ------------------------------------------------------------------ Hänger-Messung
    static void HangLoop() {
        while (!_quit) {
            try { ProbeOnce(); } catch (Exception ex) { Out(ConsoleColor.DarkRed, "  (Fehler in Hänger-Messung: " + ex.Message + ")"); }
            Thread.Sleep(_hangActive ? 50 : 200);
        }
        if (_hangActive) EndHang(DateTime.Now, "Programmende");
    }

    static void ProbeOnce() {
        IntPtr fg = GetForegroundWindow();
        if (fg == IntPtr.Zero) return;
        IntPtr target = fg;
        if (ClassOf(fg) == "Ghost") {
            IntPtr h = HungWindowFromGhostWindow(fg);
            if (h != IntPtr.Zero) target = h;
        }
        uint pid;
        GetWindowThreadProcessId(target, out pid);
        if (pid == _myPid || pid == 0) return;

        if (_hangActive && target != _hangHwnd) EndHang(DateTime.Now, "Fokus gewechselt");

        DateTime t0 = DateTime.Now;
        Stopwatch sw = Stopwatch.StartNew();
        UIntPtr res;
        IntPtr ok = SendMessageTimeout(target, WM_NULL, UIntPtr.Zero, IntPtr.Zero, SMTO_ABORTIFHUNG, 1000, out res);
        long lat = sw.ElapsedMilliseconds;
        bool hung = ok == IntPtr.Zero || IsHungAppWindow(target);

        if (hung || lat >= _stockenMs) {
            if (!_hangActive) {
                _hangActive = true;
                _hangStart = t0;
                _hangHwnd = target;
                _hangProc = GetProc(pid).Name;
                _hangTitle = TitleOf(target);
                _hangMaxLat = lat;
                _hangHard = hung;
                _hangAnnounced = false;
                _hangGpuAtStart = "GPU: " + PowerStates() + " | Rendering: " + UsageString(pid);
            } else {
                if (lat > _hangMaxLat) _hangMaxLat = lat;
                if (hung) _hangHard = true;
            }
            if (!_hangAnnounced && (DateTime.Now - _hangStart).TotalMilliseconds >= 1000 && !_flickerActive) {
                _hangAnnounced = true;
                Out(ConsoleColor.Red, string.Format("{0:HH:mm:ss.fff}  !!! HÄNGT seit >1 s: {1} \"{2}\"  ({3})", DateTime.Now, _hangProc, Trunc(_hangTitle, 40), _hangGpuAtStart));
            }
        } else if (_hangActive) {
            EndHang(DateTime.Now, "");
        }
    }

    static void EndHang(DateTime end, string note) {
        _hangActive = false;
        double dur = (end - _hangStart).TotalMilliseconds;
        string pw = PowerEventsBetween(_hangStart.AddSeconds(-2), end.AddSeconds(1), _hangStart);
        bool withPower = pw != "keine";
        string kind = (_hangHard || dur >= 1000) ? "HAENGER" : "STOCKEN";
        string render = UsageString(GetPidSafe(_hangHwnd));

        lock (_statLock) {
            _hangCount++;
            if (withPower) _hangWithPower++;
            HangStat hs;
            if (!_hangStats.TryGetValue(_hangProc, out hs)) { hs = new HangStat(); _hangStats[_hangProc] = hs; }
            hs.Count++; hs.TotalMs += dur; if (dur > hs.MaxMs) hs.MaxMs = dur; if (withPower) hs.WithPower++;
            hs.Render = render;
            Interval iv = new Interval(); iv.Start = _hangStart; iv.End = end; iv.Proc = _hangProc;
            _hangIntervals.Add(iv);
            if (_hangIntervals.Count > 500) _hangIntervals.RemoveAt(0);
        }

        string details = string.Format("max. Antwortzeit {0} ms{1} | beim Start: {2} | danach Rendering: {3} | GPU-Zustandswechsel (+-2s): {4}{5}",
            _hangMaxLat, _hangHard ? " (Windows: reagiert nicht)" : "", _hangGpuAtStart, render, pw, note != "" ? " | " + note : "");
        if (!_flickerActive || kind == "HAENGER") {
            lock (_out) {
                Console.ForegroundColor = kind == "HAENGER" ? ConsoleColor.Red : ConsoleColor.DarkYellow;
                Console.WriteLine("{0:HH:mm:ss.fff}  {1} {2,6} ms  {3} \"{4}\"{5}", end, kind == "HAENGER" ? "HÄNGER " : "STOCKEN", (long)dur,
                    _hangProc, Trunc(_hangTitle, 40), note != "" ? " (" + note + ")" : "");
                Console.WriteLine("      {0}", _hangGpuAtStart);
                if (withPower) Console.WriteLine("      GPU-Zustandswechsel dabei: " + pw);
                Console.ResetColor();
            }
        }
        Entry e = Describe(_hangHwnd, _hangStart);
        Row(_hangStart, kind, ((long)dur).ToString(), e, "", details);
    }

    static uint GetPidSafe(IntPtr hwnd) {
        uint pid = 0;
        if (hwnd != IntPtr.Zero) GetWindowThreadProcessId(hwnd, out pid);
        return pid;
    }

    static string HangsBetween(DateTime from, DateTime to) {
        StringBuilder sb = new StringBuilder();
        lock (_statLock) {
            foreach (Interval iv in _hangIntervals) {
                if (iv.End >= from && iv.Start <= to) {
                    if (sb.Length > 0) sb.Append(", ");
                    sb.Append(string.Format("{0} ({1} ms)", iv.Proc, (long)(iv.End - iv.Start).TotalMilliseconds));
                }
            }
        }
        if (_hangActive) { if (sb.Length > 0) sb.Append(", "); sb.Append(_hangProc + " (laeuft noch)"); }
        return sb.Length == 0 ? "keine" : sb.ToString();
    }

    // ------------------------------------------------------------------ GPU
    static string VendorShort(uint ven, string name) {
        if (ven == 0x10DE) return "NVIDIA";
        if (ven == 0x1002 || ven == 0x1022) return "AMD";
        if (ven == 0x8086) return "Intel";
        string[] parts = name.Split(' ');
        return parts.Length > 0 && parts[0] != "" ? parts[0] : "GPU";
    }

    static void InitAdapters() {
        // 1) DXGI: Namen + LUID (LUID verknüpft mit den GPU-Leistungsindikatoren)
        try {
            Guid iid = new Guid("770aae78-f26f-4dba-a829-253c83d1b387");
            IFsDxgiFactory1 f;
            if (CreateDXGIFactory1(ref iid, out f) == 0 && f != null) {
                for (uint i = 0; i < 16; i++) {
                    IFsDxgiAdapter1 a;
                    if (f.EnumAdapters1(i, out a) != 0 || a == null) break;
                    FsDxgiAdapterDesc1 d;
                    if (a.GetDesc1(out d) == 0 && d.VendorId != 0x1414) { // 0x1414 = Microsoft Basic Render Driver
                        FsAdapter ad = new FsAdapter();
                        ad.Name = (d.Description ?? "").Trim();
                        ad.VendorId = d.VendorId;
                        ad.Luid = string.Format("0x{0:X8}_0x{1:X8}", d.LuidHigh, d.LuidLow).ToUpperInvariant();
                        ad.Short = VendorShort(d.VendorId, ad.Name);
                        _adapters.Add(ad);
                    }
                    Marshal.ReleaseComObject(a);
                }
                Marshal.ReleaseComObject(f);
            }
        } catch (Exception ex) {
            Out(ConsoleColor.Yellow, "  Hinweis: DXGI-Abfrage fehlgeschlagen (" + ex.Message + ")");
        }

        // 2) SetupAPI: Geräte der Klasse "Grafikkarten" für den Energiezustand (D0/D3)
        try {
            Guid cls = new Guid("4d36e968-e325-11ce-bfc1-08002be10318");
            _devSet = SetupDiGetClassDevs(ref cls, IntPtr.Zero, IntPtr.Zero, DIGCF_PRESENT);
            if (_devSet == new IntPtr(-1)) { _devSet = IntPtr.Zero; return; }
            for (uint i = 0; i < 16; i++) {
                SP_DEVINFO_DATA d = new SP_DEVINFO_DATA();
                d.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
                if (!SetupDiEnumDeviceInfo(_devSet, i, ref d)) break;
                string hw = RegProp(d, SPDRP_HARDWAREID).ToUpperInvariant();
                uint ven = 0;
                Match m = Regex.Match(hw, @"VEN_([0-9A-F]{4})");
                if (m.Success) ven = Convert.ToUInt32(m.Groups[1].Value, 16);
                if (ven == 0x1414) continue;
                _devs.Add(d);
                int idx = _devs.Count - 1;
                FsAdapter match = null;
                foreach (FsAdapter a in _adapters) {
                    bool sameVendor = a.VendorId == ven || (ven == 0x1002 && a.VendorId == 0x1022) || (ven == 0x1022 && a.VendorId == 0x1002);
                    if (sameVendor && a.DevIndex < 0) { match = a; break; }
                }
                if (match == null) {
                    match = new FsAdapter();
                    match.Name = RegProp(d, SPDRP_DEVICEDESC).Trim();
                    match.VendorId = ven;
                    match.Short = VendorShort(ven, match.Name);
                    _adapters.Add(match);
                }
                match.DevIndex = idx;
                match.Power = QueryPower(idx);
            }
        } catch (Exception ex) {
            Out(ConsoleColor.Yellow, "  Hinweis: Energiezustand der Grafikkarten nicht lesbar (" + ex.Message + ")");
        }
    }

    static string RegProp(SP_DEVINFO_DATA d, uint prop) {
        byte[] buf = new byte[2048];
        uint type, req;
        if (!SetupDiGetDeviceRegistryProperty(_devSet, ref d, prop, out type, buf, (uint)buf.Length, out req)) return "";
        int len = (int)Math.Min(req, (uint)buf.Length);
        return Encoding.Unicode.GetString(buf, 0, len).Replace('\0', ' ');
    }

    static int QueryPower(int idx) {
        if (_devSet == IntPtr.Zero || idx < 0 || idx >= _devs.Count) return 0;
        SP_DEVINFO_DATA d = _devs[idx];
        DEVPROPKEY key = new DEVPROPKEY();
        key.fmtid = new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"); // DEVPKEY_Device_PowerData
        key.pid = 32;
        byte[] buf = new byte[256];
        uint type, req;
        if (!SetupDiGetDeviceProperty(_devSet, ref d, ref key, out type, buf, (uint)buf.Length, out req, 0)) return 0;
        // CM_POWER_DATA: PD_Size (4 Byte), PD_MostRecentPowerState (4 Byte) ...
        return BitConverter.ToInt32(buf, 4);
    }

    static string PS(int p) {
        switch (p) {
            case 1: return "D0";
            case 2: return "D1";
            case 3: return "D2";
            case 4: return "D3";
            default: return "?";
        }
    }

    static string PowerStates() {
        StringBuilder sb = new StringBuilder();
        foreach (FsAdapter a in _adapters) {
            if (sb.Length > 0) sb.Append(", ");
            sb.Append(a.Short + " " + PS(a.Power));
        }
        return sb.Length == 0 ? "?" : sb.ToString();
    }

    static void InitCounters() {
        try {
            if (PerformanceCounterCategory.Exists("GPU Engine")) {
                _gpuCat = new PerformanceCounterCategory("GPU Engine");
                _gpuCountersOk = true;
            }
        } catch (Exception ex) {
            Out(ConsoleColor.Yellow, "  Hinweis: GPU-Leistungsindikatoren nicht verfügbar (" + ex.Message + ")");
        }
    }

    static void PrintAdapters() {
        lock (_out) {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  Grafikkarten:");
            foreach (FsAdapter a in _adapters)
                Console.WriteLine("    {0,-7} {1,-40} Zustand {2}  LUID {3}", a.Short, Trunc(a.Name, 40), PS(a.Power), a.Luid == "" ? "-" : a.Luid);
            if (_adapters.Count == 0) Console.WriteLine("    (keine gefunden)");
            Console.WriteLine("  GPU-Last pro Prozess: " + (_gpuCountersOk ? "verfügbar" : "NICHT verfügbar"));
            Console.WriteLine("  Zustände: D0 = aktiv, D3 = schlafend/abgeschaltet");
            Console.WriteLine();
            Console.ResetColor();
        }
    }

    static void GpuLoop() {
        DateTime lastSample = DateTime.MinValue;
        while (!_quit) {
            try {
                DateTime now = DateTime.Now;
                foreach (FsAdapter a in _adapters) {
                    if (a.DevIndex < 0) continue;
                    int p = QueryPower(a.DevIndex);
                    if (p != 0 && p != a.Power) {
                        int old = a.Power;
                        a.Power = p;
                        if (old != 0) PowerChanged(a, old, p, now);
                    }
                }
                if (_gpuCountersOk && (now - lastSample).TotalMilliseconds >= 1000) {
                    lastSample = now;
                    SampleCounters();
                    WriteGpuRows(now);
                    CheckForegroundRendering(now);
                }
            } catch (Exception ex) {
                Out(ConsoleColor.DarkRed, "  (Fehler in GPU-Messung: " + ex.Message + ")");
                Thread.Sleep(2000);
            }
            Thread.Sleep(100);
        }
    }

    static void PowerChanged(FsAdapter a, int old, int p, DateTime t) {
        a.Transitions++;
        string txt = a.Short + " " + PS(old) + "->" + PS(p);
        lock (_gpuLock) {
            _powerEvents.Add(new KeyValuePair<DateTime, string>(t, txt));
            if (_powerEvents.Count > 1000) _powerEvents.RemoveAt(0);
        }
        string extra = p == 1 ? "wacht auf" : (p == 4 ? "schläft ein" : "");
        string ctx = _hangActive ? " | während UI-Hänger von " + _hangProc : "";
        if (!_flickerActive)
            Out(ConsoleColor.Blue, string.Format("{0:HH:mm:ss.fff}  GPU    {1} ({2}): {3} -> {4} {5}{6}", t, a.Short, Trunc(a.Name, 30), PS(old), PS(p), extra, ctx));
        Row(t, "GPU_ZUSTAND", "", null, "", a.Name + ": " + PS(old) + " -> " + PS(p) + ctx);
    }

    static string PowerEventsBetween(DateTime from, DateTime to, DateTime reference) {
        StringBuilder sb = new StringBuilder();
        lock (_gpuLock) {
            foreach (KeyValuePair<DateTime, string> kv in _powerEvents) {
                if (kv.Key >= from && kv.Key <= to) {
                    if (sb.Length > 0) sb.Append(", ");
                    double off = (kv.Key - reference).TotalSeconds;
                    sb.Append(string.Format("{0} ({1}{2:0.0} s)", kv.Value, off >= 0 ? "+" : "", off));
                }
            }
        }
        return sb.Length == 0 ? "keine" : sb.ToString();
    }

    static string Group(string engType) {
        string t = engType.ToLowerInvariant();
        if (t.StartsWith("3d")) return "3D";
        if (t.StartsWith("copy")) return "Copy";
        if (t.StartsWith("video")) return "Video";
        if (t.StartsWith("compute")) return "Compute";
        return "Sonst";
    }

    static void SampleCounters() {
        InstanceDataCollectionCollection all = _gpuCat.ReadCategory();
        InstanceDataCollection util = all["Utilization Percentage"];
        if (util == null) return;
        Dictionary<string, CounterSample> cur = new Dictionary<string, CounterSample>();
        foreach (InstanceData d in util.Values) cur[d.InstanceName] = d.Sample;

        if (_prevSamples != null) {
            Dictionary<string, double> engSum = new Dictionary<string, double>(); // LUID|Gruppe|Engine -> Summe aller Prozesse
            Dictionary<string, double> pidG = new Dictionary<string, double>();   // PID|LUID|Gruppe -> max über Engines
            foreach (KeyValuePair<string, CounterSample> kv in cur) {
                CounterSample old;
                if (!_prevSamples.TryGetValue(kv.Key, out old)) continue;
                float v;
                try { v = CounterSample.Calculate(old, kv.Value); } catch { continue; }
                if (v <= 0.05f || float.IsNaN(v)) continue;
                Match m = _instRx.Match(kv.Key);
                if (!m.Success) continue;
                string pid = m.Groups[1].Value;
                string luid = m.Groups[2].Value.ToUpperInvariant();
                string g = Group(m.Groups[4].Value);
                string ek = luid + "|" + g + "|" + m.Groups[3].Value;
                double s;
                engSum.TryGetValue(ek, out s);
                engSum[ek] = s + v;
                string pk = pid + "|" + luid + "|" + g;
                double pv;
                if (!pidG.TryGetValue(pk, out pv) || v > pv) pidG[pk] = v;
            }
            Dictionary<string, double> adapterUse = new Dictionary<string, double>();
            foreach (KeyValuePair<string, double> kv in engSum) {
                int last = kv.Key.LastIndexOf('|');
                string k = kv.Key.Substring(0, last);
                double v;
                double val = Math.Min(100.0, kv.Value);
                if (!adapterUse.TryGetValue(k, out v) || val > v) adapterUse[k] = val;
            }
            Dictionary<uint, Dictionary<string, double>> pidUse = new Dictionary<uint, Dictionary<string, double>>();
            foreach (KeyValuePair<string, double> kv in pidG) {
                int first = kv.Key.IndexOf('|');
                uint pid = uint.Parse(kv.Key.Substring(0, first));
                Dictionary<string, double> dd;
                if (!pidUse.TryGetValue(pid, out dd)) { dd = new Dictionary<string, double>(); pidUse[pid] = dd; }
                dd[kv.Key.Substring(first + 1)] = Math.Min(100.0, kv.Value);
            }
            lock (_gpuLock) { _adapterUse = adapterUse; _pidUse = pidUse; }
        }
        _prevSamples = cur;
    }

    static double Get(Dictionary<string, double> d, string key) {
        double v;
        if (d != null && d.TryGetValue(key, out v)) return v;
        return 0;
    }

    static string UsageString(uint pid) {
        if (!_gpuCountersOk) return "n/v";
        Dictionary<string, double> d;
        lock (_gpuLock) { _pidUse.TryGetValue(pid, out d); }
        if (d == null) return "keine GPU-Last";
        StringBuilder sb = new StringBuilder();
        string[] groups = new string[] { "3D", "Copy", "Video", "Compute", "Sonst" };
        foreach (FsAdapter a in _adapters) {
            if (a.Luid == "") continue;
            StringBuilder part = new StringBuilder();
            foreach (string g in groups) {
                double v = Get(d, a.Luid + "|" + g);
                if (v >= 0.5) part.Append(string.Format(" {0} {1:0}%", g, v));
            }
            if (part.Length > 0) { if (sb.Length > 0) sb.Append(" | "); sb.Append(a.Short + part); }
        }
        return sb.Length == 0 ? "keine GPU-Last" : sb.ToString();
    }

    static string Signature(uint pid) {
        Dictionary<string, double> d;
        lock (_gpuLock) { _pidUse.TryGetValue(pid, out d); }
        if (d == null) return "";
        StringBuilder sb = new StringBuilder();
        foreach (FsAdapter a in _adapters) {
            if (a.Luid == "") continue;
            if (Get(d, a.Luid + "|3D") >= 2) sb.Append(a.Short + "-3D ");
            if (Get(d, a.Luid + "|Copy") >= 2) sb.Append(a.Short + "-Copy ");
        }
        return sb.ToString().Trim();
    }

    static void CheckForegroundRendering(DateTime t) {
        uint pid = _fgPid;
        if (pid == 0 || pid == _myPid) return;
        string sig = Signature(pid);
        bool samePid = pid == _sigPid;
        bool first = !_sigSeen.Contains(pid);
        if ((samePid && sig != _sigLast) || first) {
            _sigSeen.Add(pid);
            string name = GetProc(pid).Name;
            string txt = UsageString(pid);
            if (!_flickerActive)
                Out(ConsoleColor.DarkCyan, string.Format("{0:HH:mm:ss.fff}  GPU    {1} {2}: {3}", t, name, first ? "nutzt" : "wechselt ->", txt));
            Row(t, "GPU_NUTZUNG", "", null, "", name + " (PID " + pid + "): " + txt);
        }
        _sigPid = pid;
        _sigLast = sig;
    }

    static void WriteGpuRows(DateTime t) {
        uint pid = _fgPid;
        string name = pid == 0 ? "" : GetProc(pid).Name;
        Dictionary<string, double> au, pu;
        lock (_gpuLock) { au = _adapterUse; _pidUse.TryGetValue(pid, out pu); }
        lock (_out) {
            if (_gpuCsv == null) return;
            foreach (FsAdapter a in _adapters) {
                string l = a.Luid;
                string[] f = new string[] {
                    t.ToString("yyyy-MM-dd HH:mm:ss.fff"), a.Short + " " + a.Name, PS(a.Power),
                    N(Get(au, l + "|3D")), N(Get(au, l + "|Copy")), N(Get(au, l + "|Video")), N(Get(au, l + "|Compute")), N(Get(au, l + "|Sonst")),
                    pid.ToString(), name,
                    N(Get(pu, l + "|3D")), N(Get(pu, l + "|Copy")), N(Get(pu, l + "|Video")), N(Get(pu, l + "|Compute"))
                };
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < f.Length; i++) { if (i > 0) sb.Append(';'); sb.Append(Q(f[i])); }
                _gpuCsv.WriteLine(sb.ToString());
            }
        }
    }

    static string N(double v) { return v.ToString("0.0"); } // Dezimaltrennzeichen der Systemsprache (Excel-kompatibel)

    static void PrintGpuStatus() {
        Dictionary<string, double> au;
        lock (_gpuLock) { au = _adapterUse; }
        lock (_out) {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine("---------------- GPU-STATUS ----------------");
            foreach (FsAdapter a in _adapters) {
                Console.WriteLine("  {0,-7} {1} | 3D {2:0}%  Copy {3:0}%  Video {4:0}%  Compute {5:0}% | Zustandswechsel bisher: {6}",
                    a.Short, PS(a.Power), Get(au, a.Luid + "|3D"), Get(au, a.Luid + "|Copy"), Get(au, a.Luid + "|Video"), Get(au, a.Luid + "|Compute"), a.Transitions);
            }
            uint pid = _fgPid;
            Console.WriteLine("  Vordergrund: {0} (PID {1}) -> {2}", GetProc(pid).Name, pid, UsageString(pid));
            Console.WriteLine("--------------------------------------------");
            Console.WriteLine();
            Console.ResetColor();
        }
    }

    // ------------------------------------------------------------------ Zusammenfassung
    static void PrintSummary() {
        lock (_out) {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine("================ ZUSAMMENFASSUNG ================");
            Console.WriteLine("Laufzeit: {0:hh\\:mm\\:ss}   Fokuswechsel: {1}   Verdachtsfälle: {2}   Markierungen: {3}",
                DateTime.Now - _startTime, _focusEvents, _suspects, _markers);
            Console.WriteLine("Flacker-Phasen: {0} (gesamt {1:0.0} s)", _flickerTotal, _flickerTotalMs / 1000.0);

            Console.WriteLine();
            Console.WriteLine("Grafikkarten:");
            foreach (FsAdapter a in _adapters)
                Console.WriteLine("  {0,-7} jetzt {1}, Zustandswechsel: {2}", a.Short, PS(a.Power), a.Transitions);

            Console.WriteLine();
            lock (_statLock) {
                Console.WriteLine("UI-Hänger/Stocken: {0}, davon mit GPU-Zustandswechsel (+-2 s): {1}", _hangCount, _hangWithPower);
                List<KeyValuePair<string, HangStat>> hl = new List<KeyValuePair<string, HangStat>>(_hangStats);
                hl.Sort(delegate (KeyValuePair<string, HangStat> x, KeyValuePair<string, HangStat> y) { return y.Value.TotalMs.CompareTo(x.Value.TotalMs); });
                foreach (KeyValuePair<string, HangStat> kv in hl) {
                    Console.WriteLine("  {0,4}x  {1,-28} gesamt {2,7:0.0} s, max {3,6:0} ms, mit GPU-Wechsel {4}x", kv.Value.Count, kv.Key,
                        kv.Value.TotalMs / 1000.0, kv.Value.MaxMs, kv.Value.WithPower);
                    Console.WriteLine("         zuletzt Rendering: " + kv.Value.Render);
                }
            }

            Console.WriteLine();
            if (_thiefCount.Count == 0) {
                Console.WriteLine("Keine Fokus-Diebe erkannt.");
            } else {
                Console.WriteLine("Fokus-Diebe:");
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
    }

    // ------------------------------------------------------------------ Hilfsfunktionen
    static void AddCount(Dictionary<string, int> d, string key) {
        int c;
        d.TryGetValue(key, out c);
        d[key] = c + 1;
    }

    static void Out(ConsoleColor c, string s) {
        lock (_out) {
            Console.ForegroundColor = c;
            Console.WriteLine(s);
            Console.ResetColor();
        }
    }

    static FsProcInfo GetProc(uint pid) {
        lock (_cacheLock) {
            FsProcInfo cached;
            if (_cache.TryGetValue(pid, out cached)) return cached;
        }
        FsProcInfo pi = new FsProcInfo();
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
        if (pi.Name != "<Prozess bereits beendet>") {
            lock (_cacheLock) { _cache[pid] = pi; }
        }
        return pi;
    }

    static void Row(DateTime t, string kind, string dur, Entry e, string suspect, string details) {
        string[] f;
        if (e != null) {
            f = new string[] {
                t.ToString("yyyy-MM-dd HH:mm:ss.fff"), kind, dur, e.Pid.ToString(), e.Name, e.Proc.Path,
                e.Proc.ParentPid.ToString(), e.Proc.ParentName, e.Title, e.Cls, e.Visible ? "ja" : "nein", e.Size, suspect, details, e.Proc.CmdLine
            };
        } else {
            f = new string[] { t.ToString("yyyy-MM-dd HH:mm:ss.fff"), kind, dur, "", "", "", "", "", "", "", "", "", suspect, details, "" };
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < f.Length; i++) { if (i > 0) sb.Append(';'); sb.Append(Q(f[i])); }
        lock (_out) {
            if (_csv != null) _csv.WriteLine(sb.ToString());
        }
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
Write-Host "  FocusSpy 2 - Fokus-, Hänger- und GPU-Überwachung" -ForegroundColor Cyan
Write-Host "  ------------------------------------------------"
Write-Host "  Log:       $LogDatei"
Write-Host "  GPU-Log:   $GpuLogDatei"
Write-Host "  Verdacht:  Fokuswechsel A -> B -> A mit B < $SchwelleMs ms"
Write-Host "  Stocken:   Vordergrundfenster antwortet langsamer als $StockenMs ms"
Write-Host "  Tasten:    [M] Markierung   [S] Zusammenfassung   [G] GPU-Status   [Q]/[ESC] Beenden"
if (-not $isAdmin) {
    Write-Host "  Hinweis:   Nicht als Administrator gestartet - Prozessinfos evtl. unvollständig." -ForegroundColor Yellow
}
Write-Host "  Farben:    grau = normal, gelb = unsichtbar/ohne Titel, lila = kein Fenster/Flackern,"
Write-Host "             rot = Verdacht/Ghost/Hänger, blau = GPU-Zustand, türkis = GPU-Nutzung"
Write-Host ""

[FocusSpy]::Run($LogDatei, $GpuLogDatei, $SchwelleMs, $StockenMs)

Write-Host "Logs gespeichert:" -ForegroundColor Green
Write-Host "  $LogDatei" -ForegroundColor Green
Write-Host "  $GpuLogDatei" -ForegroundColor Green

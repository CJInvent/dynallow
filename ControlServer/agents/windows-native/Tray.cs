using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text.Json.Nodes;
namespace DynAllow;
internal static class Tray
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate IntPtr WndProc(IntPtr hwnd, uint msg, IntPtr wp, IntPtr lp);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct WClass { public uint Style; public IntPtr Proc; public int Extra, WindowExtra; public IntPtr Instance, Icon, Cursor, Background, Menu; [MarshalAs(UnmanagedType.LPWStr)] public string Name; }
    [StructLayout(LayoutKind.Sequential)] struct Point { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] struct Message { public IntPtr Hwnd; public uint Msg; public UIntPtr WParam; public IntPtr LParam; public uint Time; public Point Pt; public uint Private; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct Notify {
        public uint Size; public IntPtr Hwnd; public uint Id, Flags, Callback; public IntPtr Icon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Tip;
        public uint State, StateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Info;
        public uint Timeout;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string Title;
        public uint InfoFlags; public Guid Guid; public IntPtr BalloonIcon;
    }
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern ushort RegisterClass(ref WClass c);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr CreateWindowEx(uint ex, string cls, string title, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr DefWindowProc(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] static extern int GetMessage(out Message m, IntPtr h, uint min, uint max);
    [DllImport("user32.dll")] static extern bool TranslateMessage(ref Message m);
    [DllImport("user32.dll")] static extern IntPtr DispatchMessage(ref Message m);
    [DllImport("user32.dll")] static extern void PostQuitMessage(int code);
    [DllImport("user32.dll")] static extern UIntPtr SetTimer(IntPtr h, UIntPtr id, uint ms, IntPtr cb);
    [DllImport("user32.dll")] static extern IntPtr CreatePopupMenu();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern bool AppendMenu(IntPtr m, uint flags, UIntPtr id, string text);
    [DllImport("user32.dll")] static extern uint TrackPopupMenu(IntPtr menu, uint flags, int x, int y, int reserved, IntPtr h, IntPtr rect);
    [DllImport("user32.dll")] static extern bool GetCursorPos(out Point p);
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] static extern bool DestroyMenu(IntPtr m);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int MessageBox(IntPtr h, string text, string title, uint type);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern uint RegisterWindowMessage(string text);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] static extern bool Shell_NotifyIcon(uint action, ref Notify data);
    [DllImport("user32.dll")] static extern IntPtr CreateIcon(IntPtr h, int w, int height, byte planes, byte bits, byte[] andBits, byte[] xorBits);
    [DllImport("user32.dll")] static extern bool DestroyIcon(IntPtr h);
    [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int cmd);
    static readonly WndProc proc = Procedure;
    static Store? store;
    static Notify notify;
    static uint taskbar;
    static IntPtr green, red, grey;
    static bool restart;
    static string details = "Waiting for service", lastColor = "";
    static IntPtr Dot(byte r, byte g, byte b)
    {
        byte[] and = Enumerable.Repeat((byte)255, 64).ToArray(), xor = new byte[16 * 16 * 4];
        for (int y = 0; y < 16; y++) for (int x = 0; x < 16; x++) if ((x - 7.5) * (x - 7.5) + (y - 7.5) * (y - 7.5) < 42) {
            and[y * 4 + x / 8] &= (byte)~(128 >> (x % 8)); int i = (y * 16 + x) * 4;
            xor[i] = b; xor[i + 1] = g; xor[i + 2] = r; xor[i + 3] = 255;
        }
        return CreateIcon(IntPtr.Zero, 16, 16, 1, 32, and, xor);
    }
    static void Update()
    {
        string color = "grey", site = "DynAllow"; var lines = new List<string>();
        try {
            var s = Store.ReadPath(Path.Combine(store!.Public, "status.json"));
            if (s is not null) {
                if (Version.TryParse(s.S("version"), out var v) && v > Version.Parse(BuildInfo.Version)) { restart = true; PostQuitMessage(0); return; }
                site = s.S("site", "DynAllow"); long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), interval = Math.Max(60, s.N("interval", 300));
                bool stale = now - s.N("updated_at") > 3 * interval + 120;
                bool bad = s["ip"].B("mismatch") || (!s.B("server_ok") && s.N("last_success_at") > 0 && now - s.N("last_success_at") > 2 * interval + 60);
                lines.Add("Control server: " + (s.B("server_ok") ? "OK" : s.S("server_error", "waiting")));
                lines.Add("Public IP: " + s["ip"].S("authoritative", "not verified") + " (" + s["ip"].S("source") + ")");
                if (s["ip"].B("mismatch")) lines.Add("IP HELD: " + s["ip"].S("detail"));
                bool pending = s["ip"].S("pending") != "" && s["ip"].S("trust_mode") == "manual";
                if (pending) lines.Add("New IP awaiting approval: " + s["ip"].S("pending"));
                foreach (var t in (s["targets"] as JsonArray ?? [])) { lines.Add("DNS " + t.S("hostname") + ": " + t.S("state")); bad |= t.S("state") == "fault"; pending |= t.S("state") == "pending"; }
                lines.Add("Identity protection: " + s.S("key_protector")); lines.Add("Prevent sleep: " + s.S("sleep_status", "off"));
                lines.Add("Agent: " + s.S("version")); lines.Add("Update: " + s.S("update_status", "none"));
                color = bad ? "red" : "green";
                if (stale || !s.B("enabled", true) || s.B("decommissioned") || s.N("last_success_at") == 0) color = "grey";
                else if (!bad && pending) color = "grey";
                if (stale) lines.Add("Service status is stale"); if (s.B("decommissioned")) lines.Add("DECOMMISSIONED");
            } else lines.Add("No service status yet");
        } catch (Exception e) { lines.Add("Status unavailable: " + e.Message); }
        details = string.Join(Environment.NewLine, lines);
        notify.Icon = color == "red" ? red : color == "green" ? green : grey;
        notify.Tip = site + " — " + color; if (notify.Tip.Length > 127) notify.Tip = notify.Tip[..127];
        notify.Flags = 1 | 2 | 4;
        if (color == "red" && lastColor != "red" && lastColor != "") { notify.Flags |= 16; notify.Info = "An agent issue needs attention. Open details or the server web UI."; notify.Title = "DynAllow issue"; notify.InfoFlags = 2; }
        Shell_NotifyIcon(1, ref notify); lastColor = color;
    }
    static IntPtr Procedure(IntPtr h, uint msg, IntPtr wp, IntPtr lp)
    {
        try {
            if (msg == taskbar) { Shell_NotifyIcon(0, ref notify); Update(); return IntPtr.Zero; }
            if (msg == 0x113) { Update(); return IntPtr.Zero; }
            if (msg == 0x8001 && lp.ToInt64() == 0x203) { MessageBox(h, details, "DynAllow", 0); return IntPtr.Zero; }
            if (msg == 0x8001 && lp.ToInt64() == 0x205) {
                var menu = CreatePopupMenu();
                try {
                    AppendMenu(menu, 0, 1, "Details"); AppendMenu(menu, 0, 2, "Check now"); AppendMenu(menu, 0, 3, "Open log"); AppendMenu(menu, 0, 4, "Hide until next sign-in");
                    GetCursorPos(out var p); SetForegroundWindow(h); uint action = TrackPopupMenu(menu, 0x100 | 2, p.X, p.Y, 0, h, IntPtr.Zero);
                    if (action == 1) MessageBox(h, details, "DynAllow", 0);
                    if (action == 2) { Native.CheckNow(); Update(); }
                    if (action == 3) { var si = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "notepad.exe")) { UseShellExecute = false }; si.ArgumentList.Add(Path.Combine(store!.Public, "agent.log")); Process.Start(si); }
                    if (action == 4) PostQuitMessage(0);
                } finally { DestroyMenu(menu); }
                return IntPtr.Zero;
            }
        } catch (Exception e) { MessageBox(h, AgentLog.Clean(e.Message), "DynAllow", 0x30); }
        return DefWindowProc(h, msg, wp, lp);
    }
    public static void Run(Store s)
    {
        using var single = new Mutex(false, @"Local\IPFailoverTray"); bool owned;
        try { owned = single.WaitOne(0); } catch (AbandonedMutexException) { owned = true; }
        if (!owned) return;
        ShowWindow(GetConsoleWindow(), 0); store = s;
        green = Dot(46, 170, 90); red = Dot(220, 60, 50); grey = Dot(150, 160, 165);
        var c = new WClass { Name = "DynAllowTray", Proc = Marshal.GetFunctionPointerForDelegate(proc) }; RegisterClass(ref c);
        var h = CreateWindowEx(0, c.Name, "DynAllow", 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (h == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        taskbar = RegisterWindowMessage("TaskbarCreated");
        notify = new Notify { Size = (uint)Marshal.SizeOf<Notify>(), Hwnd = h, Id = 1, Flags = 1 | 2 | 4, Callback = 0x8001, Icon = grey, Tip = "DynAllow", Info = "", Title = "" };
        Shell_NotifyIcon(0, ref notify); Update(); SetTimer(h, 1, 10000, IntPtr.Zero);
        try { while (GetMessage(out var m, IntPtr.Zero, 0, 0) > 0) { TranslateMessage(ref m); DispatchMessage(ref m); } }
        finally { Shell_NotifyIcon(2, ref notify); DestroyIcon(green); DestroyIcon(red); DestroyIcon(grey); single.ReleaseMutex(); }
        if (restart) Process.Start(new ProcessStartInfo(Path.Combine(Install.ProgramDir, "DynAllow.Agent.exe"), "tray") { UseShellExecute = false, CreateNoWindow = true });
    }
}

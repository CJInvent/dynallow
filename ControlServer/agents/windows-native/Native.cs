using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace DynAllow;
internal static class Native
{
    [StructLayout(LayoutKind.Sequential)] struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CryptProtectData(ref Blob input, string description, ref Blob entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)] static extern bool CryptUnprotectData(ref Blob input, IntPtr description, ref Blob entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr p);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CloseHandle(IntPtr h);
    public static byte[] Dpapi(byte[] bytes, bool protect)
    {
        var ent = Crypto.U("IPFailoverAgent-DEK-v1");
        var input = new Blob { Length = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) };
        var entropy = new Blob { Length = ent.Length, Data = Marshal.AllocHGlobal(ent.Length) };
        Blob result = default;
        try {
            Marshal.Copy(bytes, 0, input.Data, bytes.Length); Marshal.Copy(ent, 0, entropy.Data, ent.Length);
            bool ok = protect ? CryptProtectData(ref input, "DynAllow identity", ref entropy, IntPtr.Zero, IntPtr.Zero, 5, out result)
                : CryptUnprotectData(ref input, IntPtr.Zero, ref entropy, IntPtr.Zero, IntPtr.Zero, 1, out result);
            if (!ok) throw new System.Security.Cryptography.CryptographicException("DPAPI failed: " + Marshal.GetLastWin32Error());
            byte[] data = new byte[result.Length]; Marshal.Copy(result.Data, data, 0, data.Length); return data;
        } finally {
            for (int i = 0; i < input.Length; i++) Marshal.WriteByte(input.Data, i, 0);
            Marshal.FreeHGlobal(input.Data); Marshal.FreeHGlobal(entropy.Data);
            if (result.Data != IntPtr.Zero) { for (int i = 0; i < result.Length; i++) Marshal.WriteByte(result.Data, i, 0); LocalFree(result.Data); }
        }
    }
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateEventEx(ref SecurityAttributes attrs, string name, uint flags, uint access);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr OpenEvent(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetEvent(IntPtr h);
    const string CheckEvent = "Global\\IPFailoverAgentCheckNow";
    public static EventWaitHandle CreateCheckEvent()
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;;GA;;;SY)(A;;0x100002;;;IU)", 1, out var sd, out _)) throw new Win32Exception();
        try {
            var sa = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = sd };
            var h = CreateEventEx(ref sa, CheckEvent, 0, 0x1f0003);
            if (h == IntPtr.Zero) throw new Win32Exception();
            var wait = new EventWaitHandle(false, EventResetMode.AutoReset); wait.SafeWaitHandle = new SafeWaitHandle(h, true); return wait;
        } finally { LocalFree(sd); }
    }
    public static void CheckNow()
    {
        var h = OpenEvent(2, false, CheckEvent); if (h == IntPtr.Zero) throw new Win32Exception();
        try { if (!SetEvent(h)) throw new Win32Exception(); } finally { CloseHandle(h); }
    }
}
internal sealed class SleepRequest : IDisposable
{
    [StructLayout(LayoutKind.Sequential)] struct Reason { public uint Version, Flags; public IntPtr Text; }
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr PowerCreateRequest(ref Reason context);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool PowerSetRequest(IntPtr request, int type);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool PowerClearRequest(IntPtr request, int type);
    IntPtr handle;
    public string Status { get; private set; } = "off";
    public void Set(bool enabled)
    {
        if (!enabled) { Dispose(); Status = "off"; return; }
        if (handle != IntPtr.Zero) return;
        var text = Marshal.StringToHGlobalUni("DynAllow agent: administrator enabled automatic-sleep prevention");
        try {
            var context = new Reason { Flags = 1, Text = text }; handle = PowerCreateRequest(ref context);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1)) { handle = IntPtr.Zero; throw new Win32Exception(); }
            // PowerRequestSystemRequired = 1. Does not keep display on or block manual sleep/shutdown.
            if (!PowerSetRequest(handle, 1)) { Native.CloseHandle(handle); handle = IntPtr.Zero; throw new Win32Exception(); }
            Status = "on";
        } catch { Status = "failed"; throw; }
        finally { Marshal.FreeHGlobal(text); }
    }
    public void Dispose() { if (handle != IntPtr.Zero) { PowerClearRequest(handle, 1); Native.CloseHandle(handle); handle = IntPtr.Zero; } }
}
internal static class WindowsService
{
    public const string Name = "DynAllowAgent";
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate void ServiceMain(uint count, IntPtr args);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate uint Handler(uint control, uint type, IntPtr data, IntPtr context);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct Table { [MarshalAs(UnmanagedType.LPWStr)] public string? Name; public IntPtr Main; }
    [StructLayout(LayoutKind.Sequential)] struct Status { public uint Type, State, Accepted, Win32Exit, ServiceExit, Checkpoint, WaitHint; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool StartServiceCtrlDispatcher([In] Table[] table);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr RegisterServiceCtrlHandlerEx(string name, Handler handler, IntPtr context);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool SetServiceStatus(IntPtr h, ref Status status);
    static readonly ServiceMain main = OnMain;
    static readonly Handler handler = OnControl;
    static readonly CancellationTokenSource stop = new();
    static Func<CancellationToken, Task>? run;
    static IntPtr statusHandle;
    static uint currentState = 2;
    static void Report(uint state, uint exit = 0)
    {
        currentState = state;
        var s = new Status { Type = 0x10, State = state, Accepted = state == 4 ? 5u : 0u, Win32Exit = exit, WaitHint = state is 2 or 3 ? 30000u : 0u, Checkpoint = state is 2 or 3 ? 1u : 0u };
        SetServiceStatus(statusHandle, ref s);
    }
    static uint OnControl(uint control, uint type, IntPtr data, IntPtr ctx)
    {
        if (control is 1 or 5) { Report(3); stop.Cancel(); }
        else if (control == 4) Report(currentState);
        return 0;
    }
    static void OnMain(uint count, IntPtr args)
    {
        statusHandle = RegisterServiceCtrlHandlerEx(Name, handler, IntPtr.Zero);
        if (statusHandle == IntPtr.Zero) return;
        Report(4);
        try { run!(stop.Token).GetAwaiter().GetResult(); Report(1); }
        catch (OperationCanceledException) { Report(1); }
        catch (Exception e) { try { var s = Program.DefaultStore(); s.Initialize(); new AgentLog(s).Write("error", "Service terminated: " + e.Message); } catch { } Report(1, 1066); Environment.Exit(1); }
    }
    public static void Run(Func<CancellationToken, Task> work)
    {
        run = work;
        if (!StartServiceCtrlDispatcher([new Table { Name = Name, Main = Marshal.GetFunctionPointerForDelegate(main) }, new Table()])) throw new Win32Exception(Marshal.GetLastWin32Error(), "Start as a Windows service, or use run for console mode");
    }
}

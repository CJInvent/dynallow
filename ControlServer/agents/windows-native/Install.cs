using System.Diagnostics;
using System.Security.Principal;
using System.Security.AccessControl;
using Microsoft.Win32;
namespace DynAllow;
internal static class Install
{
    public static string ProgramDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "DynAllow");
    static void RejectLinks(string path)
    {
        if (!Directory.Exists(path) && !File.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Refusing reparse point: " + path);
        if (Directory.Exists(path)) foreach (string child in Directory.EnumerateFileSystemEntries(path)) RejectLinks(child);
    }
    static void SecureTree(string path, bool readable)
    {
        // Replace the DACL, including explicit legacy grants, before writing secrets/code.
        var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { "S-1-5-18", "S-1-5-32-544" }) acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        if (readable) acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-32-545"), FileSystemRights.ReadAndExecute, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        acl.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
        new DirectoryInfo(path).SetAccessControl(acl);
        foreach (string child in Directory.EnumerateFileSystemEntries(path)) Command("icacls.exe", true, child, "/reset", "/T", "/Q");
    }
    public static void RequireAdmin()
    {
        using var who = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(who).IsInRole(WindowsBuiltInRole.Administrator) && !who.IsSystem) throw new UnauthorizedAccessException("Run this command in an elevated Administrator terminal");
    }
    internal static string Command(string file, bool mustSucceed, params string[] args)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, file)) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var p = Process.Start(start)!; var output = p.StandardOutput.ReadToEndAsync(); var error = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(60000)) { p.Kill(); throw new IOException(file + " timed out"); }
        string result = output.GetAwaiter().GetResult() + error.GetAwaiter().GetResult();
        if (mustSucceed && p.ExitCode != 0) throw new IOException(file + ": " + result);
        return result;
    }
    public static void StopService()
    {
        Command("sc.exe", false, "stop", WindowsService.Name);
        var deadline = DateTime.UtcNow.AddSeconds(35);
        while (DateTime.UtcNow < deadline) {
            string output = Command("sc.exe", false, "query", WindowsService.Name);
            // sc labels are localized, numeric STATE values are stable; error 1060 = absent.
            if (output.Contains("1060") || System.Text.RegularExpressions.Regex.IsMatch(output, @":\s+1\s+")) return;
            Thread.Sleep(300);
        }
        throw new IOException("Service did not stop within 35 seconds");
    }
    public static void StartService() => Command("sc.exe", true, "start", WindowsService.Name);
    public static void Disable()
    {
        Command("sc.exe", true, "config", WindowsService.Name, "start=", "disabled");
        using var run = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true); run?.DeleteValue("DynAllowTray", false);
    }
    public static void Setup(string? profile, bool reprovision, bool tray)
    {
        RequireAdmin(); Updates.PublicPem(); // refuse production installs without an offline trust anchor
        var store = Program.DefaultStore(); RejectLinks(store.Data); RejectLinks(ProgramDir);
        store.Initialize();
        if (profile is not null) {
            var p = Store.ReadPath(Path.GetFullPath(profile)) ?? throw new FileNotFoundException("Profile missing");
            if (p.S("format") != "dynallow-provisioning" || p.S("enroll_token") == "") throw new InvalidDataException("Invalid profile");
            if (store.Read("state.json").B("enrolled") && !reprovision) throw new InvalidOperationException("Already enrolled. Omit --profile to migrate/upgrade existing identity, or use --reprovision deliberately");
        }
        if (reprovision && profile is null) throw new InvalidOperationException("--reprovision requires --profile");
        StopService();
        SecureTree(store.Data, false);
        SecureTree(store.Public, true);
        // Remove the legacy supervisor before starting the new service. Keep its data/key formats intact.
        foreach (string task in new[] { "IPFailoverAgent", "IPFailoverTray", "IPUpdater", "IPUpdaterTray" }) {
            Command("schtasks.exe", false, "/End", "/TN", task);
            Command("schtasks.exe", false, "/Delete", "/TN", task, "/F");
        }
        // The retired PowerShell agent's scripts (they ran as SYSTEM). Its identity in ProgramData stays and is reused.
        string legacyProgram = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "IPFailoverAgent");
        try { if (Directory.Exists(legacyProgram)) { RejectLinks(legacyProgram); Directory.Delete(legacyProgram, true); } }
        catch (Exception e) { Console.WriteLine("Could not remove " + legacyProgram + ": " + AgentLog.Clean(e.Message)); }
        Directory.CreateDirectory(ProgramDir);
        SecureTree(ProgramDir, true);
        string exe = Path.Combine(ProgramDir, "DynAllow.Agent.exe");
        if (!string.Equals(Environment.ProcessPath, exe, StringComparison.OrdinalIgnoreCase)) {
            if (File.Exists(exe)) File.Move(exe, exe + ".old." + Guid.NewGuid().ToString("N"));
            File.Copy(Environment.ProcessPath!, exe);
        }
        if (reprovision) {
            foreach (string f in new[] { "state.json", "master.key", "agent-key.json", "DECOMMISSIONED", "log-spool.json" }) store.Destroy(f);
            try { using var k = Identity.TpmKey(false); k.Delete(); } catch { }
        }
        if (profile is not null) { store.Write("provisioning.json", Store.ReadPath(Path.GetFullPath(profile))!); File.Delete(profile); store.Destroy("DECOMMISSIONED"); }
        if (store.Read("state.json") is null && store.Read("provisioning.json") is null) throw new InvalidOperationException("Supply --profile for a new installation");
        string bin = '"' + exe + "\" service";
        Command("sc.exe", false, "create", WindowsService.Name, "binPath=", bin, "start=", "auto", "obj=", "LocalSystem", "DisplayName=", "DynAllow IP agent");
        Command("sc.exe", true, "config", WindowsService.Name, "binPath=", bin, "start=", "auto", "obj=", "LocalSystem");
        Command("sc.exe", true, "description", WindowsService.Name, "Reports this site's public IP to the DynAllow control server. Independently signed updates; no DNS provider credentials.");
        Command("sc.exe", true, "failure", WindowsService.Name, "reset=", "86400", "actions=", "restart/30000/restart/60000/restart/300000");
        Command("sc.exe", true, "failureflag", WindowsService.Name, "1");
        using (var run = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) {
            if (tray) run.SetValue("DynAllowTray", '"' + exe + "\" tray"); else run.DeleteValue("DynAllowTray", false);
        }
        StartService();
        Console.WriteLine("Installed. The service starts at boot. Tray appears at each user sign-in; run 'DynAllow.Agent.exe tray' to show it now. Logs: " + store.Public);
    }
    public static void Remove(bool purge)
    {
        RequireAdmin(); StopService(); Command("sc.exe", false, "delete", WindowsService.Name);
        using var run = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true); run?.DeleteValue("DynAllowTray", false);
        if (purge) { try { using var k = Identity.TpmKey(false); k.Delete(); } catch { } Directory.Delete(Program.DefaultStore().Data, true); }
        Console.WriteLine("Service and sign-in entry removed. " + (purge ? "Identity deleted." : "Identity retained for reinstall; add --purge to destroy it.") + " Remove the Program Files directory after this process exits.");
    }
}

namespace DynAllow;
internal static class Program
{
    public static Store DefaultStore() => new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "IPFailoverAgent"));
    static int Main(string[] args)
    {
        try {
            string mode = args.FirstOrDefault() ?? "service";
            if (mode == "self-test") { SelfTest.Run(args.Skip(1).ToArray()); return 0; }
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows agent requires Windows");
            switch (mode) {
                case "windows-test": WindowsTests.Run(); break;
                case "service": WindowsService.Run(ct => new Agent(DefaultStore()).Run(ct)); break;
                case "run":
                case "once":
                    Install.RequireAdmin(); using (var stop = new CancellationTokenSource()) {
                        Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
                        new Agent(DefaultStore()).Run(stop.Token, mode == "once").GetAwaiter().GetResult();
                    } break;
                case "install":
                    int index = Array.IndexOf(args, "--profile");
                    Install.Setup(index >= 0 && index + 1 < args.Length ? args[index + 1] : null, args.Contains("--reprovision"), !args.Contains("--no-tray")); break;
                case "uninstall": Install.Remove(args.Contains("--purge")); break;
                case "apply-update": Updates.Apply(args.ElementAtOrDefault(1) ?? throw new ArgumentException("Missing update path")); break;
                case "tray": Tray.Run(DefaultStore()); break;
                case "check": Native.CheckNow(); break;
                case "status": Console.WriteLine(File.ReadAllText(Path.Combine(DefaultStore().Public, "status.json"))); break;
                default: Console.WriteLine("DynAllow.Agent.exe install [--profile FILE] [--reprovision] [--no-tray] | uninstall [--purge] | service | run | once | tray | check | status"); break;
            }
            return 0;
        } catch (Exception e) { Console.Error.WriteLine(AgentLog.Clean(e.Message)); return 1; }
    }
}

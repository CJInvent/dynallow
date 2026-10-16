using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
namespace DynAllow;
internal static partial class Updates
{
    public const int MaxBytes = 67108864;
    [GeneratedRegex(@"^[a-f0-9]{64}$")] private static partial Regex HashPattern();
    [GeneratedRegex(@"^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}$")] private static partial Regex VersionPattern();
    public static string PublicPem()
    {
        if (BuildInfo.DevelopmentUpdates) return "";
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("release-public.pem") ?? throw new InvalidOperationException("No offline release public key embedded; rebuild with release-public.pem");
        using var reader = new StreamReader(stream); string pem = reader.ReadToEnd();
        if (pem.Contains("PRIVATE KEY")) throw new InvalidDataException("Trust anchor must be public only");
        using var key = ECDsa.Create(); key.ImportFromPem(pem); if (key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7") throw new InvalidDataException("Expected P-256 release key");
        return pem;
    }
    public static (JsonObject Manifest, byte[] Executable) Verify(string json, string pem, string target, int sequence, string version, bool allowDevelopment = false)
    {
        if (Encoding.UTF8.GetByteCount(json) > MaxBytes) throw new InvalidDataException("Release too large");
        var bundle = J.Obj(json); if (bundle.S("manifest").Length > 12000) throw new InvalidDataException("Manifest too large");
        var raw = Crypto.B(bundle.S("manifest")); var sig = Crypto.B(bundle.S("signature"));
        var m = J.Obj(Encoding.UTF8.GetString(raw));
        bool development = m.S("format") == "dynallow-dev-release-v1";
        if (development) {
            if (!allowDevelopment || sig.Length != 0) throw new CryptographicException("Development release not permitted");
        } else {
            using var key = ECDsa.Create(); key.ImportFromPem(pem);
            if (!key.VerifyData(raw, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)) throw new CryptographicException("Offline release signature invalid");
        }
        if ((m.S("format") != "dynallow-release-v1" && !development) || m.S("target") != target || m.N("sequence") <= sequence || m.N("sequence") > int.MaxValue
            || !VersionPattern().IsMatch(m.S("version")) || Version.Parse(m.S("version")) <= Version.Parse(version)) throw new InvalidDataException("Release target/version/sequence rejected");
        if (m["files"] is not JsonArray files || files.Count != 1 || files[0].S("name") != "DynAllow.Agent.exe"
            || bundle["files"] is not JsonObject content || content.Count != 1 || !content.ContainsKey("DynAllow.Agent.exe")) throw new InvalidDataException("Unexpected release filenames");
        var f = files[0]!; var bytes = Crypto.B(content.S("DynAllow.Agent.exe"));
        if (bytes.Length == 0 || bytes.Length > 48000000 || bytes.Length != f.N("size") || !HashPattern().IsMatch(f.S("sha256"))
            || Crypto.Hex(SHA256.HashData(bytes)) != f.S("sha256")) throw new InvalidDataException("Release hash/size mismatch");
        return (m, bytes);
    }
    public static async Task Stage(JsonObject offer, JsonObject state, Store store, AgentLog log, CancellationToken ct)
    {
        string hash = offer.S("sha256"); long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (!HashPattern().IsMatch(hash) || offer.N("size") is < 1 or > MaxBytes) throw new InvalidDataException("Invalid update offer");
        if (state.S("update_attempt_hash") == hash && now - state.N("update_attempt_at") < 3600) return;
        state["update_attempt_hash"] = hash; state["update_attempt_at"] = now; store.Write("state.json", state);
        var pem = PublicPem();
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMinutes(3) };
        using var response = await http.GetAsync(state.S("control_url").TrimEnd('/') + "/release.php?sha256=" + hash, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode(); var bytes = await Agent.ReadBounded(response, MaxBytes, ct);
        if (bytes.Length != offer.N("size") || Crypto.Hex(SHA256.HashData(bytes)) != hash) throw new InvalidDataException("Downloaded release hash/size mismatch");
        var watermark = store.Read("update-watermark.json");
        var (manifest, _) = Verify(Encoding.UTF8.GetString(bytes), pem, Agent.Target, (int)Math.Max(BuildInfo.Sequence, watermark.N("sequence")), BuildInfo.Version, BuildInfo.DevelopmentUpdates);
        string dir = Path.Combine(Install.ProgramDir, "update"); Directory.CreateDirectory(dir);
        string bundle = Path.Combine(dir, "release.json"); Store.WritePath(bundle, Encoding.UTF8.GetString(bytes));
        string runner = Path.Combine(dir, "DynAllow.Update.exe");
        // Only an existing trusted executable becomes the elevated updater; never run downloaded bytes before verification.
        File.Copy(Environment.ProcessPath!, runner, true);
        state["update_status"] = "Staged verified release " + manifest.S("version"); store.Write("state.json", state); log.Write("info", state.S("update_status"));
        var start = new ProcessStartInfo(runner) { UseShellExecute = false, CreateNoWindow = true };
        start.ArgumentList.Add("apply-update"); start.ArgumentList.Add(bundle);
        using var updater = Process.Start(start) ?? throw new IOException("Could not start updater");
    }
    public static void Apply(string bundlePath)
    {
        Install.RequireAdmin();
        string expected = Path.Combine(Install.ProgramDir, "update", "release.json");
        if (!string.Equals(Path.GetFullPath(bundlePath), expected, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Update path is not the protected staging path");
        var store = Program.DefaultStore(); var log = new AgentLog(store); var watermark = store.Read("update-watermark.json");
        if (new FileInfo(bundlePath).Length > MaxBytes) throw new InvalidDataException("Oversized update");
        var (m, exe) = Verify(File.ReadAllText(bundlePath), PublicPem(), Agent.Target, (int)Math.Max(BuildInfo.Sequence, watermark.N("sequence")), BuildInfo.Version, BuildInfo.DevelopmentUpdates);
        var exePath = Path.Combine(Install.ProgramDir, "DynAllow.Agent.exe"); var backup = exePath + ".previous";
        Install.StopService(); // waits for clean stop, releases power request
        bool swapped = false;
        try {
            if (File.Exists(store.PathFor("DECOMMISSIONED"))) throw new InvalidOperationException("Agent decommissioned while update was staged");
            var next = exePath + ".next"; File.WriteAllBytes(next, exe);
            // Rename the loaded image: signed-in tray processes may still map the old EXE.
            if (File.Exists(backup)) File.Move(backup, backup + "." + Guid.NewGuid().ToString("N"));
            File.Move(exePath, backup); swapped = true; File.Move(next, exePath);
            store.Destroy("startup.json");
            Install.StartService();
            var deadline = DateTime.UtcNow.AddSeconds(45); bool healthy = false;
            while (DateTime.UtcNow < deadline) {
                Thread.Sleep(500);
                try { var started = store.Read("startup.json"); if (started.S("version") == m.S("version") && started.N("sequence") == m.N("sequence")) { healthy = true; break; } } catch (IOException) { }
            }
            if (!healthy) throw new IOException("Updated service did not initialize with expected version/sequence");
            store.Write("update-watermark.json", new JsonObject { ["sequence"] = m.N("sequence"), ["version"] = m.S("version") });
            store.Write("update-result.json", new JsonObject { ["message"] = "Installed verified release " + m.S("version") });
            log.Write("info", "Verified release installed: " + m.S("version"));
            try { File.Delete(backup); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            File.Delete(bundlePath);
        } catch (Exception e) {
            if (swapped && File.Exists(backup)) {
                Install.StopService(); if (File.Exists(exePath)) File.Move(exePath, exePath + ".failed." + Guid.NewGuid().ToString("N"));
                File.Move(backup, exePath); Install.StartService();
            }
            store.Write("update-result.json", new JsonObject { ["message"] = AgentLog.Clean("Update failed; previous executable restored: " + e.Message) });
            log.Write("error", "Update failed; previous executable restored: " + e.Message);
            throw;
        }
    }
}

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
namespace DynAllow;

internal static class J
{
    // Read by JSON kind, never by CLR type: a node built in memory from an int is a JsonValue<int>, and
    // GetValue<long>() on it THROWS (that crashed the first cycle after provisioning). PHP may also send
    // 1/0 for booleans or numbers where strings are expected. Wrong-kind values fall back, never throw.
    public static string S(this JsonNode? o, string k, string fallback = "") => o?[k] is JsonValue v ? v.GetValueKind() switch {
        JsonValueKind.String => v.GetValue<string>(),
        JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => v.ToJsonString(),
        _ => fallback } : fallback;
    public static long N(this JsonNode? o, string k, long fallback = 0)
    {
        if (o?[k] is not JsonValue v) return fallback;
        string text = v.GetValueKind() switch { JsonValueKind.Number => v.ToJsonString(), JsonValueKind.String => v.GetValue<string>(), _ => "" };
        if (long.TryParse(text, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out long l)) return l;
        return double.TryParse(text, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double d) && Math.Abs(d) < 9e18 ? (long)d : fallback;
    }
    public static bool B(this JsonNode? o, string k, bool fallback = false) => o?[k] is JsonValue v ? v.GetValueKind() switch {
        JsonValueKind.True => true, JsonValueKind.False => false,
        JsonValueKind.Number => o.N(k) != 0,
        JsonValueKind.String => v.GetValue<string>() is "1" or "true",
        _ => fallback } : fallback;
    public static JsonObject Obj(string s) => JsonNode.Parse(s, documentOptions: new() { MaxDepth = 32 }) as JsonObject ?? throw new InvalidDataException("Expected JSON object");
    public static JsonNode? Copy(this JsonNode? n) => n?.DeepClone();
}
internal sealed class Store(string data)
{
    public string Data { get; } = Path.GetFullPath(data);
    public string Public => Path.Combine(Data, "public");
    public string PathFor(string name) => Path.Combine(Data, name);
    public void Initialize() { Directory.CreateDirectory(Data); Directory.CreateDirectory(Public); }
    public JsonObject? Read(string name) => ReadPath(PathFor(name));
    public static JsonObject? ReadPath(string path)
    {
        if (!File.Exists(path)) return null;
        if (new FileInfo(path).Length > 4 * 1024 * 1024) throw new InvalidDataException("Persisted file exceeds size limit: " + Path.GetFileName(path));
        return J.Obj(File.ReadAllText(path)); // corrupt files never silently create new identity
    }
    public void Write(string name, JsonObject value) => WritePath(PathFor(name), value.ToJsonString());
    public static void WritePath(string path, string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        string tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try {
            using (var f = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { f.Write(bytes); f.Flush(true); }
            File.Move(tmp, path, true);
            if (!File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes)) throw new IOException("Read-back verification failed");
        } finally { if (File.Exists(tmp)) File.Delete(tmp); }
    }
    public void Destroy(string name) { var p = PathFor(name); if (File.Exists(p)) File.Delete(p); }
}
internal sealed partial class AgentLog(Store store)
{
    readonly object gate = new();
    // Service and elevated updater share the spool; tray is read-only.
    sealed class SpoolLock : IDisposable
    {
        readonly Mutex mutex = new(false, OperatingSystem.IsWindows() ? @"Global\DynAllowAgentLog" : "DynAllowAgentLog");
        public SpoolLock() { try { if (!mutex.WaitOne(TimeSpan.FromSeconds(10))) throw new IOException("Log spool lock timeout"); } catch (AbandonedMutexException) { } }
        public void Dispose() { mutex.ReleaseMutex(); mutex.Dispose(); }
    }
    [GeneratedRegex(@"https?://[^\s<>""']+", RegexOptions.IgnoreCase)] private static partial Regex Url();
    [GeneratedRegex(@"\b(password|token|secret|authorization|enroll_token|private_pem)\s*[:=]\s*\S+", RegexOptions.IgnoreCase)] private static partial Regex Secret();
    public static string Clean(string text) { text = Secret().Replace(Url().Replace(text, "[URL]"), "$1=[REDACTED]"); return text.Length > 400 ? text[..400] : text; }
    public void Write(string level, string message)
    {
        lock (gate) {
            using var shared = new SpoolLock();
            message = Clean(message); level = level.ToLowerInvariant();
            var q = store.Read("log-spool.json") ?? new JsonObject { ["entries"] = new JsonArray() };
            var entries = (JsonArray)q["entries"]!;
            entries.Add((JsonNode)new JsonObject { ["id"] = Guid.NewGuid().ToString("N"), ["at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["level"] = level, ["message"] = message });
            if (entries.Count > 500) {
                while (entries.Count > 498) entries.RemoveAt(0);
                entries.Insert(0, new JsonObject { ["id"] = Guid.NewGuid().ToString("N"), ["at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["level"] = "warn", ["message"] = "Log spool overflow: oldest undelivered entries dropped (500 entry limit)" });
            }
            store.Write("log-spool.json", q);
            var path = Path.Combine(store.Public, "agent.log");
            if (File.Exists(path) && new FileInfo(path).Length > 1048576) File.Move(path, path + ".1", true);
            File.AppendAllText(path, $"{DateTimeOffset.UtcNow:O} [{level}] {message}{Environment.NewLine}");
            if (Environment.UserInteractive) Console.WriteLine($"[{level}] {message}");
        }
    }
    public JsonArray Batch()
    {
        lock (gate) {
            using var shared = new SpoolLock();
            var entries = store.Read("log-spool.json")?["entries"] as JsonArray;
            return new JsonArray(entries?.Take(20).Select(x => x.Copy()).ToArray() ?? []);
        }
    }
    public void Ack(JsonArray sent, JsonArray? received)
    {
        if (received is null) return;
        var ack = received.Select(x => x!.GetValue<string>()).Intersect(sent.Select(x => x.S("id"))).ToHashSet();
        lock (gate) {
            using var shared = new SpoolLock();
            var q = store.Read("log-spool.json"); if (q?["entries"] is not JsonArray entries) return;
            for (int i = entries.Count - 1; i >= 0; i--) if (ack.Contains(entries[i].S("id"))) entries.RemoveAt(i);
            store.Write("log-spool.json", q);
        }
    }
}

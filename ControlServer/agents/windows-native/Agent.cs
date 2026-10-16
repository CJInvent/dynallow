using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Win32;
namespace DynAllow;
internal sealed class Agent(Store store)
{
    readonly AgentLog log = new(store);
    readonly HttpClient http = new(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(35) };
    public static string Target => RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "windows-arm64" : "windows-x64";
    static long Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    JsonObject ConsumeProfile()
    {
        var state = store.Read("state.json"); var p = store.Read("provisioning.json");
        if (p is null) return state ?? throw new InvalidDataException("Not provisioned");
        if (state.B("enrolled")) { store.Destroy("provisioning.json"); log.Write("warn", "Already enrolled; ignored extra provisioning profile"); return state!; }
        Profile.Validate(p);
        state = new JsonObject { ["control_url"] = p.S("control_url"), ["server_key_id"] = p.S("server_key_id"), ["server_key"] = p.S("server_key"), ["agent_uid"] = p.S("agent_uid"), ["site_name"] = p.S("site_name"), ["enroll_token"] = p.S("enroll_token"), ["enrolled"] = false, ["interval"] = 300, ["clock_offset"] = 0, ["ip_check_urls"] = new JsonArray() };
        store.Write("state.json", state); store.Destroy("provisioning.json");
        log.Write("info", "Provisioning profile persisted and consumed"); return state;
    }
    internal static async Task<byte[]> ReadBounded(HttpResponseMessage response, int limit, CancellationToken ct)
    {
        if (response.Content.Headers.ContentLength > limit) throw new IOException("HTTP body exceeds limit");
        await using var stream = await response.Content.ReadAsStreamAsync(ct); using var output = new MemoryStream(); var buffer = new byte[8192]; int n;
        while ((n = await stream.ReadAsync(buffer, ct)) > 0) { if (output.Length + n > limit) throw new IOException("HTTP body exceeds limit"); output.Write(buffer, 0, n); }
        return output.ToArray();
    }
    async Task<JsonObject> Request(JsonObject state, JsonObject plain, Identity identity, JsonNode key, CancellationToken ct)
    {
        for (int attempt = 0; ; attempt++) {
            plain["ts"] = Now + state.N("clock_offset");
            // Rotation proof binds a caller-provided nonce; retry that proof with a fresh request only if not consumed (clock error).
            if (attempt == 0 && plain["nonce"] is null) plain["nonce"] = Crypto.Hex(RandomNumberGenerator.GetBytes(16));
            var (body, context) = Wire.Seal(state, plain, data => identity.Sign(key, data));
            using var req = new HttpRequestMessage(HttpMethod.Post, state.S("control_url").TrimEnd('/') + "/api/v1.php") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            req.Headers.UserAgent.ParseAdd("dynallow-agent/" + BuildInfo.Version);
            using var response = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            var result = Wire.Open(context, Encoding.UTF8.GetString(await ReadBounded(response, 1048576, ct)));
            state["clock_offset"] = result.N("server_ts") - Now;
            if (result["server_key"] is JsonObject sk) {
                using var valid = ECDsa.Create(Crypto.Params(Crypto.B(sk.S("public_key"))));
                state["server_key_id"] = sk.S("kid"); state["server_key"] = sk.S("public_key");
                log.Write("info", "Pinned online server key rotated");
            }
            if (result.S("error") == "clock_skew" && attempt == 0) continue;
            return result;
        }
    }
    async Task<string?> Observe(IEnumerable<string> urls, AddressFamily family, CancellationToken ct)
    {
        foreach (var url in urls.Take(5)) {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https") || uri.UserInfo != "") continue;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(8));
            try {
                using var response = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                response.EnsureSuccessStatusCode(); var text = Encoding.UTF8.GetString(await ReadBounded(response, 128, timeout.Token)).Trim();
                if (IPAddress.TryParse(text, out var ip) && ip.AddressFamily == family) return ip.ToString();
            } catch (Exception) when (!ct.IsCancellationRequested) { }
        }
        return null;
    }
    static string MachineId()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
        var id = key?.GetValue("MachineGuid") as string;
        return id is null ? "" : "win:" + Crypto.Hex(SHA256.HashData(Crypto.U(id)));
    }
    async Task<JsonObject> Cycle(JsonObject state, Identity identity, SleepRequest sleep, CancellationToken ct)
    {
        var result = store.Read("update-result.json");
        if (result is not null) state["update_status"] = result.S("message");
        var keys = identity.Load();
        var urls = (state["ip_check_urls"] as JsonArray)?.Select(n => n!.GetValue<string>()).ToArray();
        if (urls is null || urls.Length == 0) urls = ["https://api.ipify.org", "https://ipv4.icanhazip.com", "https://v4.ident.me"];
        var ipv4 = Observe(urls, AddressFamily.InterNetwork, ct);
        var ipv6 = Observe(["https://api6.ipify.org"], AddressFamily.InterNetworkV6, ct);
        await Task.WhenAll(ipv4, ipv6);
        var batch = log.Batch();
        var request = new JsonObject { ["agent"] = state.S("agent_uid"), ["observed_ipv4"] = ipv4.Result, ["observed_ipv6"] = ipv6.Result,
            ["version"] = BuildInfo.Version, ["platform"] = "windows", ["release_target"] = Target, ["release_sequence"] = BuildInfo.Sequence,
            ["os"] = RuntimeInformation.OSDescription, ["hostname"] = Environment.MachineName, ["machine_id"] = MachineId(),
            ["key_protector"] = identity.Protector, ["logs"] = batch.Copy(), ["sleep_status"] = sleep.Status, ["update_status"] = state.S("update_status") };
        string slot = keys["pending"] is not null && state.B("rotation_sent") ? "pending" : "active";
        if (!state.B("enrolled")) { request["type"] = "enroll"; request["enroll_token"] = state.S("enroll_token"); request["public_key"] = keys["active"].S("public"); slot = "active"; }
        else request["type"] = "checkin";
        var response = await Request(state, request, identity, keys[slot]!, ct);
        if (response.S("error") == "bad_signature" && slot == "pending") {
            state["rotation_sent"] = false; request.Remove("nonce");
            response = await Request(state, request, identity, keys["active"]!, ct);
        }
        if (!response.B("ok")) return response;
        log.Ack(batch, response["log_ack"] as JsonArray);
        state["enrolled"] = true; state.Remove("enroll_token");
        if (keys["pending"] is JsonObject pending && response.S("active_key_id") == pending.S("key_id")) {
            keys["active"] = pending.Copy(); keys.Remove("pending"); identity.Save(keys); state["rotation_sent"] = false;
            log.Write("info", "Identity key rotation completed");
        }
        state["interval"] = Math.Clamp(response.N("interval", 300), 60, 86400);
        state["ip_check_urls"] = response["ip_check_urls"].Copy() ?? new JsonArray();
        if (response.B("rotate_key") || (keys["pending"] is not null && !state.B("rotation_sent"))) {
            if (keys["pending"] is null) { keys["pending"] = identity.NewKey(); identity.Save(keys); }
            string nonce = Crypto.Hex(RandomNumberGenerator.GetBytes(16)); string pub = keys["pending"].S("public");
            var proof = identity.Sign(keys["pending"]!, Crypto.U("IPF1|rotate|" + state.S("agent_uid") + "|" + nonce + "|" + pub));
            var rotation = new JsonObject { ["type"] = "rotate", ["agent"] = state.S("agent_uid"), ["nonce"] = nonce, ["new_public_key"] = pub, ["new_key_proof"] = Crypto.B64(proof), ["key_protector"] = identity.Protector };
            var r = await Request(state, rotation, identity, keys["active"]!, ct);
            state["rotation_sent"] = r.B("ok"); log.Write(r.B("ok") ? "info" : "warn", r.B("ok") ? "Pending identity key registered" : "Identity rotation retry needed: " + r.S("error"));
        }
        bool preventSleep = response.B("prevent_sleep") && !response.B("decommission");
        state["prevent_sleep"] = preventSleep;
        try { string before = sleep.Status; sleep.Set(preventSleep); if (before != sleep.Status) log.Write("info", "Automatic-sleep prevention " + sleep.Status); }
        catch (Exception e) { log.Write("error", "Cannot set sleep prevention: " + e.Message); }
        store.Write("state.json", state);
        if (!response.B("decommission") && response["update"] is JsonObject offer) {
            try { await Updates.Stage(offer, state, store, log, ct); }
            catch (Exception e) when (!ct.IsCancellationRequested) { state["update_status"] = AgentLog.Clean("Update rejected: " + e.Message); log.Write("error", state.S("update_status")); }
        }
        return response;
    }
    public async Task Run(CancellationToken ct, bool once = false)
    {
        store.Initialize();
        using var single = new Mutex(false, @"Global\DynAllowAgentProcess");
        bool owned; try { owned = single.WaitOne(0); } catch (AbandonedMutexException) { owned = true; }
        if (!owned) throw new InvalidOperationException("Another agent process is running");
        // Mutex thread-affinity is avoided by owning it for process lifetime, never ReleaseMutex after an await.
        using var check = Native.CreateCheckEvent();
        using var sleep = new SleepRequest();
        if (File.Exists(store.PathFor("DECOMMISSIONED"))) return;
        var state = ConsumeProfile(); var identity = new Identity(store, log);
        identity.Load();
        if (state.B("prevent_sleep")) try { sleep.Set(true); } catch (Exception e) { log.Write("error", "Sleep prevention restore failed: " + e.Message); }
        log.Write("info", "DynAllow " + BuildInfo.Version + " started; " + identity.Protector + " identity protection");
        store.Write("startup.json", new JsonObject { ["version"] = BuildInfo.Version, ["sequence"] = BuildInfo.Sequence, ["at"] = Now });
        var previous = Store.ReadPath(Path.Combine(store.Public, "status.json")) ?? new JsonObject();
        try {
            while (!ct.IsCancellationRequested) {
                JsonObject response = new(); string? error = null;
                try { response = await Cycle(state, identity, sleep, ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception e) { error = AgentLog.Clean(e.Message); }
                store.Write("state.json", state);
                bool ok = error is null && response.B("ok");
                var status = new JsonObject { ["agent_uid"] = state.S("agent_uid"), ["site"] = state.S("site_name"), ["updated_at"] = Now, ["version"] = BuildInfo.Version,
                    ["interval"] = state.N("interval", 300), ["server_ok"] = ok, ["key_protector"] = identity.Protector, ["sleep_status"] = sleep.Status,
                    ["update_status"] = state.S("update_status"), ["server_error"] = ok ? null : error ?? response.S("error") + ": " + response.S("message") };
                if (ok) {
                    status["last_success_at"] = Now; status["ip"] = response["ip"].Copy(); status["targets"] = response["targets"].Copy(); status["enabled"] = response["agent"]?["enabled"].Copy();
                    log.Write("info", "Checked in; authoritative IP " + response["ip"].S("authoritative", "none"));
                } else {
                    foreach (var key in new[] { "last_success_at", "ip", "targets", "enabled" }) status[key] = previous[key].Copy();
                    log.Write("error", status.S("server_error"));
                }
                Store.WritePath(Path.Combine(store.Public, "status.json"), status.ToJsonString()); previous = status;
                if (ok && response.B("decommission")) {
                    log.Write("warn", "Decommissioned: removing identity and disabling service");
                    try {
                        var keys = identity.Load();
                        var ack = new JsonObject { ["type"] = "decommission_ack", ["agent"] = state.S("agent_uid"), ["logs"] = log.Batch() };
                        await Request(state, ack, identity, keys["active"]!, ct);
                    } catch (Exception e) { log.Write("warn", "Decommission acknowledgment not delivered: " + e.Message); }
                    File.WriteAllText(store.PathFor("DECOMMISSIONED"), DateTimeOffset.UtcNow.ToString("O"));
                    foreach (var name in new[] { "state.json", "agent-key.json", "master.key", "provisioning.json" }) store.Destroy(name);
                    try { using var k = Identity.TpmKey(false); k.Delete(); } catch { }
                    sleep.Set(false); status["decommissioned"] = true; status["server_ok"] = false;
                    Store.WritePath(Path.Combine(store.Public, "status.json"), status.ToJsonString());
                    Install.Disable(); return;
                }
                if (once) return;
                int wait = ok ? (int)state.N("interval", 300) : new[] { "unknown_agent", "enroll_invalid", "enroll_expired", "protector_too_weak" }.Contains(response.S("error")) ? 900 : 60;
                int signaled = await Task.Run(() => WaitHandle.WaitAny([check, ct.WaitHandle], TimeSpan.FromSeconds(wait)), ct);
                if (signaled == 0) await Task.Delay(TimeSpan.FromSeconds(2), ct);
            }
        } finally { sleep.Set(false); http.Dispose(); }
    }
}

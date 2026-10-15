using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
namespace DynAllow;
internal static class Crypto
{
    public static byte[] U(string s) => Encoding.UTF8.GetBytes(s);
    public static byte[] B(string s) => Convert.FromBase64String(s);
    public static string B64(byte[] b) => Convert.ToBase64String(b);
    public static byte[] Join(params byte[][] b) { var r = new byte[b.Sum(x => x.Length)]; int i = 0; foreach (var v in b) { v.CopyTo(r, i); i += v.Length; } return r; }
    public static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    public static byte[] H(byte[] key, byte[] b) => HMACSHA256.HashData(key, b);
    public static byte[] Raw(ECParameters p) => Join([4], p.Q.X!, p.Q.Y!);
    public static ECParameters Params(byte[] raw, byte[]? d = null)
    {
        if (raw.Length != 65 || raw[0] != 4) throw new CryptographicException("Invalid P-256 public key");
        return new() { Curve = ECCurve.NamedCurves.nistP256, Q = new() { X = raw[1..33], Y = raw[33..65] }, D = d };
    }
    public static string KeyId(byte[] raw) => Hex(SHA256.HashData(raw))[..16];
    public static byte[] Encrypt(byte[] key, byte[] iv, byte[] data) { using var a = Aes.Create(); a.Key = key; return a.EncryptCbc(data, iv, PaddingMode.PKCS7); }
    public static byte[] Decrypt(byte[] key, byte[] iv, byte[] data) { using var a = Aes.Create(); a.Key = key; return a.DecryptCbc(data, iv, PaddingMode.PKCS7); }
}
internal sealed class Identity(Store store, AgentLog log)
{
    const string TpmName = "IPFailoverAgentMasterKey";
    byte[]? dek;
    public string Protector { get; private set; } = "unknown";
    public static CngKey TpmKey(bool create)
    {
        var provider = new CngProvider("Microsoft Platform Crypto Provider");
        if (CngKey.Exists(TpmName, provider, CngKeyOpenOptions.MachineKey)) return CngKey.Open(TpmName, provider, CngKeyOpenOptions.MachineKey);
        if (!create) throw new CryptographicException("TPM key missing; restore/reprovision deliberately");
        var p = new CngKeyCreationParameters { Provider = provider, KeyCreationOptions = CngKeyCreationOptions.MachineKey };
        p.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));
        return CngKey.Create(CngAlgorithm.Rsa, TpmName, p);
    }
    static byte[] Tpm(byte[] data, bool protect)
    {
        using var k = TpmKey(protect); using var rsa = new RSACng(k);
        return protect ? rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256) : rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
    }
    JsonObject Wrap(byte[] key)
    {
        try {
            var blob = Tpm(key, true);
            if (!CryptographicOperations.FixedTimeEquals(Tpm(blob, false), key)) throw new CryptographicException("TPM round-trip mismatch");
            return new() { ["protector"] = "tpm", ["blob"] = Crypto.B64(blob) };
        } catch (Exception e) when (e is CryptographicException || e is PlatformNotSupportedException) { log.Write("info", "TPM unavailable; using DPAPI machine protection"); }
        // New installs fail closed if DPAPI is unavailable. No plaintext fallback.
        return new() { ["protector"] = "dpapi", ["blob"] = Crypto.B64(Native.Dpapi(key, true)) };
    }
    public byte[] Dek()
    {
        if (dek is not null) return dek;
        var m = store.Read("master.key");
        if (m is null) {
            if (store.Read("agent-key.json") is not null) throw new CryptographicException("Identity exists but master.key is missing");
            dek = RandomNumberGenerator.GetBytes(32); m = Wrap(dek); store.Write("master.key", m);
        } else {
            var blob = Crypto.B(m.S("blob"));
            dek = m.S("protector") switch { "tpm" => Tpm(blob, false), "dpapi" => Native.Dpapi(blob, false), "plaintext" => blob, _ => throw new CryptographicException("Unknown key protector") };
            if (dek.Length != 32) throw new CryptographicException("Invalid master key");
            if (m.S("protector") != "tpm") {
                var stronger = Wrap(dek);
                if (m.S("protector") == "plaintext" || stronger.S("protector") == "tpm") { store.Write("master.key", stronger); m = stronger; log.Write("info", "Master key protection upgraded to " + m.S("protector")); }
            }
        }
        Protector = m.S("protector"); return dek;
    }
    string Seal(byte[] raw)
    {
        var key = Dek(); var iv = RandomNumberGenerator.GetBytes(16);
        var ct = Crypto.Encrypt(Crypto.H(key, Crypto.U("seal-enc")), iv, raw);
        return "sv1:" + Crypto.B64(Crypto.Join(iv, ct, Crypto.H(Crypto.H(key, Crypto.U("seal-mac")), Crypto.Join(iv, ct))));
    }
    byte[] Unseal(string s)
    {
        if (!s.StartsWith("sv1:")) throw new CryptographicException("Unknown sealed key format");
        var raw = Crypto.B(s[4..]); if (raw.Length < 64) throw new CryptographicException("Truncated sealed key");
        var key = Dek(); var iv = raw[..16]; var ct = raw[16..^32];
        if (!CryptographicOperations.FixedTimeEquals(raw[^32..], Crypto.H(Crypto.H(key, Crypto.U("seal-mac")), Crypto.Join(iv, ct)))) throw new CryptographicException("Identity integrity check failed");
        return Crypto.Decrypt(Crypto.H(key, Crypto.U("seal-enc")), iv, ct);
    }
    public JsonObject NewKey()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256); var p = ec.ExportParameters(true); var raw = Crypto.Raw(p);
        string sealedKey = Seal(p.D!); CryptographicOperations.ZeroMemory(p.D!);
        return new() { ["key_id"] = Crypto.KeyId(raw), ["public"] = Crypto.B64(raw), ["protector"] = Protector, ["sealed"] = sealedKey, ["created_at"] = DateTimeOffset.UtcNow.ToString("O") };
    }
    public byte[] Sign(JsonNode rec, byte[] data)
    {
        var d = Unseal(rec.S("sealed"));
        try { using var ec = ECDsa.Create(Crypto.Params(Crypto.B(rec.S("public")), d)); return ec.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        finally { CryptographicOperations.ZeroMemory(d); }
    }
    public JsonObject Load()
    {
        var keys = store.Read("agent-key.json");
        if (keys is null) {
            if (store.Read("state.json").B("enrolled")) throw new CryptographicException("Enrolled identity is missing; refusing to invent a replacement");
            keys = new() { ["active"] = NewKey() }; Save(keys);
        }
        Dek(); return keys;
    }
    public void Save(JsonObject keys)
    {
        store.Write("agent-key.json", keys); var back = store.Read("agent-key.json")!;
        foreach (var slot in new[] { "active", "pending" }) if (back[slot] is JsonObject rec) {
            var probe = RandomNumberGenerator.GetBytes(32); using var pub = ECDsa.Create(Crypto.Params(Crypto.B(rec.S("public"))));
            if (rec.S("public") != keys[slot].S("public") || !pub.VerifyData(probe, Sign(rec, probe), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new CryptographicException("Stored identity pair verification failed");
        }
    }
}
internal sealed record WireContext(byte[] ResponseEnc, byte[] ResponseMac, byte[] Epk, string Nonce);
internal static class Wire
{
    public static (string Body, WireContext Context) Seal(JsonObject state, JsonObject plain, Func<byte[], byte[]> signer)
    {
        using var eph = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var peer = ECDiffieHellman.Create(Crypto.Params(Crypto.B(state.S("server_key"))));
        var epk = Crypto.Raw(eph.ExportParameters(false));
        var k = eph.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256, Crypto.U("IPF1"), epk);
        byte[] Key(string label) => Crypto.H(k, Crypto.U(label));
        var iv = RandomNumberGenerator.GetBytes(16); var ct = Crypto.Encrypt(Key("req-enc"), iv, Crypto.U(plain.ToJsonString())); var kid = state.S("server_key_id");
        var mac = Crypto.H(Key("req-mac"), Crypto.Join(Crypto.U("IPF1|req|" + kid), epk, iv, ct));
        var sig = signer(Crypto.Join(Crypto.U("IPF1|sig|" + kid), epk, iv, ct, mac));
        var env = new JsonObject { ["v"] = 1, ["kid"] = kid, ["epk"] = Crypto.B64(epk), ["iv"] = Crypto.B64(iv), ["ct"] = Crypto.B64(ct), ["mac"] = Crypto.B64(mac), ["sig"] = Crypto.B64(sig) };
        return (env.ToJsonString(), new(Key("resp-enc"), Key("resp-mac"), epk, plain.S("nonce")));
    }
    public static JsonObject Open(WireContext c, string body)
    {
        var e = J.Obj(body); if (e.N("v") != 1) throw new CryptographicException("Unauthenticated server response");
        var iv = Crypto.B(e.S("iv")); var ct = Crypto.B(e.S("ct")); var mac = Crypto.B(e.S("mac"));
        if (iv.Length != 16 || !CryptographicOperations.FixedTimeEquals(mac, Crypto.H(c.ResponseMac, Crypto.Join(Crypto.U("IPF1|resp|"), c.Epk, iv, ct)))) throw new CryptographicException("Server response authentication failed");
        var p = J.Obj(Encoding.UTF8.GetString(Crypto.Decrypt(c.ResponseEnc, iv, ct)));
        if (p.S("req_nonce") != c.Nonce) throw new CryptographicException("Response nonce mismatch");
        return p;
    }
}

using System.Security.Cryptography;
using System.Text.Json.Nodes;
namespace DynAllow;
internal static class WindowsTests
{
    public static void Run()
    {
        if (Environment.GetEnvironmentVariable("DYNALLOW_DISPOSABLE_TEST") != "1") throw new InvalidOperationException("Windows tests require DYNALLOW_DISPOSABLE_TEST=1 on a disposable machine");
        var dir = Path.Combine(Path.GetTempPath(), "DynAllow-" + Guid.NewGuid().ToString("N"));
        var store = new Store(dir); store.Initialize();
        try {
            var secret = RandomNumberGenerator.GetBytes(32);
            if (!Native.Dpapi(Native.Dpapi(secret, true), false).SequenceEqual(secret)) throw new Exception("DPAPI round trip failed");
            Console.WriteLine("PASS: DPAPI machine-scope round trip");
            // Construct an actual v2 sv1 identity, then verify it survives the native migration.
            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256); var p = ec.ExportParameters(true); var raw = Crypto.Raw(p);
            var iv = RandomNumberGenerator.GetBytes(16); var ct = Crypto.Encrypt(Crypto.H(secret, Crypto.U("seal-enc")), iv, p.D!);
            var mac = Crypto.H(Crypto.H(secret, Crypto.U("seal-mac")), Crypto.Join(iv, ct));
            var record = new JsonObject { ["key_id"] = Crypto.KeyId(raw), ["public"] = Crypto.B64(raw), ["sealed"] = "sv1:" + Crypto.B64(Crypto.Join(iv, ct, mac)), ["protector"] = "plaintext" };
            store.Write("master.key", new JsonObject { ["protector"] = "plaintext", ["blob"] = Crypto.B64(secret) });
            store.Write("agent-key.json", new JsonObject { ["active"] = record });
            var identity = new Identity(store, new AgentLog(store)); var keys = identity.Load(); var data = RandomNumberGenerator.GetBytes(32);
            if (!ec.VerifyData(data, identity.Sign(keys["active"]!, data), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new Exception("Legacy identity migration failed");
            if (identity.Protector is not ("dpapi" or "tpm")) throw new Exception("Legacy plaintext protector not upgraded");
            Console.WriteLine("PASS: legacy sv1 identity preserved and protector upgraded to " + identity.Protector);
            using var power = new SleepRequest(); power.Set(true); if (power.Status != "on") throw new Exception("Power request failed"); power.Set(false);
            Console.WriteLine("PASS: power request enables and clears");
        } finally { Directory.Delete(dir, true); }
    }
}

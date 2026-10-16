namespace DynAllow;
internal static partial class BuildInfo
{
#if DYNALLOW_DEV_UPDATES
    public const bool DevelopmentUpdates = true;
#else
    public const bool DevelopmentUpdates = false;
#endif
    public static string UpdateChannel => DevelopmentUpdates ? "dev-sha256" : "signed";
}

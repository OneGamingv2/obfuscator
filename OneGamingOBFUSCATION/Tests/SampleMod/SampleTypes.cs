namespace UnityEngine
{
    public class MonoBehaviour { }
}

namespace BepInEx
{
    public class BaseUnityPlugin : UnityEngine.MonoBehaviour { }
}

namespace HarmonyLib
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public sealed class HarmonyPatch : Attribute { }
}

namespace SampleMod
{
    internal sealed class Helper
    {
        private readonly string secretField = "field-value";
        private string Secret => secretField;

        private static int Scramble(int value) => ((value * 7) ^ 31) + 5;

        private static int Branch(int value)
        {
            if (value > 2)
                return value * 2;
            return value - 1;
        }

        private string BuildMessage() => "fully-local:" + Secret + ":" + Scramble(3) + ":" + new Box<int>(Branch(4)).Value;

        internal string Run() => BuildMessage();
    }

    internal sealed class Box<T>
    {
        internal Box(T value) => Value = value;
        internal T Value { get; }
    }

    public sealed class Plugin : BepInEx.BaseUnityPlugin
    {
        public const string GUID = "com.mjb.gorillatag.sample";
        public const string Name = "SampleMod";
        public const string Version = "1.0.0";

        private string pluginState = "ready";

        public string State => pluginState;

        private void Awake() => pluginState = "awake:" + GUID;
    }

    [HarmonyLib.HarmonyPatch]
    internal static class Patch
    {
        private static void Prefix() { }
    }

    public static class Harness
    {
        private static string[] PreserveNames() => new[] { nameof(Harness), nameof(GetMessage), nameof(ReadEmbeddedMarker) };
        public static string GetMessage() => new Helper().Run();

        public static string ReadEmbeddedMarker()
        {
            using var stream = typeof(Harness).Assembly.GetManifestResourceStream("SampleMod.marker.txt");
            if (stream is null)
                return "missing";
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd().Trim();
        }
    }
}

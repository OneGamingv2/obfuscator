using OneGamingOBFUSCATION.Core;
using OneGamingOBFUSCATION.Protection;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;
using Xunit;

namespace OneGamingOBFUSCATION.Tests;

public sealed class ProtectAndExecuteTests
{
    private const string ExpectedMessage = "fully-local:field-value:15:8";
    private const string ProtectionKey = "unit-test-protection-key";

    [Fact]
    public void Unprotected_sample_mod_returns_expected_message()
    {
        Assert.Equal(ExpectedMessage, SampleMod.Harness.GetMessage());
        Assert.Equal("sample-resource-ok", SampleMod.Harness.ReadEmbeddedMarker());
    }

    [Fact]
    public void Protect_then_execute_preserves_behavior_and_entry_points()
    {
        var input = typeof(SampleMod.Harness).Assembly.Location;
        Assert.True(File.Exists(input), "SampleMod assembly was not found.");

        var outputDirectory = Path.Combine(Path.GetTempPath(), "OneGamingOBFUSCATION.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outputDirectory);
        var output = Path.Combine(outputDirectory, "SampleMod.Protected.dll");
        AssemblyLoadContext? context = null;

        try
        {
            var result = ObfuscationEngine.Protect(input, output, ObfuscationOptions.Maximum, ProtectionKey);

            Assert.False(result.IsLocked);
            Assert.True(File.Exists(output));
            Assert.True(File.Exists(result.IntegrityManifestPath));
            Assert.True(File.Exists(result.ReportPath));
            Assert.True(result.ProtectedStrings > 0);
            Assert.True(result.ProtectedResources > 0);
            Assert.True(result.RuntimeArtifacts > 0);
            Assert.Contains(result.Diagnostics, line => line.StartsWith("Const string fields:", StringComparison.Ordinal));
            Assert.Contains(result.Diagnostics, line => line.StartsWith("Virtualization", StringComparison.Ordinal));
            Assert.True(result.VirtualizedMethods > 0);
            Assert.Contains(result.Diagnostics, line => line.StartsWith("Control-flow maze:", StringComparison.Ordinal));
            Assert.Contains(result.Diagnostics, line => line.StartsWith("Embedded resources:", StringComparison.Ordinal));
            Assert.Contains("Lock protected outputs: False", File.ReadAllText(result.ReportPath));

            Assert.True(KeyedIntegrityProtection.Verify(output, result.IntegrityManifestPath, ProtectionKey));
            Assert.False(KeyedIntegrityProtection.Verify(output, result.IntegrityManifestPath, "wrong-key-wrong-key"));

            context = new AssemblyLoadContext("protected-sample", isCollectible: true);
            var assembly = context.LoadFromAssemblyPath(output);

            Assert.NotNull(assembly.GetType("SampleMod.Plugin"));
            Assert.NotNull(assembly.GetType("SampleMod.Plugin")!.GetMethod("Awake", BindingFlags.Instance | BindingFlags.NonPublic));
            Assert.Null(assembly.GetType("SampleMod.Plugin")!.GetField("GUID", BindingFlags.Public | BindingFlags.Static));
            Assert.Null(assembly.GetType("SampleMod.Plugin")!.GetField("Name", BindingFlags.Public | BindingFlags.Static));
            Assert.Null(assembly.GetType("SampleMod.Plugin")!.GetField("Version", BindingFlags.Public | BindingFlags.Static));

            Assert.NotNull(assembly.GetType("SampleMod.Patch"));
            Assert.NotNull(assembly.GetType("SampleMod.Patch")!.GetMethod("Prefix", BindingFlags.Static | BindingFlags.NonPublic));

            var harness = assembly.GetType("SampleMod.Harness");
            Assert.NotNull(harness);
            var getMessage = harness!.GetMethod("GetMessage", BindingFlags.Public | BindingFlags.Static);
            Assert.NotNull(getMessage);
            var actual = Assert.IsType<string>(getMessage!.Invoke(null, null));
            Assert.Equal(ExpectedMessage, actual);

            var pluginType = assembly.GetType("SampleMod.Plugin")!;
            System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(pluginType.TypeHandle);
            var decodedConsts = pluginType
                .GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
                .Where(field => field.FieldType == typeof(string))
                .Select(field => field.GetValue(null) as string)
                .Where(value => !string.IsNullOrEmpty(value))
                .ToArray();
            Assert.Contains("com.mjb.gorillatag.sample", decodedConsts);
            Assert.Contains("SampleMod", decodedConsts);
            Assert.Contains("1.0.0", decodedConsts);

            var readEmbedded = harness.GetMethod("ReadEmbeddedMarker", BindingFlags.Public | BindingFlags.Static);
            Assert.NotNull(readEmbedded);
            var marker = Assert.IsType<string>(readEmbedded!.Invoke(null, null));
            Assert.Equal("sample-resource-ok", marker);
        }
        finally
        {
            context?.Unload();
            TryDeleteDirectory(outputDirectory);
        }
    }

    [Fact]
    public void Optional_oglock_seal_unlocks_with_master_and_file_password()
    {
        var input = typeof(SampleMod.Harness).Assembly.Location;
        var outputDirectory = Path.Combine(Path.GetTempPath(), "OneGamingOBFUSCATION.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outputDirectory);
        var output = Path.Combine(outputDirectory, "sealed.dll");

        try
        {
            var options = ObfuscationOptions.RenameOnly with { AllowOverwrite = true, LockOutputs = true };
            var result = ObfuscationEngine.Protect(input, output, options, ProtectionKey);
            Assert.True(result.IsLocked);
            Assert.True(File.Exists(result.LockedPath));
            Assert.False(File.Exists(output));

            var viaFile = Path.Combine(outputDirectory, "via-file.dll");
            var unlockFile = FileLockProtection.UnlockFile(result.LockedPath!, viaFile, result.FilePassword!);
            Assert.False(unlockFile.UsedMasterPassword);

            var viaMaster = Path.Combine(outputDirectory, "via-master.dll");
            var unlockMaster = FileLockProtection.UnlockFile(result.LockedPath!, viaMaster, ProtectionKey, result.UnlockVaultPath);
            Assert.True(unlockMaster.UsedMasterPassword);
            Assert.Equal(result.Sha256, unlockMaster.ClearSha256, ignoreCase: true);
        }
        finally
        {
            TryDeleteDirectory(outputDirectory);
        }
    }

    [Fact]
    public void Protect_rejects_overwrite_unless_enabled()
    {
        var input = typeof(SampleMod.Harness).Assembly.Location;
        var outputDirectory = Path.Combine(Path.GetTempPath(), "OneGamingOBFUSCATION.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outputDirectory);
        var output = Path.Combine(outputDirectory, "once.dll");

        try
        {
            ObfuscationEngine.Protect(input, output, ObfuscationOptions.RenameOnly, ProtectionKey);
            Assert.Throws<IOException>(() =>
                ObfuscationEngine.Protect(input, output, ObfuscationOptions.RenameOnly, ProtectionKey));

            var withOverwrite = ObfuscationOptions.RenameOnly with { AllowOverwrite = true };
            var second = ObfuscationEngine.Protect(input, output, withOverwrite, ProtectionKey);
            Assert.True(File.Exists(second.ReportPath));
            Assert.False(second.IsLocked);
        }
        finally
        {
            TryDeleteDirectory(outputDirectory);
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
        }
        catch
        {
            // Best-effort cleanup for locked collectible contexts.
        }
    }
}

using dnlib.DotNet;
using dnlib.DotNet.Writer;
using OneGamingOBFUSCATION.Protection;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace OneGamingOBFUSCATION.Core;

public sealed record ObfuscationOptions(
    bool RenamePrivateMembers,
    bool RenameHelperTypes,
    bool AggressiveRenaming,
    bool ProtectStrings,
    bool ProtectIntegers,
    bool ProxyStaticCalls,
    bool VirtualizeInt32Methods,
    bool FlattenControlFlow,
    bool WeaveInstructions,
    bool ProtectEmbeddedResources,
    bool RuntimeObfuscation,
    bool HardenMetadataAndPe,
    bool ProtectWholeFolder,
    bool AllowOverwrite,
    bool MultilayerHardening,
    bool LockOutputs)
{
    public static ObfuscationOptions SafeDefaults { get; } = new(
        RenamePrivateMembers: true,
        RenameHelperTypes: true,
        AggressiveRenaming: true,
        ProtectStrings: true,
        ProtectIntegers: true,
        ProxyStaticCalls: true,
        VirtualizeInt32Methods: true,
        FlattenControlFlow: true,
        WeaveInstructions: true,
        ProtectEmbeddedResources: true,
        RuntimeObfuscation: true,
        HardenMetadataAndPe: true,
        ProtectWholeFolder: true,
        AllowOverwrite: true,
        MultilayerHardening: true,
        LockOutputs: false);

    public static ObfuscationOptions RenameOnly { get; } = new(
        RenamePrivateMembers: true,
        RenameHelperTypes: true,
        AggressiveRenaming: false,
        ProtectStrings: false,
        ProtectIntegers: false,
        ProxyStaticCalls: false,
        VirtualizeInt32Methods: false,
        FlattenControlFlow: false,
        WeaveInstructions: false,
        ProtectEmbeddedResources: false,
        RuntimeObfuscation: false,
        HardenMetadataAndPe: true,
        ProtectWholeFolder: false,
        AllowOverwrite: false,
        MultilayerHardening: false,
        LockOutputs: false);

    public static ObfuscationOptions Maximum { get; } = SafeDefaults;
}

public sealed record ObfuscationResult(
    int RenamedTypes,
    int RenamedMethods,
    int RenamedFields,
    int RenamedParameters,
    int RenamedProperties,
    int RenamedEvents,
    int RenamedAccessors,
    int RenamedGenericParameters,
    int ProtectedStrings,
    int ProtectedIntegers,
    int ProxiedCalls,
    int VirtualizedMethods,
    int FlattenedMethods,
    int WovenInstructions,
    int ProtectedResources,
    int RuntimeArtifacts,
    int ShuffledMetadataEntries,
    int StrippedDebugRecords,
    string ProtectedModuleName,
    string Mvid,
    int PreservedMembers,
    string Sha256,
    string IntegrityManifestPath,
    string ReportPath,
    IReadOnlyList<string> Diagnostics,
    bool IsLocked,
    string? LockedPath,
    string? FilePassword,
    string? UnlockVaultPath,
    string? PasswordsExportPath);

public sealed record BatchFileResult(string RelativePath, string Status, string Details);

public sealed record BatchObfuscationResult(
    int ProtectedAssemblies,
    int CopiedFiles,
    int SkippedDevelopmentFiles,
    IReadOnlyList<BatchFileResult> Files,
    string ReportPath,
    string? UnlockVaultPath,
    string? PasswordsExportPath);

public static class ObfuscationEngine
{
    public static string CreateDefaultOutputPath(string inputPath)
    {
        var full = Path.GetFullPath(inputPath);
        if (Directory.Exists(full))
        {
            var folderName = Path.GetFileName(full.TrimEnd(Path.DirectorySeparatorChar)) + "_OneGamingProtected";
            if (IsProtectedLocation(full))
                return Path.Combine(GetWritableProtectionRoot(), folderName);
            var parent = Directory.GetParent(full)?.FullName ?? Environment.CurrentDirectory;
            return Path.Combine(parent, folderName);
        }

        var extension = Path.GetExtension(full);
        var stem = Path.GetFileNameWithoutExtension(full);
        var fileName = $"{stem}_OneGamingProtected{extension}";
        if (IsProtectedLocation(full))
            return Path.Combine(GetWritableProtectionRoot(), fileName);

        var directory = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory;
        return Path.Combine(directory, fileName);
    }

    private static bool IsProtectedLocation(string path)
    {
        var full = Path.GetFullPath(path);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        return (!string.IsNullOrEmpty(programFiles) && full.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase)) ||
               (!string.IsNullOrEmpty(programFilesX86) && full.StartsWith(programFilesX86, StringComparison.OrdinalIgnoreCase)) ||
               full.StartsWith(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows)), StringComparison.OrdinalIgnoreCase);
    }

    private static string GetWritableProtectionRoot() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "OneGamingOBFUSCATION", "Protected");

    public static bool IsUnderProtectedOutputRoot(string path)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetFullPath(GetWritableProtectionRoot());
        return full.Equals(root, StringComparison.OrdinalIgnoreCase) ||
               full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    public static BatchObfuscationResult ProtectDirectory(
        string inputDirectory,
        string outputDirectory,
        ObfuscationOptions options,
        string protectionKey,
        IProgress<string>? progress = null)
    {
        KeyedIntegrityProtection.ValidateKey(protectionKey);
        var input = Path.GetFullPath(inputDirectory).TrimEnd(Path.DirectorySeparatorChar);
        var output = Path.GetFullPath(outputDirectory).TrimEnd(Path.DirectorySeparatorChar);
        if (!Directory.Exists(input))
            throw new DirectoryNotFoundException($"Input folder was not found: {input}");
        if (input.Equals(output, StringComparison.OrdinalIgnoreCase) ||
            output.StartsWith(input + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new IOException("The output folder must be new and outside the input folder.");

        var allowOverwrite = options.AllowOverwrite || IsUnderProtectedOutputRoot(output);
        if (Directory.Exists(output) || File.Exists(output))
        {
            if (!allowOverwrite)
                throw new IOException("The output folder already exists. Choose a new folder so nothing is overwritten.");

            progress?.Report($"Overwrite enabled — clearing existing output: {output}");
            if (File.Exists(output))
                File.Delete(output);
            if (Directory.Exists(output))
                Directory.Delete(output, recursive: true);
        }

        var sourceFiles = Directory.GetFiles(input, "*", SearchOption.AllDirectories);
        var results = new List<BatchFileResult>();
        var protectedAssemblies = 0;
        var copiedFiles = 0;
        var skippedDevelopmentFiles = 0;
        Directory.CreateDirectory(output);
        // Fresh vault/password export for this batch when locking.
        if (options.LockOutputs)
        {
            var vaultPath = Path.Combine(output, FileLockProtection.VaultFileName);
            var passwordsPath = Path.Combine(output, FileLockProtection.PasswordsExportFileName);
            if (File.Exists(vaultPath))
                File.Delete(vaultPath);
            if (File.Exists(passwordsPath))
                File.Delete(passwordsPath);
        }

        string? batchVault = null;
        string? batchPasswords = null;

        foreach (var source in sourceFiles)
        {
            var relative = Path.GetRelativePath(input, source);
            var extension = Path.GetExtension(source);
            if (IsDevelopmentPath(relative) || IsDevelopmentArtifact(extension))
            {
                results.Add(new BatchFileResult(relative, "skipped", "development/debug artifact"));
                skippedDevelopmentFiles++;
                progress?.Report($"Skipped {relative}");
                continue;
            }

            var destination = Path.Combine(output, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            if (extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(".netmodule", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    progress?.Report($"Protecting {relative}");
                    var result = Protect(source, destination, options, protectionKey, vaultDirectoryOverride: output, relativePathOverride: relative);
                    batchVault = result.UnlockVaultPath ?? batchVault;
                    batchPasswords = result.PasswordsExportPath ?? batchPasswords;
                    results.Add(new BatchFileResult(relative, result.IsLocked ? "protected+locked" : "protected",
                        $"sha256={result.Sha256}; locked={result.IsLocked}; resources={result.ProtectedResources}; runtime={result.RuntimeArtifacts}"));
                    protectedAssemblies++;
                    continue;
                }
                catch (Exception ex) when (ex is BadImageFormatException or InvalidDataException or NotSupportedException)
                {
                    File.Copy(source, destination, overwrite: false);
                    results.Add(new BatchFileResult(relative, "copied unchanged", ex.Message));
                    copiedFiles++;
                    continue;
                }
            }

            File.Copy(source, destination, overwrite: false);
            var assetHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(source)));
            var assetInfo = new FileInfo(source);
            results.Add(new BatchFileResult(relative, "copied asset",
                $"sha256={assetHash}; size={assetInfo.Length}; meta={assetInfo.Extension.TrimStart('.').ToLowerInvariant()}"));
            copiedFiles++;
            progress?.Report($"Hashed asset {relative}");
        }

        var reportPath = Path.Combine(output, "OneGamingOBFUSCATION.batch-report.txt");
        var report = new List<string>
        {
            "OneGamingOBFUSCATION local folder report",
            $"Created: {DateTimeOffset.Now:O}",
            $"Input: {input}",
            $"Output: {output}",
            $"Protected managed assemblies: {protectedAssemblies}",
            $"Copied assets/unsupported assemblies: {copiedFiles}",
            $"Excluded development/debug files: {skippedDevelopmentFiles}",
            $"Output locking: {options.LockOutputs}",
            $"Unlock vault: {batchVault ?? "(none)"}",
            $"Password export: {batchPasswords ?? "(none)"}",
            ""
        };
        report.AddRange(results.Select(item => $"[{item.Status}] {item.RelativePath} — {item.Details}"));
        File.WriteAllLines(reportPath, report, Encoding.UTF8);
        return new BatchObfuscationResult(protectedAssemblies, copiedFiles, skippedDevelopmentFiles, results, reportPath, batchVault, batchPasswords);
    }

    private static bool IsDevelopmentArtifact(string extension) => extension.Equals(".pdb", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".cs", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".vb", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".fs", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".csproj", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".vbproj", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".fsproj", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".sln", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".user", StringComparison.OrdinalIgnoreCase);

    private static bool IsDevelopmentPath(string relativePath)
    {
        var segments = relativePath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return segments.Any(segment => segment.Equals(".git", StringComparison.OrdinalIgnoreCase) ||
            segment.Equals(".vs", StringComparison.OrdinalIgnoreCase) ||
            segment.Equals(".idea", StringComparison.OrdinalIgnoreCase) ||
            segment.Equals("obj", StringComparison.OrdinalIgnoreCase) ||
            segment.Equals("bin", StringComparison.OrdinalIgnoreCase));
    }

    public static ObfuscationResult Protect(
        string inputPath,
        string outputPath,
        ObfuscationOptions options,
        string protectionKey,
        string? vaultDirectoryOverride = null,
        string? relativePathOverride = null)
    {
        KeyedIntegrityProtection.ValidateKey(protectionKey);
        ValidatePaths(inputPath, outputPath, options.AllowOverwrite || IsUnderProtectedOutputRoot(outputPath));
        var context = ModuleDef.CreateModuleContext();
        var diagnostics = new List<string>();

        if (options.AllowOverwrite || IsUnderProtectedOutputRoot(outputPath))
            ClearExistingOutputArtifacts(outputPath);

        using var module = ModuleDefMD.Load(inputPath, context);
        ValidateModule(module);

        var policy = GorillaTagCompatibilityPolicy.Analyze(module, options.AggressiveRenaming);
        var renamedTypes = 0;
        var renamedMethods = 0;
        var renamedFields = 0;
        var renamedParameters = 0;
        var renamedProperties = 0;
        var renamedEvents = 0;
        var renamedAccessors = 0;
        var renamedGenericParameters = 0;
        var protectedStrings = 0;
        var protectedIntegers = 0;
        var proxiedCalls = 0;
        var virtualizedMethods = 0;
        var flattenedMethods = 0;
        var wovenInstructions = 0;
        var protectedResources = 0;
        var runtimeArtifacts = 0;
        MetadataPeResult? metadataPeResult = null;

        if (options.VirtualizeInt32Methods)
        {
            var stats = Int32Virtualization.Apply(module, policy, aggressive: options.MultilayerHardening);
            virtualizedMethods = stats.Applied;
            diagnostics.Add($"Virtualization (real VM, aggressive={options.MultilayerHardening}): applied={stats.Applied}/{stats.Candidates}; skips: {stats.FormatSkipSummary()}");
        }

        if (options.ProxyStaticCalls)
        {
            var chainDepth = options.MultilayerHardening ? 3 : 1;
            var stats = CallProxyProtection.Apply(module, policy, chainDepth);
            proxiedCalls = stats.Applied;
            diagnostics.Add($"Call proxies (depth={chainDepth}): applied={stats.Applied}/{stats.Candidates}; skips: {stats.FormatSkipSummary()}");
        }

        if (options.RenamePrivateMembers)
        {
            var renameResult = SafeRenamer.Apply(module, policy, options.RenameHelperTypes);
            renamedTypes = renameResult.Types;
            renamedMethods = renameResult.Methods;
            renamedFields = renameResult.Fields;
            renamedParameters = renameResult.Parameters;
            renamedProperties = renameResult.Properties;
            renamedEvents = renameResult.Events;
            renamedAccessors = renameResult.Accessors;
            renamedGenericParameters = renameResult.GenericParameters;
        }

        if (options.ProtectStrings)
        {
            var constStats = ConstantStringFieldProtection.Apply(module);
            diagnostics.Add($"Const string fields: applied={constStats.Applied}/{constStats.Candidates}; skips: {constStats.FormatSkipSummary()}");
            diagnostics.Add("Note: [BepInPlugin] attribute string args stay plaintext so BepInEx can load the plugin.");

            var stats = LocalStringProtection.Apply(module, policy, options.MultilayerHardening);
            protectedStrings = stats.Applied + constStats.Applied;
            diagnostics.Add($"Strings (multilayer={options.MultilayerHardening}): applied={stats.Applied}/{stats.Candidates}; skips: {stats.FormatSkipSummary()}");
        }

        if (options.ProtectIntegers)
        {
            var stats = IntegerConstantProtection.Apply(module, policy, options.MultilayerHardening);
            protectedIntegers = stats.Applied;
            diagnostics.Add($"Integers (MBA={options.MultilayerHardening}): applied={stats.Applied}/{stats.Candidates}; skips: {stats.FormatSkipSummary()}");
        }

        if (options.MultilayerHardening)
        {
            var custom = CustomMethodProtection.Apply(module, policy, options.VirtualizeInt32Methods);
            virtualizedMethods += custom.Virtualized;
            diagnostics.Add(
                $"Custom methods: constants={custom.Constants}; binops={custom.BinOps}; virtualized={custom.Virtualized}; proxies={custom.Proxies}; vm-skips: {custom.VirtualizeSkips}");
        }

        if (options.MultilayerHardening)
        {
            var stats = MultilayerNoiseProtection.Apply(module, policy);
            diagnostics.Add($"Multilayer noise: applied={stats.Applied}/{stats.Candidates}; skips: {stats.FormatSkipSummary()}");
        }

        if (options.ProtectEmbeddedResources)
        {
            var stats = EmbeddedResourceProtection.Apply(module);
            protectedResources = stats.Applied;
            diagnostics.Add($"Embedded resources: applied={stats.Applied}/{stats.Candidates}; skips: {stats.FormatSkipSummary()}");
        }

        if (options.FlattenControlFlow)
        {
            var stats = ControlFlowProtection.Apply(module, policy);
            flattenedMethods = stats.Applied;
            diagnostics.Add($"Control-flow maze: applied={stats.Applied}/{stats.Candidates}; skips: {stats.FormatSkipSummary()}");
        }

        // Dense per-line noise first (multilayer), then weave every eligible instruction.
        if (options.WeaveInstructions && options.MultilayerHardening)
        {
            var denseStats = DenseLineObfuscationProtection.Apply(module, policy);
            wovenInstructions += denseStats.Applied;
            diagnostics.Add($"Dense per-line noise: applied={denseStats.Applied} sites; skips: {denseStats.FormatSkipSummary()}");
        }

        if (options.WeaveInstructions)
        {
            var dense = options.MultilayerHardening;
            var stats = InstructionWeavingProtection.Apply(module, policy, dense);
            wovenInstructions += stats.Applied;
            diagnostics.Add($"Instruction weave (dense={dense}): applied={stats.Applied} instructions; skips: {stats.FormatSkipSummary()}");
        }

        // Runtime decoys last so the maze never rewrites bootstrap helpers the module .cctor calls.
        if (options.RuntimeObfuscation)
        {
            var stats = RuntimeObfuscationProtection.Apply(module);
            runtimeArtifacts = stats.Applied;
            diagnostics.Add($"Runtime obfuscation: applied={stats.Applied}/{stats.Candidates}; skips: {stats.FormatSkipSummary()}");
        }

        if (options.HardenMetadataAndPe)
            metadataPeResult = MetadataPeProtection.Apply(module);

        ModuleBodyFixups.RecalculateBodies(module);

        var outputDirectory = Path.GetDirectoryName(outputPath)!;
        Directory.CreateDirectory(outputDirectory);
        var temporaryPath = Path.Combine(outputDirectory, $".{Path.GetFileName(outputPath)}.{Guid.NewGuid():N}.tmp");
        var integrityPath = outputPath + ".integrity.json";
        var temporaryIntegrityPath = temporaryPath + ".integrity.json";
        KeyedIntegrityResult? integrityResult = null;

        try
        {
            var writerOptions = new ModuleWriterOptions(module)
            {
                Logger = DummyLogger.ThrowModuleWriterExceptionOnErrorInstance
            };
            ModuleBodyFixups.ConfigureWriter(writerOptions);
            if (options.HardenMetadataAndPe)
                MetadataPeProtection.ConfigureWriter(writerOptions);
            module.Write(temporaryPath, writerOptions);

            using (var validationModule = ModuleDefMD.Load(temporaryPath))
            {
                if (validationModule.Assembly is null)
                    throw new InvalidDataException("The generated file did not contain a valid managed assembly.");
            }

            integrityResult = KeyedIntegrityProtection.Create(
                temporaryPath,
                temporaryIntegrityPath,
                protectionKey,
                Path.GetFileName(outputPath));
            File.Move(temporaryPath, outputPath, overwrite: true);
            try
            {
                File.Move(temporaryIntegrityPath, integrityPath, overwrite: true);
            }
            catch
            {
                File.Delete(outputPath);
                throw;
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
            if (File.Exists(temporaryIntegrityPath))
                File.Delete(temporaryIntegrityPath);
        }

        var sha256 = integrityResult!.Sha256;
        string? lockedPath = null;
        string? filePassword = null;
        string? unlockVaultPath = null;
        string? passwordsExportPath = null;
        var isLocked = false;

        if (options.LockOutputs)
        {
            lockedPath = FileLockProtection.ToLockedPath(outputPath);
            if ((options.AllowOverwrite || IsUnderProtectedOutputRoot(outputPath)) && File.Exists(lockedPath))
                File.Delete(lockedPath);

            var vaultDir = vaultDirectoryOverride ?? Path.GetDirectoryName(outputPath)!;
            var relative = relativePathOverride ?? Path.GetFileName(outputPath);
            var lockResult = FileLockProtection.LockFile(outputPath, lockedPath, vaultDir, relative, protectionKey);
            File.Delete(outputPath);
            isLocked = true;
            filePassword = lockResult.FilePassword;
            unlockVaultPath = lockResult.VaultPath;
            passwordsExportPath = lockResult.PasswordsExportPath;
            diagnostics.Add($"Output locked: {lockedPath}");
            diagnostics.Add("Unlock with the master (system) protection key OR the unique per-file password.");
            diagnostics.Add($"Unlock vault: {unlockVaultPath}");
            diagnostics.Add($"Password export: {passwordsExportPath}");
        }

        var reportPath = outputPath + ".report.txt";
        File.WriteAllText(reportPath, BuildReport(inputPath, isLocked ? lockedPath! : outputPath, module, options, policy,
            renamedTypes, renamedMethods, renamedFields, renamedParameters, renamedProperties, renamedEvents,
            renamedAccessors, renamedGenericParameters,
            protectedStrings, protectedIntegers, proxiedCalls, virtualizedMethods, flattenedMethods, wovenInstructions,
            protectedResources, runtimeArtifacts,
            metadataPeResult, integrityPath, sha256, diagnostics,
            isLocked, lockedPath, unlockVaultPath, passwordsExportPath), Encoding.UTF8);

        return new ObfuscationResult(renamedTypes, renamedMethods, renamedFields, renamedParameters,
            renamedProperties, renamedEvents, renamedAccessors, renamedGenericParameters,
            protectedStrings, protectedIntegers, proxiedCalls,
            virtualizedMethods, flattenedMethods, wovenInstructions,
            protectedResources, runtimeArtifacts,
            (metadataPeResult?.ShuffledTypes ?? 0) + (metadataPeResult?.ShuffledMethods ?? 0) +
            (metadataPeResult?.ShuffledFields ?? 0) + (metadataPeResult?.ShuffledPropertiesAndEvents ?? 0) +
            (metadataPeResult?.RenamedManifestResources ?? 0),
            metadataPeResult?.StrippedDebugRecords ?? 0,
            metadataPeResult?.ModuleName ?? module.Name.String,
            metadataPeResult?.Mvid ?? module.Mvid?.ToString("D") ?? string.Empty,
            policy.PreservedMemberCount, sha256, integrityPath, reportPath, diagnostics,
            isLocked, lockedPath, filePassword, unlockVaultPath, passwordsExportPath);
    }

    private static void ValidatePaths(string inputPath, string outputPath, bool allowOverwrite)
    {
        if (!File.Exists(inputPath))
            throw new FileNotFoundException("Input assembly was not found.", inputPath);

        var extension = Path.GetExtension(inputPath);
        if (!extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) &&
            !extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
            !extension.Equals(".netmodule", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Only managed .dll, .exe, and .netmodule files are supported.");

        if (Path.GetFullPath(inputPath).Equals(Path.GetFullPath(outputPath), StringComparison.OrdinalIgnoreCase))
            throw new IOException("The output must be a different path. The input is never overwritten.");

        if (!allowOverwrite)
        {
            if (File.Exists(outputPath))
                throw new IOException("The output file already exists. Enable overwrite or choose a new filename.");

            if (File.Exists(FileLockProtection.ToLockedPath(outputPath)))
                throw new IOException("A locked output already exists. Enable overwrite or choose a new filename.");

            if (File.Exists(outputPath + ".integrity.json") || File.Exists(outputPath + ".report.txt"))
                throw new IOException("An output report or integrity manifest already exists. Enable overwrite or choose a new filename.");
        }
    }

    private static void ClearExistingOutputArtifacts(string outputPath)
    {
        foreach (var path in new[]
                 {
                     outputPath,
                     FileLockProtection.ToLockedPath(outputPath),
                     outputPath + ".integrity.json",
                     outputPath + ".report.txt"
                 })
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }

    private static void ValidateModule(ModuleDefMD module)
    {
        if (module.Assembly is null)
            throw new InvalidDataException("The input is not a managed .NET assembly.");

        if (!module.IsILOnly)
            throw new NotSupportedException("Mixed-mode/native assemblies are not modified for safety.");

        if (module.IsStrongNameSigned || module.Assembly.PublicKey is { Data.Length: > 0 })
            throw new NotSupportedException("Strong-name signed assemblies are not modified because rewriting would invalidate their signature.");
    }

    private static string BuildReport(
        string inputPath,
        string outputPath,
        ModuleDefMD module,
        ObfuscationOptions options,
        CompatibilityAnalysis policy,
        int renamedTypes,
        int renamedMethods,
        int renamedFields,
        int renamedParameters,
        int renamedProperties,
        int renamedEvents,
        int renamedAccessors,
        int renamedGenericParameters,
        int protectedStrings,
        int protectedIntegers,
        int proxiedCalls,
        int virtualizedMethods,
        int flattenedMethods,
        int wovenInstructions,
        int protectedResources,
        int runtimeArtifacts,
        MetadataPeResult? metadataPeResult,
        string integrityPath,
        string sha256,
        IReadOnlyList<string> diagnostics,
        bool isLocked,
        string? lockedPath,
        string? unlockVaultPath,
        string? passwordsExportPath)
    {
        var lines = new List<string>
        {
            "OneGamingOBFUSCATION local protection report",
            $"Created: {DateTimeOffset.Now:O}",
            $"Input: {Path.GetFullPath(inputPath)}",
            $"Output: {Path.GetFullPath(outputPath)}",
            $"Assembly: {module.Assembly?.FullName}",
            $"Gorilla Tag / Unity indicators: {policy.UnityIndicators}",
            $"BepInEx indicators: {policy.BepInExIndicators}",
            $"Harmony indicators: {policy.HarmonyIndicators}",
            $"Rename private members: {options.RenamePrivateMembers}",
            $"Rename private helper types: {options.RenameHelperTypes}",
            $"Aggressive compatible identifier coverage: {options.AggressiveRenaming}",
            $"Local string protection: {options.ProtectStrings}",
            $"Integer IL encoding: {options.ProtectIntegers}",
            $"Static call indirection: {options.ProxyStaticCalls}",
            $"Eligible real VM virtualization: {options.VirtualizeInt32Methods}",
            $"Embedded resource encryption: {options.ProtectEmbeddedResources}",
            $"Runtime obfuscation bootstrap: {options.RuntimeObfuscation}",
            $"Control-flow flattening: {options.FlattenControlFlow}",
            $"Per-instruction weaving: {options.WeaveInstructions}",
            $"Multilayer hardening: {options.MultilayerHardening}",
            $"Lock protected outputs: {options.LockOutputs}",
            $"Output currently locked: {isLocked}",
            $"Locked path: {lockedPath ?? "(n/a)"}",
            $"Unlock vault: {unlockVaultPath ?? "(n/a)"}",
            $"Password export: {passwordsExportPath ?? "(n/a)"}",
            $"Metadata and PE hardening: {options.HardenMetadataAndPe}",
            $"Renamed types: {renamedTypes}",
            $"Renamed methods: {renamedMethods}",
            $"Renamed fields: {renamedFields}",
            $"Renamed parameters: {renamedParameters}",
            $"Renamed properties: {renamedProperties}",
            $"Renamed events: {renamedEvents}",
            $"Renamed property/event accessors: {renamedAccessors}",
            $"Renamed generic parameters: {renamedGenericParameters}",
            $"Protected strings: {protectedStrings}",
            $"Protected integer constants: {protectedIntegers}",
            $"Proxied static calls: {proxiedCalls}",
            $"Virtualized methods: {virtualizedMethods}",
            $"Flattened methods: {flattenedMethods}",
            $"Woven IL instructions: {wovenInstructions}",
            $"Protected embedded resources: {protectedResources}",
            $"Runtime obfuscation artifacts: {runtimeArtifacts}",
            $"Shuffled metadata entries: {(metadataPeResult?.ShuffledTypes ?? 0) + (metadataPeResult?.ShuffledMethods ?? 0) + (metadataPeResult?.ShuffledFields ?? 0) + (metadataPeResult?.ShuffledPropertiesAndEvents ?? 0)}",
            $"Manifest resource visibility hardened: {metadataPeResult?.RenamedManifestResources ?? 0}",
            $"Stripped debug/source records: {metadataPeResult?.StrippedDebugRecords ?? 0}",
            $"Protected module name: {metadataPeResult?.ModuleName ?? module.Name.String}",
            $"Randomized MVID: {metadataPeResult?.Mvid ?? module.Mvid?.ToString("D") ?? string.Empty}",
            $"PE timestamp randomized: {options.HardenMetadataAndPe}",
            $"Preserved compatibility-sensitive members: {policy.PreservedMemberCount}",
            $"SHA-256: {sha256}",
            "Keyed integrity: PBKDF2-SHA256 + HMAC-SHA256 (250,000 iterations)",
            $"Integrity manifest: {integrityPath}",
            "Protection key stored in output/report: no",
            "Network access: none",
            "Input overwritten: no",
            "Kernel drivers, anti-debug evasion, and process scanning: not included",
            "",
            "Coverage diagnostics:"
        };
        lines.AddRange(diagnostics.Count == 0 ? ["(none)"] : diagnostics);
        return string.Join(Environment.NewLine, lines) + Environment.NewLine;
    }
}

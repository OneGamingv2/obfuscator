using OneGamingOBFUSCATION.Core;
using OneGamingOBFUSCATION.Protection;
using System.IO;

namespace OneGamingOBFUSCATION;

public static class Cli
{
    public static int Run(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintHelp();
            return args.Length == 0 ? 1 : 0;
        }

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "protect" => Protect(ParseOptions(args.Skip(1).ToArray())),
                "verify" => Verify(ParseOptions(args.Skip(1).ToArray())),
                "unlock" => Unlock(ParseOptions(args.Skip(1).ToArray())),
                "list-passwords" => ListPasswords(ParseOptions(args.Skip(1).ToArray())),
                _ => Fail($"Unknown command '{args[0]}'. Use protect, verify, unlock, or list-passwords.")
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("ERROR: " + ex.Message);
            return 1;
        }
    }

    private static int Protect(Dictionary<string, string> options)
    {
        var input = Require(options, "input", "i");
        var output = options.GetValueOrDefault("output") ?? options.GetValueOrDefault("o") ??
                     ObfuscationEngine.CreateDefaultOutputPath(input);
        var key = ResolveKey(options);
        var preset = (options.GetValueOrDefault("preset") ?? "safe").ToLowerInvariant();
        var protection = preset switch
        {
            "safe" or "maximum" or "max" => ObfuscationOptions.Maximum,
            "rename" or "rename-only" => ObfuscationOptions.RenameOnly,
            _ => throw new ArgumentException($"Unknown preset '{preset}'. Use safe, maximum, or rename-only.")
        };

        protection = ApplyFlagOverrides(protection, options);

        if (File.Exists(input) && input.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
        {
            var jar = JarPluginObfuscator.Protect(input, output, new JarProtectOptions(
                RenameClasses: true,
                RenameMembers: true,
                EncryptStrings: true,
                StripDebug: true,
                ShuffleEntries: true,
                AllowOverwrite: protection.AllowOverwrite), key);
            Console.WriteLine($"Protected jar: {output}");
            Console.WriteLine(jar.Notes[0]);
            foreach (var note in jar.Notes.Skip(1))
                Console.WriteLine(note);
            Console.WriteLine($"SHA-256: {jar.Sha256}");
            return 0;
        }

        if (File.Exists(input) && (protection.ProtectWholeFolder || ParseBool(options.GetValueOrDefault("folder") ?? "false")))
        {
            var folder = Path.GetDirectoryName(Path.GetFullPath(input))!;
            Console.WriteLine($"Whole-folder mode: {folder}");
            input = folder;
            if (!options.ContainsKey("output") && !options.ContainsKey("o"))
                output = ObfuscationEngine.CreateDefaultOutputPath(folder);
        }

        if (Directory.Exists(input))
        {
            var batch = ObfuscationEngine.ProtectDirectory(input, output, protection, key,
                new Progress<string>(message => Console.WriteLine(message)));
            Console.WriteLine($"Protected assemblies: {batch.ProtectedAssemblies}");
            Console.WriteLine($"Copied files: {batch.CopiedFiles}");
            Console.WriteLine($"Report: {batch.ReportPath}");
            return 0;
        }

        var result = ObfuscationEngine.Protect(input, output, protection, key);
        Console.WriteLine(result.IsLocked
            ? $"Protected+locked: {result.LockedPath}"
            : $"Protected: {output}");
        Console.WriteLine($"SHA-256 (clear payload): {result.Sha256}");
        if (result.IsLocked)
        {
            Console.WriteLine($"Per-file unlock password: {result.FilePassword}");
            Console.WriteLine($"Master (system) password: the --key you supplied (unlocks all via vault)");
            Console.WriteLine($"Unlock vault: {result.UnlockVaultPath}");
            Console.WriteLine($"Password export: {result.PasswordsExportPath}");
        }
        Console.WriteLine($"Virtualized: {result.VirtualizedMethods}; Flattened: {result.FlattenedMethods}; Strings: {result.ProtectedStrings}; Resources: {result.ProtectedResources}");
        foreach (var line in result.Diagnostics)
            Console.WriteLine(line);
        Console.WriteLine($"Report: {result.ReportPath}");
        return 0;
    }

    private static int Unlock(Dictionary<string, string> options)
    {
        var input = Require(options, "input", "i");
        var key = ResolveKey(options);
        var output = options.GetValueOrDefault("output") ?? options.GetValueOrDefault("o") ??
                     FileLockProtection.ToUnlockedPath(input);
        var vault = options.GetValueOrDefault("vault");
        var result = FileLockProtection.UnlockFile(input, output, key, vault);
        Console.WriteLine($"Unlocked: {result.OutputPath}");
        Console.WriteLine($"Used master password: {result.UsedMasterPassword}");
        Console.WriteLine($"SHA-256: {result.ClearSha256}");
        return 0;
    }

    private static int ListPasswords(Dictionary<string, string> options)
    {
        var vault = options.GetValueOrDefault("vault") ??
                    Require(options, "input", "i");
        if (Directory.Exists(vault))
            vault = Path.Combine(vault, FileLockProtection.VaultFileName);
        var key = ResolveKey(options);
        foreach (var (relativePath, filePassword) in FileLockProtection.ListFilePasswords(vault, key))
            Console.WriteLine($"{relativePath} = {filePassword}");
        return 0;
    }

    private static int Verify(Dictionary<string, string> options)
    {
        var input = Require(options, "input", "i");
        var key = ResolveKey(options);
        var manifest = options.GetValueOrDefault("manifest") ?? input + ".integrity.json";
        var valid = KeyedIntegrityProtection.Verify(input, manifest, key);
        Console.WriteLine(valid ? "Integrity VERIFIED" : "Integrity FAILED");
        return valid ? 0 : 2;
    }

    private static ObfuscationOptions ApplyFlagOverrides(ObfuscationOptions options, Dictionary<string, string> flags)
    {
        bool Flag(string name, bool current) =>
            flags.TryGetValue(name, out var value) ? ParseBool(value) : current;

        return options with
        {
            RenamePrivateMembers = Flag("rename", options.RenamePrivateMembers),
            RenameHelperTypes = Flag("rename-types", options.RenameHelperTypes),
            AggressiveRenaming = Flag("aggressive", options.AggressiveRenaming),
            ProtectStrings = Flag("strings", options.ProtectStrings),
            ProtectIntegers = Flag("integers", options.ProtectIntegers),
            ProxyStaticCalls = Flag("proxies", options.ProxyStaticCalls),
            VirtualizeInt32Methods = Flag("virtualize", options.VirtualizeInt32Methods),
            FlattenControlFlow = Flag("flatten", options.FlattenControlFlow),
            WeaveInstructions = Flag("weave", options.WeaveInstructions),
            ProtectEmbeddedResources = Flag("resources", options.ProtectEmbeddedResources),
            RuntimeObfuscation = Flag("runtime", options.RuntimeObfuscation),
            HardenMetadataAndPe = Flag("metadata", options.HardenMetadataAndPe),
            ProtectWholeFolder = Flag("folder", options.ProtectWholeFolder),
            AllowOverwrite = Flag("overwrite", options.AllowOverwrite),
            MultilayerHardening = Flag("multilayer", options.MultilayerHardening),
            LockOutputs = Flag("lock", options.LockOutputs)
        };
    }

    private static bool ParseBool(string value) =>
        value.Equals("1", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("on", StringComparison.OrdinalIgnoreCase);

    private static string ResolveKey(Dictionary<string, string> options)
    {
        if (options.TryGetValue("key", out var key) || options.TryGetValue("k", out key))
            return key;

        if (options.TryGetValue("key-env", out var envName))
        {
            var fromEnv = Environment.GetEnvironmentVariable(envName);
            if (string.IsNullOrWhiteSpace(fromEnv))
                throw new ArgumentException($"Environment variable '{envName}' is missing or empty.");
            return fromEnv;
        }

        if (options.ContainsKey("generate-key") || options.ContainsKey("gen-key"))
        {
            var generated = KeyedIntegrityProtection.GenerateProtectionKey();
            Console.WriteLine("Generated protection key (save this):");
            Console.WriteLine(generated);
            return generated;
        }

        throw new ArgumentException("Provide --key <value>, --key-env <VARIABLE>, or --generate-key.");
    }

    private static string Require(Dictionary<string, string> options, params string[] names)
    {
        foreach (var name in names)
        {
            if (options.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value))
                return value;
        }

        throw new ArgumentException($"Missing required option --{names[0]}.");
    }

    private static Dictionary<string, string> ParseOptions(string[] args)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index++)
        {
            var token = args[index];
            if (!token.StartsWith("--", StringComparison.Ordinal) && !token.StartsWith("-", StringComparison.Ordinal))
                throw new ArgumentException($"Unexpected argument '{token}'.");

            var name = token.TrimStart('-');
            if (index + 1 >= args.Length || args[index + 1].StartsWith("-", StringComparison.Ordinal))
            {
                result[name] = "true";
                continue;
            }

            result[name] = args[++index];
        }

        return result;
    }

    private static bool IsHelp(string value) =>
        value is "-h" or "--help" or "/?" or "help";

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        PrintHelp();
        return 1;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("""
            OneGamingOBFUSCATION CLI

            protect --input <path> [--output <path>] (--key <key> | --key-env <VAR> | --generate-key)
                    [--preset safe|maximum|rename-only]
                    [--strings true|false] [--virtualize true|false] [--flatten true|false]
                    [--weave true|false] [--proxies true|false] [--integers true|false]
                    [--resources true|false] [--runtime true|false] [--folder true|false] [--overwrite true|false]
                    [--rename true|false] [--rename-types true|false] [--aggressive true|false]
                    [--metadata true|false] [--multilayer true|false] [--lock true|false]

            A .jar input is protected as a Paper, Purpur, Folia, or Bukkit plugin.

            unlock  --input <file.oglock> [--output <file.dll-or-exe>] (--key <master-or-file-password> | --key-env <VAR>)
                    [--vault <OneGaming.unlock-vault.json>]

            list-passwords --vault <OneGaming.unlock-vault.json> (--key <master> | --key-env <VAR>)

            verify  --input <path> (--key <key> | --key-env <VAR>) [--manifest <path>]

            Without arguments the GUI starts instead.
            """);
    }
}

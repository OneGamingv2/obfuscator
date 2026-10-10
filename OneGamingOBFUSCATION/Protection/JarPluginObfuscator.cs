using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace OneGamingOBFUSCATION.Protection;

public sealed record JarProtectOptions(
    bool RenameClasses,
    bool RenameMembers,
    bool EncryptStrings,
    bool StripDebug,
    bool ShuffleEntries,
    bool AllowOverwrite,
    bool MixIntegers = true,
    bool BreakArchiveDump = true);

public sealed record JarProtectResult(
    string Server,
    string? PluginName,
    string? MainClass,
    int RenamedClasses,
    int RenamedMembers,
    int EncryptedStrings,
    int StrippedDebug,
    string Sha256,
    string ManifestPath,
    IReadOnlyList<string> Notes);

public static class JarPluginObfuscator
{
    private static readonly string[] PreservedMembers =
    [
        "<init>", "<clinit>", "main", "onEnable", "onDisable", "onLoad", "onCommand", "onTabComplete",
        "execute", "tabComplete", "equals", "hashCode", "toString", "clone", "finalize", "compareTo",
        "values", "valueOf", "readObject", "writeObject", "readResolve", "writeReplace", "run", "call",
        "accept", "apply", "test", "get", "iterator", "hasNext", "next", "remove", "close",
        "bootstrap", "classloader", "onProxyInitialization", "onPlaceholderRequest", "serialize", "deserialize"
    ];

    private static readonly Regex ClassName = new(@"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$", RegexOptions.Compiled);

    public static JarProtectResult Protect(string inputPath, string outputPath, JarProtectOptions options, string protectionKey)
    {
        KeyedIntegrityProtection.ValidateKey(protectionKey);
        if (!File.Exists(inputPath))
            throw new FileNotFoundException("Input jar was not found.", inputPath);
        if (!outputPath.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Jar output has to end with .jar.");
        if (Path.GetFullPath(inputPath).Equals(Path.GetFullPath(outputPath), StringComparison.OrdinalIgnoreCase))
            throw new IOException("The output must be a different path. The input is never overwritten.");
        if (!options.AllowOverwrite && (File.Exists(outputPath) || File.Exists(outputPath + ".integrity.json")))
            throw new IOException("The output already exists. Enable overwrite or choose a new filename.");

        var scan = Scan(inputPath);
        var notes = new List<string> { scan.Summary };
        var key = RandomNumberGenerator.GetInt32(1, 120);
        var classes = new Dictionary<string, JavaClassFile>(StringComparer.Ordinal);
        var originals = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var others = new List<(string Name, byte[] Data)>();

        using (var archive = ZipFile.OpenRead(inputPath))
        {
            foreach (var entry in archive.Entries)
            {
                if (entry.FullName.EndsWith('/'))
                    continue;
                var data = ReadEntry(entry);
                if (entry.FullName.EndsWith(".class", StringComparison.OrdinalIgnoreCase) && !IsSignature(entry.FullName))
                {
                    try
                    {
                        var parsed = JavaClassFile.Read(data);
                        classes[parsed.ThisName] = parsed;
                    }
                    catch (Exception ex)
                    {
                        originals[entry.FullName] = data;
                        notes.Add($"Left {entry.FullName} unchanged: {ex.Message}");
                    }
                }
                else if (!IsSignature(entry.FullName))
                {
                    others.Add((entry.FullName, data));
                }
            }
        }

        var preserved = new HashSet<string>(scan.ClassNames.Select(name => name.Replace('.', '/')), StringComparer.Ordinal);
        var decryptorName = NewDecryptorName(classes, preserved);
        var decryptorMethod = NewDecryptorMethod();
        var style = RandomNumberGenerator.GetInt32(3);
        preserved.Add(decryptorName);

        var classMap = new Dictionary<string, string>(StringComparer.Ordinal);
        if (options.RenameClasses)
        {
            var used = new HashSet<string>(classes.Keys, StringComparer.Ordinal);
            var serial = 0;
            foreach (var name in classes.Keys.OrderBy(name => name, StringComparer.Ordinal))
            {
                if (preserved.Contains(name) || name == "module-info")
                    continue;
                string renamed;
                do
                {
                    renamed = NextClassName(serial++);
                } while (!used.Add(renamed));
                classMap[name] = renamed;
            }
        }

        var memberMap = new Dictionary<string, string>(StringComparer.Ordinal);
        if (options.RenameMembers)
        {
            var serial = 0;
            foreach (var (name, file) in classes)
            {
                foreach (var member in file.Methods.Concat(file.Fields))
                {
                    var memberName = file.Utf8(member.NameIndex);
                    if (!CanRenameMember(file, member, memberName))
                        continue;
                    var id = name + " " + memberName + " " + file.Utf8(member.DescriptorIndex);
                    memberMap[id] = "m" + serial++.ToString("x");
                }
            }
        }

        var renamedMembers = 0;
        if (memberMap.Count > 0)
            renamedMembers = RewriteMembers(classes, memberMap);

        if (classMap.Count > 0)
        {
            foreach (var file in classes.Values)
                RewriteClassNames(file, classMap);
        }

        var encrypted = 0;
        if (options.EncryptStrings)
        {
            foreach (var file in classes.Values)
            {
                var decryptRef = file.InternRef(10, decryptorName, decryptorMethod, "(Ljava/lang/String;)Ljava/lang/String;");
                try
                {
                    encrypted += JavaCodeEditor.EncryptStrings(file, decryptRef, key, style);
                }
                catch (Exception ex)
                {
                    notes.Add($"Strings left in {file.ThisName}: {ex.Message}");
                }
            }

            classes[decryptorName] = DecryptorClass.Create(decryptorName, decryptorMethod, key, style);
            notes.Add($"String cipher style {style}. Decryptor {decryptorName}.{decryptorMethod}.");
        }

        foreach (var file in classes.Values)
            AddJunk(file);

        var mixed = 0;
        if (options.MixIntegers)
        {
            foreach (var file in classes.Values)
            {
                try
                {
                    mixed += JavaCodeEditor.ObfuscateIntegers(file);
                }
                catch (Exception ex)
                {
                    notes.Add($"Integers left in {file.ThisName}: {ex.Message}");
                }
            }

            notes.Add($"Integer constants mixed: {mixed}.");
        }

        var stripped = 0;
        if (options.StripDebug)
        {
            foreach (var file in classes.Values)
                stripped += JavaCodeEditor.StripDebug(file);
        }

        if (options.RenameClasses)
            RewriteTextResources(others, classMap);

        var directory = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);
        if (File.Exists(outputPath))
            File.Delete(outputPath);

        var written = new List<(string Name, byte[] Data)>();
        foreach (var (name, file) in classes)
            written.Add((file.ThisName + ".class", file.Write()));
        written.AddRange(originals.Select(pair => (pair.Key, pair.Value)));
        written.AddRange(others);
        if (options.ShuffleEntries)
            Shuffle(written);

        using (var output = ZipFile.Open(outputPath, ZipArchiveMode.Create))
        {
            foreach (var (name, data) in written)
            {
                var entry = output.CreateEntry(name.Replace('\\', '/'), CompressionLevel.Optimal);
                using var stream = entry.Open();
                stream.Write(data, 0, data.Length);
            }
        }

        if (options.BreakArchiveDump)
        {
            ArchiveDumpBreak.MaskFile(outputPath);
            notes.Add("WinZip dump broken: extracted names are decoys. Paper, Purpur, Folia, and Bukkit still read the real entry names.");
        }

        var manifestPath = outputPath + ".integrity.json";
        var integrity = KeyedIntegrityProtection.Create(outputPath, manifestPath, protectionKey, Path.GetFileName(outputPath));
        notes.Add($"Classes renamed: {classMap.Count}. Members renamed: {renamedMembers}. Strings encrypted: {encrypted}. Debug records removed: {stripped}.");
        return new JarProtectResult(scan.Server, scan.PluginName, scan.MainClass, classMap.Count, renamedMembers, encrypted, stripped, integrity.Sha256, manifestPath, notes);
    }

    public static PluginScan Scan(string jarPath)
    {
        var classNames = new HashSet<string>(StringComparer.Ordinal);
        string? pluginName = null;
        string? main = null;
        var paper = false;
        var folia = false;
        var purpur = false;
        var bukkit = false;
        using var archive = ZipFile.OpenRead(jarPath);
        foreach (var entry in archive.Entries)
        {
            var name = entry.FullName.Replace('\\', '/');
            if (name is not ("plugin.yml" or "paper-plugin.yml" or "bungee.yml"))
                continue;
            var text = Encoding.UTF8.GetString(ReadEntry(entry));
            if (name == "paper-plugin.yml")
                paper = true;
            if (name == "plugin.yml")
                bukkit = true;
            foreach (var raw in text.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#'))
                    continue;
                var split = line.IndexOf(':');
                if (split < 0)
                    continue;
                var key = line[..split].Trim();
                var value = line[(split + 1)..].Trim().Trim('"', '\'');
                if (key.Equals("name", StringComparison.OrdinalIgnoreCase) && pluginName is null)
                    pluginName = value;
                if (key.Equals("main", StringComparison.OrdinalIgnoreCase) && ClassName.IsMatch(value))
                    main ??= value;
                if (key.Equals("folia-supported", StringComparison.OrdinalIgnoreCase) &&
                    value.Equals("true", StringComparison.OrdinalIgnoreCase))
                    folia = true;
                if (key.Contains("purpur", StringComparison.OrdinalIgnoreCase) ||
                    value.Contains("purpur", StringComparison.OrdinalIgnoreCase))
                    purpur = true;
                if (ClassName.IsMatch(value))
                    classNames.Add(value);
            }
        }

        var parts = new List<string>();
        if (paper)
            parts.Add("Paper");
        if (purpur)
            parts.Add("Purpur");
        if (folia)
            parts.Add("Folia");
        if (bukkit && parts.Count == 0)
            parts.Add("Paper / Purpur / Folia");
        var server = parts.Count == 0 ? "Generic JAR" : string.Join(" + ", parts);
        var summary = main is null
            ? $"Detected {server}."
            : $"Detected {server}. Main class {main} stays loadable.";
        return new PluginScan(server, pluginName, main, classNames.ToArray(), summary);
    }

    private static void RewriteClassNames(JavaClassFile file, Dictionary<string, string> map)
    {
        var ordered = map.OrderByDescending(pair => pair.Key.Length).ToArray();
        for (var index = 1; index < file.Pool.Count; index++)
        {
            var item = file.Pool[index];
            if (item is not { Tag: 1 })
                continue;
            item.Utf8 = RewriteText(item.Utf8, ordered);
        }
    }

    private static void RewriteTextResources(List<(string Name, byte[] Data)> others, Dictionary<string, string> map)
    {
        var ordered = map.OrderByDescending(pair => pair.Key.Length).ToArray();
        for (var index = 0; index < others.Count; index++)
        {
            var (name, data) = others[index];
            if (!name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) &&
                !name.EndsWith(".yml", StringComparison.OrdinalIgnoreCase) &&
                !name.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase) &&
                !name.Contains("META-INF/services/", StringComparison.Ordinal))
                continue;
            var text = Encoding.UTF8.GetString(data);
            var rewritten = text;
            foreach (var (oldName, newName) in ordered)
                rewritten = rewritten.Replace(oldName.Replace('/', '.'), newName.Replace('/', '.'), StringComparison.Ordinal);
            if (!ReferenceEquals(rewritten, text) && rewritten != text)
                others[index] = (name, Encoding.UTF8.GetBytes(rewritten));
        }
    }

    private static int RewriteMembers(Dictionary<string, JavaClassFile> classes, Dictionary<string, string> memberMap)
    {
        var renamed = 0;
        foreach (var file in classes.Values)
        {
            foreach (var member in file.Methods.Concat(file.Fields))
            {
                var memberName = file.Utf8(member.NameIndex);
                var descriptor = file.Utf8(member.DescriptorIndex);
                var id = file.ThisName + " " + memberName + " " + descriptor;
                if (!memberMap.TryGetValue(id, out var renamedName) || memberName == renamedName)
                    continue;
                member.NameIndex = file.InternUtf8(renamedName);
                renamed++;
            }

            for (var index = 1; index < file.Pool.Count; index++)
            {
                var item = file.Pool[index];
                if (item is not { Tag: 9 or 10 or 11 })
                    continue;
                var ownerItem = file.Pool[item.Index1];
                var nat = file.Pool[item.Index2];
                if (ownerItem is not { Tag: 7 } || nat is not { Tag: 12 })
                    continue;
                var owner = file.Utf8(ownerItem.Index1);
                var memberName = file.Utf8(nat.Index1);
                var descriptor = file.Utf8(nat.Index2);
                var id = owner + " " + memberName + " " + descriptor;
                if (!memberMap.TryGetValue(id, out var renamedName))
                    continue;
                item.Index2 = file.InternNameAndType(renamedName, descriptor);
            }

            HideRetiredNames(file, memberMap);
        }

        return renamed;
    }

    private static void HideRetiredNames(JavaClassFile file, Dictionary<string, string> memberMap)
    {
        var retired = new HashSet<string>(StringComparer.Ordinal);
        foreach (var id in memberMap.Keys)
        {
            var first = id.IndexOf(' ');
            var second = id.IndexOf(' ', first + 1);
            if (first < 0 || second < 0)
                continue;
            retired.Add(id[(first + 1)..second]);
        }

        var referenced = new HashSet<int>();
        for (var index = 1; index < file.Pool.Count; index++)
        {
            var item = file.Pool[index];
            if (item is { Tag: 9 or 10 or 11 })
                referenced.Add(item.Index2);
        }

        var dead = new List<int>();
        for (var index = 1; index < file.Pool.Count; index++)
        {
            var item = file.Pool[index];
            if (item is { Tag: 12 } && !referenced.Contains(index) && retired.Contains(file.Utf8(item.Index1)))
                dead.Add(index);
        }

        var filler = file.InternUtf8("m");
        foreach (var index in dead)
            file.Pool[index]!.Index1 = filler;

        var used = new HashSet<int>();
        foreach (var member in file.Methods.Concat(file.Fields))
        {
            used.Add(member.NameIndex);
            used.Add(member.DescriptorIndex);
        }

        for (var index = 1; index < file.Pool.Count; index++)
        {
            var item = file.Pool[index];
            if (item is null)
                continue;
            if (item.Tag is 7 or 8 or 16 or 19 or 20)
                used.Add(item.Index1);
            if (item.Tag == 12)
            {
                used.Add(item.Index1);
                used.Add(item.Index2);
            }
        }

        for (var index = 1; index < file.Pool.Count; index++)
        {
            var item = file.Pool[index];
            if (item is { Tag: 1 } && !used.Contains(index) && retired.Contains(item.Utf8))
                item.Utf8 = "m";
        }
    }

    private static string NewDecryptorName(Dictionary<string, JavaClassFile> classes, HashSet<string> preserved)
    {
        while (true)
        {
            var name = "n" + RandomNumberGenerator.GetInt32(0x1000, 0x10000).ToString("x") + "/" + (char)('a' + RandomNumberGenerator.GetInt32(26));
            if (!classes.ContainsKey(name) && !preserved.Contains(name))
                return name;
        }
    }

    private static string NewDecryptorMethod() =>
        ((char)('a' + RandomNumberGenerator.GetInt32(26))).ToString() + (char)('a' + RandomNumberGenerator.GetInt32(26));

    private static void AddJunk(JavaClassFile file)
    {
        if ((file.Access & 0x2200) != 0)
            return;
        var method = new JavaMember
        {
            Access = 0x000A,
            NameIndex = file.InternUtf8("z" + RandomNumberGenerator.GetInt32(0x100000).ToString("x")),
            DescriptorIndex = file.InternUtf8("()I")
        };
        method.Attributes.Add(new JavaAttribute
        {
            NameIndex = file.InternUtf8("Code"),
            Data = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xAC, 0x00, 0x00, 0x00, 0x00]
        });
        file.Methods.Add(method);
    }

    private static bool CanRenameMember(JavaClassFile file, JavaMember member, string name)
    {
        if (PreservedMembers.Contains(name) || HasRuntimeAnnotation(file, member))
            return false;
        var access = member.Access;
        var isPublic = (access & 0x0001) != 0;
        var isProtected = (access & 0x0004) != 0;
        return !isPublic && !isProtected;
    }

    private static bool HasRuntimeAnnotation(JavaClassFile file, JavaMember member)
    {
        foreach (var attribute in member.Attributes)
        {
            var name = file.Utf8(attribute.NameIndex);
            if (name is "RuntimeVisibleAnnotations" or "RuntimeVisibleParameterAnnotations" or "RuntimeVisibleTypeAnnotations" or "AnnotationDefault")
                return true;
        }

        return false;
    }

    private static string RewriteText(string text, KeyValuePair<string, string>[] ordered)
    {
        foreach (var (oldName, _) in ordered)
        {
            if (text == oldName)
                return ordered.First(pair => pair.Key == oldName).Value;
        }

        if (!text.Contains('L') || !text.Contains(';'))
            return text;

        var builder = new StringBuilder(text.Length);
        for (var index = 0; index < text.Length; index++)
        {
            if (text[index] == 'L')
            {
                var end = text.IndexOf(';', index + 1);
                if (end > index)
                {
                    var name = text[(index + 1)..end];
                    var match = ordered.FirstOrDefault(pair => pair.Key == name);
                    if (match.Key == name)
                    {
                        builder.Append('L');
                        builder.Append(match.Value);
                        builder.Append(';');
                        index = end;
                        continue;
                    }
                }
            }

            builder.Append(text[index]);
        }

        return builder.ToString();
    }

    private static string NextClassName(int serial)
    {
        var package = serial / 26;
        var type = (char)('a' + (serial % 26));
        return "p" + package.ToString("x") + "/" + type;
    }

    private static bool IsSignature(string name)
    {
        if (!name.StartsWith("META-INF/", StringComparison.OrdinalIgnoreCase))
            return false;
        return name.EndsWith(".SF", StringComparison.OrdinalIgnoreCase) ||
               name.EndsWith(".RSA", StringComparison.OrdinalIgnoreCase) ||
               name.EndsWith(".DSA", StringComparison.OrdinalIgnoreCase);
    }

    private static void Shuffle<T>(List<T> items)
    {
        for (var index = items.Count - 1; index > 0; index--)
        {
            var swap = RandomNumberGenerator.GetInt32(index + 1);
            (items[index], items[swap]) = (items[swap], items[index]);
        }
    }

    private static byte[] ReadEntry(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }
}

public sealed record PluginScan(string Server, string? PluginName, string? MainClass, IReadOnlyList<string> ClassNames, string Summary);

public static class DecryptorClass
{
    public static JavaClassFile Create(string internalName, string methodName, int key, int style)
    {
        var file = new JavaClassFile
        {
            Major = 49,
            Access = 0x0031
        };
        file.ThisClass = file.InternClass(internalName);
        file.SuperClass = file.InternClass("java/lang/Object");
        var toChar = file.InternRef(10, "java/lang/String", "toCharArray", "()[C");
        var init = file.InternRef(10, "java/lang/String", "<init>", "([C)V");
        var stringClass = file.InternClass("java/lang/String");
        var method = new JavaMember
        {
            Access = 0x0009,
            NameIndex = file.InternUtf8(methodName),
            DescriptorIndex = file.InternUtf8("(Ljava/lang/String;)Ljava/lang/String;")
        };
        method.Attributes.Add(new JavaAttribute
        {
            NameIndex = file.InternUtf8("Code"),
            Data = BuildCode(toChar, init, stringClass, key, style)
        });
        file.Methods.Add(method);
        return file;
    }

    private static byte[] BuildCode(ushort toChar, ushort init, ushort stringClass, int key, int style)
    {
        var code = new List<byte>();
        void Op(params byte[] bytes) => code.AddRange(bytes);
        Op(0x2A);
        Op(0xB6, (byte)(toChar >> 8), (byte)toChar);
        Op(0x4C, 0x03, 0x3D);
        var gotoAt = code.Count;
        Op(0xA7, 0, 0);
        var loop = code.Count;
        Op(0x2B, 0x1C, 0x2B, 0x1C, 0x34);
        if (style == 1)
            Op(0x1C, 0x10, 7, 0x68, 0x10, (byte)key, 0x82, 0x10, 127, 0x7E, 0x82, 0x92, 0x55);
        else
            Op(0x1C, 0x10, (byte)(style == 2 ? 3 : 13), 0x68, 0x10, (byte)key, 0x60, 0x10, 127, 0x7E, 0x82, 0x92, 0x55);
        Op(0x84, 0x02, 0x01);
        var check = code.Count;
        Op(0x1C, 0x2B, 0xBE);
        var branchAt = code.Count;
        Op(0xA1, 0, 0);
        Op(0xBB, (byte)(stringClass >> 8), (byte)stringClass);
        Op(0x59, 0x2B);
        Op(0xB7, (byte)(init >> 8), (byte)init);
        Op(0xB0);
        var gotoOffset = (short)(check - gotoAt);
        code[gotoAt + 1] = (byte)(gotoOffset >> 8);
        code[gotoAt + 2] = (byte)gotoOffset;
        var branchOffset = (short)(loop - branchAt);
        code[branchAt + 1] = (byte)(branchOffset >> 8);
        code[branchAt + 2] = (byte)branchOffset;

        var writer = new ByteWriter();
        writer.U2(6);
        writer.U2(3);
        writer.U4((uint)code.Count);
        writer.Bytes(code.ToArray());
        writer.U2(0);
        writer.U2(0);
        return writer.ToArray();
    }
}

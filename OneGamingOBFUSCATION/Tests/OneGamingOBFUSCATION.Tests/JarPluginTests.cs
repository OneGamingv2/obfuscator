using OneGamingOBFUSCATION.Protection;
using System.IO;
using System.IO.Compression;
using System.Text;
using Xunit;

namespace OneGamingOBFUSCATION.Tests;

public sealed class JarPluginTests
{
    private const string ProtectionKey = "unit-test-protection-key";

    [Fact]
    public void Protect_plugin_jar_keeps_main_and_hides_helper()
    {
        var directory = Path.Combine(Path.GetTempPath(), "OneGamingOBFUSCATION.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var input = Path.Combine(directory, "Example.jar");
        var output = Path.Combine(directory, "Example_OneGamingProtected.jar");
        WritePlugin(input);

        var result = JarPluginObfuscator.Protect(input, output, new JarProtectOptions(true, true, true, true, false, true), ProtectionKey);

        Assert.Equal("Paper + Folia", result.Server);
        Assert.Equal("Example", result.PluginName);
        Assert.Equal("com.example.Main", result.MainClass);
        Assert.True(result.RenamedClasses >= 1);
        Assert.True(result.RenamedMembers >= 2);
        Assert.True(result.EncryptedStrings >= 1);
        Assert.True(result.StrippedDebug >= 1);
        Assert.Contains(result.Notes, note => note.Contains("WinZip dump broken", StringComparison.Ordinal));
        Assert.Contains(result.Notes, note => note.Contains("Integer constants mixed:", StringComparison.Ordinal) && !note.Contains(": 0.", StringComparison.Ordinal));
        Assert.True(KeyedIntegrityProtection.Verify(output, result.ManifestPath, ProtectionKey));
        Assert.True(ArchiveDumpBreak.MasksExtractorNames(output));

        using var archive = ZipFile.OpenRead(output);
        var names = archive.Entries.Select(entry => entry.FullName.Replace('\\', '/')).ToArray();
        Assert.Contains("com/example/Main.class", names);
        Assert.DoesNotContain("com/example/Helper.class", names);
        var helperName = Assert.Single(names, name => name.StartsWith("p0/", StringComparison.Ordinal) && name.EndsWith(".class"));

        var yml = ReadText(archive, "plugin.yml");
        Assert.Contains("com.example.Main", yml);
        Assert.DoesNotContain("com.example.Helper", yml);

        var main = JavaClassFile.Read(ReadBytes(archive, "com/example/Main.class"));
        Assert.Contains(main.Methods, method => main.Utf8(method.NameIndex) == "onEnable");
        Assert.DoesNotContain(Utf8(main), value => value is "com/example/Helper" or "secret" or "server-secret");

        var helper = JavaClassFile.Read(ReadBytes(archive, helperName));
        Assert.DoesNotContain(helper.Methods, method => helper.Utf8(method.NameIndex) == "secret");
        Assert.DoesNotContain(helper.Fields, field => helper.Utf8(field.NameIndex) == "token");
        Assert.DoesNotContain(Utf8(helper), value => value is "server-secret" or "secret" or "token");
        Assert.DoesNotContain(helper.Attributes, attribute => helper.Utf8(attribute.NameIndex) == "SourceFile");
        Assert.Contains(helper.Methods, method => helper.Utf8(method.NameIndex) == "onJoin");
        Assert.Contains(helper.Methods, method => helper.Utf8(method.DescriptorIndex) == "()I" && MethodBytes(method).Contains((byte)0x82));

        JavaClassFile? decryptor = null;
        foreach (var name in names.Where(name => name.EndsWith(".class", StringComparison.Ordinal)))
        {
            var parsed = JavaClassFile.Read(ReadBytes(archive, name));
            if (parsed.Major == 49)
                decryptor = parsed;
        }

        Assert.NotNull(decryptor);
        var decryptName = decryptor.Utf8(Assert.Single(decryptor.Methods, method => decryptor.Utf8(method.DescriptorIndex) == "(Ljava/lang/String;)Ljava/lang/String;").NameIndex);
        Assert.Contains(helper.Pool, item => item is { Tag: 10 } && NameOfRef(helper, item) == decryptName);
    }

    [Fact]
    public void Scan_reads_paper_purpur_and_generic_jars()
    {
        var directory = Path.Combine(Path.GetTempPath(), "OneGamingOBFUSCATION.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        var paper = Path.Combine(directory, "paper.jar");
        WriteTextJar(paper, "paper-plugin.yml", "name: PaperPlug\nmain: com.example.PaperMain\n");
        var paperScan = JarPluginObfuscator.Scan(paper);
        Assert.Equal("Paper", paperScan.Server);
        Assert.Equal("PaperPlug", paperScan.PluginName);
        Assert.Equal("com.example.PaperMain", paperScan.MainClass);

        var purpur = Path.Combine(directory, "purpur.jar");
        WriteTextJar(purpur, "plugin.yml", "name: PurpurPlug\nmain: com.example.PurpurMain\napi: Purpur\n");
        var purpurScan = JarPluginObfuscator.Scan(purpur);
        Assert.Equal("Purpur", purpurScan.Server);

        var generic = Path.Combine(directory, "generic.jar");
        WriteTextJar(generic, "readme.txt", "hello");
        var genericScan = JarPluginObfuscator.Scan(generic);
        Assert.Equal("Generic JAR", genericScan.Server);
        Assert.Null(genericScan.MainClass);
    }

    private static void WritePlugin(string path)
    {
        var helper = new JavaClassFile { Major = 52, Access = 0x0021 };
        helper.ThisClass = helper.InternClass("com/example/Helper");
        helper.SuperClass = helper.InternClass("java/lang/Object");
        var secretText = helper.InternUtf8("server-secret");
        helper.Pool.Add(new CpItem { Tag = 8, Index1 = secretText });
        var secretString = (ushort)(helper.Pool.Count - 1);
        var secret = new JavaMember
        {
            Access = 0x000A,
            NameIndex = helper.InternUtf8("secret"),
            DescriptorIndex = helper.InternUtf8("()Ljava/lang/String;")
        };
        secret.Attributes.Add(new JavaAttribute
        {
            NameIndex = helper.InternUtf8("Code"),
            Data = Code(1, 0, 0x12, (byte)secretString, 0xB0)
        });
        helper.Methods.Add(secret);
        helper.Fields.Add(new JavaMember
        {
            Access = 0x0002,
            NameIndex = helper.InternUtf8("token"),
            DescriptorIndex = helper.InternUtf8("I")
        });
        var count = new JavaMember
        {
            Access = 0x000A,
            NameIndex = helper.InternUtf8("count"),
            DescriptorIndex = helper.InternUtf8("()I")
        };
        count.Attributes.Add(new JavaAttribute
        {
            NameIndex = helper.InternUtf8("Code"),
            Data = Code(1, 0, 0x10, 42, 0xAC)
        });
        helper.Methods.Add(count);
        var handler = helper.InternUtf8("Lorg/bukkit/event/EventHandler;");
        var annotation = new ByteWriter();
        annotation.U2(1);
        annotation.U2(handler);
        annotation.U2(0);
        var listener = new JavaMember
        {
            Access = 0x000A,
            NameIndex = helper.InternUtf8("onJoin"),
            DescriptorIndex = helper.InternUtf8("()V")
        };
        listener.Attributes.Add(new JavaAttribute
        {
            NameIndex = helper.InternUtf8("Code"),
            Data = Code(0, 0, 0xB1)
        });
        listener.Attributes.Add(new JavaAttribute
        {
            NameIndex = helper.InternUtf8("RuntimeVisibleAnnotations"),
            Data = annotation.ToArray()
        });
        helper.Methods.Add(listener);
        var source = helper.InternUtf8("Helper.java");
        helper.Attributes.Add(new JavaAttribute
        {
            NameIndex = helper.InternUtf8("SourceFile"),
            Data = [(byte)(source >> 8), (byte)source]
        });

        var main = new JavaClassFile { Major = 52, Access = 0x0021 };
        main.ThisClass = main.InternClass("com/example/Main");
        main.SuperClass = main.InternClass("java/lang/Object");
        var call = main.InternRef(10, "com/example/Helper", "secret", "()Ljava/lang/String;");
        var caller = new JavaMember
        {
            Access = 0x000A,
            NameIndex = main.InternUtf8("call"),
            DescriptorIndex = main.InternUtf8("()Ljava/lang/String;")
        };
        caller.Attributes.Add(new JavaAttribute
        {
            NameIndex = main.InternUtf8("Code"),
            Data = Code(1, 0, 0xB8, (byte)(call >> 8), (byte)call, 0xB0)
        });
        main.Methods.Add(caller);
        var enable = new JavaMember
        {
            Access = 0x0001,
            NameIndex = main.InternUtf8("onEnable"),
            DescriptorIndex = main.InternUtf8("()V")
        };
        enable.Attributes.Add(new JavaAttribute
        {
            NameIndex = main.InternUtf8("Code"),
            Data = Code(0, 1, 0xB1)
        });
        main.Methods.Add(enable);

        var plugin = "name: Example\nmain: com.example.Main\nversion: 1.0\nfolia-supported: true\n";
        var paper = "name: Example\nmain: com.example.Main\n";
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        Add(archive, "com/example/Helper.class", helper.Write());
        Add(archive, "com/example/Main.class", main.Write());
        Add(archive, "plugin.yml", Encoding.UTF8.GetBytes(plugin));
        Add(archive, "paper-plugin.yml", Encoding.UTF8.GetBytes(paper));
        Add(archive, "META-INF/TEST.SF", [1, 2, 3]);
    }

    private static byte[] Code(ushort maxStack, ushort maxLocals, params byte[] bytecode)
    {
        var writer = new ByteWriter();
        writer.U2(maxStack);
        writer.U2(maxLocals);
        writer.U4((uint)bytecode.Length);
        writer.Bytes(bytecode);
        writer.U2(0);
        writer.U2(0);
        return writer.ToArray();
    }

    private static void WriteTextJar(string path, string name, string text)
    {
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        Add(archive, name, Encoding.UTF8.GetBytes(text));
    }

    private static void Add(ZipArchive archive, string name, byte[] data)
    {
        var entry = archive.CreateEntry(name);
        using var stream = entry.Open();
        stream.Write(data);
    }

    private static byte[] ReadBytes(ZipArchive archive, string name)
    {
        var entry = archive.GetEntry(name) ?? throw new FileNotFoundException(name);
        using var stream = entry.Open();
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }

    private static string ReadText(ZipArchive archive, string name) => Encoding.UTF8.GetString(ReadBytes(archive, name));

    private static IEnumerable<string> Utf8(JavaClassFile file) =>
        file.Pool.Where(item => item is { Tag: 1 }).Select(item => item!.Utf8);

    private static byte[] MethodBytes(JavaMember method) =>
        method.Attributes.SelectMany(attribute => attribute.Data).ToArray();

    private static string NameOfRef(JavaClassFile file, CpItem item)
    {
        var nat = file.Pool[item.Index2];
        return nat is { Tag: 12 } ? file.Utf8(nat.Index1) : "";
    }
}

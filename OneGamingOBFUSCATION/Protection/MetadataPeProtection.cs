using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using System.Security.Cryptography;

namespace OneGamingOBFUSCATION.Protection;

public sealed record MetadataPeResult(
    int ShuffledTypes,
    int ShuffledMethods,
    int ShuffledFields,
    int ShuffledPropertiesAndEvents,
    int StrippedDebugRecords,
    int RenamedManifestResources,
    string ModuleName,
    string Mvid);

/// <summary>
/// Applies valid CLR metadata and PE variations without corrupting tables,
/// signatures, section layout, or loader-critical headers.
/// </summary>
public static class MetadataPeProtection
{
    public static MetadataPeResult Apply(ModuleDef module)
    {
        module.Mvid = Guid.NewGuid();
        module.Name = "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant() +
                      (module.Kind is ModuleKind.Console or ModuleKind.Windows ? ".exe" : ".dll");

        AddSuppressIldasmAttribute(module);
        var strippedDebugRecords = StripDebugInformation(module);
        var renamedManifestResources = RenamePublicManifestResourceMetadata(module);
        var shuffledTypes = Shuffle(module.Types, startIndex: 1);
        var shuffledMethods = 0;
        var shuffledFields = 0;
        var shuffledPropertiesAndEvents = 0;

        foreach (var type in module.GetTypes().Where(type => !type.IsGlobalModuleType).ToArray())
        {
            shuffledTypes += Shuffle(type.NestedTypes, startIndex: 0);
            shuffledMethods += ShuffleEligibleMethods(type.Methods);
            shuffledFields += ShuffleEligibleFields(type.Fields);
            shuffledPropertiesAndEvents += Shuffle(type.Properties, startIndex: 0);
            shuffledPropertiesAndEvents += Shuffle(type.Events, startIndex: 0);
        }

        return new MetadataPeResult(
            shuffledTypes,
            shuffledMethods,
            shuffledFields,
            shuffledPropertiesAndEvents,
            strippedDebugRecords,
            renamedManifestResources,
            module.Name.String,
            module.Mvid?.ToString("D") ?? string.Empty);
    }

    public static void ConfigureWriter(ModuleWriterOptions writerOptions)
    {
        writerOptions.PEHeadersOptions.TimeDateStamp = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
    }

    private static void AddSuppressIldasmAttribute(ModuleDef module)
    {
        const string attributeName = "System.Runtime.CompilerServices.SuppressIldasmAttribute";
        if (module.CustomAttributes.Any(attribute => attribute.AttributeType.FullName == attributeName))
            return;

        var attributeType = new TypeRefUser(
            module,
            "System.Runtime.CompilerServices",
            "SuppressIldasmAttribute",
            module.CorLibTypes.AssemblyRef);
        var constructor = new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void),
            attributeType);
        module.CustomAttributes.Add(new CustomAttribute(constructor));
    }

    private static int StripDebugInformation(ModuleDef module)
    {
        var stripped = module.CustomDebugInfos.Count;
        module.CustomDebugInfos.Clear();
        foreach (var type in module.GetTypes())
        {
            stripped += type.CustomDebugInfos.Count;
            type.CustomDebugInfos.Clear();
            foreach (var method in type.Methods)
            {
                stripped += method.CustomDebugInfos.Count;
                method.CustomDebugInfos.Clear();
                if (!method.HasBody)
                    continue;
                foreach (var instruction in method.Body.Instructions)
                {
                    if (instruction.SequencePoint is null)
                        continue;
                    instruction.SequencePoint = null;
                    stripped++;
                }
            }
        }
        return stripped;
    }

    private static int RenamePublicManifestResourceMetadata(ModuleDef module)
    {
        // Resources already handled by EmbeddedResourceProtection keep their names.
        // Here we only normalize ManifestResource visibility flags where safe.
        var count = 0;
        foreach (var resource in module.Resources)
        {
            if (resource is not EmbeddedResource embedded)
                continue;
            if (embedded.Attributes != ManifestResourceAttributes.Private)
            {
                embedded.Attributes = ManifestResourceAttributes.Private;
                count++;
            }
        }

        return count;
    }

    private static int ShuffleEligibleFields(IList<FieldDef> fields)
    {
        var indices = Enumerable.Range(0, fields.Count)
            .Where(index => IsSafeToReorderField(fields[index]))
            .ToArray();
        if (indices.Length < 2)
            return 0;

        var values = indices.Select(index => fields[index]).ToArray();
        for (var index = indices.Length - 1; index >= 0; index--)
            fields.RemoveAt(indices[index]);
        ShuffleArray(values);
        for (var index = 0; index < indices.Length; index++)
            fields.Insert(indices[index], values[index]);
        return indices.Length;
    }

    private static bool IsSafeToReorderField(FieldDef field) =>
        !field.IsLiteral && !field.IsRuntimeSpecialName && !field.HasFieldRVA && field.ImplMap is null;

    private static int ShuffleEligibleMethods(IList<MethodDef> methods)
    {
        var indices = Enumerable.Range(0, methods.Count)
            .Where(index => IsSafeToReorder(methods[index]))
            .ToArray();
        if (indices.Length < 2)
            return 0;

        var values = indices.Select(index => methods[index]).ToArray();
        for (var index = indices.Length - 1; index >= 0; index--)
            methods.RemoveAt(indices[index]);
        ShuffleArray(values);
        for (var index = 0; index < indices.Length; index++)
            methods.Insert(indices[index], values[index]);
        return indices.Length;
    }

    private static bool IsSafeToReorder(MethodDef method) =>
        !method.IsConstructor && !method.IsStaticConstructor && !method.IsVirtual && !method.IsAbstract &&
        !method.IsRuntimeSpecialName && method.ImplMap is null && !method.HasOverrides;

    private static int Shuffle<T>(IList<T> items, int startIndex)
    {
        if (items.Count - startIndex < 2)
            return 0;
        var values = Enumerable.Range(startIndex, items.Count - startIndex)
            .Select(index => items[index])
            .ToArray();
        for (var index = items.Count - 1; index >= startIndex; index--)
            items.RemoveAt(index);
        ShuffleArray(values);
        for (var index = 0; index < values.Length; index++)
            items.Insert(startIndex + index, values[index]);
        return values.Length;
    }

    private static void ShuffleArray<T>(T[] items)
    {
        for (var index = items.Length - 1; index > 0; index--)
        {
            var other = RandomNumberGenerator.GetInt32(index + 1);
            (items[index], items[other]) = (items[other], items[index]);
        }
    }
}

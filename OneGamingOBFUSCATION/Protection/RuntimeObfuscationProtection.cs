using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;

namespace OneGamingOBFUSCATION.Protection;

/// <summary>
/// Injects runtime noise: decoy types/methods and a module bootstrap that
/// materializes opaque runtime state used by other local protections.
/// </summary>
public static class RuntimeObfuscationProtection
{
    public static ProtectionStats Apply(ModuleDef module)
    {
        var stats = new ProtectionStats { Candidates = 1 };
        var decoys = CreateDecoyTypes(module, count: 4);
        var decoyStrings = CreateDecoyPluginStrings(module, count: 12);
        var stateField = CreateStateField(module);
        InjectBootstrap(module, stateField, decoys);
        stats.Applied = decoys.Count + decoyStrings + 1;
        return stats;
    }

    private static int CreateDecoyPluginStrings(ModuleDef module, int count)
    {
        var prefixes = new[] { "com.mod.", "org.plugin.", "net.gt.", "com.gorilla.", "com.bepinex." };
        var suffixes = new[] { "core", "helper", "runtime", "bridge", "toolkit", "loader", "utils" };
        for (var index = 0; index < count; index++)
        {
            var type = new TypeDefUser(
                "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant(),
                CreateRuntimeName(),
                module.CorLibTypes.Object.TypeDefOrRef)
            {
                Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit |
                             TypeAttributes.Abstract
            };
            module.Types.Add(type);

            var fakeGuid = prefixes[index % prefixes.Length] +
                           Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant() + "." +
                           suffixes[RandomNumberGenerator.GetInt32(suffixes.Length)];
            foreach (var (name, value) in new[]
                     {
                         ("_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant(), fakeGuid),
                         ("_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant(),
                             "Mod" + RandomNumberGenerator.GetInt32(1000, 9999)),
                         ("_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant(),
                             "1." + RandomNumberGenerator.GetInt32(0, 9) + "." + RandomNumberGenerator.GetInt32(0, 20))
                     })
            {
                var field = new FieldDefUser(
                    name,
                    new FieldSig(module.CorLibTypes.String),
                    FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.InitOnly);
                type.Fields.Add(field);
                // Store as encrypted-looking static assigned in module cctor later via ldstr decoy
                // Use literal constant so metadata search finds many GUID-like hits.
                field.Attributes = FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.Literal |
                                   FieldAttributes.HasDefault;
                field.Constant = new ConstantUser(value);
            }
        }

        return count * 3;
    }

    private static List<MethodDef> CreateDecoyTypes(ModuleDef module, int count)
    {
        var methods = new List<MethodDef>();
        for (var index = 0; index < count; index++)
        {
            var type = new TypeDefUser(
                "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant(),
                CreateRuntimeName(),
                module.CorLibTypes.Object.TypeDefOrRef)
            {
                Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit
            };
            module.Types.Add(type);

            for (var methodIndex = 0; methodIndex < 2; methodIndex++)
            {
                var method = new MethodDefUser(
                    CreateRuntimeName(),
                    MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                    MethodImplAttributes.IL | MethodImplAttributes.Managed,
                    MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig)
                {
                    Body = new CilBody()
                };
                var key = RandomNumberGenerator.GetInt32(2, 97);
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
                method.Body.Instructions.Add(Instruction.CreateLdcI4(key));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Xor));
                method.Body.Instructions.Add(Instruction.CreateLdcI4(key * 3 + 1));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                type.Methods.Add(method);
                methods.Add(method);
            }
        }

        return methods;
    }

    private static FieldDef CreateStateField(ModuleDef module)
    {
        var field = new FieldDefUser(
            CreateRuntimeName(),
            new FieldSig(module.CorLibTypes.Int32),
            FieldAttributes.Assembly | FieldAttributes.Static);
        module.GlobalType.Fields.Add(field);
        return field;
    }

    private static void InjectBootstrap(ModuleDef module, FieldDef stateField, List<MethodDef> decoys)
    {
        var cctor = module.GlobalType.FindStaticConstructor();
        if (cctor is null)
        {
            cctor = new MethodDefUser(
                ".cctor",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig |
                MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(cctor);
        }

        var tickCount = new MemberRefUser(
            module,
            "get_TickCount",
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            new TypeRefUser(module, "System", "Environment", module.CorLibTypes.AssemblyRef));

        var insertAt = Math.Max(0, cctor.Body.Instructions.Count - 1);
        var batch = new List<Instruction>
        {
            Instruction.Create(OpCodes.Call, tickCount),
            Instruction.CreateLdcI4(RandomNumberGenerator.GetInt32(1, int.MaxValue)),
            Instruction.Create(OpCodes.Xor),
            Instruction.Create(OpCodes.Stsfld, stateField)
        };

        // Opaque live call into one decoy so the type is not tree-shaken and looks "used".
        if (decoys.Count > 0)
        {
            var decoy = decoys[RandomNumberGenerator.GetInt32(decoys.Count)];
            batch.Add(Instruction.Create(OpCodes.Ldsfld, stateField));
            batch.Add(Instruction.Create(OpCodes.Call, decoy));
            batch.Add(Instruction.Create(OpCodes.Ldsfld, stateField));
            batch.Add(Instruction.Create(OpCodes.Xor));
            batch.Add(Instruction.Create(OpCodes.Stsfld, stateField));
        }

        for (var index = 0; index < batch.Count; index++)
            cctor.Body.Instructions.Insert(insertAt + index, batch[index]);
    }

    private static string CreateRuntimeName() =>
        "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
}

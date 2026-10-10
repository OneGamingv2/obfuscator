using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;

namespace OneGamingOBFUSCATION.Protection;

public static class MultilayerNoiseProtection
{
    public static ProtectionStats Apply(ModuleDef module, CompatibilityAnalysis policy)
    {
        var stats = new ProtectionStats { Candidates = 1 };
        var junkHelpers = CreateJunkHelpers(module, count: 6);
        var decoyDecoders = CreateDecoyDecoders(module, count: 4);
        InjectDeadReferences(module, junkHelpers, decoyDecoders);
        var mutated = MutateSafeMethods(module, policy, junkHelpers);
        stats.Applied = junkHelpers.Count + decoyDecoders.Count + mutated;
        return stats;
    }

    private static List<MethodDef> CreateJunkHelpers(ModuleDef module, int count)
    {
        var helpers = new List<MethodDef>();
        for (var index = 0; index < count; index++)
        {
            var method = new MethodDefUser(
                CreateName(),
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig)
            {
                Body = new CilBody()
            };

            var body = method.Body.Instructions;
            body.Add(Instruction.Create(OpCodes.Ldarg_0));
            body.Add(Instruction.Create(OpCodes.Ldarg_1));
            body.Add(Instruction.Create(OpCodes.Xor));
            body.Add(Instruction.Create(OpCodes.Ldarg_0));
            body.Add(Instruction.Create(OpCodes.Ldarg_1));
            body.Add(Instruction.Create(OpCodes.And));
            body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            body.Add(Instruction.Create(OpCodes.Shl));
            body.Add(Instruction.Create(OpCodes.Add));
            body.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(method);
            helpers.Add(method);
        }

        return helpers;
    }

    private static List<MethodDef> CreateDecoyDecoders(ModuleDef module, int count)
    {
        var decoys = new List<MethodDef>();
        var byteArray = new SZArraySig(module.CorLibTypes.Byte);
        for (var index = 0; index < count; index++)
        {
            var method = new MethodDefUser(
                CreateName(),
                MethodSig.CreateStatic(module.CorLibTypes.String, byteArray, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig)
            {
                Body = new CilBody()
            };

            var encodingType = new TypeRefUser(module, "System.Text", "Encoding", module.CorLibTypes.AssemblyRef);
            var getUtf8 = new MemberRefUser(module, "get_UTF8", MethodSig.CreateStatic(encodingType.ToTypeSig()), encodingType);
            var getString = new MemberRefUser(module, "GetString", MethodSig.CreateInstance(module.CorLibTypes.String, byteArray), encodingType);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getUtf8));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getString));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(method);
            decoys.Add(method);
        }

        return decoys;
    }

    private static void InjectDeadReferences(ModuleDef module, List<MethodDef> junkHelpers, List<MethodDef> decoyDecoders)
    {
        var cctor = EnsureStaticConstructor(module.GlobalType);
        var insertAt = Math.Max(0, cctor.Body.Instructions.Count - 1);

        if (junkHelpers.Count > 0)
        {
            var helper = junkHelpers[RandomNumberGenerator.GetInt32(junkHelpers.Count)];
            var skip = Instruction.Create(OpCodes.Nop);
            var batch = new List<Instruction>
            {
                Instruction.Create(OpCodes.Ldc_I4_0),
                Instruction.Create(OpCodes.Ldc_I4_1),
                Instruction.Create(OpCodes.Ceq),
                Instruction.Create(OpCodes.Brfalse, skip),
                Instruction.Create(OpCodes.Ldc_I4_1),
                Instruction.Create(OpCodes.Ldc_I4_2),
                Instruction.Create(OpCodes.Call, helper),
                Instruction.Create(OpCodes.Pop)
            };
            if (decoyDecoders.Count > 0)
            {
                var decoy = decoyDecoders[RandomNumberGenerator.GetInt32(decoyDecoders.Count)];
                batch.Add(Instruction.Create(OpCodes.Ldftn, decoy));
                batch.Add(Instruction.Create(OpCodes.Pop));
            }

            batch.Add(skip);
            for (var index = 0; index < batch.Count; index++)
                cctor.Body.Instructions.Insert(insertAt + index, batch[index]);
        }
    }

    private static int MutateSafeMethods(ModuleDef module, CompatibilityAnalysis policy, List<MethodDef> junkHelpers)
    {
        if (junkHelpers.Count == 0)
            return 0;

        var mutated = 0;
        foreach (var method in module.GetTypes()
                     .Where(type => !type.IsGlobalModuleType)
                     .SelectMany(type => type.Methods)
                     .Where(method => policy.IsMethodTransformationSafe(method))
                     .ToArray())
        {
            if (method.Body.Instructions.Count > 250 || method.Body.HasExceptionHandlers)
                continue;

            method.Body.SimplifyBranches();
            var instructions = method.Body.Instructions;
            for (var index = 0; index < instructions.Count; index++)
            {
                if (!instructions[index].IsLdcI4())
                    continue;
                if (RandomNumberGenerator.GetInt32(100) > 35)
                    continue;

                var helper = junkHelpers[RandomNumberGenerator.GetInt32(junkHelpers.Count)];
                instructions.Insert(index + 1, Instruction.Create(OpCodes.Ldc_I4_0));
                instructions.Insert(index + 2, Instruction.Create(OpCodes.Call, helper));
                index += 2;
                mutated++;
                if (mutated > 64)
                    return mutated;
            }
        }

        return mutated;
    }

    private static string CreateName() => InvisibleNames.Next();

    private static MethodDef EnsureStaticConstructor(TypeDef type)
    {
        var existing = type.FindStaticConstructor();
        if (existing is not null)
            return existing;

        var cctor = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(type.Module.CorLibTypes.Void),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(cctor);
        return cctor;
    }
}

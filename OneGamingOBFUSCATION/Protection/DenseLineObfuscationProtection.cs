using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;

namespace OneGamingOBFUSCATION.Protection;

public static class DenseLineObfuscationProtection
{
    public static ProtectionStats Apply(ModuleDef module, CompatibilityAnalysis policy)
    {
        var stats = new ProtectionStats();
        foreach (var method in module.GetTypes()
                     .Where(type => !type.IsGlobalModuleType)
                     .SelectMany(type => type.Methods)
                     .Where(method => method.HasBody)
                     .ToArray())
        {
            if (!policy.IsMethodTransformationSafe(method))
            {
                stats.Skip("preserved-or-unsafe");
                continue;
            }

            stats.Candidates++;
            if (method.Body.HasExceptionHandlers)
            {
                stats.Skip("exception-handlers");
                continue;
            }

            if (method.Body.Instructions.Count is < 2 or > 350)
            {
                stats.Skip("size-limit");
                continue;
            }

            if (method.Body.Instructions.Any(IsBranchOrPrefix))
            {
                stats.Skip("branch-or-prefix");
                continue;
            }

            method.Body.SimplifyBranches();
            var scratch = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(scratch);
            method.Body.InitLocals = true;

            var instructions = method.Body.Instructions;
            var inserted = 0;
            for (var index = 0; index < instructions.Count; index++)
            {

                if (inserted > 500)
                    break;

                var target = instructions[index];
                if (target.OpCode == OpCodes.Nop || target.OpCode == OpCodes.Ret)
                    continue;

                var noise = BuildNoise(method.Module, scratch);
                for (var n = 0; n < noise.Length; n++)
                    instructions.Insert(index + n, noise[n]);
                index += noise.Length;
                inserted += noise.Length;
                stats.Applied++;
            }
        }

        return stats;
    }

    private static Instruction[] BuildNoise(ModuleDef module, Local scratch)
    {
        var a = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
        if (RandomNumberGenerator.GetInt32(2) == 0)
        {
            var k = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
            var xor = CustomMethodProtection.NextXor(module);
            return
            [
                Instruction.Create(OpCodes.Ldc_I4, a),
                Instruction.Create(OpCodes.Ldc_I4, k),
                Instruction.Create(OpCodes.Call, xor),
                Instruction.Create(OpCodes.Ldc_I4, k),
                Instruction.Create(OpCodes.Call, xor),
                Instruction.Create(OpCodes.Stloc, scratch)
            ];
        }

        return
        [
            Instruction.Create(OpCodes.Ldc_I4, a),
            Instruction.Create(OpCodes.Call, CustomMethodProtection.NextMixer(module)),
            Instruction.Create(OpCodes.Stloc, scratch)
        ];
    }

    private static bool IsBranchOrPrefix(Instruction instruction) =>
        instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch ||
        instruction.OpCode == OpCodes.Switch ||
        instruction.OpCode.Code is Code.Jmp or Code.Calli or Code.Constrained or Code.Readonly or
            Code.Tailcall or Code.Unaligned or Code.Volatile or Code.No;
}

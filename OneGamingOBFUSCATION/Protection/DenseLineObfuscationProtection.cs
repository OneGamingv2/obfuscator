using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;

namespace OneGamingOBFUSCATION.Protection;

/// <summary>
/// Second-pass densifier: for straight-line methods the weave skip (or already-woven
/// bodies under size cap), inject stack-neutral junk before as many IL ops as possible.
/// Does not detect dumpers or enforce single-use — loader-safe IL noise only.
/// </summary>
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
                // Skip if this looks like already-dense weave prologue adjacent noise saturation
                if (inserted > 500)
                    break;

                var target = instructions[index];
                if (target.OpCode == OpCodes.Nop || target.OpCode == OpCodes.Ret)
                    continue;

                var noise = BuildNoise(scratch);
                for (var n = 0; n < noise.Length; n++)
                    instructions.Insert(index + n, noise[n]);
                index += noise.Length;
                inserted += noise.Length;
                stats.Applied++;
            }
        }

        return stats;
    }

    private static Instruction[] BuildNoise(Local scratch)
    {
        var a = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
        var k = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
        return
        [
            Instruction.Create(OpCodes.Ldc_I4, a),
            Instruction.Create(OpCodes.Ldc_I4, k),
            Instruction.Create(OpCodes.Xor),
            Instruction.Create(OpCodes.Ldc_I4, k),
            Instruction.Create(OpCodes.Xor),
            Instruction.Create(OpCodes.Stloc, scratch)
        ];
    }

    private static bool IsBranchOrPrefix(Instruction instruction) =>
        instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch ||
        instruction.OpCode == OpCodes.Switch ||
        instruction.OpCode.Code is Code.Jmp or Code.Calli or Code.Constrained or Code.Readonly or
            Code.Tailcall or Code.Unaligned or Code.Volatile or Code.No;
}

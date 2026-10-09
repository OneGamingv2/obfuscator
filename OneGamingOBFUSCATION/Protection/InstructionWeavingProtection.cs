using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;

namespace OneGamingOBFUSCATION.Protection;

/// <summary>
/// Wraps every eligible IL instruction with state guards and (in dense mode)
/// stack-neutral MBA noise so decompilers see a wall of junk per original line.
/// Branching / exception / Unity-sensitive methods stay skipped for loader safety.
/// </summary>
public static class InstructionWeavingProtection
{
    public static ProtectionStats Apply(ModuleDef module, CompatibilityAnalysis policy, bool dense = false)
    {
        var stats = new ProtectionStats();
        var methods = module.GetTypes()
            .Where(type => !type.IsGlobalModuleType)
            .SelectMany(type => type.Methods)
            .ToArray();

        foreach (var method in methods)
        {
            if (!policy.IsMethodTransformationSafe(method))
            {
                if (method.HasBody)
                    stats.Skip("preserved-or-unsafe");
                continue;
            }

            stats.Candidates++;
            if (!CanWeave(method, dense, out var reason))
            {
                stats.Skip(reason);
                continue;
            }

            method.Body.SimplifyBranches();
            var originals = method.Body.Instructions.ToArray();
            if (originals.Length == 0)
            {
                stats.Skip("empty-body");
                continue;
            }

            // Branching weave remaps targets and frequently produces stack-ambiguous IL.
            // Leave branching helpers to control-flow flattening.
            if (originals.Any(IsBranch))
            {
                stats.Skip("branching-body");
                continue;
            }

            stats.Applied += WeaveStraightBody(method, originals, dense);
        }

        return stats;
    }

    private static int WeaveStraightBody(MethodDef method, Instruction[] originals, bool dense)
    {
        var module = method.Module;

        var state = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(state);
        Local? scratch = null;
        if (dense)
        {
            scratch = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(scratch);
        }

        method.Body.InitLocals = true;
        method.Body.Instructions.Clear();

        var current = RandomNumberGenerator.GetInt32(1, int.MaxValue);
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, current));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, state));

        foreach (var original in originals)
        {
            var key = RandomNumberGenerator.GetInt32(1, int.MaxValue);
            current ^= key;

            // Per-instruction state gate
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, state));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, key));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Xor));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, state));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, state));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, current));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Beq, original));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, current));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, state));

            if (dense && scratch is not null)
                EmitDenseNoise(method.Body.Instructions, scratch, original);

            method.Body.Instructions.Add(original);
        }

        return originals.Length;
    }

    /// <summary>
    /// Stack-neutral noise inserted immediately before each original instruction.
    /// Uses MBA identity: (a ^ b) + 2*(a &amp; b) == a + b; with b=0 => a.
    /// </summary>
    private static void EmitDenseNoise(IList<Instruction> body, Local scratch, Instruction continueAt)
    {
        var a = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
        var mode = RandomNumberGenerator.GetInt32(0, 3);
        switch (mode)
        {
            case 0:
                // scratch = a; scratch = (scratch ^ 0) + 2*(scratch & 0) => scratch; pop via store only
                body.Add(Instruction.Create(OpCodes.Ldc_I4, a));
                body.Add(Instruction.Create(OpCodes.Stloc, scratch));
                body.Add(Instruction.Create(OpCodes.Ldloc, scratch));
                body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
                body.Add(Instruction.Create(OpCodes.Xor));
                body.Add(Instruction.Create(OpCodes.Ldloc, scratch));
                body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
                body.Add(Instruction.Create(OpCodes.And));
                body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
                body.Add(Instruction.Create(OpCodes.Shl));
                body.Add(Instruction.Create(OpCodes.Add));
                body.Add(Instruction.Create(OpCodes.Stloc, scratch));
                break;
            case 1:
                // (x ^ k) ^ k == x discarded into scratch
                var k = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
                body.Add(Instruction.Create(OpCodes.Ldc_I4, a));
                body.Add(Instruction.Create(OpCodes.Ldc_I4, k));
                body.Add(Instruction.Create(OpCodes.Xor));
                body.Add(Instruction.Create(OpCodes.Ldc_I4, k));
                body.Add(Instruction.Create(OpCodes.Xor));
                body.Add(Instruction.Create(OpCodes.Stloc, scratch));
                break;
            default:
                // Opaque true branch that still lands on the real instruction
                var left = RandomNumberGenerator.GetInt32(1, int.MaxValue);
                body.Add(Instruction.Create(OpCodes.Ldc_I4, left));
                body.Add(Instruction.Create(OpCodes.Ldc_I4, left));
                body.Add(Instruction.Create(OpCodes.Ceq));
                body.Add(Instruction.Create(OpCodes.Brtrue, continueAt));
                body.Add(Instruction.Create(OpCodes.Ldc_I4, RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue)));
                body.Add(Instruction.Create(OpCodes.Stloc, scratch));
                break;
        }
    }

    private static bool CanWeave(MethodDef method, bool dense, out string reason)
    {
        reason = "ok";
        if (method.Body.HasExceptionHandlers)
        {
            reason = "exception-handlers";
            return false;
        }

        var maxSize = dense ? 400 : 600;
        if (method.Body.Instructions.Count > maxSize)
        {
            reason = "too-large";
            return false;
        }

        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.OpCode == OpCodes.Switch)
            {
                reason = "switch-dispatcher";
                return false;
            }

            if (instruction.OpCode.Code == Code.Jmp ||
                instruction.OpCode.Code is Code.Constrained or Code.Readonly or Code.Tailcall or
                    Code.Unaligned or Code.Volatile or Code.No or Code.Prefix1 or Code.Prefix2 or
                    Code.Prefix3 or Code.Prefix4 or Code.Prefix5 or Code.Prefix6 or Code.Prefix7 or Code.Prefixref)
            {
                reason = "unsupported-prefix";
                return false;
            }
        }

        return true;
    }

    private static bool IsBranch(Instruction instruction) =>
        instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch ||
        instruction.OpCode == OpCodes.Switch;
}

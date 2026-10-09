using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace OneGamingOBFUSCATION.Protection;

/// <summary>
/// Ensures MaxStack and branch forms stay valid after heavy IL expansion.
/// Uses KeepOldMaxStack with a raised ceiling so dnlib does not abort the write
/// when a transform produces stack-ambiguous but runtime-valid Mono IL.
/// </summary>
public static class ModuleBodyFixups
{
    public static void RecalculateBodies(ModuleDef module)
    {
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody))
        {
            var body = method.Body;
            try
            {
                body.SimplifyBranches();
                body.OptimizeBranches();
                body.UpdateInstructionOffsets();
            }
            catch
            {
                // Keep the body as-is if branch optimization fails after transforms.
            }

            var estimated = ComputeMaxStack(body);
            body.MaxStack = (ushort)Math.Min(ushort.MaxValue, Math.Max(body.MaxStack, estimated));
            body.KeepOldMaxStack = true;
        }
    }

    public static void ConfigureWriter(ModuleWriterOptions writerOptions)
    {
        writerOptions.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
        writerOptions.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;
    }

    private static int ComputeMaxStack(CilBody body)
    {
        // Generous ceiling after weave/string/proxy expansion. Prefer oversize to
        // InvalidProgramException / writer abort from an undersized MaxStack.
        var pushes = 0;
        foreach (var instruction in body.Instructions)
        {
            pushes += instruction.OpCode.StackBehaviourPush switch
            {
                StackBehaviour.Push1 or StackBehaviour.Pushi or StackBehaviour.Pushi8 or
                    StackBehaviour.Pushr4 or StackBehaviour.Pushr8 or StackBehaviour.Pushref => 1,
                StackBehaviour.Push1_push1 => 2,
                _ => 0
            };
        }

        var fromInstructions = Math.Min(ushort.MaxValue - 8, body.Instructions.Count / 2 + 32);
        var fromPushes = Math.Min(ushort.MaxValue - 8, pushes / 3 + 24);
        return Math.Max(16, Math.Max(fromInstructions, fromPushes));
    }
}

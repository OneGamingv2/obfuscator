using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;

namespace OneGamingOBFUSCATION.Protection;

public static class ControlFlowProtection
{
    public static ProtectionStats Apply(ModuleDef module, CompatibilityAnalysis policy)
    {
        var stats = new ProtectionStats();
        foreach (var method in module.GetTypes()
                     .Where(type => !type.IsGlobalModuleType)
                     .SelectMany(type => type.Methods)
                     .ToArray())
        {
            if (!policy.IsMethodTransformationSafe(method))
            {
                if (method.HasBody)
                    stats.Skip("preserved-or-unsafe");
                continue;
            }

            stats.Candidates++;
            if (!CanFlatten(method, out var reason))
            {
                stats.Skip(reason);
                continue;
            }

            if (!TryBuildMaze(method))
            {
                stats.Skip("maze-failed");
                continue;
            }

            stats.Applied++;
        }

        return stats;
    }

    private static bool CanFlatten(MethodDef method, out string reason)
    {
        reason = "ok";
        if (method.Body.HasExceptionHandlers)
        {
            reason = "exception-handlers";
            return false;
        }

        if (method.Body.Instructions.Count is < 4 or > 400)
        {
            reason = "size-limit";
            return false;
        }

        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.OpCode.Code is Code.Jmp or Code.Calli or Code.Cpobj or Code.Initblk or Code.Cpblk ||
                instruction.OpCode.Code is Code.Constrained or Code.Readonly or Code.Tailcall or
                    Code.Unaligned or Code.Volatile or Code.No ||
                instruction.OpCode == OpCodes.Switch)
            {
                reason = "unsupported-opcode";
                return false;
            }
        }

        return true;
    }

    private static bool TryBuildMaze(MethodDef method)
    {
        method.Body.SimplifyBranches();
        var originals = method.Body.Instructions.ToList();
        var blocks = BuildBlocks(originals);
        if (blocks.Count < 2)
            return false;

        var firstInstructionBlock = new Dictionary<Instruction, int>();
        for (var index = 0; index < blocks.Count; index++)
            firstInstructionBlock[blocks[index][0]] = index;

        var module = method.Module;
        var state = new Local(module.CorLibTypes.Int32);
        var key = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(state);
        method.Body.Variables.Add(key);
        method.Body.InitLocals = true;

        var xorKey = RandomNumberGenerator.GetInt32(1, int.MaxValue);
        var trapCount = Math.Clamp(blocks.Count, 2, 6);
        var totalRooms = blocks.Count + trapCount;
        int Encode(int dense) => dense ^ xorKey;

        var order = Enumerable.Range(0, totalRooms).ToArray();
        for (var i = order.Length - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (order[i], order[j]) = (order[j], order[i]);
        }

        var denseToCase = new int[totalRooms];
        for (var caseIndex = 0; caseIndex < totalRooms; caseIndex++)
            denseToCase[order[caseIndex]] = caseIndex;

        int EncodeRoom(int denseRoom) => Encode(denseToCase[denseRoom]);

        var dispatcher = Instruction.Create(OpCodes.Nop);
        var caseLabels = Enumerable.Range(0, totalRooms).Select(_ => Instruction.Create(OpCodes.Nop)).ToArray();
        var body = new List<Instruction>
        {
            Instruction.CreateLdcI4(xorKey),
            Instruction.Create(OpCodes.Stloc, key),
            Instruction.CreateLdcI4(EncodeRoom(0)),
            Instruction.Create(OpCodes.Stloc, state),
            Instruction.Create(OpCodes.Br, dispatcher),
            dispatcher,
            Instruction.Create(OpCodes.Ldloc, state),
            Instruction.Create(OpCodes.Ldloc, key),
            Instruction.Create(OpCodes.Xor),
            Instruction.Create(OpCodes.Switch, caseLabels)
        };
        AppendFallbackReturn(method, body);

        for (var caseIndex = 0; caseIndex < totalRooms; caseIndex++)
        {
            var room = order[caseIndex];
            body.Add(caseLabels[caseIndex]);

            if (room >= blocks.Count)
            {
                var nextTrap = blocks.Count + ((room - blocks.Count + 1) % trapCount);
                EmitGoto(body, state, EncodeRoom(nextTrap), dispatcher);
                continue;
            }

            var block = blocks[room];
            for (var instructionIndex = 0; instructionIndex < block.Count; instructionIndex++)
            {
                var instruction = block[instructionIndex];
                if (instruction.OpCode.FlowControl == FlowControl.Branch &&
                    instruction.Operand is Instruction target &&
                    firstInstructionBlock.TryGetValue(target, out var branchTarget))
                {
                    EmitGoto(body, state, EncodeRoom(branchTarget), dispatcher);
                    continue;
                }

                if (instruction.OpCode.FlowControl == FlowControl.Cond_Branch &&
                    instruction.Operand is Instruction condTarget &&
                    firstInstructionBlock.TryGetValue(condTarget, out var takenIndex))
                {
                    var fallthroughIndex = room + 1;
                    if (fallthroughIndex >= blocks.Count)
                        return false;

                    var takenLabel = Instruction.Create(OpCodes.Nop);
                    body.Add(Instruction.Create(instruction.OpCode, takenLabel));
                    EmitGoto(body, state, EncodeRoom(fallthroughIndex), dispatcher);
                    body.Add(takenLabel);
                    EmitGoto(body, state, EncodeRoom(takenIndex), dispatcher);
                    continue;
                }

                if (instruction.OpCode == OpCodes.Ret)
                {
                    body.Add(Instruction.Create(OpCodes.Ret));
                    continue;
                }

                body.Add(new Instruction(instruction.OpCode, instruction.Operand));
            }

            var last = block[^1];
            var endsWithTransfer = last.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch
                or FlowControl.Return or FlowControl.Throw;
            if (!endsWithTransfer)
            {
                if (room + 1 >= blocks.Count)
                    return false;
                EmitGoto(body, state, EncodeRoom(room + 1), dispatcher);
            }
        }

        method.Body.Instructions.Clear();
        foreach (var instruction in body)
            method.Body.Instructions.Add(instruction);
        return true;
    }

    private static void AppendFallbackReturn(MethodDef method, List<Instruction> body)
    {
        if (method.ReturnType.ElementType == ElementType.Void)
        {
            body.Add(Instruction.Create(OpCodes.Ret));
            return;
        }

        if (method.ReturnType.ElementType is ElementType.I4 or ElementType.U4 or ElementType.Boolean or
            ElementType.I2 or ElementType.U2 or ElementType.I1 or ElementType.U1 or ElementType.Char or
            ElementType.I or ElementType.U)
        {
            body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            body.Add(Instruction.Create(OpCodes.Ret));
            return;
        }

        if (method.ReturnType.ElementType is ElementType.I8 or ElementType.U8)
        {
            body.Add(Instruction.Create(OpCodes.Ldc_I8, 0L));
            body.Add(Instruction.Create(OpCodes.Ret));
            return;
        }

        if (method.ReturnType.ElementType is ElementType.R4)
        {
            body.Add(Instruction.Create(OpCodes.Ldc_R4, 0f));
            body.Add(Instruction.Create(OpCodes.Ret));
            return;
        }

        if (method.ReturnType.ElementType is ElementType.R8)
        {
            body.Add(Instruction.Create(OpCodes.Ldc_R8, 0d));
            body.Add(Instruction.Create(OpCodes.Ret));
            return;
        }

        if (method.ReturnType.IsValueType)
        {
            var local = new Local(method.ReturnType);
            method.Body.Variables.Add(local);
            body.Add(Instruction.Create(OpCodes.Ldloca, local));
            body.Add(Instruction.Create(OpCodes.Initobj, method.ReturnType.ToTypeDefOrRef()));
            body.Add(Instruction.Create(OpCodes.Ldloc, local));
            body.Add(Instruction.Create(OpCodes.Ret));
            return;
        }

        body.Add(Instruction.Create(OpCodes.Ldnull));
        body.Add(Instruction.Create(OpCodes.Ret));
    }

    private static void EmitGoto(List<Instruction> body, Local state, int encodedState, Instruction dispatcher)
    {
        body.Add(Instruction.CreateLdcI4(encodedState));
        body.Add(Instruction.Create(OpCodes.Stloc, state));
        body.Add(Instruction.Create(OpCodes.Br, dispatcher));
    }

    private static List<List<Instruction>> BuildBlocks(List<Instruction> instructions)
    {
        var leaders = new HashSet<Instruction> { instructions[0] };
        for (var index = 0; index < instructions.Count; index++)
        {
            var instruction = instructions[index];
            if (instruction.Operand is Instruction target)
                leaders.Add(target);

            if (instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch
                or FlowControl.Return or FlowControl.Throw)
            {
                if (index + 1 < instructions.Count)
                    leaders.Add(instructions[index + 1]);
            }
        }

        var blocks = new List<List<Instruction>>();
        List<Instruction>? current = null;
        foreach (var instruction in instructions)
        {
            if (leaders.Contains(instruction))
            {
                current = [];
                blocks.Add(current);
            }

            current!.Add(instruction);
        }

        return blocks;
    }
}

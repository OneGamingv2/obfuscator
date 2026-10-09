using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;

namespace OneGamingOBFUSCATION.Protection;

/// <summary>
/// Real stack-machine virtualization for eligible Int32/bool/void helpers.
/// Original IL is replaced by encrypted VM bytecode + an embedded interpreter.
/// </summary>
public static class Int32Virtualization
{
    private const byte OpLoadArgument = 0;
    private const byte OpLoadConstant = 1;
    private const byte OpAdd = 2;
    private const byte OpSub = 3;
    private const byte OpMul = 4;
    private const byte OpXor = 5;
    private const byte OpAnd = 6;
    private const byte OpOr = 7;
    private const byte OpDiv = 8;
    private const byte OpRem = 9;
    private const byte OpShl = 10;
    private const byte OpShr = 11;
    private const byte OpNeg = 12;
    private const byte OpNot = 13;
    private const byte OpDup = 14;
    private const byte OpPop = 15;
    private const byte OpLoadLocal = 16;
    private const byte OpStoreLocal = 17;
    private const byte OpCeq = 18;
    private const byte OpClt = 19;
    private const byte OpCgt = 20;
    private const byte OpBr = 21;
    private const byte OpBrTrue = 22;
    private const byte OpBrFalse = 23;
    private const byte OpBeq = 24;
    private const byte OpBne = 25;
    private const byte OpBlt = 26;
    private const byte OpBle = 27;
    private const byte OpBgt = 28;
    private const byte OpBge = 29;
    private const byte OpRet = 30;
    private const byte OpRetVoid = 31;
    private const int LogicalOpcodeCount = 32;

    public static ProtectionStats Apply(
        ModuleDef module,
        CompatibilityAnalysis policy,
        bool aggressive = false,
        IReadOnlySet<MethodDef>? onlyMethods = null)
    {
        var stats = new ProtectionStats();
        var wire = ScrambleOpcodes();
        var candidates = new List<(MethodDef Method, byte[] Bytecode, int LocalCount, bool ReturnsVoid)>();

        foreach (var method in module.GetTypes().Where(type => !type.IsGlobalModuleType).SelectMany(type => type.Methods).ToArray())
        {
            if (onlyMethods is not null && !onlyMethods.Contains(method))
                continue;

            if (!policy.IsMethodTransformationSafe(method))
            {
                if (method.HasBody)
                    stats.Skip("preserved-or-unsafe");
                continue;
            }

            stats.Candidates++;
            if (!TryCompile(method, wire, aggressive, out var bytecode, out var localCount, out var returnsVoid, out var reason))
            {
                stats.Skip(reason);
                continue;
            }

            candidates.Add((method, bytecode, localCount, returnsVoid));
        }

        if (candidates.Count == 0)
            return stats;

        var interpreter = CreateInterpreter(module, wire);
        foreach (var candidate in candidates)
        {
            Rewrite(candidate.Method, candidate.Bytecode, candidate.LocalCount, candidate.ReturnsVoid, interpreter);
            stats.Applied++;
        }

        return stats;
    }

    private static byte[] ScrambleOpcodes()
    {
        var values = Enumerable.Range(0, LogicalOpcodeCount).Select(i => (byte)i).ToArray();
        for (var i = values.Length - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (values[i], values[j]) = (values[j], values[i]);
        }

        return values;
    }

    private static bool TryCompile(
        MethodDef method,
        byte[] wire,
        bool aggressive,
        out byte[] bytecode,
        out int localCount,
        out bool returnsVoid,
        out string reason)
    {
        bytecode = Array.Empty<byte>();
        localCount = 0;
        returnsVoid = false;
        reason = "unsupported";

        var signature = method.MethodSig;
        if (!method.IsStatic)
        {
            reason = "instance-method";
            return false;
        }

        if (signature is null || signature.GenParamCount != 0)
        {
            reason = "generic-signature";
            return false;
        }

        returnsVoid = signature.RetType.ElementType == ElementType.Void;
        var returnsI4 = signature.RetType.ElementType is ElementType.I4 or ElementType.Boolean;
        if (!returnsVoid && !returnsI4)
        {
            reason = "unsupported-return";
            return false;
        }

        var maxParams = aggressive ? 12 : 8;
        var maxLocals = aggressive ? 16 : 8;
        var maxInstr = aggressive ? 120 : 80;

        if (signature.Params.Count > maxParams ||
            signature.Params.Any(type => type.ElementType is not (ElementType.I4 or ElementType.Boolean)))
        {
            reason = "unsupported-parameters";
            return false;
        }

        if (method.Body.HasExceptionHandlers)
        {
            reason = "exception-handlers";
            return false;
        }

        if (method.Body.Variables.Count > maxLocals ||
            method.Body.Variables.Any(local => local.Type.ElementType is not (ElementType.I4 or ElementType.Boolean)))
        {
            reason = "unsupported-locals";
            return false;
        }

        if (method.Body.Instructions.Count > maxInstr)
        {
            reason = "too-large";
            return false;
        }

        localCount = method.Body.Variables.Count;
        method.Body.SimplifyMacros(method.Parameters);

        var pieces = new List<Piece>();
        var instrStart = new Dictionary<Instruction, int>();

        foreach (var instruction in method.Body.Instructions)
        {
            instrStart[instruction] = pieces.Count;

            if (instruction.OpCode == OpCodes.Nop)
                continue;

            if (TryGetArgumentIndex(instruction, out var argumentIndex))
            {
                if (argumentIndex < 0 || argumentIndex >= signature.Params.Count)
                {
                    reason = "bad-argument";
                    return false;
                }

                pieces.Add(Piece.Op(wire[OpLoadArgument], (byte)argumentIndex));
                continue;
            }

            if (TryGetLocalIndex(instruction, isStore: false, out var loadLocal))
            {
                if (loadLocal < 0 || loadLocal >= localCount)
                {
                    reason = "bad-local";
                    return false;
                }

                pieces.Add(Piece.Op(wire[OpLoadLocal], (byte)loadLocal));
                continue;
            }

            if (TryGetLocalIndex(instruction, isStore: true, out var storeLocal))
            {
                if (storeLocal < 0 || storeLocal >= localCount)
                {
                    reason = "bad-local";
                    return false;
                }

                pieces.Add(Piece.Op(wire[OpStoreLocal], (byte)storeLocal));
                continue;
            }

            if (instruction.IsLdcI4())
            {
                pieces.Add(Piece.Op(wire[OpLoadConstant], BitConverter.GetBytes(instruction.GetLdcI4Value())));
                continue;
            }

            if (instruction.OpCode.Code is Code.Br or Code.Br_S)
            {
                if (instruction.Operand is not Instruction target)
                {
                    reason = "bad-branch";
                    return false;
                }

                pieces.Add(Piece.Branch(wire[OpBr], target));
                continue;
            }

            if (TryMapCondBranch(instruction, wire, out var branchOp, out var branchTarget))
            {
                pieces.Add(Piece.Branch(branchOp, branchTarget!));
                continue;
            }

            var mapped = instruction.OpCode.Code switch
            {
                Code.Add => wire[OpAdd],
                Code.Sub => wire[OpSub],
                Code.Mul => wire[OpMul],
                Code.Xor => wire[OpXor],
                Code.And => wire[OpAnd],
                Code.Or => wire[OpOr],
                Code.Div => wire[OpDiv],
                Code.Rem => wire[OpRem],
                Code.Shl => wire[OpShl],
                Code.Shr => wire[OpShr],
                Code.Neg => wire[OpNeg],
                Code.Not => wire[OpNot],
                Code.Dup => wire[OpDup],
                Code.Pop => wire[OpPop],
                Code.Ceq => wire[OpCeq],
                Code.Clt => wire[OpClt],
                Code.Cgt => wire[OpCgt],
                Code.Ret => returnsVoid ? wire[OpRetVoid] : wire[OpRet],
                _ => (byte?)null
            };

            if (mapped is null)
            {
                reason = "unsupported-opcode:" + instruction.OpCode.Name;
                return false;
            }

            pieces.Add(Piece.Op(mapped.Value));
        }

        if (pieces.Count < 2)
        {
            reason = "too-small-or-invalid";
            return false;
        }

        var piecePc = new int[pieces.Count];
        var pc = 0;
        for (var i = 0; i < pieces.Count; i++)
        {
            piecePc[i] = pc;
            pc += pieces[i].Size;
        }

        int TargetPc(Instruction target)
        {
            if (!instrStart.TryGetValue(target, out var pieceIndex))
                throw new InvalidOperationException("Missing branch target.");
            while (pieceIndex < pieces.Count && pieces[pieceIndex].Size == 0)
                pieceIndex++;
            return pieceIndex >= pieces.Count ? pc : piecePc[pieceIndex];
        }

        var output = new List<byte>(pc);
        foreach (var piece in pieces)
        {
            output.Add(piece.Opcode);
            if (piece.Immediate is not null)
                output.AddRange(piece.Immediate);
            if (piece.BranchTarget is not null)
                output.AddRange(BitConverter.GetBytes(TargetPc(piece.BranchTarget)));
        }

        bytecode = output.ToArray();
        return bytecode.Length > 0;
    }

    private static bool TryMapCondBranch(Instruction instruction, byte[] wire, out byte opcode, out Instruction? target)
    {
        target = instruction.Operand as Instruction;
        opcode = 0xFF;
        if (target is null)
            return false;

        opcode = instruction.OpCode.Code switch
        {
            Code.Brtrue or Code.Brtrue_S => wire[OpBrTrue],
            Code.Brfalse or Code.Brfalse_S => wire[OpBrFalse],
            Code.Beq or Code.Beq_S => wire[OpBeq],
            Code.Bne_Un or Code.Bne_Un_S => wire[OpBne],
            Code.Blt or Code.Blt_S or Code.Blt_Un or Code.Blt_Un_S => wire[OpBlt],
            Code.Ble or Code.Ble_S or Code.Ble_Un or Code.Ble_Un_S => wire[OpBle],
            Code.Bgt or Code.Bgt_S or Code.Bgt_Un or Code.Bgt_Un_S => wire[OpBgt],
            Code.Bge or Code.Bge_S or Code.Bge_Un or Code.Bge_Un_S => wire[OpBge],
            _ => (byte)0xFF
        };
        return opcode != 0xFF;
    }

    private sealed class Piece
    {
        public byte Opcode { get; private init; }
        public byte[]? Immediate { get; private init; }
        public Instruction? BranchTarget { get; private init; }
        public int Size => 1 + (Immediate?.Length ?? 0) + (BranchTarget is null ? 0 : 4);

        public static Piece Op(byte opcode, params byte[] immediate) => new()
        {
            Opcode = opcode,
            Immediate = immediate.Length == 0 ? null : immediate
        };

        public static Piece Branch(byte opcode, Instruction target) => new()
        {
            Opcode = opcode,
            BranchTarget = target
        };
    }

    private static bool TryGetArgumentIndex(Instruction instruction, out int index)
    {
        index = instruction.OpCode.Code switch
        {
            Code.Ldarg_0 => 0,
            Code.Ldarg_1 => 1,
            Code.Ldarg_2 => 2,
            Code.Ldarg_3 => 3,
            Code.Ldarg or Code.Ldarg_S when instruction.Operand is Parameter parameter => parameter.MethodSigIndex,
            _ => -1
        };
        return index >= 0;
    }

    private static bool TryGetLocalIndex(Instruction instruction, bool isStore, out int index)
    {
        index = isStore
            ? instruction.OpCode.Code switch
            {
                Code.Stloc_0 => 0,
                Code.Stloc_1 => 1,
                Code.Stloc_2 => 2,
                Code.Stloc_3 => 3,
                Code.Stloc or Code.Stloc_S when instruction.Operand is Local local => local.Index,
                _ => -1
            }
            : instruction.OpCode.Code switch
            {
                Code.Ldloc_0 => 0,
                Code.Ldloc_1 => 1,
                Code.Ldloc_2 => 2,
                Code.Ldloc_3 => 3,
                Code.Ldloc or Code.Ldloc_S when instruction.Operand is Local local => local.Index,
                _ => -1
            };
        return index >= 0;
    }

    private static void Rewrite(MethodDef method, byte[] bytecode, int localCount, bool returnsVoid, MethodDef interpreter)
    {
        var key = RandomNumberGenerator.GetInt32(1, 256);
        var encrypted = new byte[bytecode.Length];
        for (var index = 0; index < bytecode.Length; index++)
            encrypted[index] = (byte)(bytecode[index] ^ unchecked((byte)(key + index * 17)));

        var module = method.Module;
        var body = new CilBody { InitLocals = true };
        method.Body = body;

        body.Instructions.Add(Instruction.CreateLdcI4(encrypted.Length));
        body.Instructions.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte));
        for (var index = 0; index < encrypted.Length; index++)
        {
            body.Instructions.Add(Instruction.Create(OpCodes.Dup));
            body.Instructions.Add(Instruction.CreateLdcI4(index));
            body.Instructions.Add(Instruction.CreateLdcI4(encrypted[index]));
            body.Instructions.Add(Instruction.Create(OpCodes.Stelem_I1));
        }

        body.Instructions.Add(Instruction.CreateLdcI4(method.MethodSig!.Params.Count));
        body.Instructions.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));
        for (var index = 0; index < method.MethodSig.Params.Count; index++)
        {
            var parameter = method.Parameters.Single(item => item.IsNormalMethodParameter && item.MethodSigIndex == index);
            body.Instructions.Add(Instruction.Create(OpCodes.Dup));
            body.Instructions.Add(Instruction.CreateLdcI4(index));
            body.Instructions.Add(Instruction.Create(OpCodes.Ldarg, parameter));
            body.Instructions.Add(Instruction.Create(OpCodes.Stelem_I4));
        }

        body.Instructions.Add(Instruction.CreateLdcI4(localCount));
        body.Instructions.Add(Instruction.CreateLdcI4(key));
        body.Instructions.Add(Instruction.Create(OpCodes.Call, interpreter));
        if (returnsVoid)
            body.Instructions.Add(Instruction.Create(OpCodes.Pop));
        body.Instructions.Add(Instruction.Create(OpCodes.Ret));
    }

    private static MethodDef CreateInterpreter(ModuleDef module, byte[] wire)
    {
        var byteArray = new SZArraySig(module.CorLibTypes.Byte);
        var intArray = new SZArraySig(module.CorLibTypes.Int32);
        var method = new MethodDefUser(
            CreateRuntimeName(),
            MethodSig.CreateStatic(module.CorLibTypes.Int32, byteArray, intArray, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig)
        {
            Body = new CilBody { InitLocals = true }
        };
        module.GlobalType.Methods.Add(method);

        var code = new Local(byteArray);
        var decodeIndex = new Local(module.CorLibTypes.Int32);
        var stack = new Local(intArray);
        var locals = new Local(intArray);
        var sp = new Local(module.CorLibTypes.Int32);
        var pc = new Local(module.CorLibTypes.Int32);
        var op = new Local(module.CorLibTypes.Int32);
        var tmp = new Local(module.CorLibTypes.Int32);
        var left = new Local(module.CorLibTypes.Int32);
        var right = new Local(module.CorLibTypes.Int32);
        var translate = new Local(byteArray);
        foreach (var local in new[] { code, decodeIndex, stack, locals, sp, pc, op, tmp, left, right, translate })
            method.Body.Variables.Add(local);

        var toInt32 = new MemberRefUser(
            module,
            "ToInt32",
            MethodSig.CreateStatic(module.CorLibTypes.Int32, byteArray, module.CorLibTypes.Int32),
            new TypeRefUser(module, "System", "BitConverter", module.CorLibTypes.AssemblyRef));

        var body = method.Body.Instructions;
        var loop = Instruction.Create(OpCodes.Nop);
        var cases = Enumerable.Range(0, LogicalOpcodeCount).Select(_ => Instruction.Create(OpCodes.Nop)).ToArray();
        var decodeBody = Instruction.Create(OpCodes.Nop);
        var decodeCheck = Instruction.Create(OpCodes.Nop);

        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Stloc, code));

        body.Add(Instruction.CreateLdcI4(256));
        body.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte));
        body.Add(Instruction.Create(OpCodes.Stloc, translate));
        for (var logical = 0; logical < LogicalOpcodeCount; logical++)
        {
            body.Add(Instruction.Create(OpCodes.Ldloc, translate));
            body.Add(Instruction.CreateLdcI4(wire[logical]));
            body.Add(Instruction.CreateLdcI4(logical));
            body.Add(Instruction.Create(OpCodes.Stelem_I1));
        }

        body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        body.Add(Instruction.Create(OpCodes.Stloc, decodeIndex));
        body.Add(Instruction.Create(OpCodes.Br, decodeCheck));
        body.Add(decodeBody);
        body.Add(Instruction.Create(OpCodes.Ldloc, code));
        body.Add(Instruction.Create(OpCodes.Ldloc, decodeIndex));
        body.Add(Instruction.Create(OpCodes.Ldloc, code));
        body.Add(Instruction.Create(OpCodes.Ldloc, decodeIndex));
        body.Add(Instruction.Create(OpCodes.Ldelem_U1));
        body.Add(Instruction.Create(OpCodes.Ldarg_3));
        body.Add(Instruction.Create(OpCodes.Ldloc, decodeIndex));
        body.Add(Instruction.CreateLdcI4(17));
        body.Add(Instruction.Create(OpCodes.Mul));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Xor));
        body.Add(Instruction.Create(OpCodes.Conv_U1));
        body.Add(Instruction.Create(OpCodes.Stelem_I1));
        Inc(body, decodeIndex, 1);
        body.Add(decodeCheck);
        body.Add(Instruction.Create(OpCodes.Ldloc, decodeIndex));
        body.Add(Instruction.Create(OpCodes.Ldloc, code));
        body.Add(Instruction.Create(OpCodes.Ldlen));
        body.Add(Instruction.Create(OpCodes.Conv_I4));
        body.Add(Instruction.Create(OpCodes.Blt, decodeBody));

        body.Add(Instruction.CreateLdcI4(128));
        body.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));
        body.Add(Instruction.Create(OpCodes.Stloc, stack));
        body.Add(Instruction.Create(OpCodes.Ldarg_2));
        body.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));
        body.Add(Instruction.Create(OpCodes.Stloc, locals));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        body.Add(Instruction.Create(OpCodes.Stloc, sp));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        body.Add(Instruction.Create(OpCodes.Stloc, pc));
        body.Add(Instruction.Create(OpCodes.Br, loop));

        body.Add(loop);
        body.Add(Instruction.Create(OpCodes.Ldloc, code));
        body.Add(Instruction.Create(OpCodes.Ldloc, pc));
        body.Add(Instruction.Create(OpCodes.Ldelem_U1));
        body.Add(Instruction.Create(OpCodes.Stloc, tmp));
        Inc(body, pc, 1);
        body.Add(Instruction.Create(OpCodes.Ldloc, translate));
        body.Add(Instruction.Create(OpCodes.Ldloc, tmp));
        body.Add(Instruction.Create(OpCodes.Ldelem_U1));
        body.Add(Instruction.Create(OpCodes.Stloc, op));
        body.Add(Instruction.Create(OpCodes.Ldloc, op));
        body.Add(Instruction.Create(OpCodes.Switch, cases));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        body.Add(Instruction.Create(OpCodes.Ret));

        // LoadArg
        body.Add(cases[OpLoadArgument]);
        PushSlot(body, stack, sp);
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Ldloc, code));
        body.Add(Instruction.Create(OpCodes.Ldloc, pc));
        body.Add(Instruction.Create(OpCodes.Ldelem_U1));
        body.Add(Instruction.Create(OpCodes.Ldelem_I4));
        body.Add(Instruction.Create(OpCodes.Stelem_I4));
        Inc(body, sp, 1);
        Inc(body, pc, 1);
        body.Add(Instruction.Create(OpCodes.Br, loop));

        // LoadConst
        body.Add(cases[OpLoadConstant]);
        PushSlot(body, stack, sp);
        body.Add(Instruction.Create(OpCodes.Ldloc, code));
        body.Add(Instruction.Create(OpCodes.Ldloc, pc));
        body.Add(Instruction.Create(OpCodes.Call, toInt32));
        body.Add(Instruction.Create(OpCodes.Stelem_I4));
        Inc(body, sp, 1);
        Inc(body, pc, 4);
        body.Add(Instruction.Create(OpCodes.Br, loop));

        EmitBin(body, cases[OpAdd], stack, sp, OpCodes.Add, loop);
        EmitBin(body, cases[OpSub], stack, sp, OpCodes.Sub, loop);
        EmitBin(body, cases[OpMul], stack, sp, OpCodes.Mul, loop);
        EmitBin(body, cases[OpXor], stack, sp, OpCodes.Xor, loop);
        EmitBin(body, cases[OpAnd], stack, sp, OpCodes.And, loop);
        EmitBin(body, cases[OpOr], stack, sp, OpCodes.Or, loop);
        EmitBin(body, cases[OpDiv], stack, sp, OpCodes.Div, loop);
        EmitBin(body, cases[OpRem], stack, sp, OpCodes.Rem, loop);
        EmitBin(body, cases[OpShl], stack, sp, OpCodes.Shl, loop);
        EmitBin(body, cases[OpShr], stack, sp, OpCodes.Shr, loop);
        EmitUnary(body, cases[OpNeg], stack, sp, OpCodes.Neg, loop);
        EmitUnary(body, cases[OpNot], stack, sp, OpCodes.Not, loop);

        body.Add(cases[OpDup]);
        PushSlot(body, stack, sp);
        body.Add(Instruction.Create(OpCodes.Ldloc, stack));
        body.Add(Instruction.Create(OpCodes.Ldloc, sp));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Sub));
        body.Add(Instruction.Create(OpCodes.Ldelem_I4));
        body.Add(Instruction.Create(OpCodes.Stelem_I4));
        Inc(body, sp, 1);
        body.Add(Instruction.Create(OpCodes.Br, loop));

        body.Add(cases[OpPop]);
        Inc(body, sp, -1);
        body.Add(Instruction.Create(OpCodes.Br, loop));

        body.Add(cases[OpLoadLocal]);
        PushSlot(body, stack, sp);
        body.Add(Instruction.Create(OpCodes.Ldloc, locals));
        body.Add(Instruction.Create(OpCodes.Ldloc, code));
        body.Add(Instruction.Create(OpCodes.Ldloc, pc));
        body.Add(Instruction.Create(OpCodes.Ldelem_U1));
        body.Add(Instruction.Create(OpCodes.Ldelem_I4));
        body.Add(Instruction.Create(OpCodes.Stelem_I4));
        Inc(body, sp, 1);
        Inc(body, pc, 1);
        body.Add(Instruction.Create(OpCodes.Br, loop));

        body.Add(cases[OpStoreLocal]);
        Inc(body, sp, -1);
        body.Add(Instruction.Create(OpCodes.Ldloc, locals));
        body.Add(Instruction.Create(OpCodes.Ldloc, code));
        body.Add(Instruction.Create(OpCodes.Ldloc, pc));
        body.Add(Instruction.Create(OpCodes.Ldelem_U1));
        body.Add(Instruction.Create(OpCodes.Ldloc, stack));
        body.Add(Instruction.Create(OpCodes.Ldloc, sp));
        body.Add(Instruction.Create(OpCodes.Ldelem_I4));
        body.Add(Instruction.Create(OpCodes.Stelem_I4));
        Inc(body, pc, 1);
        body.Add(Instruction.Create(OpCodes.Br, loop));

        EmitBin(body, cases[OpCeq], stack, sp, OpCodes.Ceq, loop);
        EmitBin(body, cases[OpClt], stack, sp, OpCodes.Clt, loop);
        EmitBin(body, cases[OpCgt], stack, sp, OpCodes.Cgt, loop);

        EmitBr(body, cases[OpBr], code, stack, sp, pc, tmp, left, right, toInt32, loop, BranchKind.Always);
        EmitBr(body, cases[OpBrTrue], code, stack, sp, pc, tmp, left, right, toInt32, loop, BranchKind.True);
        EmitBr(body, cases[OpBrFalse], code, stack, sp, pc, tmp, left, right, toInt32, loop, BranchKind.False);
        EmitBr(body, cases[OpBeq], code, stack, sp, pc, tmp, left, right, toInt32, loop, BranchKind.Beq);
        EmitBr(body, cases[OpBne], code, stack, sp, pc, tmp, left, right, toInt32, loop, BranchKind.Bne);
        EmitBr(body, cases[OpBlt], code, stack, sp, pc, tmp, left, right, toInt32, loop, BranchKind.Blt);
        EmitBr(body, cases[OpBle], code, stack, sp, pc, tmp, left, right, toInt32, loop, BranchKind.Ble);
        EmitBr(body, cases[OpBgt], code, stack, sp, pc, tmp, left, right, toInt32, loop, BranchKind.Bgt);
        EmitBr(body, cases[OpBge], code, stack, sp, pc, tmp, left, right, toInt32, loop, BranchKind.Bge);

        body.Add(cases[OpRet]);
        body.Add(Instruction.Create(OpCodes.Ldloc, stack));
        body.Add(Instruction.Create(OpCodes.Ldloc, sp));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Sub));
        body.Add(Instruction.Create(OpCodes.Ldelem_I4));
        body.Add(Instruction.Create(OpCodes.Ret));

        body.Add(cases[OpRetVoid]);
        body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        body.Add(Instruction.Create(OpCodes.Ret));

        return method;
    }

    private enum BranchKind { Always, True, False, Beq, Bne, Blt, Ble, Bgt, Bge }

    private static void EmitBr(
        IList<Instruction> body, Instruction label, Local code, Local stack, Local sp, Local pc, Local tmp,
        Local left, Local right, IMethod toInt32, Instruction loop, BranchKind kind)
    {
        body.Add(label);
        var take = Instruction.Create(OpCodes.Nop);
        var fall = Instruction.Create(OpCodes.Nop);

        body.Add(Instruction.Create(OpCodes.Ldloc, code));
        body.Add(Instruction.Create(OpCodes.Ldloc, pc));
        body.Add(Instruction.Create(OpCodes.Call, toInt32));
        body.Add(Instruction.Create(OpCodes.Stloc, tmp));
        Inc(body, pc, 4);

        if (kind == BranchKind.Always)
        {
            body.Add(Instruction.Create(OpCodes.Ldloc, tmp));
            body.Add(Instruction.Create(OpCodes.Stloc, pc));
            body.Add(Instruction.Create(OpCodes.Br, loop));
            return;
        }

        if (kind is BranchKind.True or BranchKind.False)
        {
            Inc(body, sp, -1);
            body.Add(Instruction.Create(OpCodes.Ldloc, stack));
            body.Add(Instruction.Create(OpCodes.Ldloc, sp));
            body.Add(Instruction.Create(OpCodes.Ldelem_I4));
            body.Add(Instruction.Create(kind == BranchKind.True ? OpCodes.Brtrue : OpCodes.Brfalse, take));
            body.Add(Instruction.Create(OpCodes.Br, fall));
        }
        else
        {
            body.Add(Instruction.Create(OpCodes.Ldloc, stack));
            body.Add(Instruction.Create(OpCodes.Ldloc, sp));
            body.Add(Instruction.Create(OpCodes.Ldc_I4_2));
            body.Add(Instruction.Create(OpCodes.Sub));
            body.Add(Instruction.Create(OpCodes.Ldelem_I4));
            body.Add(Instruction.Create(OpCodes.Stloc, left));
            body.Add(Instruction.Create(OpCodes.Ldloc, stack));
            body.Add(Instruction.Create(OpCodes.Ldloc, sp));
            body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            body.Add(Instruction.Create(OpCodes.Sub));
            body.Add(Instruction.Create(OpCodes.Ldelem_I4));
            body.Add(Instruction.Create(OpCodes.Stloc, right));
            Inc(body, sp, -2);
            body.Add(Instruction.Create(OpCodes.Ldloc, left));
            body.Add(Instruction.Create(OpCodes.Ldloc, right));
            body.Add(kind switch
            {
                BranchKind.Beq => Instruction.Create(OpCodes.Beq, take),
                BranchKind.Bne => Instruction.Create(OpCodes.Bne_Un, take),
                BranchKind.Blt => Instruction.Create(OpCodes.Blt, take),
                BranchKind.Ble => Instruction.Create(OpCodes.Ble, take),
                BranchKind.Bgt => Instruction.Create(OpCodes.Bgt, take),
                _ => Instruction.Create(OpCodes.Bge, take)
            });
            body.Add(Instruction.Create(OpCodes.Br, fall));
        }

        body.Add(take);
        body.Add(Instruction.Create(OpCodes.Ldloc, tmp));
        body.Add(Instruction.Create(OpCodes.Stloc, pc));
        body.Add(Instruction.Create(OpCodes.Br, loop));
        body.Add(fall);
        body.Add(Instruction.Create(OpCodes.Br, loop));
    }

    private static void EmitBin(IList<Instruction> body, Instruction label, Local stack, Local sp, OpCode op, Instruction loop)
    {
        body.Add(label);
        body.Add(Instruction.Create(OpCodes.Ldloc, stack));
        body.Add(Instruction.Create(OpCodes.Ldloc, sp));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_2));
        body.Add(Instruction.Create(OpCodes.Sub));
        body.Add(Instruction.Create(OpCodes.Ldloc, stack));
        body.Add(Instruction.Create(OpCodes.Ldloc, sp));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_2));
        body.Add(Instruction.Create(OpCodes.Sub));
        body.Add(Instruction.Create(OpCodes.Ldelem_I4));
        body.Add(Instruction.Create(OpCodes.Ldloc, stack));
        body.Add(Instruction.Create(OpCodes.Ldloc, sp));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Sub));
        body.Add(Instruction.Create(OpCodes.Ldelem_I4));
        body.Add(Instruction.Create(op));
        body.Add(Instruction.Create(OpCodes.Stelem_I4));
        Inc(body, sp, -1);
        body.Add(Instruction.Create(OpCodes.Br, loop));
    }

    private static void EmitUnary(IList<Instruction> body, Instruction label, Local stack, Local sp, OpCode op, Instruction loop)
    {
        body.Add(label);
        body.Add(Instruction.Create(OpCodes.Ldloc, stack));
        body.Add(Instruction.Create(OpCodes.Ldloc, sp));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Sub));
        body.Add(Instruction.Create(OpCodes.Ldloc, stack));
        body.Add(Instruction.Create(OpCodes.Ldloc, sp));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Sub));
        body.Add(Instruction.Create(OpCodes.Ldelem_I4));
        body.Add(Instruction.Create(op));
        body.Add(Instruction.Create(OpCodes.Stelem_I4));
        body.Add(Instruction.Create(OpCodes.Br, loop));
    }

    private static void PushSlot(IList<Instruction> body, Local stack, Local sp)
    {
        body.Add(Instruction.Create(OpCodes.Ldloc, stack));
        body.Add(Instruction.Create(OpCodes.Ldloc, sp));
    }

    private static void Inc(IList<Instruction> body, Local local, int amount)
    {
        body.Add(Instruction.Create(OpCodes.Ldloc, local));
        body.Add(Instruction.CreateLdcI4(Math.Abs(amount)));
        body.Add(Instruction.Create(amount >= 0 ? OpCodes.Add : OpCodes.Sub));
        body.Add(Instruction.Create(OpCodes.Stloc, local));
    }

    private static string CreateRuntimeName() =>
        "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
}

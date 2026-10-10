using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;
using System.Text;

namespace OneGamingOBFUSCATION.Protection;

public static class LocalStringProtection
{
    public static ProtectionStats Apply(ModuleDef module, CompatibilityAnalysis? policy = null, bool multilayer = false)
    {
        var stats = new ProtectionStats();
        var decoderPool = new List<MethodDef>();
        var poolSize = multilayer ? RandomNumberGenerator.GetInt32(3, 6) : 1;
        for (var i = 0; i < poolSize; i++)
            decoderPool.Add(CreateDecoder(module, multilayer));

        var methods = module.GetTypes()
            .Where(type => !type.IsGlobalModuleType)
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .ToArray();

        foreach (var method in methods)
        {
            if (policy is not null && !policy.IsMethodTransformationSafe(method))
            {
                stats.Skip("preserved-or-unsafe");
                continue;
            }

            method.Body.SimplifyBranches();
            var instructions = method.Body.Instructions;
            for (var index = 0; index < instructions.Count; index++)
            {
                var instruction = instructions[index];
                if (instruction.OpCode != OpCodes.Ldstr || instruction.Operand is not string text)
                    continue;

                stats.Candidates++;
                if (text.Length == 0)
                {
                    stats.Skip("empty");
                    continue;
                }

                if (text.Length > 2048)
                {
                    stats.Skip("too-large");
                    continue;
                }

                if (IsLikelyCompatibilityLiteral(text))
                {
                    stats.Skip("compat-literal");
                    continue;
                }

                var rounds = multilayer ? RandomNumberGenerator.GetInt32(2, 4) : 1;
                var keys = new byte[rounds];
                RandomNumberGenerator.Fill(keys);
                var payload = Encoding.UTF8.GetBytes(text);
                for (var round = 0; round < rounds; round++)
                {
                    for (var i = 0; i < payload.Length; i++)
                        payload[i] = (byte)(payload[i] ^ keys[round] ^ unchecked((byte)(i + round * 17)));
                }

                var decoder = decoderPool[RandomNumberGenerator.GetInt32(0, decoderPool.Count)];
                var emit = new List<Instruction>
                {
                    Instruction.CreateLdcI4(payload.Length),
                    Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte)
                };
                for (var i = 0; i < payload.Length; i++)
                {
                    emit.Add(Instruction.Create(OpCodes.Dup));
                    emit.Add(Instruction.CreateLdcI4(i));
                    emit.Add(Instruction.CreateLdcI4(payload[i]));
                    emit.Add(Instruction.Create(OpCodes.Stelem_I1));
                }

                if (multilayer)
                {
                    emit.Add(Instruction.CreateLdcI4(rounds));
                    emit.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte));
                    for (var k = 0; k < rounds; k++)
                    {
                        emit.Add(Instruction.Create(OpCodes.Dup));
                        emit.Add(Instruction.CreateLdcI4(k));
                        emit.Add(Instruction.CreateLdcI4(keys[k]));
                        emit.Add(Instruction.Create(OpCodes.Stelem_I1));
                    }
                }
                else
                {
                    emit.Add(Instruction.CreateLdcI4(keys[0]));
                }

                emit.Add(Instruction.Create(OpCodes.Call, decoder));

                instructions[index].OpCode = emit[0].OpCode;
                instructions[index].Operand = emit[0].Operand;
                for (var i = 1; i < emit.Count; i++)
                    instructions.Insert(index + i, emit[i]);
                index += emit.Count - 1;
                stats.Applied++;
            }
        }

        return stats;
    }

    private static MethodDef CreateDecoder(ModuleDef module, bool multilayer) =>
        multilayer ? CreateMultiKeyDecoder(module) : CreateSimpleDecoder(module);

    private static MethodDef CreateSimpleDecoder(ModuleDef module)
    {
        var method = new MethodDefUser(
            CreateName(),
            MethodSig.CreateStatic(module.CorLibTypes.String, new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.Int32),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig)
        {
            Body = new CilBody { InitLocals = true }
        };

        var length = new Local(module.CorLibTypes.Int32);
        var index = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(length);
        method.Body.Variables.Add(index);

        var loop = Instruction.Create(OpCodes.Nop);
        var done = Instruction.Create(OpCodes.Nop);

        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldlen));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_I4));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, length));
        method.Body.Instructions.Add(Instruction.CreateLdcI4(0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, index));
        method.Body.Instructions.Add(loop);
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, index));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, length));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Bge_S, done));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, index));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, index));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldelem_U1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Xor));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, index));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Xor));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_U1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stelem_I1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, index));
        method.Body.Instructions.Add(Instruction.CreateLdcI4(1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, index));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Br_S, loop));
        method.Body.Instructions.Add(done);
        EmitUtf8Return(module, method);
        module.GlobalType.Methods.Add(method);
        return method;
    }

    private static MethodDef CreateMultiKeyDecoder(ModuleDef module)
    {
        var method = new MethodDefUser(
            CreateName(),
            MethodSig.CreateStatic(module.CorLibTypes.String, new SZArraySig(module.CorLibTypes.Byte), new SZArraySig(module.CorLibTypes.Byte)),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig)
        {
            Body = new CilBody { InitLocals = true }
        };

        var round = new Local(module.CorLibTypes.Int32);
        var i = new Local(module.CorLibTypes.Int32);
        var key = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(round);
        method.Body.Variables.Add(i);
        method.Body.Variables.Add(key);

        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldlen));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_I4));
        method.Body.Instructions.Add(Instruction.CreateLdcI4(1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Sub));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, round));

        var outer = Instruction.Create(OpCodes.Nop);
        var outerDone = Instruction.Create(OpCodes.Nop);
        method.Body.Instructions.Add(outer);
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, round));
        method.Body.Instructions.Add(Instruction.CreateLdcI4(0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Blt_S, outerDone));

        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, round));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldelem_U1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, key));

        method.Body.Instructions.Add(Instruction.CreateLdcI4(0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, i));
        var inner = Instruction.Create(OpCodes.Nop);
        var innerDone = Instruction.Create(OpCodes.Nop);
        method.Body.Instructions.Add(inner);
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, i));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldlen));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_I4));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Bge_S, innerDone));

        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, i));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, i));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldelem_U1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, key));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Xor));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, i));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, round));
        method.Body.Instructions.Add(Instruction.CreateLdcI4(17));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Mul));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Xor));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_U1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stelem_I1));

        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, i));
        method.Body.Instructions.Add(Instruction.CreateLdcI4(1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, i));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Br_S, inner));
        method.Body.Instructions.Add(innerDone);

        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, round));
        method.Body.Instructions.Add(Instruction.CreateLdcI4(1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Sub));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, round));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Br_S, outer));
        method.Body.Instructions.Add(outerDone);

        EmitUtf8Return(module, method);
        module.GlobalType.Methods.Add(method);
        return method;
    }

    private static void EmitUtf8Return(ModuleDef module, MethodDef method)
    {
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, module.Import(typeof(Encoding).GetProperty(nameof(Encoding.UTF8))!.GetMethod!)));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, module.Import(typeof(Encoding).GetMethod(nameof(Encoding.GetString), [typeof(byte[])])!)));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
    }

    private static string CreateName() => InvisibleNames.Next();

    private static bool IsLikelyCompatibilityLiteral(string text) =>
        text.StartsWith("com.", StringComparison.OrdinalIgnoreCase) ||
        text.StartsWith("org.", StringComparison.OrdinalIgnoreCase);
}

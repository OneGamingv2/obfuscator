using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;
using System.Text;

namespace OneGamingOBFUSCATION.Protection;

/// <summary>
/// Converts <c>const string</c> fields (e.g. BepInEx GUID/Name/Version) into
/// encrypted static fields initialized at runtime. Custom attribute blobs that
/// already inlined the same literals (like [BepInPlugin(...)]) are left intact
/// so loaders keep working, while dnSpy no longer shows a readable const.
/// </summary>
public static class ConstantStringFieldProtection
{
    public static ProtectionStats Apply(ModuleDef module)
    {
        var stats = new ProtectionStats();
        var decoder = CreateDecoder(module);
        var cctor = EnsureStaticConstructor(module.GlobalType);
        var insertAt = Math.Max(0, cctor.Body.Instructions.Count - 1);
        var blobOrdinal = 0;
        var converted = 0;

        foreach (var type in module.GetTypes().Where(type => !type.IsGlobalModuleType && !type.IsEnum).ToArray())
        {
            foreach (var field in type.Fields.ToArray())
            {
                stats.Candidates++;
                if (!field.IsLiteral || !field.HasConstant || field.Constant?.Value is not string value)
                {
                    stats.Skip("not-string-const");
                    continue;
                }

                if (field.FieldSig?.Type.ElementType != ElementType.String)
                {
                    stats.Skip("non-string-type");
                    continue;
                }

                if (value.Length == 0)
                {
                    stats.Skip("empty");
                    continue;
                }

                // Strip literal metadata so dnSpy cannot display = "..."
                field.Attributes = (field.Attributes & ~(FieldAttributes.Literal | FieldAttributes.HasDefault))
                                   | FieldAttributes.Static;
                field.Constant = null;

                var seed = RandomNumberGenerator.GetInt32(1, int.MaxValue);
                var blob = CreateBlobField(module, blobOrdinal++);
                EmitBlobInitializer(cctor, blob, Encrypt(value, seed), ref insertAt);
                EmitFieldAssignment(cctor, field, blob, seed, decoder, ref insertAt);
                converted++;
                stats.Applied++;
            }
        }

        if (converted == 0)
        {
            module.GlobalType.Methods.Remove(decoder);
            if (cctor.Body.Instructions.Count == 1 && cctor.Body.Instructions[0].OpCode == OpCodes.Ret &&
                cctor.DeclaringType.FindStaticConstructor() == cctor &&
                module.GlobalType.Methods.Contains(cctor) &&
                !module.GlobalType.Fields.Any())
            {
                // leave empty cctor; other passes may use it
            }
        }

        return stats;
    }

    private static void EmitFieldAssignment(
        MethodDef cctor,
        FieldDef target,
        FieldDef blob,
        int seed,
        MethodDef decoder,
        ref int insertAt)
    {
        var batch = new[]
        {
            Instruction.Create(OpCodes.Ldsfld, blob),
            Instruction.CreateLdcI4(seed),
            Instruction.Create(OpCodes.Call, decoder),
            Instruction.Create(OpCodes.Stsfld, target)
        };
        for (var index = 0; index < batch.Length; index++)
            cctor.Body.Instructions.Insert(insertAt + index, batch[index]);
        insertAt += batch.Length;
    }

    private static void EmitBlobInitializer(MethodDef cctor, FieldDef field, byte[] encrypted, ref int insertAt)
    {
        var module = cctor.Module;
        var batch = new List<Instruction>
        {
            Instruction.CreateLdcI4(encrypted.Length),
            Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef)
        };
        for (var index = 0; index < encrypted.Length; index++)
        {
            batch.Add(Instruction.Create(OpCodes.Dup));
            batch.Add(Instruction.CreateLdcI4(index));
            batch.Add(Instruction.CreateLdcI4(encrypted[index]));
            batch.Add(Instruction.Create(OpCodes.Stelem_I1));
        }

        batch.Add(Instruction.Create(OpCodes.Stsfld, field));
        for (var index = 0; index < batch.Count; index++)
            cctor.Body.Instructions.Insert(insertAt + index, batch[index]);
        insertAt += batch.Count;
    }

    private static FieldDef CreateBlobField(ModuleDef module, int ordinal)
    {
        var field = new FieldDefUser(
            "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(10)).ToLowerInvariant() + ordinal.ToString("x"),
            new FieldSig(new SZArraySig(module.CorLibTypes.Byte)),
            FieldAttributes.Assembly | FieldAttributes.Static);
        module.GlobalType.Fields.Add(field);
        return field;
    }

    private static MethodDef EnsureStaticConstructor(TypeDef type)
    {
        var existing = type.FindStaticConstructor();
        if (existing is not null)
        {
            if (!existing.HasBody)
                existing.Body = new CilBody();
            if (existing.Body.Instructions.Count == 0 || existing.Body.Instructions[^1].OpCode != OpCodes.Ret)
                existing.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            return existing;
        }

        var cctor = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(type.Module.CorLibTypes.Void),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig |
            MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(cctor);
        return cctor;
    }

    private static byte[] Encrypt(string value, int seed)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var state = unchecked((uint)seed);
        for (var index = 0; index < bytes.Length; index++)
        {
            state = state * 1664525u + 1013904223u;
            bytes[index] ^= (byte)(state >> 16);
            bytes[index] ^= (byte)(index * 131 + (seed & 0xFF));
        }

        return bytes;
    }

    private static MethodDef CreateDecoder(ModuleDef module)
    {
        var byteArray = new SZArraySig(module.CorLibTypes.Byte);
        var method = new MethodDefUser(
            "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant(),
            MethodSig.CreateStatic(module.CorLibTypes.String, byteArray, module.CorLibTypes.Int32),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig)
        {
            Body = new CilBody { InitLocals = true }
        };

        var bytesLocal = new Local(byteArray);
        var indexLocal = new Local(module.CorLibTypes.Int32);
        var stateLocal = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(bytesLocal);
        method.Body.Variables.Add(indexLocal);
        method.Body.Variables.Add(stateLocal);

        var encodingType = new TypeRefUser(module, "System.Text", "Encoding", module.CorLibTypes.AssemblyRef);
        var arrayType = new TypeRefUser(module, "System", "Array", module.CorLibTypes.AssemblyRef);
        var getUtf8 = new MemberRefUser(module, "get_UTF8", MethodSig.CreateStatic(encodingType.ToTypeSig()), encodingType);
        var getString = new MemberRefUser(module, "GetString", MethodSig.CreateInstance(module.CorLibTypes.String, byteArray), encodingType);
        var arrayCopy = new MemberRefUser(
            module,
            "Copy",
            MethodSig.CreateStatic(module.CorLibTypes.Void, new ClassSig(arrayType), new ClassSig(arrayType), module.CorLibTypes.Int32),
            arrayType);

        var loopBody = Instruction.Create(OpCodes.Ldloc, stateLocal);
        var loopCheck = Instruction.Create(OpCodes.Ldloc, indexLocal);
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldlen));
        body.Add(Instruction.Create(OpCodes.Conv_I4));
        body.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
        body.Add(Instruction.Create(OpCodes.Stloc, bytesLocal));
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldloc, bytesLocal));
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldlen));
        body.Add(Instruction.Create(OpCodes.Conv_I4));
        body.Add(Instruction.Create(OpCodes.Call, arrayCopy));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Stloc, stateLocal));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        body.Add(Instruction.Create(OpCodes.Stloc, indexLocal));
        body.Add(Instruction.Create(OpCodes.Br, loopCheck));
        body.Add(loopBody);
        body.Add(Instruction.CreateLdcI4(1664525));
        body.Add(Instruction.Create(OpCodes.Mul));
        body.Add(Instruction.CreateLdcI4(1013904223));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Stloc, stateLocal));
        body.Add(Instruction.Create(OpCodes.Ldloc, bytesLocal));
        body.Add(Instruction.Create(OpCodes.Ldloc, indexLocal));
        body.Add(Instruction.Create(OpCodes.Ldloc, bytesLocal));
        body.Add(Instruction.Create(OpCodes.Ldloc, indexLocal));
        body.Add(Instruction.Create(OpCodes.Ldelem_U1));
        body.Add(Instruction.Create(OpCodes.Ldloc, stateLocal));
        body.Add(Instruction.CreateLdcI4(16));
        body.Add(Instruction.Create(OpCodes.Shr_Un));
        body.Add(Instruction.Create(OpCodes.Xor));
        body.Add(Instruction.Create(OpCodes.Ldloc, indexLocal));
        body.Add(Instruction.CreateLdcI4(131));
        body.Add(Instruction.Create(OpCodes.Mul));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.CreateLdcI4(0xFF));
        body.Add(Instruction.Create(OpCodes.And));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Xor));
        body.Add(Instruction.Create(OpCodes.Conv_U1));
        body.Add(Instruction.Create(OpCodes.Stelem_I1));
        body.Add(Instruction.Create(OpCodes.Ldloc, indexLocal));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Stloc, indexLocal));
        body.Add(loopCheck);
        body.Add(Instruction.Create(OpCodes.Ldloc, bytesLocal));
        body.Add(Instruction.Create(OpCodes.Ldlen));
        body.Add(Instruction.Create(OpCodes.Conv_I4));
        body.Add(Instruction.Create(OpCodes.Blt, loopBody));
        body.Add(Instruction.Create(OpCodes.Call, getUtf8));
        body.Add(Instruction.Create(OpCodes.Ldloc, bytesLocal));
        body.Add(Instruction.Create(OpCodes.Callvirt, getString));
        body.Add(Instruction.Create(OpCodes.Ret));
        module.GlobalType.Methods.Add(method);
        return method;
    }
}

using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;
using System.Text;

namespace OneGamingOBFUSCATION.Protection;

public static class EmbeddedResourceProtection
{
    public static ProtectionStats Apply(ModuleDef module)
    {
        var stats = new ProtectionStats();
        var entries = new List<ResourceEntry>();

        foreach (var resource in module.Resources.ToArray())
        {
            stats.Candidates++;
            if (resource is not EmbeddedResource embedded)
            {
                stats.Skip("non-embedded-resource");
                continue;
            }

            var originalName = embedded.Name.String;
            if (string.IsNullOrWhiteSpace(originalName))
            {
                stats.Skip("empty-name");
                continue;
            }

            if (originalName.EndsWith(".resources", StringComparison.OrdinalIgnoreCase) ||
                originalName.EndsWith(".resource", StringComparison.OrdinalIgnoreCase))
            {
                stats.Skip("resx-satellite");
                continue;
            }

            byte[] plain;
            try { plain = embedded.CreateReader().ToArray(); }
            catch
            {
                stats.Skip("unreadable");
                continue;
            }

            if (plain.Length == 0)
            {
                stats.Skip("empty-data");
                continue;
            }

            var seed = RandomNumberGenerator.GetInt32(1, int.MaxValue);
            var encrypted = Encrypt(plain, seed);
            var newName = "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(14)).ToLowerInvariant();
            module.Resources[module.Resources.IndexOf(resource)] =
                new EmbeddedResource(newName, encrypted, embedded.Attributes);
            entries.Add(new ResourceEntry(originalName, newName, seed));
            stats.Applied++;
        }

        if (entries.Count == 0)
            return stats;

        var decrypt = CreateDecryptMethod(module);
        var readAll = CreateReadAllBytesHelper(module);
        var resolver = CreateResolver(module, entries, decrypt, readAll);
        PatchCallSites(module, resolver);
        return stats;
    }

    private static void PatchCallSites(ModuleDef module, MethodDef resolver)
    {
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody))
        {
            if (method == resolver)
                continue;

            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt)
                    continue;
                if (instruction.Operand is not IMethod target)
                    continue;

                var fullName = target.FullName;
                if (fullName.Contains("GetManifestResourceStream", StringComparison.Ordinal) &&
                    target.MethodSig?.Params.Count == 1 &&
                    target.MethodSig.Params[0].ElementType == ElementType.String)
                {
                    instruction.OpCode = OpCodes.Call;
                    instruction.Operand = resolver;
                }
            }
        }
    }

    private static MethodDef CreateResolver(
        ModuleDef module,
        List<ResourceEntry> entries,
        MethodDef decrypt,
        MethodDef readAll)
    {
        var streamType = new TypeRefUser(module, "System.IO", "Stream", module.CorLibTypes.AssemblyRef);
        var memoryStreamType = new TypeRefUser(module, "System.IO", "MemoryStream", module.CorLibTypes.AssemblyRef);
        var assemblyType = new TypeRefUser(module, "System.Reflection", "Assembly", module.CorLibTypes.AssemblyRef);
        var byteArray = new SZArraySig(module.CorLibTypes.Byte);
        var stringArray = new SZArraySig(module.CorLibTypes.String);

        var method = new MethodDefUser(
            CreateRuntimeName(),
            MethodSig.CreateStatic(new ClassSig(streamType), new ClassSig(assemblyType), module.CorLibTypes.String),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig)
        {
            Body = new CilBody { InitLocals = true }
        };
        module.GlobalType.Methods.Add(method);

        var getStream = new MemberRefUser(
            module,
            "GetManifestResourceStream",
            MethodSig.CreateInstance(new ClassSig(streamType), module.CorLibTypes.String),
            assemblyType);
        var memoryCtor = new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void, byteArray),
            memoryStreamType);
        var mapField = CreateMapField(module);
        EnsureMapInitializer(module, mapField, entries);

        var mapLocal = new Local(stringArray);
        var indexLocal = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(mapLocal);
        method.Body.Variables.Add(indexLocal);

        var loopBody = Instruction.Create(OpCodes.Ldloc, mapLocal);
        var loopCheck = Instruction.Create(OpCodes.Ldloc, indexLocal);
        var notFound = Instruction.Create(OpCodes.Ldarg_0);
        var found = Instruction.Create(OpCodes.Ldarg_0);
        var body = method.Body.Instructions;

        body.Add(Instruction.Create(OpCodes.Ldsfld, mapField));
        body.Add(Instruction.Create(OpCodes.Stloc, mapLocal));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        body.Add(Instruction.Create(OpCodes.Stloc, indexLocal));
        body.Add(Instruction.Create(OpCodes.Br, loopCheck));

        body.Add(loopBody);
        body.Add(Instruction.Create(OpCodes.Ldloc, indexLocal));
        body.Add(Instruction.Create(OpCodes.Ldelem_Ref));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Call, CreateStringEquals(module)));
        body.Add(Instruction.Create(OpCodes.Brtrue, found));
        body.Add(Instruction.Create(OpCodes.Ldloc, indexLocal));
        body.Add(Instruction.CreateLdcI4(3));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Stloc, indexLocal));

        body.Add(loopCheck);
        body.Add(Instruction.Create(OpCodes.Ldloc, mapLocal));
        body.Add(Instruction.Create(OpCodes.Ldlen));
        body.Add(Instruction.Create(OpCodes.Conv_I4));
        body.Add(Instruction.Create(OpCodes.Blt, loopBody));

        body.Add(notFound);
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Callvirt, getStream));
        body.Add(Instruction.Create(OpCodes.Ret));

        body.Add(found);
        body.Add(Instruction.Create(OpCodes.Ldloc, mapLocal));
        body.Add(Instruction.Create(OpCodes.Ldloc, indexLocal));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Ldelem_Ref));
        body.Add(Instruction.Create(OpCodes.Callvirt, getStream));
        body.Add(Instruction.Create(OpCodes.Call, readAll));
        body.Add(Instruction.Create(OpCodes.Ldloc, mapLocal));
        body.Add(Instruction.Create(OpCodes.Ldloc, indexLocal));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_2));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Ldelem_Ref));
        body.Add(Instruction.Create(OpCodes.Call, CreateParseInt32(module)));
        body.Add(Instruction.Create(OpCodes.Call, decrypt));
        body.Add(Instruction.Create(OpCodes.Newobj, memoryCtor));
        body.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static FieldDef CreateMapField(ModuleDef module)
    {
        var field = new FieldDefUser(
            CreateRuntimeName(),
            new FieldSig(new SZArraySig(module.CorLibTypes.String)),
            FieldAttributes.Assembly | FieldAttributes.Static);
        module.GlobalType.Fields.Add(field);
        return field;
    }

    private static void EnsureMapInitializer(ModuleDef module, FieldDef mapField, List<ResourceEntry> entries)
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

        var insertAt = Math.Max(0, cctor.Body.Instructions.Count - 1);
        var batch = new List<Instruction>
        {
            Instruction.CreateLdcI4(entries.Count * 3),
            Instruction.Create(OpCodes.Newarr, module.CorLibTypes.String.ToTypeDefOrRef())
        };
        for (var index = 0; index < entries.Count; index++)
        {
            var entry = entries[index];
            void Store(int slot, string value)
            {
                batch.Add(Instruction.Create(OpCodes.Dup));
                batch.Add(Instruction.CreateLdcI4(index * 3 + slot));
                batch.Add(Instruction.Create(OpCodes.Ldstr, value));
                batch.Add(Instruction.Create(OpCodes.Stelem_Ref));
            }

            Store(0, entry.OriginalName);
            Store(1, entry.NewName);
            Store(2, entry.Seed.ToString());
        }

        batch.Add(Instruction.Create(OpCodes.Stsfld, mapField));
        for (var index = 0; index < batch.Count; index++)
            cctor.Body.Instructions.Insert(insertAt + index, batch[index]);
    }

    private static MethodDef CreateDecryptMethod(ModuleDef module)
    {
        var byteArray = new SZArraySig(module.CorLibTypes.Byte);
        var method = new MethodDefUser(
            CreateRuntimeName(),
            MethodSig.CreateStatic(byteArray, byteArray, module.CorLibTypes.Int32),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig)
        {
            Body = new CilBody { InitLocals = true }
        };
        module.GlobalType.Methods.Add(method);

        var data = new Local(byteArray);
        var index = new Local(module.CorLibTypes.Int32);
        var state = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(data);
        method.Body.Variables.Add(index);
        method.Body.Variables.Add(state);

        var arrayType = new TypeRefUser(module, "System", "Array", module.CorLibTypes.AssemblyRef);
        var arrayCopy = new MemberRefUser(
            module,
            "Copy",
            MethodSig.CreateStatic(module.CorLibTypes.Void, new ClassSig(arrayType), new ClassSig(arrayType), module.CorLibTypes.Int32),
            arrayType);

        var loopBody = Instruction.Create(OpCodes.Ldloc, state);
        var loopCheck = Instruction.Create(OpCodes.Ldloc, index);
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldlen));
        body.Add(Instruction.Create(OpCodes.Conv_I4));
        body.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
        body.Add(Instruction.Create(OpCodes.Stloc, data));
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldloc, data));
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldlen));
        body.Add(Instruction.Create(OpCodes.Conv_I4));
        body.Add(Instruction.Create(OpCodes.Call, arrayCopy));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Stloc, state));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        body.Add(Instruction.Create(OpCodes.Stloc, index));
        body.Add(Instruction.Create(OpCodes.Br, loopCheck));
        body.Add(loopBody);
        body.Add(Instruction.CreateLdcI4(1664525));
        body.Add(Instruction.Create(OpCodes.Mul));
        body.Add(Instruction.CreateLdcI4(1013904223));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Stloc, state));
        body.Add(Instruction.Create(OpCodes.Ldloc, data));
        body.Add(Instruction.Create(OpCodes.Ldloc, index));
        body.Add(Instruction.Create(OpCodes.Ldloc, data));
        body.Add(Instruction.Create(OpCodes.Ldloc, index));
        body.Add(Instruction.Create(OpCodes.Ldelem_U1));
        body.Add(Instruction.Create(OpCodes.Ldloc, state));
        body.Add(Instruction.CreateLdcI4(16));
        body.Add(Instruction.Create(OpCodes.Shr_Un));
        body.Add(Instruction.Create(OpCodes.Xor));
        body.Add(Instruction.Create(OpCodes.Ldloc, index));
        body.Add(Instruction.CreateLdcI4(131));
        body.Add(Instruction.Create(OpCodes.Mul));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.CreateLdcI4(0xFF));
        body.Add(Instruction.Create(OpCodes.And));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Xor));
        body.Add(Instruction.Create(OpCodes.Conv_U1));
        body.Add(Instruction.Create(OpCodes.Stelem_I1));
        body.Add(Instruction.Create(OpCodes.Ldloc, index));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Stloc, index));
        body.Add(loopCheck);
        body.Add(Instruction.Create(OpCodes.Ldloc, data));
        body.Add(Instruction.Create(OpCodes.Ldlen));
        body.Add(Instruction.Create(OpCodes.Conv_I4));
        body.Add(Instruction.Create(OpCodes.Blt, loopBody));
        body.Add(Instruction.Create(OpCodes.Ldloc, data));
        body.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static MethodDef CreateReadAllBytesHelper(ModuleDef module)
    {
        var streamType = new TypeRefUser(module, "System.IO", "Stream", module.CorLibTypes.AssemblyRef);
        var memoryStreamType = new TypeRefUser(module, "System.IO", "MemoryStream", module.CorLibTypes.AssemblyRef);
        var byteArray = new SZArraySig(module.CorLibTypes.Byte);
        var method = new MethodDefUser(
            CreateRuntimeName(),
            MethodSig.CreateStatic(byteArray, new ClassSig(streamType)),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig)
        {
            Body = new CilBody { InitLocals = true }
        };
        module.GlobalType.Methods.Add(method);

        var ms = new Local(new ClassSig(memoryStreamType));
        var result = new Local(byteArray);
        method.Body.Variables.Add(ms);
        method.Body.Variables.Add(result);

        var msCtor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), memoryStreamType);
        var copyTo = new MemberRefUser(
            module,
            "CopyTo",
            MethodSig.CreateInstance(module.CorLibTypes.Void, new ClassSig(streamType)),
            streamType);
        var toArray = new MemberRefUser(module, "ToArray", MethodSig.CreateInstance(byteArray), memoryStreamType);
        var dispose = new MemberRefUser(
            module,
            "Dispose",
            MethodSig.CreateInstance(module.CorLibTypes.Void),
            new TypeRefUser(module, "System", "IDisposable", module.CorLibTypes.AssemblyRef));

        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Newobj, msCtor));
        body.Add(Instruction.Create(OpCodes.Stloc, ms));
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldloc, ms));
        body.Add(Instruction.Create(OpCodes.Callvirt, copyTo));
        body.Add(Instruction.Create(OpCodes.Ldloc, ms));
        body.Add(Instruction.Create(OpCodes.Callvirt, toArray));
        body.Add(Instruction.Create(OpCodes.Stloc, result));
        body.Add(Instruction.Create(OpCodes.Ldloc, ms));
        body.Add(Instruction.Create(OpCodes.Callvirt, dispose));
        body.Add(Instruction.Create(OpCodes.Ldloc, result));
        body.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static MemberRefUser CreateStringEquals(ModuleDef module) =>
        new(module, "op_Equality",
            MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.String, module.CorLibTypes.String),
            module.CorLibTypes.String.ToTypeDefOrRef());

    private static MemberRefUser CreateParseInt32(ModuleDef module) =>
        new(module, "Parse", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.String),
            module.CorLibTypes.Int32.ToTypeDefOrRef());

    private static byte[] Encrypt(byte[] plain, int seed)
    {
        var bytes = (byte[])plain.Clone();
        var state = unchecked((uint)seed);
        for (var index = 0; index < bytes.Length; index++)
        {
            state = state * 1664525u + 1013904223u;
            bytes[index] ^= (byte)(state >> 16);
            bytes[index] ^= (byte)(index * 131 + (seed & 0xFF));
        }

        return bytes;
    }

    private static string CreateRuntimeName() =>
        "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();

    private sealed record ResourceEntry(string OriginalName, string NewName, int Seed);
}

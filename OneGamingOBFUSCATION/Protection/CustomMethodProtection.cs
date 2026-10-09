using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace OneGamingOBFUSCATION.Protection;

public readonly record struct CustomMethodResult(
    int Constants,
    int BinOps,
    int Virtualized,
    int Proxies,
    string VirtualizeSkips);

/// <summary>
/// Per-build custom methods. Constants and integer math are rewritten into
/// unique algebra helpers (not a fixed xor template), hidden behind proxies,
/// then virtualized. Noise passes call the same kind of helpers.
/// </summary>
public static class CustomMethodProtection
{
    private const int MaxConstantsPerMethod = 8;
    private const int MaxConstantsTotal = 64;
    private const int MaxBinOpsPerMethod = 16;
    private const int MaxBinOpsTotal = 100;

    private static readonly ConditionalWeakTable<ModuleDef, Kit> Kits = new();

    public static CustomMethodResult Apply(ModuleDef module, CompatibilityAnalysis policy, bool virtualize)
    {
        var targets = module.GetTypes()
            .Where(type => !type.IsGlobalModuleType)
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .ToArray();

        var kit = KitFor(module);
        var proxies = new Dictionary<MethodDef, MethodDef>();
        var referenced = new HashSet<MethodDef>();
        var constants = 0;
        var binOps = 0;
        var constBudget = MaxConstantsTotal;
        var binBudget = MaxBinOpsTotal;
        var ordered = targets.ToList();
        Shuffle(ordered);

        foreach (var method in ordered)
        {
            if (constBudget <= 0 && binBudget <= 0)
                break;
            if (!policy.IsMethodTransformationSafe(method) || method.Body.HasExceptionHandlers)
                continue;
            if (method.Body.Instructions.Count is 0 or > 2500)
                continue;

            binOps += OutlineBinOps(kit, method, proxies, referenced, ref binBudget);
            constants += LiftConstants(kit, method, proxies, referenced, ref constBudget);
        }

        var virtualized = 0;
        var skips = virtualize ? "none" : "disabled";
        if (virtualize && referenced.Count > 0)
        {
            var stats = Int32Virtualization.Apply(module, policy, aggressive: true, referenced);
            virtualized = stats.Applied;
            skips = stats.FormatSkipSummary();
        }

        kit.Stamp();
        return new CustomMethodResult(constants, binOps, virtualized, proxies.Count, skips);
    }

    internal static MethodDef NextMixer(ModuleDef module) => Pick(KitFor(module).Mixers);

    internal static MethodDef NextPredicate(ModuleDef module) => Pick(KitFor(module).Predicates);

    internal static MethodDef NextXor(ModuleDef module) => Pick(KitFor(module).Xors);

    private static Kit KitFor(ModuleDef module) => Kits.GetValue(module, CreateKit);

    private static MethodDef Pick(MethodDef[] methods) =>
        methods[RandomNumberGenerator.GetInt32(methods.Length)];

    private static int OutlineBinOps(
        Kit kit,
        MethodDef method,
        Dictionary<MethodDef, MethodDef> proxies,
        HashSet<MethodDef> referenced,
        ref int budget)
    {
        if (budget <= 0)
            return 0;

        var instructions = method.Body.Instructions;
        var hits = new List<Instruction>();
        var limit = Math.Min(MaxBinOpsPerMethod, budget);
        for (var index = 2; index < instructions.Count && hits.Count < limit; index++)
        {
            if (!kit.Operators.ContainsKey(instructions[index].OpCode.Code))
                continue;
            if (!PushesInt32(method, instructions[index - 1]) || !PushesInt32(method, instructions[index - 2]))
                continue;
            hits.Add(instructions[index]);
        }

        foreach (var instruction in hits)
        {
            var real = Pick(kit.Operators[instruction.OpCode.Code]);
            instruction.OpCode = OpCodes.Call;
            instruction.Operand = ProxyFor(kit, real, proxies, referenced);
        }

        budget -= hits.Count;
        return hits.Count;
    }

    private static int LiftConstants(
        Kit kit,
        MethodDef method,
        Dictionary<MethodDef, MethodDef> proxies,
        HashSet<MethodDef> referenced,
        ref int budget)
    {
        if (budget <= 0)
            return 0;

        var big = new List<Instruction>();
        var small = new List<Instruction>();
        foreach (var instruction in method.Body.Instructions)
        {
            if (!instruction.IsLdcI4())
                continue;
            if (Math.Abs(instruction.GetLdcI4Value()) > 8)
                big.Add(instruction);
            else
                small.Add(instruction);
        }

        Shuffle(big);
        Shuffle(small);
        var take = Math.Min(MaxConstantsPerMethod, budget);
        var chosen = new List<Instruction>(take);
        foreach (var instruction in big)
        {
            if (chosen.Count >= take)
                break;
            chosen.Add(instruction);
        }

        foreach (var instruction in small)
        {
            if (chosen.Count >= take)
                break;
            if (RandomNumberGenerator.GetInt32(100) < 35)
                chosen.Add(instruction);
        }

        foreach (var instruction in chosen)
        {
            var value = instruction.GetLdcI4Value();
            var real = CreateConstantMethod(kit, value);
            instruction.OpCode = OpCodes.Call;
            instruction.Operand = ProxyFor(kit, real, proxies, referenced);
        }

        budget -= chosen.Count;
        return chosen.Count;
    }

    private static MethodDef ProxyFor(
        Kit kit,
        MethodDef real,
        Dictionary<MethodDef, MethodDef> proxies,
        HashSet<MethodDef> referenced)
    {
        referenced.Add(real);
        if (proxies.TryGetValue(real, out var existing))
            return existing;

        var proxy = CreateMethod(kit.Carrier, "_" + Token(), real.MethodSig);
        EmitLoadArgs(proxy);
        proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Call, real));
        proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        proxies.Add(real, proxy);
        return proxy;
    }

    private static bool PushesInt32(MethodDef method, Instruction instruction)
    {
        if (instruction.IsLdcI4())
            return true;

        var localIndex = instruction.OpCode.Code switch
        {
            Code.Ldloc_0 => 0,
            Code.Ldloc_1 => 1,
            Code.Ldloc_2 => 2,
            Code.Ldloc_3 => 3,
            Code.Ldloc or Code.Ldloc_S when instruction.Operand is Local local => local.Index,
            _ => -1
        };
        if (localIndex >= 0)
            return localIndex < method.Body.Variables.Count && IsInt32(method.Body.Variables[localIndex].Type);

        if (instruction.Operand is Parameter parameter)
            return parameter.IsNormalMethodParameter && IsInt32(parameter.Type);

        var slot = instruction.OpCode.Code switch
        {
            Code.Ldarg_0 => 0,
            Code.Ldarg_1 => 1,
            Code.Ldarg_2 => 2,
            Code.Ldarg_3 => 3,
            _ => -1
        };
        if (slot < 0)
            return false;

        var sigIndex = method.IsStatic ? slot : slot - 1;
        if (sigIndex < 0)
            return false;

        var match = method.Parameters.FirstOrDefault(item => item.IsNormalMethodParameter && item.MethodSigIndex == sigIndex);
        return match is not null && IsInt32(match.Type);
    }

    private static bool IsInt32(TypeSig type) =>
        type.ElementType is ElementType.I4 or ElementType.Boolean;

    private static Kit CreateKit(ModuleDef module)
    {
        var kit = new Kit
        {
            Carrier = CreateType(module, module.CorLibTypes.Object.TypeDefOrRef, abstractSealed: true)
        };
        module.Types.Add(kit.Carrier);
        CreateStamp(module, kit);

        kit.Mixers =
        [
            CreateUnary(kit, EmitMixerXor),
            CreateUnary(kit, EmitMixerNot),
            CreateUnary(kit, EmitMixerAdd),
            CreateUnary(kit, EmitMixerMba)
        ];
        kit.Predicates =
        [
            CreatePredicate(kit, oddSquare: true),
            CreatePredicate(kit, oddSquare: false),
            CreatePredicate(kit, oddSquare: true)
        ];
        kit.Xors =
        [
            CreateBinary(kit, EmitXorOrAnd),
            CreateBinary(kit, EmitXorAndNot)
        ];
        kit.Operators = new Dictionary<Code, MethodDef[]>
        {
            [Code.Add] = [CreateBinary(kit, EmitAddMba), CreateBinary(kit, EmitAddOrAnd), CreateBinary(kit, EmitAddNeg)],
            [Code.Sub] = [CreateBinary(kit, EmitSubNeg), CreateBinary(kit, EmitSubXor)],
            [Code.Xor] = [CreateBinary(kit, EmitXorOrAnd), CreateBinary(kit, EmitXorAndNot)],
            [Code.And] = [CreateBinary(kit, EmitAndDemorgan), CreateBinary(kit, EmitAndDemorgan)],
            [Code.Or] = [CreateBinary(kit, EmitOrAdd), CreateBinary(kit, EmitOrDemorgan)],
            [Code.Mul] = [CreateBinary(kit, EmitMulSplit), CreateBinary(kit, EmitMulSplit)]
        };
        return kit;
    }

    private static MethodDef CreateConstantMethod(Kit kit, int value)
    {
        var method = CreateMethod(kit.Carrier, "_" + Token(), MethodSig.CreateStatic(kit.Carrier.Module.CorLibTypes.Int32));
        var local = new Local(kit.Carrier.Module.CorLibTypes.Int32);
        method.Body.Variables.Add(local);
        var real = Instruction.Create(OpCodes.Nop);
        var end = Instruction.Create(OpCodes.Nop);
        var seed = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
        var fake = unchecked(value ^ RandomNumberGenerator.GetInt32(1, int.MaxValue));
        var body = method.Body.Instructions;

        // (seed | 1)^2 is always odd, so this branch is always taken.
        body.Add(Instruction.CreateLdcI4(seed));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Or));
        body.Add(Instruction.Create(OpCodes.Dup));
        body.Add(Instruction.Create(OpCodes.Mul));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.And));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Ceq));
        body.Add(Instruction.Create(OpCodes.Brtrue, real));
        body.Add(Instruction.CreateLdcI4(fake));
        body.Add(Instruction.Create(OpCodes.Br, end));
        body.Add(real);
        EmitConstantPayload(body, value);
        body.Add(end);
        body.Add(Instruction.Create(OpCodes.Stloc, local));
        body.Add(Instruction.Create(OpCodes.Ldloc, local));
        body.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static void EmitConstantPayload(IList<Instruction> body, int value)
    {
        switch (RandomNumberGenerator.GetInt32(6))
        {
            case 0:
            {
                var key = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
                body.Add(Instruction.CreateLdcI4(value ^ key));
                body.Add(Instruction.CreateLdcI4(key));
                body.Add(Instruction.Create(OpCodes.Xor));
                break;
            }
            case 1:
            {
                var key = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
                body.Add(Instruction.CreateLdcI4(unchecked(value + key)));
                body.Add(Instruction.CreateLdcI4(key));
                body.Add(Instruction.Create(OpCodes.Sub));
                break;
            }
            case 2:
            {
                var odd = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue) | 1;
                var inverse = ModularInverse(odd);
                var encoded = unchecked((int)((uint)value * (uint)inverse));
                body.Add(Instruction.CreateLdcI4(encoded));
                body.Add(Instruction.CreateLdcI4(odd));
                body.Add(Instruction.Create(OpCodes.Mul));
                break;
            }
            case 3:
                body.Add(Instruction.CreateLdcI4(~value));
                body.Add(Instruction.Create(OpCodes.Not));
                break;
            case 4:
            {
                var key = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
                var left = unchecked(value - key);
                body.Add(Instruction.CreateLdcI4(left));
                body.Add(Instruction.CreateLdcI4(key));
                body.Add(Instruction.Create(OpCodes.Xor));
                body.Add(Instruction.CreateLdcI4(left));
                body.Add(Instruction.CreateLdcI4(key));
                body.Add(Instruction.Create(OpCodes.And));
                body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
                body.Add(Instruction.Create(OpCodes.Shl));
                body.Add(Instruction.Create(OpCodes.Add));
                break;
            }
            default:
            {
                var key = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
                var left = unchecked(value - key);
                body.Add(Instruction.CreateLdcI4(left));
                body.Add(Instruction.CreateLdcI4(key));
                body.Add(Instruction.Create(OpCodes.Or));
                body.Add(Instruction.CreateLdcI4(left));
                body.Add(Instruction.CreateLdcI4(key));
                body.Add(Instruction.Create(OpCodes.And));
                body.Add(Instruction.Create(OpCodes.Add));
                break;
            }
        }
    }

    private static int ModularInverse(int odd)
    {
        var value = (uint)odd;
        var inverse = value;
        inverse *= 2 - value * inverse;
        inverse *= 2 - value * inverse;
        inverse *= 2 - value * inverse;
        inverse *= 2 - value * inverse;
        inverse *= 2 - value * inverse;
        return unchecked((int)inverse);
    }

    private static MethodDef CreateUnary(Kit kit, Action<IList<Instruction>, int> emit)
    {
        var module = kit.Carrier.Module;
        var method = CreateMethod(kit.Carrier, "_" + Token(), MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32));
        emit(method.Body.Instructions, RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static MethodDef CreateBinary(Kit kit, Action<IList<Instruction>, int> emit)
    {
        var module = kit.Carrier.Module;
        var method = CreateMethod(
            kit.Carrier,
            "_" + Token(),
            MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32));
        emit(method.Body.Instructions, RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static MethodDef CreatePredicate(Kit kit, bool oddSquare)
    {
        var module = kit.Carrier.Module;
        var method = CreateMethod(kit.Carrier, "_" + Token(), MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.Int32));
        var body = method.Body.Instructions;
        if (oddSquare)
        {
            body.Add(Instruction.Create(OpCodes.Ldarg_0));
            body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            body.Add(Instruction.Create(OpCodes.Or));
            body.Add(Instruction.Create(OpCodes.Dup));
            body.Add(Instruction.Create(OpCodes.Mul));
            body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            body.Add(Instruction.Create(OpCodes.And));
            body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            body.Add(Instruction.Create(OpCodes.Ceq));
        }
        else
        {
            body.Add(Instruction.Create(OpCodes.Ldarg_0));
            body.Add(Instruction.Create(OpCodes.Ldarg_0));
            body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            body.Add(Instruction.Create(OpCodes.Add));
            body.Add(Instruction.Create(OpCodes.Mul));
            body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            body.Add(Instruction.Create(OpCodes.And));
            body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            body.Add(Instruction.Create(OpCodes.Ceq));
        }

        body.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static void EmitMixerXor(IList<Instruction> body, int key)
    {
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.CreateLdcI4(key));
        body.Add(Instruction.Create(OpCodes.Xor));
        body.Add(Instruction.CreateLdcI4(key));
        body.Add(Instruction.Create(OpCodes.Xor));
    }

    private static void EmitMixerNot(IList<Instruction> body, int key)
    {
        _ = key;
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Not));
        body.Add(Instruction.Create(OpCodes.Not));
    }

    private static void EmitMixerAdd(IList<Instruction> body, int key)
    {
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.CreateLdcI4(key));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.CreateLdcI4(key));
        body.Add(Instruction.Create(OpCodes.Sub));
    }

    private static void EmitMixerMba(IList<Instruction> body, int key)
    {
        // ((x ^ k) + 2*(x & k)) - k == x
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.CreateLdcI4(key));
        body.Add(Instruction.Create(OpCodes.Xor));
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.CreateLdcI4(key));
        body.Add(Instruction.Create(OpCodes.And));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Shl));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.CreateLdcI4(key));
        body.Add(Instruction.Create(OpCodes.Sub));
    }

    private static void EmitAddMba(IList<Instruction> body, int key)
    {
        _ = key;
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Xor));
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.And));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Shl));
        body.Add(Instruction.Create(OpCodes.Add));
    }

    private static void EmitAddOrAnd(IList<Instruction> body, int key)
    {
        _ = key;
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Or));
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.And));
        body.Add(Instruction.Create(OpCodes.Add));
    }

    private static void EmitAddNeg(IList<Instruction> body, int key)
    {
        // ~(~a - b) == a + b
        _ = key;
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Not));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Sub));
        body.Add(Instruction.Create(OpCodes.Not));
    }

    private static void EmitSubNeg(IList<Instruction> body, int key)
    {
        // a + (~b + 1) == a - b
        _ = key;
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Not));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Add));
    }

    private static void EmitSubXor(IList<Instruction> body, int key)
    {
        // (a ^ ~b) - 2*(~a & ~b) is not used; (a + k) - (b + k) == a - b
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.CreateLdcI4(key));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.CreateLdcI4(key));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Sub));
    }

    private static void EmitXorOrAnd(IList<Instruction> body, int key)
    {
        // (a | b) - (a & b) == a ^ b
        _ = key;
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Or));
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.And));
        body.Add(Instruction.Create(OpCodes.Sub));
    }

    private static void EmitXorAndNot(IList<Instruction> body, int key)
    {
        // (a & ~b) | (~a & b) == a ^ b
        _ = key;
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Not));
        body.Add(Instruction.Create(OpCodes.And));
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Not));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.And));
        body.Add(Instruction.Create(OpCodes.Or));
    }

    private static void EmitAndDemorgan(IList<Instruction> body, int key)
    {
        // ~(~a | ~b) == a & b
        _ = key;
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Not));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Not));
        body.Add(Instruction.Create(OpCodes.Or));
        body.Add(Instruction.Create(OpCodes.Not));
    }

    private static void EmitOrAdd(IList<Instruction> body, int key)
    {
        // (a & b) + (a ^ b) == a | b
        _ = key;
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.And));
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Xor));
        body.Add(Instruction.Create(OpCodes.Add));
    }

    private static void EmitOrDemorgan(IList<Instruction> body, int key)
    {
        // ~(~a & ~b) == a | b
        _ = key;
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Not));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Not));
        body.Add(Instruction.Create(OpCodes.And));
        body.Add(Instruction.Create(OpCodes.Not));
    }

    private static void EmitMulSplit(IList<Instruction> body, int key)
    {
        // (a + k) * b - k * b == a * b
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.CreateLdcI4(key));
        body.Add(Instruction.Create(OpCodes.Add));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Mul));
        body.Add(Instruction.CreateLdcI4(key));
        body.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Add(Instruction.Create(OpCodes.Mul));
        body.Add(Instruction.Create(OpCodes.Sub));
    }

    private static void EmitLoadArgs(MethodDef method)
    {
        var count = method.MethodSig.Params.Count;
        for (var index = 0; index < count; index++)
        {
            method.Body.Instructions.Add(index switch
            {
                0 => Instruction.Create(OpCodes.Ldarg_0),
                1 => Instruction.Create(OpCodes.Ldarg_1),
                2 => Instruction.Create(OpCodes.Ldarg_2),
                _ => Instruction.Create(OpCodes.Ldarg_3)
            });
        }
    }

    private static MethodDef CreateMethod(TypeDef carrier, string name, MethodSig signature)
    {
        var method = new MethodDefUser(
            name,
            signature,
            MethodImplAttributes.IL | MethodImplAttributes.Managed | MethodImplAttributes.NoInlining,
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig)
        {
            Body = new CilBody { InitLocals = true, MaxStack = 8 }
        };
        carrier.Methods.Add(method);
        return method;
    }

    private static TypeDefUser CreateType(ModuleDef module, ITypeDefOrRef baseType, bool abstractSealed)
    {
        var attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit;
        if (abstractSealed)
            attributes |= TypeAttributes.Abstract;
        return new TypeDefUser("_" + Token(), "_" + Token(), baseType)
        {
            Attributes = attributes
        };
    }

    private static void CreateStamp(ModuleDef module, Kit kit)
    {
        var attributeBase = new TypeRefUser(module, "System", "Attribute", module.CorLibTypes.AssemblyRef);
        kit.AttributeType = CreateType(module, attributeBase, abstractSealed: false);
        module.Types.Add(kit.AttributeType);
        var baseCtor = new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void),
            attributeBase);
        kit.StampCtor = new MethodDefUser(
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
        {
            Body = new CilBody { MaxStack = 1 }
        };
        kit.StampCtor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        kit.StampCtor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, baseCtor));
        kit.StampCtor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        kit.AttributeType.Methods.Add(kit.StampCtor);
    }

    private static void Shuffle<T>(List<T> items)
    {
        for (var index = items.Count - 1; index > 0; index--)
        {
            var swap = RandomNumberGenerator.GetInt32(index + 1);
            (items[index], items[swap]) = (items[swap], items[index]);
        }
    }

    private static string Token() => Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();

    private sealed class Kit
    {
        public TypeDef Carrier { get; set; } = null!;
        public TypeDef AttributeType { get; set; } = null!;
        public MethodDef StampCtor { get; set; } = null!;
        public MethodDef[] Mixers { get; set; } = [];
        public MethodDef[] Predicates { get; set; } = [];
        public MethodDef[] Xors { get; set; } = [];
        public Dictionary<Code, MethodDef[]> Operators { get; set; } = new();

        public void Stamp()
        {
            foreach (var method in Carrier.Methods)
            {
                if (method.IsConstructor || method.CustomAttributes.Any(attribute => attribute.Constructor == StampCtor))
                    continue;
                method.CustomAttributes.Add(new CustomAttribute(StampCtor));
            }
        }
    }
}

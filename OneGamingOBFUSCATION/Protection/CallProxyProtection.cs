using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;

namespace OneGamingOBFUSCATION.Protection;

public static class CallProxyProtection
{
    public static ProtectionStats Apply(ModuleDef module, CompatibilityAnalysis policy, int chainDepth = 1)
    {
        chainDepth = Math.Clamp(chainDepth, 1, 3);
        var stats = new ProtectionStats();
        var totalApplied = 0;
        for (var pass = 0; pass < chainDepth; pass++)
        {
            var passStats = ApplyOnce(module, policy, pass == 0);
            totalApplied += passStats.Applied;
            foreach (var pair in passStats.SkipReasons)
            {
                for (var i = 0; i < pair.Value; i++)
                    stats.Skip(pair.Key);
            }

            stats.Candidates += passStats.Candidates;
        }

        stats.Applied = totalApplied;
        return stats;
    }

    private static ProtectionStats ApplyOnce(ModuleDef module, CompatibilityAnalysis policy, bool countSkips)
    {
        var stats = new ProtectionStats();
        var proxies = new Dictionary<string, MethodDef>(StringComparer.Ordinal);
        var methods = module.GetTypes()
            .Where(type => !type.IsGlobalModuleType)
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .ToArray();

        foreach (var method in methods)
        {
            if (!policy.IsMethodTransformationSafe(method))
            {
                if (countSkips && method.HasBody)
                    stats.Skip("preserved-or-unsafe");
                continue;
            }

            if (method.DeclaringType.IsGlobalModuleType)
                continue;

            var instructions = method.Body.Instructions;
            for (var index = 0; index < instructions.Count; index++)
            {
                var instruction = instructions[index];
                if (instruction.OpCode != OpCodes.Call || instruction.Operand is not IMethod target)
                    continue;

                stats.Candidates++;
                if (!IsEligible(target, out var reason))
                {
                    if (countSkips)
                        stats.Skip(reason);
                    continue;
                }

                if (index > 0 && instructions[index - 1].OpCode == OpCodes.Tailcall)
                {
                    if (countSkips)
                        stats.Skip("tailcall");
                    continue;
                }

                if (!proxies.TryGetValue(target.FullName, out var proxy))
                {
                    proxy = CreateProxy(module, target);
                    proxies[target.FullName] = proxy;
                }

                instruction.Operand = proxy;
                stats.Applied++;
            }
        }

        return stats;
    }

    private static bool IsEligible(IMethod target, out string reason)
    {
        reason = "ok";
        if (target is MethodSpec || target.Name.String is ".ctor" or ".cctor")
        {
            reason = "ctor-or-generic-spec";
            return false;
        }

        var signature = target.MethodSig;
        if (signature is null || signature.HasThis || signature.GenParamCount != 0 || !IsSafeType(signature.RetType))
        {
            reason = "unsupported-signature";
            return false;
        }

        if (signature.Params.Any(type => !IsSafeType(type)))
        {
            reason = "byref-or-pointer";
            return false;
        }

        MethodDef? definition = target as MethodDef;
        if (definition is null && target is MemberRef memberRef)
        {
            try { definition = memberRef.ResolveMethod(); }
            catch { definition = null; }
        }

        if (definition is not null && !(definition.IsPublic || definition.IsAssembly))
        {
            reason = "inaccessible-callee";
            return false;
        }

        return true;
    }

    private static bool IsSafeType(TypeSig type) =>
        !type.IsByRef && !type.IsPointer && !type.IsFunctionPointer && !type.ContainsGenericParameter;

    private static MethodDef CreateProxy(ModuleDef module, IMethod target)
    {
        var proxy = new MethodDefUser(
            InvisibleNames.Next(),
            target.MethodSig!.Clone(),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig)
        {
            Body = new CilBody()
        };

        module.GlobalType.Methods.Add(proxy);
        foreach (var parameter in proxy.Parameters.Where(parameter => parameter.IsNormalMethodParameter))
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg, parameter));
        proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
        proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return proxy;
    }
}

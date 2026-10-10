using dnlib.DotNet;

namespace OneGamingOBFUSCATION.Protection;

public sealed record RenameResult(
    int Types,
    int Methods,
    int Fields,
    int Parameters,
    int Properties,
    int Events,
    int Accessors,
    int GenericParameters);

public static class SafeRenamer
{
    public static RenameResult Apply(ModuleDef module, CompatibilityAnalysis policy, bool renameHelperTypes)
    {
        var memberReferences = CaptureMemberReferences(module);
        var typeReferences = CaptureTypeReferences(module);
        var types = 0;
        var methods = 0;
        var fields = 0;
        var parameters = 0;
        var properties = 0;
        var events = 0;
        var accessors = 0;
        var genericParameters = 0;
        var usedNames = new HashSet<string>(StringComparer.Ordinal);
        var renamedMethods = new HashSet<MethodDef>();

        if (renameHelperTypes)
        {
            foreach (var type in module.GetTypes().Where(type => !type.IsGlobalModuleType).ToArray())
            {
                if (policy.ShouldPreserve(type))
                    continue;

                var identity = type.FullName;
                if (!type.IsNested)
                    type.Namespace = CreateName("n", type.Namespace + "." + identity, usedNames);
                type.Name = CreateName("t", identity, usedNames);
                types++;
            }
        }

        foreach (var type in module.GetTypes())
        {
            if (type.IsGlobalModuleType)
                continue;

            if (!policy.ShouldPreserve(type))
            {
                foreach (var genericParameter in type.GenericParameters)
                {
                    genericParameter.Name = CreateName("g", type.FullName + ":" + genericParameter.Number, usedNames);
                    genericParameters++;
                }
            }

            foreach (var property in type.Properties)
            {
                if (policy.ShouldPreserve(property))
                    continue;

                var identity = property.FullName;
                var name = CreateName("q", identity, usedNames);
                property.Name = name;
                properties++;
                foreach (var accessor in PropertyAccessors(property))
                {
                    var prefix = accessor.IsGetter ? "get_" : accessor.IsSetter ? "set_" : "use_";
                    accessor.Name = prefix + name;
                    renamedMethods.Add(accessor);
                    accessors++;
                    parameters += RenameParameters(accessor, identity, usedNames);
                }
            }

            foreach (var @event in type.Events)
            {
                if (policy.ShouldPreserve(@event))
                    continue;

                var identity = @event.FullName;
                var name = CreateName("e", identity, usedNames);
                @event.Name = name;
                events++;
                foreach (var accessor in EventAccessors(@event))
                {
                    var prefix = accessor.IsAddOn ? "add_" : accessor.IsRemoveOn ? "remove_" : "raise_";
                    accessor.Name = prefix + name;
                    renamedMethods.Add(accessor);
                    accessors++;
                    parameters += RenameParameters(accessor, identity, usedNames);
                }
            }

            foreach (var method in type.Methods)
            {
                if (renamedMethods.Contains(method) || policy.ShouldPreserve(method))
                    continue;

                var identity = method.FullName;
                method.Name = CreateName("m", identity, usedNames);
                methods++;
                parameters += RenameParameters(method, identity, usedNames);
                foreach (var genericParameter in method.GenericParameters)
                {
                    genericParameter.Name = CreateName("g", identity + ":" + genericParameter.Number, usedNames);
                    genericParameters++;
                }
            }

            foreach (var field in type.Fields)
            {
                if (policy.ShouldPreserve(field))
                    continue;

                field.Name = CreateName("f", field.FullName, usedNames);
                fields++;
            }

        }

        UpdateReferences(memberReferences, typeReferences);
        return new RenameResult(types, methods, fields, parameters, properties, events, accessors, genericParameters);
    }

    public static int HideSyntheticMembers(ModuleDef module)
    {
        var memberReferences = CaptureMemberReferences(module);
        var typeReferences = CaptureTypeReferences(module);
        var usedNames = new HashSet<string>(StringComparer.Ordinal);
        var hidden = 0;

        foreach (var type in module.GetTypes().ToArray())
        {
            if (!type.IsGlobalModuleType && IsSynthetic(type.Namespace))
            {
                type.Namespace = InvisibleNames.Next(usedNames);
                hidden++;
            }

            if (!type.IsGlobalModuleType && IsSynthetic(type.Name))
            {
                type.Name = InvisibleNames.Next(usedNames);
                hidden++;
            }

            foreach (var method in type.Methods)
            {
                if (method.IsRuntimeSpecialName || method.Name == ".ctor" || method.Name == ".cctor")
                    continue;
                if (!IsSynthetic(method.Name))
                    continue;
                method.Name = InvisibleNames.Next(usedNames);
                hidden++;
            }

            foreach (var field in type.Fields)
            {
                if (!IsSynthetic(field.Name))
                    continue;
                field.Name = InvisibleNames.Next(usedNames);
                hidden++;
            }

            foreach (var property in type.Properties)
            {
                if (!IsSynthetic(property.Name))
                    continue;
                property.Name = InvisibleNames.Next(usedNames);
                hidden++;
            }

            foreach (var @event in type.Events)
            {
                if (!IsSynthetic(@event.Name))
                    continue;
                @event.Name = InvisibleNames.Next(usedNames);
                hidden++;
            }
        }

        UpdateReferences(memberReferences, typeReferences);
        return hidden;
    }

    private static bool IsSynthetic(string? name)
    {
        if (string.IsNullOrEmpty(name) || name[0] != '_' || name.Length < 7)
            return false;
        for (var index = 1; index < name.Length; index++)
        {
            var character = name[index];
            var hex = character is >= '0' and <= '9' or >= 'a' and <= 'f';
            if (!hex)
                return false;
        }

        return true;
    }

    private static List<(MemberRef Reference, IMemberDef Definition)> CaptureMemberReferences(ModuleDef module)
    {
        var captured = new List<(MemberRef, IMemberDef)>();
        var references = new List<MemberRef>();
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody))
        {
            foreach (var instruction in method.Body.Instructions)
            {
                var reference = instruction.Operand switch
                {
                    MemberRef direct => direct,
                    MethodSpec { Method: MemberRef genericMethod } => genericMethod,
                    _ => null
                };
                if (reference is not null && !references.Any(existing => ReferenceEquals(existing, reference)))
                    references.Add(reference);
            }
        }

        foreach (var reference in references)
        {
            IMemberDef? definition = null;
            try { definition = reference.IsMethodRef ? reference.ResolveMethod() : reference.ResolveField(); }
            catch { }
            definition ??= ResolveGenericOwnerMember(reference);
            if (definition?.Module == module)
                captured.Add((reference, definition));
        }
        return captured;
    }

    private static IMemberDef? ResolveGenericOwnerMember(MemberRef reference)
    {
        if (reference.Class is not TypeSpec typeSpec)
            return null;

        TypeSig signature = typeSpec.TypeSig;
        while (signature is ModifierSig modifier)
            signature = modifier.Next;

        ITypeDefOrRef? ownerReference = signature switch
        {
            GenericInstSig generic => generic.GenericType.TypeDefOrRef,
            TypeDefOrRefSig direct => direct.TypeDefOrRef,
            _ => null
        };
        var owner = ownerReference switch
        {
            TypeDef definition => definition,
            TypeRef typeReference => typeReference.Resolve(),
            _ => null
        };
        if (owner is null)
            return null;

        if (reference.IsFieldRef)
            return owner.Fields.SingleOrDefault(field => field.Name == reference.Name);

        var candidates = owner.Methods.Where(method =>
            method.Name == reference.Name &&
            method.MethodSig?.Params.Count == reference.MethodSig?.Params.Count &&
            method.MethodSig?.HasThis == reference.MethodSig?.HasThis).ToArray();
        return candidates.Length == 1 ? candidates[0] : null;
    }

    private static List<(TypeRef Reference, TypeDef Definition)> CaptureTypeReferences(ModuleDef module)
    {
        var captured = new List<(TypeRef, TypeDef)>();
        foreach (var reference in module.GetTypeRefs())
        {
            TypeDef? definition = null;
            try { definition = reference.Resolve(); }
            catch { }
            if (definition?.Module == module)
                captured.Add((reference, definition));
        }
        return captured;
    }

    private static void UpdateReferences(
        IEnumerable<(MemberRef Reference, IMemberDef Definition)> memberReferences,
        IEnumerable<(TypeRef Reference, TypeDef Definition)> typeReferences)
    {
        foreach (var (reference, definition) in memberReferences)
            reference.Name = definition.Name;

        foreach (var (reference, definition) in typeReferences)
        {
            reference.Name = definition.Name;
            reference.Namespace = definition.Namespace;
        }
    }

    private static int RenameParameters(MethodDef method, string identity, HashSet<string> usedNames)
    {
        var count = 0;
        foreach (var parameter in method.Parameters.Where(parameter => parameter.IsNormalMethodParameter))
        {
            parameter.Name = CreateName("a", identity + ":" + parameter.MethodSigIndex, usedNames);
            count++;
        }
        return count;
    }

    private static IEnumerable<MethodDef> PropertyAccessors(PropertyDef property) =>
        new[] { property.GetMethod, property.SetMethod }
            .Where(method => method is not null)
            .Cast<MethodDef>()
            .Concat(property.OtherMethods)
            .Distinct();

    private static IEnumerable<MethodDef> EventAccessors(EventDef @event) =>
        new[] { @event.AddMethod, @event.RemoveMethod, @event.InvokeMethod }
            .Where(method => method is not null)
            .Cast<MethodDef>()
            .Concat(@event.OtherMethods)
            .Distinct();

    private static string CreateName(string prefix, string identity, HashSet<string> usedNames)
    {
        _ = prefix;
        _ = identity;
        return InvisibleNames.Next(usedNames);
    }
}

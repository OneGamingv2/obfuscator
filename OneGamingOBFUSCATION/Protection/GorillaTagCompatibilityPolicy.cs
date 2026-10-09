using dnlib.DotNet;

namespace OneGamingOBFUSCATION.Protection;

public sealed class CompatibilityAnalysis
{
    private readonly HashSet<IMemberDef> _preserved = new();
    private readonly HashSet<string> _literalNames;

    internal CompatibilityAnalysis(HashSet<string> literalNames, bool aggressiveRenaming)
    {
        _literalNames = literalNames;
        AggressiveRenaming = aggressiveRenaming;
    }

    public bool AggressiveRenaming { get; }

    public int UnityIndicators { get; internal set; }
    public int BepInExIndicators { get; internal set; }
    public int HarmonyIndicators { get; internal set; }
    public int PreservedMemberCount => _preserved.Count;

    public bool ShouldPreserve(TypeDef type)
    {
        var preserve = type.IsGlobalModuleType || GorillaTagCompatibilityPolicy.IsRuntimeSensitiveType(type) ||
                       GorillaTagCompatibilityPolicy.HasNameSensitiveAttribute(type) || _literalNames.Contains(type.Name) ||
                       _literalNames.Contains(type.FullName) ||
                       type.Namespace.String.StartsWith("UnityEngine", StringComparison.Ordinal) ||
                       type.Namespace.String.StartsWith("BepInEx", StringComparison.Ordinal) ||
                       type.Namespace.String.StartsWith("Harmony", StringComparison.Ordinal) ||
                       type.Namespace.String.Contains("Gorilla", StringComparison.OrdinalIgnoreCase) ||
                       (!AggressiveRenaming &&
                        (type.IsPublic || type.IsNestedPublic || type.IsNestedFamily || type.IsNestedFamilyOrAssembly));

        if (preserve)
            _preserved.Add(type);
        return preserve;
    }

    public bool ShouldPreserve(MethodDef method)
    {
        var preserve = method.IsConstructor || method.IsStaticConstructor || method.IsSpecialName ||
                       (!AggressiveRenaming && !method.IsPrivate) || method.IsVirtual || method.IsAbstract || method.HasOverrides ||
                       method.ImplMap is not null || GorillaTagCompatibilityPolicy.HasNameSensitiveAttribute(method) ||
                       GorillaTagCompatibilityPolicy.IsKnownCallback(method.Name) ||
                       GorillaTagCompatibilityPolicy.IsHarmonyMethod(method.Name) ||
                       _literalNames.Contains(method.Name);

        if (preserve)
            _preserved.Add(method);
        return preserve;
    }

    public bool ShouldPreserve(FieldDef field)
    {

        var preserve = (!AggressiveRenaming && !field.IsPrivate) || field.IsSpecialName ||
                       field.DeclaringType.IsEnum || GorillaTagCompatibilityPolicy.HasNameSensitiveAttribute(field) ||
                       _literalNames.Contains(field.Name);

        if (preserve)
            _preserved.Add(field);
        return preserve;
    }

    public bool ShouldPreserve(PropertyDef property)
    {
        var accessors = new[] { property.GetMethod, property.SetMethod }
            .Where(method => method is not null)
            .Cast<MethodDef>()
            .Concat(property.OtherMethods);
        var preserve = !accessors.Any() || (!AggressiveRenaming && accessors.Any(method => !method.IsPrivate)) ||
                       GorillaTagCompatibilityPolicy.HasNameSensitiveAttribute(property) ||
                       _literalNames.Contains(property.Name);
        if (preserve)
            _preserved.Add(property);
        return preserve;
    }

    public bool ShouldPreserve(EventDef @event)
    {
        var accessors = new[] { @event.AddMethod, @event.RemoveMethod, @event.InvokeMethod }
            .Where(method => method is not null)
            .Cast<MethodDef>()
            .Concat(@event.OtherMethods);
        var preserve = !accessors.Any() || (!AggressiveRenaming && accessors.Any(method => !method.IsPrivate)) ||
                       GorillaTagCompatibilityPolicy.HasNameSensitiveAttribute(@event) ||
                       _literalNames.Contains(@event.Name);
        if (preserve)
            _preserved.Add(@event);
        return preserve;
    }

    public bool IsMethodTransformationSafe(MethodDef method) =>
        method.HasBody && !ShouldPreserve(method) && method.DeclaringType is not null;
}

public static class GorillaTagCompatibilityPolicy
{
    private static readonly HashSet<string> UnityCallbacks = new(StringComparer.Ordinal)
    {
        "Awake", "Start", "Update", "LateUpdate", "FixedUpdate", "OnEnable", "OnDisable", "OnDestroy",
        "Reset", "OnValidate", "OnGUI", "OnApplicationFocus", "OnApplicationPause", "OnApplicationQuit",
        "OnCollisionEnter", "OnCollisionStay", "OnCollisionExit", "OnCollisionEnter2D", "OnCollisionStay2D",
        "OnCollisionExit2D", "OnTriggerEnter", "OnTriggerStay", "OnTriggerExit", "OnTriggerEnter2D",
        "OnTriggerStay2D", "OnTriggerExit2D", "OnAnimatorIK", "OnAnimatorMove", "OnAudioFilterRead",
        "OnBecameVisible", "OnBecameInvisible", "OnControllerColliderHit", "OnDrawGizmos",
        "OnDrawGizmosSelected", "OnMouseDown", "OnMouseDrag", "OnMouseEnter", "OnMouseExit", "OnMouseOver",
        "OnMouseUp", "OnMouseUpAsButton", "OnParticleCollision", "OnParticleSystemStopped",
        "OnPostRender", "OnPreCull", "OnPreRender", "OnRenderImage", "OnRenderObject", "OnTransformChildrenChanged",
        "OnTransformParentChanged", "OnWillRenderObject"
    };

    private static readonly HashSet<string> HarmonyMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "Prefix", "Postfix", "Transpiler", "Finalizer", "TargetMethod", "TargetMethods", "Prepare", "Cleanup"
    };

    private static readonly string[] BenignAttributePrefixes =
    [
        "System.Runtime.CompilerServices.",
        "System.Diagnostics.",
        "System.Runtime.InteropServices.CompilerGeneratedAttribute"
    ];

    private static readonly HashSet<string> BenignAttributeNames = new(StringComparer.Ordinal)
    {
        "System.ObsoleteAttribute",
        "System.Obsolete",
        "System.Runtime.CompilerServices.CompilerGeneratedAttribute",
        "System.Diagnostics.DebuggerHiddenAttribute",
        "System.Diagnostics.DebuggerStepThroughAttribute",
        "System.Diagnostics.DebuggerNonUserCodeAttribute",
        "System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute"
    };

    public static CompatibilityAnalysis Analyze(ModuleDef module, bool aggressiveRenaming = false)
    {
        var literals = new HashSet<string>(StringComparer.Ordinal);
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody))
        {
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is string value && !string.IsNullOrWhiteSpace(value))
                    literals.Add(value);
            }
        }

        var result = new CompatibilityAnalysis(literals, aggressiveRenaming);
        foreach (var reference in module.GetAssemblyRefs())
        {
            var name = reference.Name.String;
            if (name.StartsWith("UnityEngine", StringComparison.OrdinalIgnoreCase) || name.Contains("Gorilla", StringComparison.OrdinalIgnoreCase))
                result.UnityIndicators++;
            if (name.StartsWith("BepInEx", StringComparison.OrdinalIgnoreCase))
                result.BepInExIndicators++;
            if (name.Contains("Harmony", StringComparison.OrdinalIgnoreCase) || name.Equals("0Harmony", StringComparison.OrdinalIgnoreCase))
                result.HarmonyIndicators++;
        }

        return result;
    }

    internal static bool IsKnownCallback(string name) => UnityCallbacks.Contains(name);
    internal static bool IsHarmonyMethod(string name) => HarmonyMethods.Contains(name);

    internal static bool IsRuntimeSensitiveType(TypeDef type)
    {
        for (var current = type.BaseType; current is not null; current = current.ResolveTypeDef()?.BaseType)
        {
            var fullName = current.FullName;
            if (fullName.Contains("UnityEngine.MonoBehaviour", StringComparison.Ordinal) ||
                fullName.Contains("BepInEx.BaseUnityPlugin", StringComparison.Ordinal) ||
                fullName.Contains("BepInEx.Unity.IL2CPP.BasePlugin", StringComparison.Ordinal))
                return true;

            if (current.ResolveTypeDef() is null)
                break;
        }

        return type.CustomAttributes.Any(attribute =>
            attribute.AttributeType.FullName.Contains("BepInPlugin", StringComparison.Ordinal) ||
            attribute.AttributeType.FullName.Contains("HarmonyPatch", StringComparison.Ordinal) ||
            attribute.AttributeType.FullName.Contains("SerializeField", StringComparison.Ordinal));
    }

    internal static bool HasNameSensitiveAttribute(IHasCustomAttribute member) =>
        member.CustomAttributes.Any(attribute => !IsBenignAttribute(attribute.AttributeType.FullName));

    private static bool IsBenignAttribute(string fullName) =>
        BenignAttributeNames.Contains(fullName) ||
        BenignAttributePrefixes.Any(prefix => fullName.StartsWith(prefix, StringComparison.Ordinal));
}

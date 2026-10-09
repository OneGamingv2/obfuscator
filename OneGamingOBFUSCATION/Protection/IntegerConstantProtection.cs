using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Security.Cryptography;

namespace OneGamingOBFUSCATION.Protection;

/// <summary>
/// Encodes integer constants with randomized multi-op expression trees
/// so simple single xor-key pattern matchers fail.
/// </summary>
public static class IntegerConstantProtection
{
    public static ProtectionStats Apply(ModuleDef module, CompatibilityAnalysis policy, bool multilayer = false)
    {
        var stats = new ProtectionStats();
        foreach (var method in module.GetTypes().Where(type => !type.IsGlobalModuleType).SelectMany(type => type.Methods).ToArray())
        {
            if (!policy.IsMethodTransformationSafe(method))
            {
                if (method.HasBody)
                    stats.Skip("preserved-or-unsafe");
                continue;
            }

            method.Body.SimplifyBranches();
            var instructions = method.Body.Instructions;
            for (var index = 0; index < instructions.Count; index++)
            {
                var instruction = instructions[index];
                if (!instruction.IsLdcI4())
                    continue;

                stats.Candidates++;
                var value = instruction.GetLdcI4Value();
                var inserted = multilayer
                    ? EmitMultilayer(instructions, index, value)
                    : EmitSimpleXor(instructions, index, value);
                index += inserted;
                stats.Applied++;
            }
        }

        return stats;
    }

    private static int EmitSimpleXor(IList<Instruction> instructions, int index, int value)
    {
        var key = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
        instructions[index].OpCode = OpCodes.Ldc_I4;
        instructions[index].Operand = value ^ key;
        instructions.Insert(index + 1, Instruction.Create(OpCodes.Ldc_I4, key));
        instructions.Insert(index + 2, Instruction.Create(OpCodes.Xor));
        return 2;
    }

    private static int EmitMultilayer(IList<Instruction> instructions, int index, int value)
    {
        switch (RandomNumberGenerator.GetInt32(0, 4))
        {
            case 0:
                return EmitSimpleXor(instructions, index, value);
            case 1:
            {
                var key = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
                instructions[index].OpCode = OpCodes.Ldc_I4;
                instructions[index].Operand = unchecked(value + key);
                instructions.Insert(index + 1, Instruction.Create(OpCodes.Ldc_I4, key));
                instructions.Insert(index + 2, Instruction.Create(OpCodes.Sub));
                return 2;
            }
            case 2:
            {
                var k1 = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
                var k2 = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
                instructions[index].OpCode = OpCodes.Ldc_I4;
                instructions[index].Operand = unchecked((value ^ k1) + k2);
                instructions.Insert(index + 1, Instruction.Create(OpCodes.Ldc_I4, k2));
                instructions.Insert(index + 2, Instruction.Create(OpCodes.Sub));
                instructions.Insert(index + 3, Instruction.Create(OpCodes.Ldc_I4, k1));
                instructions.Insert(index + 4, Instruction.Create(OpCodes.Xor));
                return 4;
            }
            default:
            {
                // ((value - k1) ^ k2) ^ k2 + k1
                var k1 = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
                var k2 = RandomNumberGenerator.GetInt32(1, int.MaxValue);
                instructions[index].OpCode = OpCodes.Ldc_I4;
                instructions[index].Operand = unchecked((value - k1) ^ k2);
                instructions.Insert(index + 1, Instruction.Create(OpCodes.Ldc_I4, k2));
                instructions.Insert(index + 2, Instruction.Create(OpCodes.Xor));
                instructions.Insert(index + 3, Instruction.Create(OpCodes.Ldc_I4, k1));
                instructions.Insert(index + 4, Instruction.Create(OpCodes.Add));
                return 4;
            }
        }
    }
}

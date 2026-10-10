using System.IO;
using System.Security.Cryptography;

namespace OneGamingOBFUSCATION.Protection;

public static class JavaCodeEditor
{
    private static readonly int[] Lengths = BuildLengths();

    public static int EncryptStrings(JavaClassFile file, ushort decryptRef, int key, int style)
    {
        var encrypted = 0;
        foreach (var method in file.Methods)
        {
            var code = method.Attributes.FirstOrDefault(attribute => file.Utf8(attribute.NameIndex) == "Code");
            if (code is null)
                continue;
            if (TryEncrypt(file, code, decryptRef, key, style))
                encrypted += CountEncrypted(file, code, decryptRef);
        }

        return encrypted;
    }

    public static int ObfuscateIntegers(JavaClassFile file)
    {
        var mixed = 0;
        foreach (var method in file.Methods)
        {
            var code = method.Attributes.FirstOrDefault(attribute => file.Utf8(attribute.NameIndex) == "Code");
            if (code is null)
                continue;
            mixed += TryMixIntegers(file, code);
        }

        return mixed;
    }

    public static int StripDebug(JavaClassFile file)
    {
        var removed = Strip(file, file.Attributes);
        foreach (var member in file.Fields.Concat(file.Methods))
            removed += Strip(file, member.Attributes);
        foreach (var method in file.Methods)
        {
            var code = method.Attributes.FirstOrDefault(attribute => file.Utf8(attribute.NameIndex) == "Code");
            if (code is null)
                continue;
            var cursor = new ByteCursor(code.Data);
            var maxStack = cursor.U2();
            var maxLocals = cursor.U2();
            var codeLength = (int)cursor.U4();
            var bytecode = cursor.Bytes(codeLength);
            var exceptions = cursor.U2();
            var exceptionBytes = cursor.Bytes(exceptions * 8);
            var attributes = new List<JavaAttribute>();
            var count = cursor.U2();
            for (var index = 0; index < count; index++)
            {
                var name = cursor.U2();
                var length = (int)cursor.U4();
                var data = cursor.Bytes(length);
                var attributeName = file.Utf8(name);
                if (attributeName is "LineNumberTable" or "LocalVariableTable" or "LocalVariableTypeTable")
                {
                    removed++;
                    continue;
                }

                attributes.Add(new JavaAttribute { NameIndex = name, Data = data });
            }

            var writer = new ByteWriter();
            writer.U2(maxStack);
            writer.U2(maxLocals);
            writer.U4((uint)bytecode.Length);
            writer.Bytes(bytecode);
            writer.U2(exceptions);
            writer.Bytes(exceptionBytes);
            writer.U2((ushort)attributes.Count);
            foreach (var attribute in attributes)
            {
                writer.U2(attribute.NameIndex);
                writer.U4((uint)attribute.Data.Length);
                writer.Bytes(attribute.Data);
            }

            code.Data = writer.ToArray();
        }

        return removed;
    }

    private static int Strip(JavaClassFile file, List<JavaAttribute> attributes)
    {
        var removed = attributes.RemoveAll(attribute =>
            file.Utf8(attribute.NameIndex) is "SourceFile" or "SourceDebugExtension" or "LineNumberTable" or
                "LocalVariableTable" or "LocalVariableTypeTable");
        return removed;
    }

    private static int TryMixIntegers(JavaClassFile file, JavaAttribute code)
    {
        if (!TryOpen(file, code, out var maxStack, out var maxLocals, out var bytecode, out var exceptions, out var attributes, out var stackMap))
            return 0;
        var instructions = Decode(bytecode);
        var oldToNew = new Dictionary<int, int> { [bytecode.Length] = 0 };
        var built = new List<byte>();
        var changed = 0;
        foreach (var instruction in instructions)
        {
            oldToNew[instruction.Pc] = built.Count;
            if (TryReadInt(file, instruction, out var value) && EncodeInt(value) is byte[] encoded)
            {
                built.AddRange(encoded);
                changed++;
                continue;
            }

            built.AddRange(instruction.Bytes);
        }

        if (changed == 0)
            return 0;
        Finish(code, (ushort)Math.Min(ushort.MaxValue, maxStack + 1), maxLocals, bytecode, instructions, oldToNew, built, exceptions, attributes, stackMap);
        return changed;
    }

    private static bool TryEncrypt(JavaClassFile file, JavaAttribute code, ushort decryptRef, int key, int style)
    {
        if (!TryOpen(file, code, out var maxStack, out var maxLocals, out var bytecode, out var exceptions, out var attributes, out var stackMap))
            return false;

        var instructions = Decode(bytecode);
        var replacements = new Dictionary<int, ushort>();
        foreach (var instruction in instructions)
        {
            if (!TryReadString(file, instruction, out var stringIndex, out var text) || !CanEncrypt(text, key, style))
                continue;
            if (replacements.ContainsKey(stringIndex))
                continue;
            var utfIndex = file.Pool[stringIndex]!.Index1;
            var encrypted = Encrypt(text, key, style);
            if (ExclusiveString(file, utfIndex))
            {
                file.Pool[utfIndex]!.Utf8 = encrypted;
                for (var index = 1; index < file.Pool.Count; index++)
                {
                    var item = file.Pool[index];
                    if (item is { Tag: 8 } && item.Index1 == utfIndex)
                        replacements[index] = (ushort)index;
                }
            }
            else
            {
                replacements[stringIndex] = NewStringConstant(file, file.InternUtf8(encrypted));
            }
        }

        var oldToNew = new Dictionary<int, int> { [bytecode.Length] = 0 };
        var built = new List<byte>();
        var changed = false;
        foreach (var instruction in instructions)
        {
            oldToNew[instruction.Pc] = built.Count;
            if (TryReadString(file, instruction, out var stringIndex, out _) && replacements.TryGetValue(stringIndex, out var replacement))
            {
                if (instruction.Bytes[0] == 0x12 && replacement <= byte.MaxValue)
                {
                    built.Add(0x12);
                    built.Add((byte)replacement);
                }
                else
                {
                    built.Add(0x13);
                    built.Add((byte)(replacement >> 8));
                    built.Add((byte)replacement);
                }

                built.Add(0xB8);
                built.Add((byte)(decryptRef >> 8));
                built.Add((byte)decryptRef);
                changed = true;
                continue;
            }

            built.AddRange(instruction.Bytes);
        }

        if (!changed)
            return false;

        Finish(code, maxStack, maxLocals, bytecode, instructions, oldToNew, built, exceptions, attributes, stackMap);
        return true;
    }

    private static bool TryOpen(
        JavaClassFile file,
        JavaAttribute code,
        out ushort maxStack,
        out ushort maxLocals,
        out byte[] bytecode,
        out List<(ushort Start, ushort End, ushort Handler, ushort Type)> exceptions,
        out List<JavaAttribute> attributes,
        out JavaAttribute? stackMap)
    {
        maxStack = 0;
        maxLocals = 0;
        bytecode = [];
        exceptions = [];
        attributes = [];
        stackMap = null;
        var cursor = new ByteCursor(code.Data);
        maxStack = cursor.U2();
        maxLocals = cursor.U2();
        var codeLength = (int)cursor.U4();
        bytecode = cursor.Bytes(codeLength);
        var exceptionCount = cursor.U2();
        for (var index = 0; index < exceptionCount; index++)
            exceptions.Add((cursor.U2(), cursor.U2(), cursor.U2(), cursor.U2()));
        var attributeCount = cursor.U2();
        for (var index = 0; index < attributeCount; index++)
        {
            var name = cursor.U2();
            var length = (int)cursor.U4();
            var data = cursor.Bytes(length);
            var attribute = new JavaAttribute { NameIndex = name, Data = data };
            if (file.Utf8(name) == "StackMapTable")
                stackMap = attribute;
            else if (file.Utf8(name) is "LineNumberTable" or "LocalVariableTable" or "LocalVariableTypeTable")
                continue;
            else
                return false;

            if (file.Utf8(name) == "StackMapTable")
                attributes.Add(attribute);
        }

        return bytecode.AsSpan().IndexOf((byte)0xAA) < 0 && bytecode.AsSpan().IndexOf((byte)0xAB) < 0;
    }

    private static void Finish(
        JavaAttribute code,
        ushort maxStack,
        ushort maxLocals,
        byte[] bytecode,
        List<Instruction> instructions,
        Dictionary<int, int> oldToNew,
        List<byte> built,
        List<(ushort Start, ushort End, ushort Handler, ushort Type)> exceptions,
        List<JavaAttribute> attributes,
        JavaAttribute? stackMap)
    {
        oldToNew[bytecode.Length] = built.Count;
        PatchBranches(instructions, oldToNew, built);
        PatchExceptions(exceptions, oldToNew);
        if (stackMap is not null)
            stackMap.Data = ShiftStackMap(stackMap.Data, oldToNew);

        var writer = new ByteWriter();
        writer.U2(maxStack);
        writer.U2(maxLocals);
        writer.U4((uint)built.Count);
        writer.Bytes(built.ToArray());
        writer.U2((ushort)exceptions.Count);
        foreach (var exception in exceptions)
        {
            writer.U2(exception.Start);
            writer.U2(exception.End);
            writer.U2(exception.Handler);
            writer.U2(exception.Type);
        }

        writer.U2((ushort)attributes.Count);
        foreach (var attribute in attributes)
        {
            writer.U2(attribute.NameIndex);
            writer.U4((uint)attribute.Data.Length);
            writer.Bytes(attribute.Data);
        }

        code.Data = writer.ToArray();
    }

    private static int CountEncrypted(JavaClassFile file, JavaAttribute code, ushort decryptRef)
    {
        var cursor = new ByteCursor(code.Data);
        cursor.U2();
        cursor.U2();
        var bytecode = cursor.Bytes((int)cursor.U4());
        var count = 0;
        for (var pc = 0; pc < bytecode.Length;)
        {
            if (bytecode[pc] == 0xB8)
            {
                var index = (bytecode[pc + 1] << 8) | bytecode[pc + 2];
                if (index == decryptRef)
                    count++;
            }

            var length = InstructionLength(bytecode, pc);
            if (length <= 0 || pc + length > bytecode.Length)
                break;
            pc += length;
        }

        return count;
    }

    private static ushort NewStringConstant(JavaClassFile file, ushort utfIndex)
    {
        for (var index = 1; index < file.Pool.Count; index++)
        {
            var item = file.Pool[index];
            if (item is { Tag: 8 } && item.Index1 == utfIndex)
                return (ushort)index;
        }

        file.Pool.Add(new CpItem { Tag = 8, Index1 = utfIndex });
        return (ushort)(file.Pool.Count - 1);
    }

    private static bool TryReadString(JavaClassFile file, Instruction instruction, out int index, out string text)
    {
        text = "";
        index = 0;
        if (instruction.Bytes[0] == 0x12)
            index = instruction.Bytes[1];
        else if (instruction.Bytes[0] == 0x13)
            index = (instruction.Bytes[1] << 8) | instruction.Bytes[2];
        else
            return false;

        var item = file.Pool[index];
        if (item is not { Tag: 8 })
            return false;
        text = file.Utf8(item.Index1);
        return true;
    }

    private static bool ExclusiveString(JavaClassFile file, int utfIndex)
    {
        for (var index = 1; index < file.Pool.Count; index++)
        {
            var item = file.Pool[index];
            if (item is null || index == utfIndex)
                continue;
            if (item.Tag == 8 && item.Index1 == utfIndex)
                continue;
            if (item.Tag is 7 or 16 or 19 or 20 && item.Index1 == utfIndex)
                return false;
            if (item.Tag == 12 && (item.Index1 == utfIndex || item.Index2 == utfIndex))
                return false;
        }

        return true;
    }

    private static bool CanEncrypt(string text, int key, int style)
    {
        if (text.Length is 0 or > 4000)
            return false;
        for (var index = 0; index < text.Length; index++)
        {
            var mixed = text[index] ^ (Mask(key, index, style) & 0x7F);
            if (mixed is >= 0xD800 and <= 0xDFFF)
                return false;
        }

        return true;
    }

    public static string Encrypt(string text, int key, int style)
    {
        var chars = new char[text.Length];
        for (var index = 0; index < text.Length; index++)
            chars[index] = (char)(text[index] ^ (Mask(key, index, style) & 0x7F));
        return new string(chars);
    }

    private static int Mask(int key, int index, int style) => style switch
    {
        1 => key ^ (index * 7),
        2 => key + (index * 3),
        _ => key + (index * 13)
    };

    private static bool TryReadInt(JavaClassFile file, Instruction instruction, out int value)
    {
        var opcode = instruction.Bytes[0];
        if (opcode is >= 0x02 and <= 0x08)
        {
            value = opcode - 3;
            return true;
        }

        if (opcode == 0x10)
        {
            value = (sbyte)instruction.Bytes[1];
            return true;
        }

        if (opcode == 0x11)
        {
            value = (short)((instruction.Bytes[1] << 8) | instruction.Bytes[2]);
            return true;
        }

        if (opcode is 0x12 or 0x13)
        {
            var index = opcode == 0x12 ? instruction.Bytes[1] : (instruction.Bytes[1] << 8) | instruction.Bytes[2];
            var item = file.Pool[index];
            if (item is { Tag: 3, Payload.Length: 4 })
            {
                value = (item.Payload[0] << 24) | (item.Payload[1] << 16) | (item.Payload[2] << 8) | item.Payload[3];
                return value is >= short.MinValue and <= short.MaxValue;
            }
        }

        value = 0;
        return false;
    }

    private static byte[]? EncodeInt(int value)
    {
        var mask = RandomNumberGenerator.GetInt32(1, 128);
        var mixed = value ^ mask;
        if (mixed is < short.MinValue or > short.MaxValue)
            return null;
        return
        [
            0x11, (byte)(mixed >> 8), (byte)mixed,
            0x10, (byte)mask,
            0x82
        ];
    }

    private static List<Instruction> Decode(byte[] code)
    {
        var list = new List<Instruction>();
        for (var pc = 0; pc < code.Length;)
        {
            var length = InstructionLength(code, pc);
            if (length <= 0 || pc + length > code.Length)
                throw new InvalidDataException("A method body could not be read.");
            var bytes = code.AsSpan(pc, length).ToArray();
            var instruction = new Instruction { Pc = pc, Bytes = bytes };
            if (IsShortBranch(bytes[0]))
            {
                instruction.Branch = true;
                instruction.Target = pc + (short)((bytes[1] << 8) | bytes[2]);
            }
            else if (bytes[0] is 0xC8 or 0xC9)
            {
                instruction.Branch = true;
                instruction.WideBranch = true;
                instruction.Target = pc + ReadI4(bytes, 1);
            }

            list.Add(instruction);
            pc += length;
        }

        return list;
    }

    private static void PatchBranches(List<Instruction> instructions, Dictionary<int, int> oldToNew, List<byte> built)
    {
        foreach (var instruction in instructions)
        {
            if (!instruction.Branch)
                continue;
            var site = oldToNew[instruction.Pc];
            var target = oldToNew[instruction.Target];
            var offset = target - site;
            if (instruction.WideBranch)
            {
                built[site + 1] = (byte)(offset >> 24);
                built[site + 2] = (byte)(offset >> 16);
                built[site + 3] = (byte)(offset >> 8);
                built[site + 4] = (byte)offset;
                continue;
            }

            if (offset is < short.MinValue or > short.MaxValue)
                throw new InvalidDataException("A branch no longer fits after string encryption.");
            built[site + 1] = (byte)(offset >> 8);
            built[site + 2] = (byte)offset;
        }
    }

    private static void PatchExceptions(List<(ushort Start, ushort End, ushort Handler, ushort Type)> exceptions, Dictionary<int, int> oldToNew)
    {
        for (var index = 0; index < exceptions.Count; index++)
        {
            var exception = exceptions[index];
            exceptions[index] = (
                (ushort)oldToNew[exception.Start],
                (ushort)oldToNew[exception.End],
                (ushort)oldToNew[exception.Handler],
                exception.Type);
        }
    }

    private static byte[] ShiftStackMap(byte[] data, Dictionary<int, int> oldToNew)
    {
        if (data.Length < 2)
            return data;
        var cursor = new ByteCursor(data);
        var count = cursor.U2();
        var frames = new List<StackFrame>();
        var previous = -1;
        for (var index = 0; index < count; index++)
        {
            var frame = StackFrame.Read(cursor, previous);
            previous = frame.Absolute;
            frame.Absolute = oldToNew.TryGetValue(frame.Absolute, out var shifted) ? shifted : frame.Absolute;
            frames.Add(frame);
        }

        var writer = new ByteWriter();
        writer.U2((ushort)frames.Count);
        previous = -1;
        foreach (var frame in frames)
        {
            var delta = frame.Absolute - previous - 1;
            frame.Write(writer, delta);
            previous = frame.Absolute;
        }

        return writer.ToArray();
    }

    private static int InstructionLength(byte[] code, int pc)
    {
        var opcode = code[pc];
        if (opcode == 0xC4)
            return code[pc + 1] == 0x84 ? 6 : 4;
        if (opcode == 0xAA)
        {
            var aligned = (pc + 4) & ~3;
            var low = ReadI4(code, aligned + 4);
            var high = ReadI4(code, aligned + 8);
            return aligned + 12 + ((high - low + 1) * 4) - pc;
        }

        if (opcode == 0xAB)
        {
            var aligned = (pc + 4) & ~3;
            var pairs = ReadI4(code, aligned + 4);
            return aligned + 8 + (pairs * 8) - pc;
        }

        return Lengths[opcode];
    }

    private static bool IsShortBranch(byte opcode) =>
        opcode is >= 0x99 and <= 0xA8 or 0xC6 or 0xC7;

    private static int ReadI4(byte[] data, int offset) =>
        (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];

    private static int[] BuildLengths()
    {
        var lengths = new int[256];
        for (var index = 0; index < lengths.Length; index++)
            lengths[index] = 1;
        foreach (var opcode in new byte[] { 0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3A, 0xA9, 0xBC })
            lengths[opcode] = 2;
        for (var opcode = 0x99; opcode <= 0xA8; opcode++)
            lengths[opcode] = 3;
        foreach (var opcode in new byte[] { 0x11, 0x13, 0x14, 0x84, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xBB, 0xBD, 0xC0, 0xC1, 0xC6, 0xC7 })
            lengths[opcode] = 3;
        foreach (var opcode in new byte[] { 0xB9, 0xBA, 0xC5, 0xC8, 0xC9 })
            lengths[opcode] = 5;
        return lengths;
    }

    private sealed class Instruction
    {
        public int Pc { get; set; }
        public byte[] Bytes { get; set; } = [];
        public bool Branch { get; set; }
        public bool WideBranch { get; set; }
        public int Target { get; set; }
    }

    private sealed class StackFrame
    {
        public int Kind { get; set; }
        public int Absolute { get; set; }
        public byte[] Payload { get; set; } = [];

        public static StackFrame Read(ByteCursor reader, int previous)
        {
            var tag = reader.U1();
            var frame = new StackFrame { Kind = tag };
            if (tag <= 63)
            {
                frame.Absolute = previous + tag + 1;
            }
            else if (tag <= 127)
            {
                frame.Absolute = previous + (tag - 64) + 1;
                frame.Payload = ReadVerification(reader);
            }
            else if (tag == 247)
            {
                var delta = reader.U2();
                frame.Absolute = previous + delta + 1;
                frame.Payload = ReadVerification(reader);
            }
            else if (tag is >= 248 and <= 251)
            {
                var delta = reader.U2();
                frame.Absolute = previous + delta + 1;
            }
            else if (tag is >= 252 and <= 254)
            {
                var delta = reader.U2();
                frame.Absolute = previous + delta + 1;
                var payload = new List<byte>();
                for (var index = 0; index < tag - 251; index++)
                    payload.AddRange(ReadVerification(reader));
                frame.Payload = payload.ToArray();
            }
            else if (tag == 255)
            {
                var delta = reader.U2();
                frame.Absolute = previous + delta + 1;
                var payload = new List<byte>();
                var locals = reader.U2();
                payload.Add((byte)(locals >> 8));
                payload.Add((byte)locals);
                for (var index = 0; index < locals; index++)
                    payload.AddRange(ReadVerification(reader));
                var stack = reader.U2();
                payload.Add((byte)(stack >> 8));
                payload.Add((byte)stack);
                for (var index = 0; index < stack; index++)
                    payload.AddRange(ReadVerification(reader));
                frame.Payload = payload.ToArray();
            }
            else
            {
                throw new InvalidDataException("A stack map frame is not supported.");
            }

            return frame;
        }

        public void Write(ByteWriter writer, int delta)
        {
            if (Kind <= 63)
            {
                if (delta <= 63)
                {
                    writer.U1((byte)delta);
                    return;
                }

                writer.U1(251);
                writer.U2((ushort)delta);
                return;
            }

            if (Kind <= 127)
            {
                if (delta <= 63)
                {
                    writer.U1((byte)(64 + delta));
                    writer.Bytes(Payload);
                    return;
                }

                writer.U1(247);
                writer.U2((ushort)delta);
                writer.Bytes(Payload);
                return;
            }

            writer.U1((byte)Kind);
            writer.U2((ushort)delta);
            if (Payload.Length > 0)
                writer.Bytes(Payload);
        }

        private static byte[] ReadVerification(ByteCursor reader)
        {
            var tag = reader.U1();
            if (tag is 7 or 8)
                return [tag, reader.U1(), reader.U1()];
            return [tag];
        }
    }
}

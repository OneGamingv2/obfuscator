using System.IO;
using System.Text;

namespace OneGamingOBFUSCATION.Protection;

public sealed class JavaClassFile
{
    public ushort Minor { get; set; }
    public ushort Major { get; set; } = 52;
    public List<CpItem?> Pool { get; } = [null];
    public ushort Access { get; set; }
    public ushort ThisClass { get; set; }
    public ushort SuperClass { get; set; }
    public List<ushort> Interfaces { get; } = [];
    public List<JavaMember> Fields { get; } = [];
    public List<JavaMember> Methods { get; } = [];
    public List<JavaAttribute> Attributes { get; } = [];

    public string ThisName => Utf8(Pool[ThisClass]!.Index1);

    public string Utf8(int index) => Pool[index]!.Utf8;

    public ushort InternUtf8(string value)
    {
        for (var index = 1; index < Pool.Count; index++)
        {
            var item = Pool[index];
            if (item is { Tag: 1 } && item.Utf8 == value)
                return (ushort)index;
        }

        Pool.Add(new CpItem { Tag = 1, Utf8 = value });
        return (ushort)(Pool.Count - 1);
    }

    public ushort InternClass(string internalName)
    {
        var utf = InternUtf8(internalName);
        for (var index = 1; index < Pool.Count; index++)
        {
            var item = Pool[index];
            if (item is { Tag: 7 } && item.Index1 == utf)
                return (ushort)index;
        }

        Pool.Add(new CpItem { Tag = 7, Index1 = utf });
        return (ushort)(Pool.Count - 1);
    }

    public ushort InternNameAndType(string name, string descriptor)
    {
        var nameIndex = InternUtf8(name);
        var descIndex = InternUtf8(descriptor);
        for (var index = 1; index < Pool.Count; index++)
        {
            var item = Pool[index];
            if (item is { Tag: 12 } && item.Index1 == nameIndex && item.Index2 == descIndex)
                return (ushort)index;
        }

        Pool.Add(new CpItem { Tag = 12, Index1 = nameIndex, Index2 = descIndex });
        return (ushort)(Pool.Count - 1);
    }

    public ushort InternRef(byte tag, string owner, string name, string descriptor)
    {
        var ownerIndex = InternClass(owner);
        var nat = InternNameAndType(name, descriptor);
        for (var index = 1; index < Pool.Count; index++)
        {
            var item = Pool[index];
            if (item is not null && item.Tag == tag && item.Index1 == ownerIndex && item.Index2 == nat)
                return (ushort)index;
        }

        Pool.Add(new CpItem { Tag = tag, Index1 = ownerIndex, Index2 = nat });
        return (ushort)(Pool.Count - 1);
    }

    public static JavaClassFile Read(byte[] data)
    {
        var reader = new ByteCursor(data);
        if (reader.U4() != 0xCAFEBABE)
            throw new InvalidDataException("The class file magic is missing.");

        var file = new JavaClassFile
        {
            Minor = reader.U2(),
            Major = reader.U2()
        };
        var count = reader.U2();
        for (var index = 1; index < count; index++)
        {
            var item = CpItem.Read(reader);
            file.Pool.Add(item);
            if (item.Wide)
            {
                file.Pool.Add(null);
                index++;
            }
        }

        file.Access = reader.U2();
        file.ThisClass = reader.U2();
        file.SuperClass = reader.U2();
        var interfaces = reader.U2();
        for (var index = 0; index < interfaces; index++)
            file.Interfaces.Add(reader.U2());
        ReadMembers(reader, file.Fields);
        ReadMembers(reader, file.Methods);
        ReadAttributes(reader, file.Attributes);
        return file;
    }

    public byte[] Write()
    {
        var writer = new ByteWriter();
        writer.U4(0xCAFEBABE);
        writer.U2(Minor);
        writer.U2(Major);
        writer.U2((ushort)Pool.Count);
        for (var index = 1; index < Pool.Count; index++)
        {
            var item = Pool[index];
            if (item is null)
                continue;
            item.Write(writer);
        }

        writer.U2(Access);
        writer.U2(ThisClass);
        writer.U2(SuperClass);
        writer.U2((ushort)Interfaces.Count);
        foreach (var item in Interfaces)
            writer.U2(item);
        WriteMembers(writer, Fields);
        WriteMembers(writer, Methods);
        WriteAttributes(writer, Attributes);
        return writer.ToArray();
    }

    private static void ReadMembers(ByteCursor reader, List<JavaMember> members)
    {
        var count = reader.U2();
        for (var index = 0; index < count; index++)
        {
            var member = new JavaMember
            {
                Access = reader.U2(),
                NameIndex = reader.U2(),
                DescriptorIndex = reader.U2()
            };
            ReadAttributes(reader, member.Attributes);
            members.Add(member);
        }
    }

    private static void WriteMembers(ByteWriter writer, List<JavaMember> members)
    {
        writer.U2((ushort)members.Count);
        foreach (var member in members)
        {
            writer.U2(member.Access);
            writer.U2(member.NameIndex);
            writer.U2(member.DescriptorIndex);
            WriteAttributes(writer, member.Attributes);
        }
    }

    private static void ReadAttributes(ByteCursor reader, List<JavaAttribute> attributes)
    {
        var count = reader.U2();
        for (var index = 0; index < count; index++)
        {
            var name = reader.U2();
            var length = reader.U4();
            attributes.Add(new JavaAttribute { NameIndex = name, Data = reader.Bytes((int)length) });
        }
    }

    private static void WriteAttributes(ByteWriter writer, List<JavaAttribute> attributes)
    {
        writer.U2((ushort)attributes.Count);
        foreach (var attribute in attributes)
        {
            writer.U2(attribute.NameIndex);
            writer.U4((uint)attribute.Data.Length);
            writer.Bytes(attribute.Data);
        }
    }
}

public sealed class CpItem
{
    public byte Tag { get; set; }
    public string Utf8 { get; set; } = "";
    public ushort Index1 { get; set; }
    public ushort Index2 { get; set; }
    public byte ReferenceKind { get; set; }
    public byte[] Payload { get; set; } = [];
    public bool Wide { get; set; }

    public static CpItem Read(ByteCursor reader)
    {
        var tag = reader.U1();
        var item = new CpItem { Tag = tag };
        switch (tag)
        {
            case 1:
                item.Utf8 = ModifiedUtf8.Decode(reader.Bytes(reader.U2()));
                break;
            case 3:
            case 4:
                item.Payload = reader.Bytes(4);
                break;
            case 5:
            case 6:
                item.Payload = reader.Bytes(8);
                item.Wide = true;
                break;
            case 7:
            case 8:
            case 16:
            case 19:
            case 20:
                item.Index1 = reader.U2();
                break;
            case 9:
            case 10:
            case 11:
            case 12:
            case 17:
            case 18:
                item.Index1 = reader.U2();
                item.Index2 = reader.U2();
                break;
            case 15:
                item.ReferenceKind = reader.U1();
                item.Index1 = reader.U2();
                break;
            default:
                throw new InvalidDataException($"Unsupported constant-pool tag {tag}.");
        }

        return item;
    }

    public void Write(ByteWriter writer)
    {
        writer.U1(Tag);
        switch (Tag)
        {
            case 1:
                var encoded = ModifiedUtf8.Encode(Utf8);
                writer.U2((ushort)encoded.Length);
                writer.Bytes(encoded);
                break;
            case 3:
            case 4:
            case 5:
            case 6:
                writer.Bytes(Payload);
                break;
            case 7:
            case 8:
            case 16:
            case 19:
            case 20:
                writer.U2(Index1);
                break;
            case 9:
            case 10:
            case 11:
            case 12:
            case 17:
            case 18:
                writer.U2(Index1);
                writer.U2(Index2);
                break;
            case 15:
                writer.U1(ReferenceKind);
                writer.U2(Index1);
                break;
        }
    }
}

public sealed class JavaMember
{
    public ushort Access { get; set; }
    public ushort NameIndex { get; set; }
    public ushort DescriptorIndex { get; set; }
    public List<JavaAttribute> Attributes { get; } = [];
}

public sealed class JavaAttribute
{
    public ushort NameIndex { get; set; }
    public byte[] Data { get; set; } = [];
}

public static class ModifiedUtf8
{
    public static string Decode(byte[] data)
    {
        var chars = new List<char>(data.Length);
        for (var index = 0; index < data.Length; index++)
        {
            var first = data[index];
            if ((first & 0x80) == 0)
            {
                chars.Add((char)first);
            }
            else if ((first & 0xE0) == 0xC0)
            {
                var second = data[++index];
                chars.Add((char)(((first & 0x1F) << 6) | (second & 0x3F)));
            }
            else
            {
                var second = data[++index];
                var third = data[++index];
                chars.Add((char)(((first & 0x0F) << 12) | ((second & 0x3F) << 6) | (third & 0x3F)));
            }
        }

        return new string(chars.ToArray());
    }

    public static byte[] Encode(string value)
    {
        var bytes = new List<byte>(value.Length);
        foreach (var character in value)
        {
            if (character is >= '\u0001' and <= '\u007F')
            {
                bytes.Add((byte)character);
            }
            else if (character == '\0' || character <= '\u07FF')
            {
                bytes.Add((byte)(0xC0 | ((character >> 6) & 0x1F)));
                bytes.Add((byte)(0x80 | (character & 0x3F)));
            }
            else
            {
                bytes.Add((byte)(0xE0 | ((character >> 12) & 0x0F)));
                bytes.Add((byte)(0x80 | ((character >> 6) & 0x3F)));
                bytes.Add((byte)(0x80 | (character & 0x3F)));
            }
        }

        if (bytes.Count > ushort.MaxValue)
            throw new InvalidDataException("A Java string is too long for the constant pool.");
        return bytes.ToArray();
    }
}

public sealed class ByteCursor
{
    private readonly byte[] _data;
    private int _offset;

    public ByteCursor(byte[] data) => _data = data;

    public byte U1() => _data[_offset++];

    public ushort U2()
    {
        var value = (ushort)((_data[_offset] << 8) | _data[_offset + 1]);
        _offset += 2;
        return value;
    }

    public uint U4()
    {
        var value = ((uint)_data[_offset] << 24) | ((uint)_data[_offset + 1] << 16) |
                    ((uint)_data[_offset + 2] << 8) | _data[_offset + 3];
        _offset += 4;
        return value;
    }

    public byte[] Bytes(int count)
    {
        var slice = _data.AsSpan(_offset, count).ToArray();
        _offset += count;
        return slice;
    }
}

public sealed class ByteWriter
{
    private readonly MemoryStream _stream = new();

    public void U1(byte value) => _stream.WriteByte(value);

    public void U2(ushort value)
    {
        _stream.WriteByte((byte)(value >> 8));
        _stream.WriteByte((byte)value);
    }

    public void U4(uint value)
    {
        _stream.WriteByte((byte)(value >> 24));
        _stream.WriteByte((byte)(value >> 16));
        _stream.WriteByte((byte)(value >> 8));
        _stream.WriteByte((byte)value);
    }

    public void Bytes(byte[] value) => _stream.Write(value, 0, value.Length);

    public byte[] ToArray() => _stream.ToArray();
}

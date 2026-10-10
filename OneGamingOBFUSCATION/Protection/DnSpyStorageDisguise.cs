using System.IO;
using System.Text;

namespace OneGamingOBFUSCATION.Protection;

public static class DnSpyStorageDisguise
{
    public static void Apply(string pePath)
    {
        var bytes = File.ReadAllBytes(pePath);
        var metadata = FindMetadataRoot(bytes);
        bytes[metadata + 16 + ReadUInt32(bytes, metadata + 12)] = 0x11;
        var tables = metadata + FindStreamOffset(bytes, metadata, "#~");
        bytes[tables + 6] |= 0x40;
        if (ReadUInt32(bytes, CliHeader(bytes) + 20) == 0)
        {
            var flagsAt = CliHeader(bytes) + 16;
            WriteUInt32(bytes, flagsAt, ReadUInt32(bytes, flagsAt) | 0x11);
        }

        File.WriteAllBytes(pePath, bytes);
    }

    public static void Remove(string pePath)
    {
        var bytes = File.ReadAllBytes(pePath);
        var metadata = FindMetadataRoot(bytes);
        bytes[metadata + 16 + ReadUInt32(bytes, metadata + 12)] = 0;
        var tables = metadata + FindStreamOffset(bytes, metadata, "#~");
        bytes[tables + 6] = (byte)(bytes[tables + 6] & ~0x40);
        var flagsAt = CliHeader(bytes) + 16;
        WriteUInt32(bytes, flagsAt, ReadUInt32(bytes, flagsAt) & ~0x10);
        File.WriteAllBytes(pePath, bytes);
    }

    private static int FindMetadataRoot(byte[] bytes)
    {
        var cli = CliHeader(bytes);
        var rva = ReadUInt32(bytes, cli + 8);
        return RvaToOffset(bytes, rva);
    }

    private static int CliHeader(byte[] bytes)
    {
        var pe = ReadUInt32(bytes, 0x3C);
        var magic = ReadUInt16(bytes, pe + 24);
        var dataDirectory = pe + 24 + (magic == 0x20B ? 112 : 96);
        var cliRva = ReadUInt32(bytes, dataDirectory + 14 * 8);
        return RvaToOffset(bytes, cliRva);
    }

    private static int FindStreamOffset(byte[] bytes, int metadata, string name)
    {
        var versionLength = ReadUInt32(bytes, metadata + 12);
        var cursor = metadata + 16 + versionLength + 4;
        var count = ReadUInt16(bytes, metadata + 16 + versionLength + 2);
        for (var index = 0; index < count; index++)
        {
            var offset = ReadUInt32(bytes, cursor);
            var nameStart = cursor + 8;
            var length = 0;
            while (nameStart + length < bytes.Length && bytes[nameStart + length] != 0 && length < 32)
                length++;
            var found = Encoding.ASCII.GetString(bytes, nameStart, length);
            cursor = nameStart + ((length + 1 + 3) & ~3);
            if (found == name || (name == "#~" && found == "#-"))
                return offset;
        }

        throw new InvalidDataException("The metadata tables stream was not found.");
    }

    private static int RvaToOffset(byte[] bytes, int rva)
    {
        var pe = ReadUInt32(bytes, 0x3C);
        var sections = ReadUInt16(bytes, pe + 6);
        var optional = ReadUInt16(bytes, pe + 20);
        var section = pe + 24 + optional;
        for (var index = 0; index < sections; index++)
        {
            var virtualSize = ReadUInt32(bytes, section + 8);
            var virtualAddress = ReadUInt32(bytes, section + 12);
            var rawSize = ReadUInt32(bytes, section + 16);
            var rawPointer = ReadUInt32(bytes, section + 20);
            var span = Math.Max(virtualSize, rawSize);
            if ((uint)rva >= virtualAddress && (uint)rva < virtualAddress + span)
                return rawPointer + (rva - virtualAddress);
            section += 40;
        }

        throw new InvalidDataException("A PE data directory pointed outside the file.");
    }

    private static int ReadUInt16(byte[] bytes, int offset) => bytes[offset] | (bytes[offset + 1] << 8);

    private static int ReadUInt32(byte[] bytes, int offset) =>
        bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);

    private static void WriteUInt32(byte[] bytes, int offset, int value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
        bytes[offset + 2] = (byte)(value >> 16);
        bytes[offset + 3] = (byte)(value >> 24);
    }
}

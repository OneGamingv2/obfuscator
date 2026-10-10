using System.IO;
using System.IO.Compression;
using System.Text;

namespace OneGamingOBFUSCATION.Protection;

public static class ArchiveDumpBreak
{
    public const string DecoyMarker = "OneGaming-dump-view.txt";

    public static void MaskFile(string path)
    {
        var masked = Mask(File.ReadAllBytes(path));
        File.WriteAllBytes(path, masked);
    }

    public static void AppendDecoy(string path)
    {
        var overlay = Mask(CreateDecoy());
        using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.None);
        stream.Write(overlay);
    }

    public static bool MasksExtractorNames(string path)
    {
        var entries = Read(File.ReadAllBytes(path));
        return entries.Count > 0 && entries.All(entry => !entry.LocalName.AsSpan().SequenceEqual(entry.Name));
    }

    public static bool HasDecoyMarker(string path) =>
        Encoding.ASCII.GetString(File.ReadAllBytes(path)).Contains(DecoyMarker, StringComparison.Ordinal);

    private static byte[] CreateDecoy()
    {
        using var memory = new MemoryStream();
        using (var archive = new ZipArchive(memory, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteText(archive, DecoyMarker, "This view is not the loadable file.");
            WriteText(archive, "classes.dat", "00");
        }

        return memory.ToArray();
    }

    private static void WriteText(ZipArchive archive, string name, string text)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        using var stream = entry.Open();
        var data = Encoding.UTF8.GetBytes(text);
        stream.Write(data);
    }

    private static byte[] Mask(byte[] zip)
    {
        var entries = Read(zip);
        var output = new List<byte>(zip.Length + (entries.Count * 48));
        var offsets = new int[entries.Count];
        for (var index = 0; index < entries.Count; index++)
        {
            offsets[index] = output.Count;
            var decoy = Encoding.UTF8.GetBytes($"\u200b{index:x4}\u200c.bin");
            var localExtra = Extra(decoy, Crc32(decoy));
            var flags = (ushort)((entries[index].Flags & ~0x0008) | 0x0800);
            WriteLocal(output, entries[index], flags, decoy, localExtra);
            output.AddRange(entries[index].Data);
        }

        var central = output.Count;
        for (var index = 0; index < entries.Count; index++)
        {
            var entry = entries[index];
            var decoy = Encoding.UTF8.GetBytes($"\u200b{index:x4}\u200c.bin");
            var extra = Combine(entry.Extra, Extra(decoy, Crc32(entry.Name)));
            var flags = (ushort)(entry.Flags & ~0x0008);
            WriteCentral(output, entry, flags, extra, offsets[index]);
        }

        var centralSize = output.Count - central;
        WriteU4(output, 0x06054b50);
        WriteU2(output, 0);
        WriteU2(output, 0);
        WriteU2(output, (ushort)entries.Count);
        WriteU2(output, (ushort)entries.Count);
        WriteU4(output, (uint)centralSize);
        WriteU4(output, (uint)central);
        WriteU2(output, 0);
        return output.ToArray();
    }

    private static List<ZipPart> Read(byte[] zip)
    {
        var eocd = FindEocd(zip);
        var count = ReadU2(zip, eocd + 10);
        var cursor = ReadU4(zip, eocd + 16);
        var entries = new List<ZipPart>(count);
        for (var index = 0; index < count; index++)
        {
            if (ReadU4(zip, cursor) != 0x02014b50)
                throw new InvalidDataException("The jar central directory is not readable.");
            var flags = ReadU2(zip, cursor + 8);
            var method = ReadU2(zip, cursor + 10);
            var crc = ReadU4(zip, cursor + 16);
            var compressed = ReadU4(zip, cursor + 20);
            var uncompressed = ReadU4(zip, cursor + 24);
            var nameLength = ReadU2(zip, cursor + 28);
            var extraLength = ReadU2(zip, cursor + 30);
            var commentLength = ReadU2(zip, cursor + 32);
            var local = ReadU4(zip, cursor + 42);
            var name = zip[(cursor + 46)..(cursor + 46 + nameLength)];
            var extra = zip[(cursor + 46 + nameLength)..(cursor + 46 + nameLength + extraLength)];
            if (ReadU4(zip, local) != 0x04034b50)
                throw new InvalidDataException("A jar local header is not readable.");
            var localName = ReadU2(zip, local + 26);
            var localExtra = ReadU2(zip, local + 28);
            var dataAt = local + 30 + localName + localExtra;
            entries.Add(new ZipPart(
                ReadU2(zip, cursor + 4),
                ReadU2(zip, cursor + 6),
                flags,
                method,
                ReadU2(zip, cursor + 12),
                ReadU2(zip, cursor + 14),
                crc,
                compressed,
                uncompressed,
                name,
                extra,
                zip[dataAt..(dataAt + compressed)],
                zip[(local + 30)..(local + 30 + localName)]));
            cursor += 46 + nameLength + extraLength + commentLength;
        }

        return entries;
    }

    private static int FindEocd(byte[] zip)
    {
        var start = Math.Max(0, zip.Length - 22 - 65535);
        for (var index = zip.Length - 22; index >= start; index--)
        {
            if (ReadU4(zip, index) != 0x06054b50)
                continue;
            if (index + 22 + ReadU2(zip, index + 20) == zip.Length)
                return index;
        }

        throw new InvalidDataException("The archive directory was not found.");
    }

    private static byte[] Extra(byte[] unicodeName, uint nameCrc)
    {
        var extra = new byte[2 + 2 + 1 + 4 + unicodeName.Length];
        extra[0] = 0x75;
        extra[1] = 0x70;
        var size = (ushort)(1 + 4 + unicodeName.Length);
        extra[2] = (byte)size;
        extra[3] = (byte)(size >> 8);
        extra[4] = 1;
        extra[5] = (byte)nameCrc;
        extra[6] = (byte)(nameCrc >> 8);
        extra[7] = (byte)(nameCrc >> 16);
        extra[8] = (byte)(nameCrc >> 24);
        unicodeName.CopyTo(extra, 9);
        return extra;
    }

    private static byte[] Combine(byte[] existing, byte[] added)
    {
        var combined = new byte[existing.Length + added.Length];
        existing.CopyTo(combined, 0);
        added.CopyTo(combined, existing.Length);
        return combined;
    }

    private static void WriteLocal(List<byte> output, ZipPart entry, ushort flags, byte[] name, byte[] extra)
    {
        WriteU4(output, 0x04034b50);
        WriteU2(output, entry.VersionNeeded);
        WriteU2(output, flags);
        WriteU2(output, entry.Method);
        WriteU2(output, entry.Time);
        WriteU2(output, entry.Date);
        WriteU4(output, (uint)entry.Crc);
        WriteU4(output, (uint)entry.Compressed);
        WriteU4(output, (uint)entry.Uncompressed);
        WriteU2(output, (ushort)name.Length);
        WriteU2(output, (ushort)extra.Length);
        output.AddRange(name);
        output.AddRange(extra);
    }

    private static void WriteCentral(List<byte> output, ZipPart entry, ushort flags, byte[] extra, int offset)
    {
        WriteU4(output, 0x02014b50);
        WriteU2(output, entry.VersionMade);
        WriteU2(output, entry.VersionNeeded);
        WriteU2(output, flags);
        WriteU2(output, entry.Method);
        WriteU2(output, entry.Time);
        WriteU2(output, entry.Date);
        WriteU4(output, (uint)entry.Crc);
        WriteU4(output, (uint)entry.Compressed);
        WriteU4(output, (uint)entry.Uncompressed);
        WriteU2(output, (ushort)entry.Name.Length);
        WriteU2(output, (ushort)extra.Length);
        WriteU2(output, 0);
        WriteU2(output, 0);
        WriteU2(output, 0);
        WriteU4(output, 0);
        WriteU4(output, (uint)offset);
        output.AddRange(entry.Name);
        output.AddRange(extra);
    }

    private static uint Crc32(byte[] data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var value in data)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++)
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }

        return ~crc;
    }

    private static void WriteU2(List<byte> output, ushort value)
    {
        output.Add((byte)value);
        output.Add((byte)(value >> 8));
    }

    private static void WriteU4(List<byte> output, uint value)
    {
        output.Add((byte)value);
        output.Add((byte)(value >> 8));
        output.Add((byte)(value >> 16));
        output.Add((byte)(value >> 24));
    }

    private static ushort ReadU2(byte[] data, int offset) =>
        (ushort)(data[offset] | (data[offset + 1] << 8));

    private static int ReadU4(byte[] data, int offset) =>
        data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);

    private sealed record ZipPart(
        ushort VersionMade,
        ushort VersionNeeded,
        ushort Flags,
        ushort Method,
        ushort Time,
        ushort Date,
        int Crc,
        int Compressed,
        int Uncompressed,
        byte[] Name,
        byte[] Extra,
        byte[] Data,
        byte[] LocalName);
}

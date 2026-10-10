using System.Security.Cryptography;

namespace OneGamingOBFUSCATION.Protection;

public static class InvisibleNames
{
    private static readonly char[] Marks =
    [
        '\u200B', '\u200C', '\u200D', '\u200E', '\u200F',
        '\u2060', '\u2061', '\u2062', '\u2063', '\u2064',
        '\uFEFF', '\u00AD', '\u034F', '\u061C',
        '\u202A', '\u202B', '\u202D', '\u202E',
        '\u2066', '\u2067', '\u2068', '\u2069',
        '\u2800', '\u3164', '\uFFA0'
    ];

    private static int _sequence;

    public static string Next(HashSet<string>? used = null)
    {
        string candidate;
        do
        {
            candidate = Build();
        } while (used is not null && !used.Add(candidate));

        return candidate;
    }

    private static string Build()
    {
        var id = Interlocked.Increment(ref _sequence);
        var random = RandomNumberGenerator.GetBytes(10);
        var chars = new char[28];
        var index = 0;
        chars[index++] = '\u202E';
        for (var bit = 0; bit < 16; bit++)
            chars[index++] = ((id >> bit) & 1) == 0 ? '\u200B' : '\u200C';
        foreach (var value in random)
            chars[index++] = Marks[value % Marks.Length];
        chars[index] = '\u202C';
        return new string(chars);
    }
}

namespace OneGamingOBFUSCATION.Protection;

public sealed class ProtectionStats
{
    private readonly Dictionary<string, int> _skipReasons = new(StringComparer.Ordinal);

    public int Candidates { get; set; }
    public int Applied { get; set; }
    public IReadOnlyDictionary<string, int> SkipReasons => _skipReasons;

    public void Skip(string reason)
    {
        _skipReasons[reason] = _skipReasons.GetValueOrDefault(reason) + 1;
    }

    public string FormatSkipSummary(int maxReasons = 8)
    {
        if (_skipReasons.Count == 0)
            return "none";

        return string.Join(", ",
            _skipReasons.OrderByDescending(pair => pair.Value)
                .ThenBy(pair => pair.Key, StringComparer.Ordinal)
                .Take(maxReasons)
                .Select(pair => $"{pair.Key}={pair.Value}"));
    }
}

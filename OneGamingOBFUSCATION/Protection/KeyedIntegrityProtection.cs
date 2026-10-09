using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO;

namespace OneGamingOBFUSCATION.Protection;

public sealed record IntegrityManifest(
    string Format,
    string Algorithm,
    int Pbkdf2Iterations,
    string Salt,
    string Sha256,
    string HmacSha256,
    string ProtectedFile);

public sealed record KeyedIntegrityResult(string ManifestPath, string Sha256, string HmacSha256);

public static class KeyedIntegrityProtection
{
    public const int MinimumKeyLength = 16;
    private const int Iterations = 250_000;

    public static void ValidateKey(string protectionKey)
    {
        if (string.IsNullOrWhiteSpace(protectionKey) || protectionKey.Length < MinimumKeyLength)
            throw new ArgumentException($"Protection key must contain at least {MinimumKeyLength} characters.", nameof(protectionKey));
    }

    public static string GenerateProtectionKey(int length = 32)
    {
        if (length < MinimumKeyLength)
            length = MinimumKeyLength;
        if (length > 128)
            length = 128;

        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%*-_";
        var bytes = RandomNumberGenerator.GetBytes(length);
        var chars = new char[length];
        for (var index = 0; index < length; index++)
            chars[index] = alphabet[bytes[index] % alphabet.Length];
        CryptographicOperations.ZeroMemory(bytes);
        return new string(chars);
    }

    public static KeyedIntegrityResult Create(string protectedFile, string manifestPath, string protectionKey, string protectedFileName)
    {
        ValidateKey(protectionKey);
        var salt = RandomNumberGenerator.GetBytes(16);
        var passwordBytes = Encoding.UTF8.GetBytes(protectionKey);
        var derivedKey = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, Iterations, HashAlgorithmName.SHA256, 32);
        try
        {
            var fileBytes = File.ReadAllBytes(protectedFile);
            try
            {
                var sha256 = Convert.ToHexString(SHA256.HashData(fileBytes));
                var hmacSha256 = Convert.ToHexString(HMACSHA256.HashData(derivedKey, fileBytes));
                var manifest = new IntegrityManifest(
                    "OneGamingOBFUSCATION-KeyedIntegrity-v1",
                    "PBKDF2-SHA256 + HMAC-SHA256",
                    Iterations,
                    Convert.ToBase64String(salt),
                    sha256,
                    hmacSha256,
                    protectedFileName);
                File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
                return new KeyedIntegrityResult(manifestPath, sha256, hmacSha256);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(fileBytes);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(derivedKey);
        }
    }

    public static bool Verify(string protectedFile, string manifestPath, string protectionKey)
    {
        ValidateKey(protectionKey);
        var manifest = JsonSerializer.Deserialize<IntegrityManifest>(File.ReadAllText(manifestPath, Encoding.UTF8))
            ?? throw new InvalidDataException("The integrity manifest is invalid.");
        var salt = Convert.FromBase64String(manifest.Salt);
        var expectedHmac = Convert.FromHexString(manifest.HmacSha256);
        var passwordBytes = Encoding.UTF8.GetBytes(protectionKey);
        var derivedKey = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, manifest.Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);
        try
        {
            using var stream = File.OpenRead(protectedFile);
            var actualHmac = HMACSHA256.HashData(derivedKey, stream);
            try
            {
                return CryptographicOperations.FixedTimeEquals(actualHmac, expectedHmac);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actualHmac);
                CryptographicOperations.ZeroMemory(expectedHmac);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(derivedKey);
            CryptographicOperations.ZeroMemory(salt);
        }
    }
}

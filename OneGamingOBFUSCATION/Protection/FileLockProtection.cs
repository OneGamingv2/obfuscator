using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO;

namespace OneGamingOBFUSCATION.Protection;

public sealed record UnlockVaultEntry(
    string RelativePath,
    string FileSalt,
    string WrappedFilePassword,
    string WrapNonce,
    string WrapTag,
    string ClearSha256,
    string FilePasswordHint);

public sealed record UnlockVault(
    string Format,
    int Pbkdf2Iterations,
    string MasterSalt,
    IReadOnlyList<UnlockVaultEntry> Entries);

public sealed record FileLockResult(
    string LockedPath,
    string VaultPath,
    string PasswordsExportPath,
    string FilePassword,
    string ClearSha256);

public sealed record UnlockResult(
    string OutputPath,
    string ClearSha256,
    bool UsedMasterPassword);

public static class FileLockProtection
{
    public const string LockedExtension = ".oglock";
    public const string VaultFileName = "OneGaming.unlock-vault.json";
    public const string PasswordsExportFileName = "UNLOCK-PASSWORDS.txt";
    public const int MinimumKeyLength = KeyedIntegrityProtection.MinimumKeyLength;
    private const int Iterations = 250_000;
    private static readonly byte[] Magic = "OGLOCK01"u8.ToArray();

    public static void ValidatePassword(string password, string name = "password")
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < MinimumKeyLength)
            throw new ArgumentException($"{name} must contain at least {MinimumKeyLength} characters.", name);
    }

    public static string GenerateFilePassword(int length = 28) =>
        KeyedIntegrityProtection.GenerateProtectionKey(length);

    public static string ToLockedPath(string clearOutputPath) =>
        clearOutputPath.EndsWith(LockedExtension, StringComparison.OrdinalIgnoreCase)
            ? clearOutputPath
            : clearOutputPath + LockedExtension;

    public static string ToUnlockedPath(string lockedPath)
    {
        if (lockedPath.EndsWith(LockedExtension, StringComparison.OrdinalIgnoreCase))
            return lockedPath[..^LockedExtension.Length];
        return lockedPath;
    }

    public static FileLockResult LockFile(
        string clearPath,
        string lockedPath,
        string vaultDirectory,
        string relativePath,
        string masterPassword)
    {
        ValidatePassword(masterPassword, "master password");
        if (!File.Exists(clearPath))
            throw new FileNotFoundException("Clear protected file was not found.", clearPath);

        var filePassword = GenerateFilePassword();
        var clearBytes = File.ReadAllBytes(clearPath);
        var clearSha256 = Convert.ToHexString(SHA256.HashData(clearBytes));
        var fileSalt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var key = DeriveKey(filePassword, fileSalt);
        var ciphertext = new byte[clearBytes.Length];
        var tag = new byte[16];
        try
        {
            using (var aes = new AesGcm(key, 16))
                aes.Encrypt(nonce, clearBytes, ciphertext, tag);

            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(lockedPath))!);
            using (var stream = File.Create(lockedPath))
            {
                stream.Write(Magic);
                stream.Write(fileSalt);
                stream.Write(nonce);
                stream.Write(tag);
                stream.Write(ciphertext);
            }

            var vaultPath = Path.Combine(vaultDirectory, VaultFileName);
            var passwordsPath = Path.Combine(vaultDirectory, PasswordsExportFileName);
            AddOrReplaceVaultEntry(vaultPath, masterPassword, relativePath, filePassword, fileSalt, clearSha256);
            AppendPasswordExport(passwordsPath, relativePath, filePassword, masterPassword.Length);

            return new FileLockResult(lockedPath, vaultPath, passwordsPath, filePassword, clearSha256);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clearBytes);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(fileSalt);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    public static bool IsLockedFile(string path)
    {
        if (!File.Exists(path) || new FileInfo(path).Length < Magic.Length)
            return false;
        Span<byte> header = stackalloc byte[8];
        using var stream = File.OpenRead(path);
        if (stream.Read(header) != 8)
            return false;
        return header.SequenceEqual(Magic);
    }

    public static UnlockResult UnlockFile(
        string lockedPath,
        string outputPath,
        string password,
        string? vaultPath = null)
    {
        ValidatePassword(password);
        if (!File.Exists(lockedPath))
            throw new FileNotFoundException("Locked file was not found.", lockedPath);
        if (!IsLockedFile(lockedPath))
            throw new InvalidDataException("File is not a OneGaming locked container (.oglock).");

        vaultPath ??= FindVaultNear(lockedPath);
        var usedMaster = false;
        string filePassword = password;
        string? expectedSha = null;

        if (vaultPath is not null &&
            TryResolveFilePasswordFromVault(vaultPath, lockedPath, password, out var unwrapped, out expectedSha))
        {
            filePassword = unwrapped!;
            usedMaster = true;
        }

        var clear = DecryptWithFilePassword(lockedPath, filePassword);
        try
        {
            var actualSha = Convert.ToHexString(SHA256.HashData(clear));
            if (expectedSha is not null &&
                !actualSha.Equals(expectedSha, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("Unlocked payload hash did not match the vault record.");

            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
            File.WriteAllBytes(outputPath, clear);
            return new UnlockResult(outputPath, actualSha, usedMaster);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clear);
        }
    }

    public static IReadOnlyList<(string RelativePath, string FilePassword)> ListFilePasswords(
        string vaultPath,
        string masterPassword)
    {
        ValidatePassword(masterPassword, "master password");
        var vault = ReadVault(vaultPath);
        var masterSalt = Convert.FromBase64String(vault.MasterSalt);
        var results = new List<(string, string)>();
        foreach (var entry in vault.Entries)
        {
            var password = UnwrapSecret(
                masterPassword,
                masterSalt,
                Convert.FromBase64String(entry.WrappedFilePassword),
                Convert.FromBase64String(entry.WrapNonce),
                Convert.FromBase64String(entry.WrapTag));
            results.Add((entry.RelativePath, password));
        }

        return results;
    }

    private static void AddOrReplaceVaultEntry(
        string vaultPath,
        string masterPassword,
        string relativePath,
        string filePassword,
        byte[] fileSalt,
        string clearSha256)
    {
        relativePath = relativePath.Replace('\\', '/');
        byte[] masterSalt;
        var entries = new List<UnlockVaultEntry>();

        if (File.Exists(vaultPath))
        {
            var existing = ReadVault(vaultPath);
            masterSalt = Convert.FromBase64String(existing.MasterSalt);
            entries.AddRange(existing.Entries.Where(item =>
                !item.RelativePath.Equals(relativePath, StringComparison.OrdinalIgnoreCase)));
        }
        else
        {
            masterSalt = RandomNumberGenerator.GetBytes(16);
        }

        var wrapped = WrapSecret(masterPassword, filePassword, masterSalt, out var wrapNonce, out var wrapTag);
        entries.Add(new UnlockVaultEntry(
            RelativePath: relativePath,
            FileSalt: Convert.ToBase64String(fileSalt),
            WrappedFilePassword: wrapped,
            WrapNonce: Convert.ToBase64String(wrapNonce),
            WrapTag: Convert.ToBase64String(wrapTag),
            ClearSha256: clearSha256,
            FilePasswordHint: filePassword[..Math.Min(4, filePassword.Length)] + "…" +
                              filePassword[^Math.Min(2, filePassword.Length)..]));

        var vault = new UnlockVault(
            "OneGamingOBFUSCATION-UnlockVault-v1",
            Iterations,
            Convert.ToBase64String(masterSalt),
            entries);

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(vaultPath))!);
        File.WriteAllText(vaultPath, JsonSerializer.Serialize(vault, new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
        CryptographicOperations.ZeroMemory(wrapNonce);
        CryptographicOperations.ZeroMemory(wrapTag);
    }

    private static string? FindVaultNear(string lockedPath)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(lockedPath));
        while (!string.IsNullOrEmpty(dir))
        {
            var candidate = Path.Combine(dir, VaultFileName);
            if (File.Exists(candidate))
                return candidate;
            var parent = Path.GetDirectoryName(dir);
            if (parent is null || parent.Equals(dir, StringComparison.OrdinalIgnoreCase))
                break;
            dir = parent;
        }

        return null;
    }

    private static bool TryResolveFilePasswordFromVault(
        string vaultPath,
        string lockedPath,
        string masterPassword,
        out string? filePassword,
        out string? clearSha256)
    {
        filePassword = null;
        clearSha256 = null;
        try
        {
            var vault = ReadVault(vaultPath);
            var entry = FindEntry(vault, lockedPath);
            if (entry is null)
                return false;

            var masterSalt = Convert.FromBase64String(vault.MasterSalt);
            filePassword = UnwrapSecret(
                masterPassword,
                masterSalt,
                Convert.FromBase64String(entry.WrappedFilePassword),
                Convert.FromBase64String(entry.WrapNonce),
                Convert.FromBase64String(entry.WrapTag));
            clearSha256 = entry.ClearSha256;
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (InvalidDataException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static UnlockVaultEntry? FindEntry(UnlockVault vault, string lockedPath)
    {
        var full = Path.GetFullPath(lockedPath);
        var fileName = Path.GetFileName(full);
        var withoutExt = ToUnlockedPath(fileName);

        UnlockVaultEntry? Match(Func<UnlockVaultEntry, bool> predicate) =>
            vault.Entries.FirstOrDefault(predicate);

        return Match(e => Path.GetFileName(e.RelativePath).Equals(withoutExt, StringComparison.OrdinalIgnoreCase))
               ?? Match(e => Path.GetFileName(e.RelativePath).Equals(fileName, StringComparison.OrdinalIgnoreCase))
               ?? Match(e => (e.RelativePath + LockedExtension).Equals(fileName, StringComparison.OrdinalIgnoreCase))
               ?? Match(e => full.EndsWith(e.RelativePath.Replace('/', Path.DirectorySeparatorChar) + LockedExtension,
                   StringComparison.OrdinalIgnoreCase))
               ?? Match(e => full.EndsWith(e.RelativePath.Replace('/', Path.DirectorySeparatorChar),
                   StringComparison.OrdinalIgnoreCase))
               ?? (vault.Entries.Count == 1 ? vault.Entries[0] : null);
    }

    private static byte[] DecryptWithFilePassword(string lockedPath, string filePassword)
    {
        var blob = File.ReadAllBytes(lockedPath);
        if (blob.Length < Magic.Length + 16 + 12 + 16)
            throw new InvalidDataException("Locked file is truncated or invalid.");
        if (!blob.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            throw new InvalidDataException("File is not a OneGaming locked container (.oglock).");

        var salt = blob.AsSpan(Magic.Length, 16).ToArray();
        var nonce = blob.AsSpan(Magic.Length + 16, 12).ToArray();
        var tag = blob.AsSpan(Magic.Length + 28, 16).ToArray();
        var ciphertext = blob.AsSpan(Magic.Length + 44).ToArray();
        var key = DeriveKey(filePassword, salt);
        var clear = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, ciphertext, tag, clear);
            return clear;
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("Unlock failed. Wrong file password or master password.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(blob);
        }
    }

    private static UnlockVault ReadVault(string vaultPath)
    {
        var vault = JsonSerializer.Deserialize<UnlockVault>(File.ReadAllText(vaultPath, Encoding.UTF8))
            ?? throw new InvalidDataException("Unlock vault is invalid.");
        if (!string.Equals(vault.Format, "OneGamingOBFUSCATION-UnlockVault-v1", StringComparison.Ordinal))
            throw new InvalidDataException($"Unsupported unlock vault format: {vault.Format}");
        if (string.IsNullOrWhiteSpace(vault.MasterSalt))
            throw new InvalidDataException("Unlock vault is missing MasterSalt.");
        return vault;
    }

    private static string WrapSecret(string masterPassword, string secret, byte[] masterSalt, out byte[] nonce, out byte[] tag)
    {
        var key = DeriveKey(masterPassword, masterSalt);
        var plain = Encoding.UTF8.GetBytes(secret);
        nonce = RandomNumberGenerator.GetBytes(12);
        tag = new byte[16];
        var cipher = new byte[plain.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, plain, cipher, tag);
            return Convert.ToBase64String(cipher);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    private static string UnwrapSecret(string masterPassword, byte[] masterSalt, byte[] cipher, byte[] nonce, byte[] tag)
    {
        var key = DeriveKey(masterPassword, masterSalt);
        var plain = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, cipher, tag, plain);
            return Encoding.UTF8.GetString(plain);
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("Master password rejected by the unlock vault.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[] DeriveKey(string password, byte[] salt)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, Iterations, HashAlgorithmName.SHA256, 32);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static void AppendPasswordExport(string path, string relativePath, string filePassword, int masterPasswordLength)
    {
        var lines = new List<string>();
        if (!File.Exists(path))
        {
            lines.Add("OneGamingOBFUSCATION unlock passwords");
            lines.Add("Keep this file private. Delete it after you store the passwords safely.");
            lines.Add($"Master (system) password = the protection key you typed ({masterPasswordLength} chars).");
            lines.Add($"Master unlocks EVERY locked file through {VaultFileName}.");
            lines.Add("Each line below is a unique per-file password (unlocks only that file).");
            lines.Add("");
        }

        lines.Add($"{relativePath.Replace('\\', '/')} = {filePassword}");
        File.AppendAllLines(path, lines, Encoding.UTF8);
    }
}

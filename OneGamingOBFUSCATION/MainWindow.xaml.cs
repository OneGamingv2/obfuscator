using Microsoft.Win32;
using OneGamingOBFUSCATION.Core;
using OneGamingOBFUSCATION.Protection;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace OneGamingOBFUSCATION;

public partial class MainWindow : Window
{
    private bool _suppressPresetSync;
    private bool _syncingKey;

    public MainWindow()
    {
        InitializeComponent();
        ShowPage("dll");
        Log("Ready. One DLL, EXE, or plugin JAR at a time.");
        Log("CLI: OneGamingOBFUSCATION.exe protect --input <path> --key <key>");
        StateChanged += (_, _) => SyncChrome();
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left)
            return;
        if (e.ClickCount == 2)
        {
            ToggleMaximize();
            return;
        }

        DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void ToggleMaximize() =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void SyncChrome()
    {
        ChromeInset.Margin = WindowState == WindowState.Maximized ? new Thickness(7) : new Thickness(0);
        MaxGlyph.Text = WindowState == WindowState.Maximized ? "\uE923" : "\uE922";
    }

    private void BrowseInput_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose a DLL, EXE, or plugin JAR",
            Filter = "DLL, EXE, and JAR (*.dll;*.exe;*.jar)|*.dll;*.exe;*.jar|Library (*.dll)|*.dll|Executable (*.exe)|*.exe|Plugin JAR (*.jar)|*.jar",
            CheckFileExists = true
        };

        if (dialog.ShowDialog(this) == true)
            SetInput(dialog.FileName);
    }

    private void BrowseOutput_Click(object sender, RoutedEventArgs e)
    {
        var input = InputPathBox.Text.Trim();
        var extension = Path.GetExtension(input);
        var isExe = extension.Equals(".exe", StringComparison.OrdinalIgnoreCase);
        var isJar = extension.Equals(".jar", StringComparison.OrdinalIgnoreCase);
        var dialog = new SaveFileDialog
        {
            Title = "Choose a new output file",
            Filter = isJar
                ? "Plugin JAR (*.jar)|*.jar"
                : "Library (*.dll)|*.dll|Executable (*.exe)|*.exe",
            FilterIndex = isJar || !isExe ? 1 : 2,
            DefaultExt = isJar ? "jar" : isExe ? "exe" : "dll",
            AddExtension = true,
            FileName = string.IsNullOrWhiteSpace(input)
                ? "Protected.dll"
                : ObfuscationEngine.CreateDefaultOutputPath(input)
        };

        if (dialog.ShowDialog(this) == true)
            OutputPathBox.Text = dialog.FileName;
    }

    private async void ProtectButton_Click(object sender, RoutedEventArgs e)
    {
        SetBusy(true);
        StatusText.Text = "Working locally…";
        var succeeded = false;

        try
        {
            var input = Path.GetFullPath(InputPathBox.Text.Trim());
            var output = Path.GetFullPath(OutputPathBox.Text.Trim());
            var protectionKey = RequireProtectionKey();
            Log($"Input:  {input}");
            Log($"Output: {output}");
            Log("Protection password accepted — starting obfuscation maze.");

            if (IsJar(input))
            {
                if (!output.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Jar output has to end with .jar.");
                var jarOptions = new JarProtectOptions(
                    JarRenameClassesBox.IsChecked == true,
                    JarRenameMembersBox.IsChecked == true,
                    JarStringsBox.IsChecked == true,
                    JarStripDebugBox.IsChecked == true,
                    JarShuffleBox.IsChecked == true,
                    OverwriteBox.IsChecked == true,
                    JarNumbersBox.IsChecked == true,
                    JarArchiveBox.IsChecked == true);
                var jar = await Task.Run(() => JarPluginObfuscator.Protect(input, output, jarOptions, protectionKey));
                foreach (var note in jar.Notes)
                    Log(note);
                Log($"SHA-256: {jar.Sha256}");
                Log($"Keyed integrity manifest: {jar.ManifestPath}");
                StatusText.Text = "Finished. Protected JAR is ready.";
                succeeded = true;
                return;
            }

            if (!IsDllOrExe(input))
                throw new InvalidDataException("Choose a single .dll, .exe, or .jar.");

            var options = ReadOptions();
            var result = await Task.Run(() => ObfuscationEngine.Protect(input, output, options, protectionKey));
            Log($"Renamed helper types: {result.RenamedTypes}");
            Log($"Renamed methods: {result.RenamedMethods}");
            Log($"Renamed fields:  {result.RenamedFields}");
            Log($"Renamed parameters: {result.RenamedParameters}");
            Log($"Renamed properties/events: {result.RenamedProperties}/{result.RenamedEvents}");
            Log($"Renamed accessors/generic parameters: {result.RenamedAccessors}/{result.RenamedGenericParameters}");
            Log($"Protected strings: {result.ProtectedStrings}");
            Log($"Protected integers: {result.ProtectedIntegers}");
            Log($"Protected embedded resources: {result.ProtectedResources}");
            Log($"Runtime obfuscation artifacts: {result.RuntimeArtifacts}");
            Log($"Proxied static calls: {result.ProxiedCalls}");
            Log($"Virtualized methods: {result.VirtualizedMethods}");
            Log($"Flattened methods: {result.FlattenedMethods}");
            Log($"Woven IL instructions: {result.WovenInstructions}");
            Log($"Shuffled metadata entries: {result.ShuffledMetadataEntries}");
            Log($"Stripped debug/source records: {result.StrippedDebugRecords}");
            Log($"Protected module / MVID: {result.ProtectedModuleName} / {result.Mvid}");
            Log($"Preserved compatibility-sensitive members: {result.PreservedMembers}");
            foreach (var diagnostic in result.Diagnostics)
                Log(diagnostic);
            Log($"SHA-256 (clear payload): {result.Sha256}");
            Log($"Keyed integrity manifest: {result.IntegrityManifestPath}");
            if (result.IsLocked)
            {
                Log($"LOCKED output: {result.LockedPath}");
                Log($"Per-file unlock password: {result.FilePassword}");
                Log("Master (system) password = the protection key you entered (unlocks all via vault).");
                Log($"Unlock vault: {result.UnlockVaultPath}");
                Log($"Password export: {result.PasswordsExportPath}");
            }
            Log($"Local report: {result.ReportPath}");
            var kind = Path.GetExtension(output).Equals(".exe", StringComparison.OrdinalIgnoreCase) ? "EXE" : "DLL";
            StatusText.Text = result.IsLocked
                ? "Finished. Unlock the .oglock before it can run."
                : $"Finished. Protected {kind} is ready.";
            succeeded = true;
        }
        catch (Exception ex)
        {
            Log($"ERROR: {ex.Message}");
            StatusText.Text = "Nothing was overwritten. Review the error above. Protection key was kept.";
        }
        finally
        {
            if (succeeded)
                ClearProtectionKey();
            SetBusy(false);
        }
    }

    private async void UnlockButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose a locked OneGaming file (.oglock)",
            Filter = "Locked assemblies (*.oglock)|*.oglock|All files (*.*)|*.*",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) != true)
            return;

        SetBusy(true);
        var succeeded = false;
        try
        {
            var locked = dialog.FileName;
            var password = GetProtectionKey();
            if (string.IsNullOrWhiteSpace(password) || password.Length < FileLockProtection.MinimumKeyLength)
                throw new ArgumentException($"Enter the master or per-file unlock password ({FileLockProtection.MinimumKeyLength}+ characters).");

            var output = FileLockProtection.ToUnlockedPath(locked);
            var result = await Task.Run(() => FileLockProtection.UnlockFile(locked, output, password));
            Log($"Unlocked: {result.OutputPath}");
            Log($"Used master password: {result.UsedMasterPassword}");
            Log($"SHA-256: {result.ClearSha256}");
            StatusText.Text = "Unlock finished — clear assembly written beside the .oglock.";
            succeeded = true;
        }
        catch (Exception ex)
        {
            Log($"UNLOCK ERROR: {ex.Message}");
            StatusText.Text = "Unlock failed. Check the password and try again.";
        }
        finally
        {
            if (succeeded)
                ClearProtectionKey();
            SetBusy(false);
        }
    }

    private async void VerifyButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose a OneGaming-protected assembly",
            Filter = "DLL, EXE, and JAR (*.dll;*.exe;*.jar)|*.dll;*.exe;*.jar",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) != true)
            return;

        SetBusy(true);
        var succeeded = false;
        try
        {
            var protectedFile = dialog.FileName;
            var manifest = protectedFile + ".integrity.json";
            var protectionKey = GetProtectionKey();
            if (string.IsNullOrWhiteSpace(protectionKey) || protectionKey.Length < KeyedIntegrityProtection.MinimumKeyLength)
                throw new ArgumentException($"Enter the original protection key ({KeyedIntegrityProtection.MinimumKeyLength}+ characters) to verify.");
            var valid = await Task.Run(() => KeyedIntegrityProtection.Verify(protectedFile, manifest, protectionKey));
            Log(valid
                ? $"Integrity VERIFIED: {protectedFile}"
                : $"Integrity FAILED (wrong key or modified file): {protectedFile}");
            StatusText.Text = valid ? "Integrity verified with the supplied key." : "Integrity verification failed.";
            succeeded = valid;
        }
        catch (Exception ex)
        {
            Log($"VERIFY ERROR: {ex.Message}");
            StatusText.Text = "Integrity verification could not be completed. Protection key was kept.";
        }
        finally
        {
            if (succeeded)
                ClearProtectionKey();
            SetBusy(false);
        }
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = FirstSupported(e.Data) is null ? DragDropEffects.None : DragDropEffects.Copy;
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        var path = FirstSupported(e.Data);
        if (path is null)
        {
            Log("Drop a single .dll, .exe, or .jar.");
            StatusText.Text = "Only a DLL, EXE, or plugin JAR can be protected.";
            return;
        }

        SetInput(path);
    }

    private void SetInput(string path)
    {
        if (!IsSupported(path))
        {
            Log("Only a .dll, .exe, or .jar can be selected.");
            StatusText.Text = "Only a DLL, EXE, or plugin JAR can be protected.";
            return;
        }

        InputPathBox.Text = Path.GetFullPath(path);
        OutputPathBox.Text = ObfuscationEngine.CreateDefaultOutputPath(path);
        var extension = Path.GetExtension(path);
        if (extension.Equals(".jar", StringComparison.OrdinalIgnoreCase))
        {
            ShowPage("jar");
            FileKindText.Text = "JAR";
            try
            {
                var scan = JarPluginObfuscator.Scan(path);
                var plugin = string.IsNullOrWhiteSpace(scan.PluginName) ? "unnamed plugin" : scan.PluginName;
                JarDetectedText.Text = scan.MainClass is null
                    ? $"{scan.Server}. {plugin}."
                    : $"{scan.Server}. {plugin}. Main {scan.MainClass}.";
                Log(scan.Summary);
            }
            catch (Exception ex)
            {
                JarDetectedText.Text = "This JAR could not be scanned as a plugin.";
                Log(ex.Message);
            }
        }
        else if (extension.Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            ShowPage("exe");
            FileKindText.Text = "EXE";
        }
        else
        {
            ShowPage("dll");
            FileKindText.Text = "DLL";
        }

        Log($"Selected: {path}");
        StatusText.Text = $"Ready to protect this {FileKindText.Text}.";
    }

    private void ShowDllPage_Click(object sender, RoutedEventArgs e) => ShowPage("dll");

    private void ShowExePage_Click(object sender, RoutedEventArgs e) => ShowPage("exe");

    private void ShowJarPage_Click(object sender, RoutedEventArgs e) => ShowPage("jar");

    private void ShowPage(string page)
    {
        var jar = page == "jar";
        var exe = page == "exe";
        DotNetPage.Visibility = jar ? Visibility.Collapsed : Visibility.Visible;
        JarPage.Visibility = jar ? Visibility.Visible : Visibility.Collapsed;
        DllNote.Visibility = exe || jar ? Visibility.Collapsed : Visibility.Visible;
        ExeNote.Visibility = exe ? Visibility.Visible : Visibility.Collapsed;
        DotNetPageTitle.Text = exe ? "EXE page" : "DLL page";
        PaintPage(DllPageButton, page == "dll");
        PaintPage(ExePageButton, exe);
        PaintPage(JarPageButton, jar);
    }

    private void PaintPage(Button button, bool selected)
    {
        button.Background = selected ? (Brush)FindResource("AccentBrush") : Brushes.White;
        button.Foreground = selected ? Brushes.White : (Brush)FindResource("TextBrush");
        button.BorderBrush = selected ? (Brush)FindResource("AccentBrush") : (Brush)FindResource("LineBrush");
    }

    private static string? FirstSupported(IDataObject data)
    {
        if (data.GetData(DataFormats.FileDrop) is not string[] files)
            return null;
        return files.FirstOrDefault(IsSupported);
    }

    private static bool IsSupported(string path) => IsDllOrExe(path) || IsJar(path);

    private static bool IsJar(string path) =>
        File.Exists(path) && Path.GetExtension(path).Equals(".jar", StringComparison.OrdinalIgnoreCase);

    private static bool IsDllOrExe(string path)
    {
        var extension = Path.GetExtension(path);
        return File.Exists(path) &&
               (extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(".exe", StringComparison.OrdinalIgnoreCase));
    }

    private ObfuscationOptions ReadOptions() => new(
        RenamePrivateMembers: RenameMembersBox.IsChecked == true,
        RenameHelperTypes: RenameTypesBox.IsChecked == true,
        AggressiveRenaming: AggressiveRenamingBox.IsChecked == true,
        ProtectStrings: ProtectStringsBox.IsChecked == true,
        ProtectIntegers: ProtectIntegersBox.IsChecked == true,
        ProxyStaticCalls: ProxyCallsBox.IsChecked == true,
        VirtualizeInt32Methods: VirtualizeBox.IsChecked == true,
        FlattenControlFlow: FlattenBox.IsChecked == true,
        WeaveInstructions: WeaveInstructionsBox.IsChecked == true,
        ProtectEmbeddedResources: ProtectResourcesBox.IsChecked == true,
        RuntimeObfuscation: RuntimeObfuscationBox.IsChecked == true,
        HardenMetadataAndPe: MetadataPeBox.IsChecked == true,
        ProtectWholeFolder: false,
        AllowOverwrite: OverwriteBox.IsChecked == true,
        MultilayerHardening: MultilayerBox.IsChecked == true,
        LockOutputs: LockOutputsBox.IsChecked == true);

    private void PresetBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || _suppressPresetSync || PresetBox.SelectedItem is not ComboBoxItem item)
            return;

        var tag = item.Tag?.ToString() ?? "custom";
        if (tag == "custom")
            return;

        _suppressPresetSync = true;
        var options = tag == "rename" ? ObfuscationOptions.RenameOnly : ObfuscationOptions.Maximum;
        RenameMembersBox.IsChecked = options.RenamePrivateMembers;
        RenameTypesBox.IsChecked = options.RenameHelperTypes;
        AggressiveRenamingBox.IsChecked = options.AggressiveRenaming;
        ProtectStringsBox.IsChecked = options.ProtectStrings;
        ProtectIntegersBox.IsChecked = options.ProtectIntegers;
        ProxyCallsBox.IsChecked = options.ProxyStaticCalls;
        VirtualizeBox.IsChecked = options.VirtualizeInt32Methods;
        FlattenBox.IsChecked = options.FlattenControlFlow;
        WeaveInstructionsBox.IsChecked = options.WeaveInstructions;
        ProtectResourcesBox.IsChecked = options.ProtectEmbeddedResources;
        RuntimeObfuscationBox.IsChecked = options.RuntimeObfuscation;
        MetadataPeBox.IsChecked = options.HardenMetadataAndPe;
        OverwriteBox.IsChecked = options.AllowOverwrite;
        MultilayerBox.IsChecked = options.MultilayerHardening;
        LockOutputsBox.IsChecked = options.LockOutputs;
        _suppressPresetSync = false;
        Log($"Preset applied: {item.Content}");
    }

    private void LayerCheckBox_Click(object sender, RoutedEventArgs e)
    {
        if (_suppressPresetSync)
            return;
        _suppressPresetSync = true;
        foreach (ComboBoxItem item in PresetBox.Items)
        {
            if (item.Tag?.ToString() == "custom")
            {
                PresetBox.SelectedItem = item;
                break;
            }
        }
        _suppressPresetSync = false;
    }

    private void GenerateKey_Click(object sender, RoutedEventArgs e) => ApplyGeneratedKey(announce: true);

    private void ApplyGeneratedKey(bool announce)
    {
        var key = KeyedIntegrityProtection.GenerateProtectionKey();
        SetProtectionKey(key);
        SetConfirmKey(key);
        ShowKeyBox.IsChecked = true;
        ShowKeyBox_Changed(ShowKeyBox, new RoutedEventArgs());
        if (!announce)
            return;

        Log("Generated protection password (save this — required to obfuscate again / verify):");
        Log(key);
        try
        {
            Clipboard.SetText(key);
            Log("Password copied to clipboard.");
            StatusText.Text = "Password generated, confirmed, and copied. Protect is unlocked.";
        }
        catch
        {
            StatusText.Text = "Password generated and confirmed. Copy it from the key box.";
        }
    }

    private string RequireProtectionKey()
    {
        var existing = GetProtectionKey();
        var confirm = GetConfirmKey();
        if (string.IsNullOrWhiteSpace(existing) || existing.Length < KeyedIntegrityProtection.MinimumKeyLength)
            throw new ArgumentException(
                $"Enter a protection password ({KeyedIntegrityProtection.MinimumKeyLength}+ characters) or click Generate. Obfuscation will not run without it.");

        if (!string.Equals(existing, confirm, StringComparison.Ordinal))
            throw new ArgumentException("Password confirmation does not match. Re-enter both fields (or click Generate).");

        KeyedIntegrityProtection.ValidateKey(existing);
        return existing;
    }

    private void SetProtectionKey(string key)
    {
        _syncingKey = true;
        ProtectionKeyBox.Password = key;
        VisibleKeyBox.Text = key;
        _syncingKey = false;
        UpdateKeyStrength();
    }

    private void SetConfirmKey(string key)
    {
        _syncingKey = true;
        ConfirmKeyBox.Password = key;
        VisibleConfirmKeyBox.Text = key;
        _syncingKey = false;
        UpdateKeyStrength();
    }

    private void ProtectionKeyBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_syncingKey)
            return;
        _syncingKey = true;
        VisibleKeyBox.Text = ProtectionKeyBox.Password;
        _syncingKey = false;
        UpdateKeyStrength();
    }

    private void VisibleKeyBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_syncingKey)
            return;
        _syncingKey = true;
        ProtectionKeyBox.Password = VisibleKeyBox.Text;
        _syncingKey = false;
        UpdateKeyStrength();
    }

    private void ConfirmKeyBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_syncingKey)
            return;
        _syncingKey = true;
        VisibleConfirmKeyBox.Text = ConfirmKeyBox.Password;
        _syncingKey = false;
        UpdateKeyStrength();
    }

    private void VisibleConfirmKeyBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_syncingKey)
            return;
        _syncingKey = true;
        ConfirmKeyBox.Password = VisibleConfirmKeyBox.Text;
        _syncingKey = false;
        UpdateKeyStrength();
    }

    private void ShowKeyBox_Changed(object sender, RoutedEventArgs e)
    {
        var show = ShowKeyBox.IsChecked == true;
        VisibleKeyBox.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        ProtectionKeyBox.Visibility = show ? Visibility.Collapsed : Visibility.Visible;
        VisibleConfirmKeyBox.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        ConfirmKeyBox.Visibility = show ? Visibility.Collapsed : Visibility.Visible;
        if (show)
        {
            VisibleKeyBox.Text = ProtectionKeyBox.Password;
            VisibleConfirmKeyBox.Text = ConfirmKeyBox.Password;
        }
        else
        {
            ProtectionKeyBox.Password = VisibleKeyBox.Text;
            ConfirmKeyBox.Password = VisibleConfirmKeyBox.Text;
        }
    }

    private void UpdateKeyStrength()
    {
        var key = GetProtectionKey();
        var confirm = GetConfirmKey();
        if (key.Length == 0)
        {
            KeyStrengthText.Text = "Enter a password twice, or click Generate. 16 characters minimum.";
            return;
        }

        if (key.Length < KeyedIntegrityProtection.MinimumKeyLength)
        {
            KeyStrengthText.Text = $"Too short ({key.Length}/{KeyedIntegrityProtection.MinimumKeyLength}). Protect stays locked.";
            return;
        }

        if (!string.Equals(key, confirm, StringComparison.Ordinal))
        {
            KeyStrengthText.Text = "Passwords do not match yet — confirm the same key in the second box.";
            return;
        }

        KeyStrengthText.Text = key.Length < 24
            ? "Password accepted. Protect is unlocked. Save this key for Verify later."
            : "Strong password accepted. Protect is unlocked. Save this key for Verify later.";
    }

    private string GetProtectionKey() =>
        VisibleKeyBox.Visibility == Visibility.Visible ? VisibleKeyBox.Text : ProtectionKeyBox.Password;

    private string GetConfirmKey() =>
        VisibleConfirmKeyBox.Visibility == Visibility.Visible ? VisibleConfirmKeyBox.Text : ConfirmKeyBox.Password;

    private void ClearProtectionKey()
    {
        _syncingKey = true;
        ProtectionKeyBox.Clear();
        VisibleKeyBox.Text = string.Empty;
        ConfirmKeyBox.Clear();
        VisibleConfirmKeyBox.Text = string.Empty;
        _syncingKey = false;
        UpdateKeyStrength();
    }

    private void SetBusy(bool busy)
    {
        ProtectButton.IsEnabled = !busy;
        VerifyButton.IsEnabled = !busy;
        UnlockButton.IsEnabled = !busy;
        WorkProgress.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Log(string message)
    {
        LogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
        LogBox.ScrollToEnd();
    }
}

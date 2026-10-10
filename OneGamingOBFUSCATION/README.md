# OneGamingOBFUSCATION

A fully local, layered IL obfuscator for managed Gorilla Tag, Unity, BepInEx, and Harmony mods.

## Safety design

- Never overwrites the input assembly.
- Never connects to the network or uploads strings.
- Refuses native, mixed-mode, and strong-name signed assemblies.
- Writes to a temporary file and validates the finished managed assembly before moving it into place.
- Preserves Unity lifecycle messages, BepInEx plugin identities, Harmony patch methods, serialized fields, virtual/override contracts, and names found in reflection strings.
- Benign compiler attributes (for example `CompilerGenerated`) no longer block otherwise-safe transforms.
- Does not include anti-debug, anti-dump, anti-tamper, invalid-metadata, or other high-risk transformations.
- Produces a local report and SHA-256 hash beside every output.
- Requires a user-supplied protection key of at least 16 characters; the raw key is never written to the DLL, report, or manifest.
- Recalculates method MaxStack after IL expansion so Mono/Unity loaders are not left with stale stack depths.

## Protection layers

- Aggressive compatible renaming of self-contained public/internal/private methods, fields, helper types, nested types, and namespaces.
- Property/event metadata plus accessor, parameter, and generic-parameter renaming.
- Per-string encrypted static byte blobs with a local runtime decoder (no readable Base64 `ldstr` payloads). Multilayer mode uses multi-round XOR and a rotating decoder pool.
- `const string` fields (including BepInEx `GUID` / `Name` / `Version`) are converted to encrypted statics and renamed so dnSpy no longer shows `public const string GUID = "..."`.
- Embedded resource encryption with renamed manifest metadata and a runtime `GetManifestResourceStream` resolver (`.resources` satellites left intact for ResourceManager).
- Runtime obfuscation bootstrap with decoy types/methods and opaque module initialization state.
- Integer constant encoding directly in IL, with multilayer MBA-style expression trees (xor/add/sub mixes) so single-key pattern matchers fail more often.
- Custom per-build methods: real constants and integer math are moved into unique algebra helpers (add/sub/xor/and/or/mul identities, modular multiply, opaque predicates), called through proxies, then virtualized. Dense noise and the instruction weave call those helpers too, so cleanup cannot match one fixed xor template.
- Static-call indirection through generated proxy methods, optionally chained 2–3 deep under multilayer hardening.
- Multilayer noise: junk MBA helpers, decoy “decoders,” and identity wrappers that break single-pass cleanup heuristics.
- Guarded method virtualization: eligible Int32/bool/void helpers (including branches) are compiled to encrypted stack-machine bytecode and executed by an embedded interpreter — original IL is removed from the method. Multilayer scrambles opcodes per build and raises size limits.
- Control-flow maze for eligible helper methods.
- Per-instruction state weaving for eligible straight-line methods; multilayer adds dense MBA junk before each IL op (“every line” noise).
- Namespace scattering for compatibility-safe internal helper types.
- Renamed identifiers are unique zero-width, blank, and bidirectional marks. A decompiler dump shows empty names and the exported project is not valid C#. Unity callbacks, BepInEx identity, and Harmony patch names stay readable.
- Coverage diagnostics in the UI log and `.report.txt` explain applied counts and top skip reasons.

Nothing is “AI-proof.” Stronger multilayer transforms raise the cost of automated cleanup; a determined reverse engineer with a debugger can still recover behavior. BepInPlugin attribute string arguments remain plaintext so BepInEx can load plugins.

Anti-dump / single-use-in-game / runtime kill-switches are intentionally not included: they break Mono/Unity, false-positive on normal BepInEx tooling, and are trivial to patch out of a client DLL. Use **Verify integrity** offline with your master key.

## Metadata and PE hardening

- Randomized managed module name (`.cpp`, so dnSpy's module list looks like C++) and Module Version ID (MVID) on every output.
- Metadata storage flags are set to `0x11`, the `#~` heap flags include ExtraData, and the COR20 flags include `0x11` (IL-only plus the native-entry bit, with the entry still 0). dnSpy's default CLR reader shifts the tables and shows a fake assembly instead of the real methods. Gorilla Tag's Mono loader skips the storage flags and the ExtraData bit, and it does not treat `0x10` as a native entry, so the game still loads the DLL. In dnSpy, switch the metadata reader to Mono if you need to inspect your own output.
- Randomized valid PE/COFF timestamp.
- Ownership-safe metadata token reordering for types, non-virtual methods, fields, properties, and events.
- Manifest resource visibility hardened to private where applicable.
- Embedded sequence points, source paths, and custom debug records are removed.
- A standard `SuppressIldasmAttribute` marker is added without corrupting CLR metadata.
- Assembly identity, runtime-critical PE flags, method signatures, resources, and loader-critical headers remain valid.

The storage-flag and ExtraData bits above are the only metadata values written off the normal CLR layout. Tables, PE sections, and method bodies stay structurally valid for Mono. The tool does not add packer stubs or fake headers.

## Keyed integrity verification

- Each protected DLL/EXE receives an `.integrity.json` sidecar (hashes the clear protected payload).
- PBKDF2-SHA256 derives a 256-bit key using a fresh random salt and 250,000 iterations.
- HMAC-SHA256 detects modification and rejects an incorrect protection key using a constant-time comparison.
- Select **Verify integrity** on an unlocked clear assembly and supply the original master key.

## Master password + optional offline seal

- The protection key is your **master password** for integrity verification (and for the optional `.oglock` seal).
- **Default Safe/Maximum output is a normal managed DLL** the game / BepInEx can load immediately.
- “Code lock” means the IL layers (rename, encrypted strings, MBA integers, proxy chains, control-flow maze, weave, decoys, metadata hardening). dnSpy's default reader opens the PE but misreads it as another assembly; the Mono metadata reader is what shows the real module, and that view is meant to be unreadable junk rather than your source.
- Optional checkbox / `--lock true` writes AES-GCM `.oglock` containers instead (not loadable until `unlock`). Use that only when you want an offline sealed package, not for in-game plugins.

Nothing can make a loadable Unity/BepInEx plugin literally impossible to open in dnSpy: if the CLR can read the file, a decompiler can too. Invalid-metadata / anti-dnSpy crash tricks are intentionally not used because they break Mono/Unity and are easy to strip. Keep the master key private if you want integrity manifests to stay unforgeable.

## Safety boundary

OneGamingOBFUSCATION does not install kernel drivers, request administrator privileges, scan other processes, evade debuggers, hide files, or modify Windows security settings. Kernel anti-cheat requires audited driver engineering, code signing, a secure update pipeline, and ongoing compatibility work; bundling such a driver into an obfuscator would make the tool less safe rather than protect managed IL.

Virtualization and control-flow flattening are limited to eligible private helpers. Unity callbacks, BepInEx entry points, Harmony patches, reflection-sensitive names, exception-heavy methods, and unsupported IL are preserved or skipped. Turn off **Maximum compatible identifier coverage** if the assembly exposes an API that other DLLs call directly.

“Per instruction” refers to compiled IL, not source-code lines. Source line boundaries and comments are normally absent from a release DLL. The weaving pass surrounds every supported IL instruction in eligible methods with a state-dependent guard; methods where that could alter Unity or CLR behavior are skipped.

## Team sync

Download [OneGaming.bat](https://raw.githubusercontent.com/OneGamingv2/obfuscator/main/OneGaming.bat), put it in an empty folder, and double-click it. The file downloads this repo, replaces missing or changed tracked files with the GitHub copy, then opens a command menu to build and run.

```text
OneGaming.bat
OneGaming.bat sync
OneGaming.bat build
OneGaming.bat rebuild
OneGaming.bat run
```

Git and the .NET 8 SDK have to be installed. Extra files that were never committed stay where they are.

## GUI use

1. Open `OneGamingOBFUSCATION.exe`.
2. Drop one managed DLL or EXE onto the window, or choose **Browse**. The output keeps the same extension.
3. Enter a strong protection key of at least 16 characters and store it securely.
4. Pick a preset (**Safe**, **Maximum**, or **Rename only**) or customize layers.
5. Choose a new output path and select **Protect**.
6. Test the protected file in a private development environment before distribution.

## CLI use

```text
OneGamingOBFUSCATION.exe protect --input Mod.dll --output Mod_Protected.dll --key "your-16+-char-key"
OneGamingOBFUSCATION.exe protect --input Tool.exe --output Tool_Protected.exe --key "your-16+-char-key"
OneGamingOBFUSCATION.exe unlock --input Mod_Protected.dll.oglock --key "your-16+-char-key"
OneGamingOBFUSCATION.exe list-passwords --vault OneGaming.unlock-vault.json --key "your-16+-char-key"
OneGamingOBFUSCATION.exe verify --input Mod_Protected.dll --key "your-16+-char-key"
```

Locked `.oglock` outputs are **optional** (`--lock true`). Default protect writes a normal DLL the game can load; use `unlock` only if you sealed offline.
Without arguments the GUI starts.

## Tests

```text
dotnet test OneGamingOBFUSCATION.sln -c Release
```

The protect-and-execute suite builds `SampleMod`, protects it with all layers, loads the output, and asserts `Harness.GetMessage()` still returns the expected value while Unity/Harmony entry names remain intact.

The tool protects ordinary managed assemblies. It does not modify native DLLs or IL2CPP binaries.

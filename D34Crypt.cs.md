**Structural changes**

- Main is more lean, it only parses args and dispatches. Logic resides in Run, Clean, WriteRegistry, RemoveRegistry, and CreateTestFiles
- [SupportedOSPlatform("windows")] moved to the class level since the entire tool is Windows-only (yeah...)
- Constants AppName and RegKeyPassword replace magic strings that were scattered throughout previous code

**Error handling**

- Typed try/catch blocks (UnauthorizedAccessException, IOException, CryptographicException) used everywhere instead of naked catch {}. Useful [ERR] / [WARN] messages to stderr...cause I hate vague troubleshooting/debugging.
- Main has a top-level catch (Exception) that prints [FATAL] and exits with code 2
- Clean checks if a directory exists before attempting to delete, and reports skipped directories
- Registry helpers are fully wrapped — failures are reported but don't cause tool to crash anymore
- AddAllFiles now warns on inaccessible directories rather than silently moving on

**Cleanup & modernization**

- File.ReadAllBytes replaces the manual FileStream + MemoryStream read pattern in EncryptFile
- Path.Combine replaces string concatenation for file paths
- Random.Shared.Next replaces new Random() in Shuffle (avoids the old seeding collision risk on .NET 6+)
- string.Equals / switch on command replaces String.Compare(...) == 0
- Redundant salt loop in Crypto reduced to a single RandomNumberGenerator.Fill call
- PrintUsage() extracted so usage info is defined once and shown consistently on bad args
- Rijndael updated to AES
- Rfc2898DeriveBytes constructor explicitly calls Rfc2898DeriveBytes.Pbkdf2() - PBKDF2 uses SHA-256 instead of SHA-1

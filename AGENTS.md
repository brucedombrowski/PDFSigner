# AGENTS.md

Instructions for AI agents working with this repository.

## Project Overview

PdfSigner is a Windows tool for digitally signing PDFs using certificates from the Windows Certificate Store, including PIV/CAC smart cards.

## Target Environment

**Windows 11** (designed for airgapped systems with security hardening):
- CIS Windows 11 Enterprise baseline
- DISA STIG Windows 11 baseline
- Microsoft Security Baseline

## File Structure

```
PdfSigner/
├── Program.cs           # Main application code (single file)
├── PdfSigner.csproj     # .NET project file
├── README.md            # User documentation
├── AGENTS.md            # This file
├── CHANGELOG.md         # Version history
├── LICENSE              # MIT License
├── sign.bat             # Drag-and-drop signing script
├── .gitignore           # Git ignore rules
├── .github/workflows/   # CI/CD automation
│   ├── build.yml        # Build and format check
│   └── release.yml      # Release automation
└── examples/
    └── sample.pdf       # Example PDF for testing
```

## Code Architecture

The application is a single-file C# console application with these key components:

### Constants
- `EmailProtectionEku` - OID `1.3.6.1.5.5.7.3.4` for S/MIME signing
- `DocumentSigningEku` - OID `1.3.6.1.4.1.311.10.3.12` for document signing

### Main Entry Point
- `Main()` - Parses arguments, handles `--list`, `--verify`, `--gui` flags, displays version banner
- `GetOutputPath()` - Generates `_signed.pdf` output filename

### Certificate Filtering
- `GetSigningCertificates()` - Main filter function, applies all criteria
- `HasDigitalSignatureUsage()` - Checks Key Usage and EKU extensions
- `IsPersonCertificate()` - Excludes device/machine certificates
- `IsExcludedIssuer()` - Excludes VPN/network security vendor certs
- `IsGovernmentCert()` - Identifies PIV/CAC certificates

### Certificate Selection
- `SelectSigningCertificate()` - Console-based picker with grouping
- `SelectSigningCertificateGui()` - Native Windows certificate dialog
- `PrintNoCertificatesMessage()` - Displays helpful error when no valid certs found

### PDF Signing
- `SignPdf()` - Core signing logic using iText7
- `GetNextSignatureFieldName()` - Generates unique field names for multi-sig
- `X509Certificate2Signature` - Bridges .NET certs to iText signature interface

### Signature Verification
- `VerifySignatures()` - Validates all signatures on a PDF, checks integrity
- Uses `ExtractCommonName()` for consistent signer name display

## Certificate Filtering Logic

Certificates must pass ALL of these filters:

1. **Not expired**: `cert.NotAfter >= DateTime.Now`
2. **Digital Signature key usage**: X509KeyUsageFlags.DigitalSignature
3. **Correct EKU** (one of):
   - `EmailProtectionEku` (`1.3.6.1.5.5.7.3.4`) - S/MIME signing
   - `DocumentSigningEku` (`1.3.6.1.4.1.311.10.3.12`) - Document Signing
4. **Person certificate**: Not device/machine/system cert
5. **Not excluded issuer**: Not from VPN/network security vendors

### Excluded Issuers
```csharp
"Palo Alto", "GlobalProtect", "Cisco", "AnyConnect", "Zscaler",
"Fortinet", "FortiClient", "Pulse Secure", "F5", "Citrix",
"VMware", "Workspace ONE"
```

### Excluded CN Patterns
```csharp
"MS-Organization-Access", "Microsoft Intune", "Windows Hello",
"YOURDEVICE", "TPM", "Device", "Machine", "Computer", "Workstation"
```

## Building

### Prerequisites
- .NET 6.0 SDK or later
- Windows target (uses Windows-specific certificate APIs)

### Build Commands

```bash
# Debug build
dotnet build

# Release build
dotnet build -c Release

# Publish self-contained Windows executable
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

# Output location
# bin/Release/net6.0-windows/win-x64/publish/PdfSigner.exe
```

### Cross-Compile from macOS/Linux

```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

The output is a ~72MB self-contained executable that runs on Windows without .NET runtime installed.

## Dependencies

NuGet packages (defined in PdfSigner.csproj):
- `itext7` (8.0.2) - PDF manipulation and signing
- `itext7.bouncy-castle-adapter` (8.0.2) - Cryptographic operations
- `System.Windows.Extensions` (8.0.0) - Certificate UI dialog

## Testing Changes

After modifying Program.cs:

1. **Build**: `dotnet build`
2. **Test on Windows**: Copy to Windows and test with:
   - PIV/CAC smart card
   - Multi-signature (sign same PDF twice)
3. **Verify output**: Check signed PDF in Adobe Reader

### Test Commands (Windows)

```powershell
# List certificates
.\PdfSigner.exe --list

# Sign with GUI picker
.\PdfSigner.exe document.pdf --gui

# Sign with console picker
.\PdfSigner.exe document.pdf

# Add second signature
.\PdfSigner.exe document_signed.pdf --gui

# Verify signatures
.\PdfSigner.exe --verify document_signed.pdf
```

## Common Tasks

### Adding a new certificate filter

1. Add filter array if needed (like `ExcludedIssuers`)
2. Create filter method (like `IsExcludedIssuer()`)
3. Add check in `GetSigningCertificates()` loop
4. Test with real certificates

### Adding a new command-line option

1. Check for flag in `Main()` args parsing
2. Handle the option appropriately
3. Update usage text in `Main()`
4. Update README.md

### Modifying signature behavior

Key method is `SignPdf()`:
- `StampingProperties.UseAppendMode()` - Preserves existing signatures
- `signer.SetFieldName()` - Must be unique for each signature
- `PdfSigner.CryptoStandard.CMS` - Signature format

## Related Projects

This tool is used by [DecisionDocument](https://github.com/brucedombrowski/LaTeX) for signing LaTeX-generated PDF decision documents.

## Code Style

- Single-file architecture (all code in Program.cs)
- Static methods for utility functions
- XML doc comments for public classes
- Descriptive variable names
- Guard clauses for early returns
- Run `dotnet format` before committing

## CI/CD

- **Build workflow**: Runs on every push/PR to main
  - Restores dependencies
  - Checks code formatting (`dotnet format --verify-no-changes`)
  - Builds release configuration
  - Uploads artifact

- **Release workflow**: Runs when a version tag is pushed (e.g., `v1.0.0`)
  - Builds and publishes self-contained executable
  - Creates ZIP with executable, sign.bat, sample PDF, README, LICENSE
  - Generates SHA256 checksum
  - Creates GitHub Release with auto-generated notes

### Creating a Release

```bash
# Tag the release
git tag v1.0.0
git push origin v1.0.0
# GitHub Actions will automatically create the release
```

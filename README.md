# PdfSigner

A lightweight Windows tool for digitally signing PDFs using certificates from the Windows Certificate Store, including PIV/CAC smart cards.

## Features

- **Smart Card Support**: Works with PIV/CAC badges (DOD, NASA, FPKI, etc.)
- **Multi-Signature Support**: Add multiple signatures to a single PDF
- **Certificate Filtering**:
  - Shows only valid document signing certificates
  - Filters by Email Protection or Document Signing EKU
  - Excludes VPN/network security certs, device certs, and authentication-only certs
- **Two Selection Modes**:
  - Console: Text-based certificate picker with grouping
  - GUI: Native Windows certificate selection dialog (`--gui`)
- **Zero Dependencies**: Self-contained executable (~72MB), no Java or runtime installation required

## Usage

```powershell
# Console mode (default) - text-based certificate selection
.\PdfSigner.exe document.pdf

# GUI mode - native Windows certificate picker (recommended)
.\PdfSigner.exe document.pdf --gui

# Custom output filename
.\PdfSigner.exe input.pdf output_signed.pdf

# List all certificates
.\PdfSigner.exe --list

# Verify signatures on a PDF
.\PdfSigner.exe --verify document_signed.pdf
```

## Output

- Creates `<filename>_signed.pdf` (or custom output name)
- Windows Security prompts for PIN when using smart card certificates
- Adding a signature to an already-signed PDF preserves existing signatures

## Certificate Selection

Certificates are filtered to show only those that:
- Are not expired
- Have Digital Signature key usage
- Have Email Protection (1.3.6.1.5.5.7.3.4) or Document Signing (1.3.6.1.4.1.311.10.3.12) EKU
- Are person certificates (not device/machine certificates)
- Are not from VPN/network security vendors (Palo Alto, Cisco, Zscaler, etc.)

Certificates are grouped by type:
1. **PIV/CAC**: Government smart card certificates (shown first, recommended)
2. **Other**: Software certificates, self-signed test certificates

## Multi-Signature Workflow

PDFs can have multiple signatures for multi-party approval workflows:

```powershell
# First signature
.\PdfSigner.exe document.pdf --gui
# Creates document_signed.pdf with Signature1

# Second signature (different badge/cert)
.\PdfSigner.exe document_signed.pdf --gui
# Updates document_signed.pdf with Signature2

# Verify all signatures
.\PdfSigner.exe --verify document_signed.pdf
```

## Building

Requires .NET 6.0 SDK (or later).

```bash
# Build
dotnet build

# Publish self-contained Windows executable
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

# Output: bin/Release/net6.0-windows/win-x64/publish/PdfSigner.exe
```

### Cross-Compile from macOS/Linux

```bash
cd PdfSigner
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
# Output: bin/Release/net6.0-windows/win-x64/publish/PdfSigner.exe
```

## Dependencies

NuGet packages (automatically restored):
- `itext7` (8.0.2) - PDF manipulation and signing
- `itext7.bouncy-castle-adapter` (8.0.2) - Cryptographic operations
- `System.Windows.Extensions` (8.0.0) - Certificate UI dialog

## Target Environment

Designed for **airgapped Windows 11** systems with security hardening:
- CIS Windows 11 Enterprise baseline
- DISA STIG Windows 11 baseline
- Microsoft Security Baseline

## Related

Used by [DecisionDocument](https://github.com/brucedombrowski/LaTeX) for signing LaTeX-generated PDF decision documents.

## License

MIT License - see [LICENSE](LICENSE) file.

# PdfSigner

Sign PDF documents with your smart card (PIV/CAC badge) or software certificate on Windows.

## Quick Start

**Easiest way to sign a PDF:**

1. Download `PdfSigner.exe` and `sign.bat` to the same folder
2. Drag your PDF onto `sign.bat`
3. Select your certificate from the popup
4. Enter your PIN when prompted (for smart cards)
5. Done! Your signed PDF is saved as `filename_signed.pdf`

## Requirements

- Windows 10 or 11
- Your smart card reader and badge (PIV/CAC), OR a software certificate installed

## Usage Options

### Drag and Drop (Easiest)
Drag a PDF file onto `sign.bat` - a Windows dialog will open to select your certificate.

### Command Line

```powershell
# Sign with GUI certificate picker (recommended)
.\PdfSigner.exe document.pdf --gui

# Sign with console-based picker
.\PdfSigner.exe document.pdf

# Specify output filename
.\PdfSigner.exe input.pdf output_signed.pdf

# Verify signatures on a PDF
.\PdfSigner.exe --verify document_signed.pdf

# List available certificates
.\PdfSigner.exe --list
```

## Multi-Signature Workflow

Need multiple people to sign the same document? Each person signs in turn:

```powershell
# Person 1 signs
.\PdfSigner.exe document.pdf --gui
# Creates document_signed.pdf

# Person 2 signs the already-signed PDF
.\PdfSigner.exe document_signed.pdf --gui
# Adds second signature, keeps first signature intact

# Verify all signatures
.\PdfSigner.exe --verify document_signed.pdf
```

## Certificate Selection

The tool automatically filters to show only certificates suitable for document signing:
- Valid (not expired)
- PIV/CAC smart card certificates are shown first
- VPN and device certificates are hidden

## Output

- Creates `<filename>_signed.pdf` in the same folder (or your specified name)
- Windows will prompt for your smart card PIN when signing
- Open in Adobe Reader to see signature details

---

## For Developers

### Building from Source

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
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

### Dependencies

NuGet packages (automatically restored):
- `itext7` (8.0.2) - PDF manipulation and signing
- `itext7.bouncy-castle-adapter` (8.0.2) - Cryptographic operations
- `System.Windows.Extensions` (8.0.0) - Certificate UI dialog

### Target Environment

Designed for **airgapped Windows 11** systems with security hardening:
- CIS Windows 11 Enterprise baseline
- DISA STIG Windows 11 baseline
- Microsoft Security Baseline

### Related Projects

Used by [DecisionDocument](https://github.com/brucedombrowski/LaTeX) for signing LaTeX-generated PDF decision documents.

## License

MIT License - see [LICENSE](LICENSE) file.

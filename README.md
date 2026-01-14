# PdfSigner

## Software Version Description (SVD)

**Document Identifier:** PdfSigner-SVD
**Version:** 1.0.5
**Date:** 2026-01-14
**Classification:** UNCLASSIFIED

---

## 1. Scope

### 1.1 Identification

This Software Version Description (SVD) identifies and describes version 1.0.5 of PdfSigner, a Windows application for digitally signing PDF documents using certificates from the Windows Certificate Store.

### 1.2 System Overview

PdfSigner enables users to apply digital signatures to PDF documents using PIV/CAC smart cards. The tool supports multi-signature workflows where multiple individuals sign a single document sequentially.

### 1.3 Document Overview

This document provides version identification, installation procedures, operational instructions, and change history for PdfSigner.

---

## 2. Referenced Documents

This document follows the Software Version Description (SVD) format specified in MIL-STD-498.

- [CHANGELOG.md](CHANGELOG.md) - Detailed version history
- [AGENTS.md](AGENTS.md) - Developer documentation
- [LICENSE](LICENSE) - MIT License terms
- [EXPORT.md](EXPORT.md) - Export compliance (ECCN 5D002, License Exception TSU)
- [MIL-STD-498](http://everyspec.com/MIL-STD/MIL-STD-0300-0499/MIL-STD-498_25500/) - Software Development and Documentation

---

## 3. Version Description

### 3.1 Inventory of Materials Released

| Item | Filename | Description |
|------|----------|-------------|
| Executable | `PdfSigner.exe` | Self-contained Windows x64 application (~72MB) |
| Batch Script | `sign.bat` | Drag-and-drop signing helper |
| Sample Document | `sample.pdf` | Example PDF for testing |
| Documentation | `README.md` | This document |
| License | `LICENSE` | MIT License |

### 3.2 Inventory of Software Contents

| Component | Version | Purpose |
|-----------|---------|---------|
| .NET Runtime | 6.0 | Application framework (bundled) |
| iText7 | 8.0.2 | PDF manipulation and signing |
| BouncyCastle | 8.0.2 | Cryptographic operations |
| System.Windows.Extensions | 8.0.0 | Certificate UI dialog |

### 3.3 Changes Installed

**Version 1.0.5** (Current Release):
- Replace sample PDF with Decision Memorandum from DecisionDocument project

See [CHANGELOG.md](CHANGELOG.md) for complete version history.

### 3.4 Adaptation Data

No site-specific adaptation required. The application uses the Windows Certificate Store directly.

### 3.5 Interface Compatibility

- **Input:** PDF documents (PDF 1.4 or later)
- **Output:** Signed PDF documents with CMS digital signatures
- **Certificates:** Windows Certificate Store (CurrentUser\My)
- **Smart Cards:** PIV/CAC compatible (DOD, NASA, FPKI, etc.)

### 3.6 Installation Instructions

1. Download the release ZIP from GitHub Releases
2. Extract all files to a folder (e.g., `C:\Tools\PdfSigner\`)
3. No installation required - the executable is self-contained

### 3.7 Possible Problems and Known Errors

| Issue | Workaround |
|-------|------------|
| "No valid signing certificates found" | Ensure smart card is inserted and certificate is not expired |
| PIN prompt does not appear | Check Windows smart card service is running |
| Signature not visible in Adobe | Enable "Validate all signatures" in Adobe preferences |

---

## 4. Operating Procedures

### 4.1 Quick Start (Drag and Drop)

1. Place `PdfSigner.exe` and `sign.bat` in the same folder
2. Drag a PDF file onto `sign.bat`
3. Select your certificate from the Windows dialog
4. Enter your PIN when prompted (smart cards)
5. Signed PDF saved as `<filename>_signed.pdf`

### 4.2 Command Line Usage

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

### 4.3 Multi-Signature Workflow

```powershell
# Person 1 signs the document
.\PdfSigner.exe document.pdf --gui
# Creates document_signed.pdf

# Person 2 signs the already-signed PDF
.\PdfSigner.exe document_signed.pdf --gui
# Adds second signature, preserves first signature

# Verify all signatures
.\PdfSigner.exe --verify document_signed.pdf
```

### 4.4 Certificate Selection

The tool automatically filters certificates to show only those suitable for document signing:
- Not expired
- Email Protection or Document Signing EKU
- PIV/CAC certificates shown first
- VPN and device certificates excluded

---

## 5. Target Environment

### 5.1 Hardware Requirements

- x64 processor
- Smart card reader (for PIV/CAC)
- 100MB available disk space

### 5.2 Software Requirements

- Windows 10 or Windows 11
- No .NET runtime installation required (self-contained)

### 5.3 Security Environment

Designed for airgapped Windows 11 systems with security hardening:
- CIS Windows 11 Enterprise baseline
- DISA STIG Windows 11 baseline
- Microsoft Security Baseline

---

## 6. Notes

### 6.1 Related Projects

Used by [DecisionDocument](https://github.com/brucedombrowski/LaTeX) for signing LaTeX-generated PDF decision documents.

### 6.2 Support

Report issues at: https://github.com/brucedombrowski/PdfSigner/issues

### 6.3 License

MIT License - see [LICENSE](LICENSE) file.

---

## Appendix A. Building from Source

### A.1 Prerequisites

- .NET 6.0 SDK or later
- Windows, macOS, or Linux build environment

### A.2 Build Commands

```bash
# Debug build
dotnet build

# Release build
dotnet build -c Release

# Publish self-contained Windows executable
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

# Output: bin/Release/net6.0-windows/win-x64/publish/PdfSigner.exe
```

### A.3 Cross-Compilation

Build from macOS/Linux for Windows:

```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

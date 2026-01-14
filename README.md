# PdfSigner

A lightweight Windows tool for digitally signing PDFs using certificates from the Windows Certificate Store, including PIV/CAC smart cards.

## Features

- **Smart Card Support**: Works with PIV/CAC badges (DOD, NASA, FPKI, etc.)
- **Certificate Filtering**: Shows only valid signing certificates (not expired, has Digital Signature key usage)
- **Two Selection Modes**:
  - Console: Text-based certificate picker with grouping
  - GUI: Native Windows certificate selection dialog
- **Zero Dependencies**: Self-contained executable, no Java or runtime installation required

## Usage

```powershell
# Console mode (default) - text-based certificate selection
.\PdfSigner.exe document.pdf

# GUI mode - native Windows certificate picker
.\PdfSigner.exe document.pdf --gui

# Custom output filename
.\PdfSigner.exe input.pdf output_signed.pdf

# List all certificates
.\PdfSigner.exe --list
```

## Output

- Creates `<filename>_signed.pdf` (or custom output name)
- Windows Security prompts for PIN when using smart card certificates

## Certificate Selection

Certificates are filtered to show only those that are:
- Not expired
- Have Digital Signature key usage

Certificates are grouped by type:
1. **PIV/CAC**: Government smart card certificates (shown first)
2. **Other**: Software certificates, self-signed test certificates

## Building

Requires .NET 6.0 SDK.

```bash
# From the PdfSigner directory
dotnet publish -c Release -r win-x64 --self-contained true

# Output: bin/Release/net6.0-windows/win-x64/publish/PdfSigner.exe
```

### Cross-Compile from macOS/Linux

```bash
cd PdfSigner
dotnet publish -c Release -r win-x64 --self-contained true
cp bin/Release/net6.0-windows/win-x64/publish/PdfSigner.exe ../bin/
```

## Dependencies

NuGet packages (automatically restored):
- `itext7` (8.0.2) - PDF manipulation and signing
- `itext7.bouncy-castle-adapter` (8.0.2) - Cryptographic operations
- `System.Windows.Extensions` (8.0.0) - Certificate UI dialog

## License

Part of the DecisionDocument project.

# Maintainer Guide

Quick reference for maintaining and releasing PdfSigner.

## Daily Use (Signing PDFs)

### Easiest Method
1. Drag a PDF onto `sign.bat`
2. Pick your certificate from the popup
3. Enter PIN if using smart card
4. Signed file appears as `filename_signed.pdf`

### Command Line
```powershell
# Sign with GUI picker
.\PdfSigner.exe document.pdf --gui

# Verify signatures
.\PdfSigner.exe --verify document_signed.pdf

# List your certificates
.\PdfSigner.exe --list
```

## Making Changes

### Local Development
```bash
# Build after making changes
dotnet build

# Check code formatting
dotnet format

# Test locally (on Windows)
.\bin\Debug\net6.0-windows\win-x64\PdfSigner.exe --list
```

### Commit Changes
```bash
git add -A
git commit -m "Description of changes"
git push
```

GitHub Actions will automatically:
- Build the project
- Check code formatting
- Upload build artifacts

## Creating a Release

### 1. Update Version Numbers
Edit `PdfSigner.csproj`:
```xml
<Version>1.1.0</Version>
<FileVersion>1.1.0</FileVersion>
<AssemblyVersion>1.1.0</AssemblyVersion>
```

### 2. Update CHANGELOG.md
Add a new section at the top:
```markdown
## [1.1.0] - 2026-XX-XX

### Added
- New feature description

### Fixed
- Bug fix description
```

### 3. Commit and Tag
```bash
git add -A
git commit -m "Release v1.1.0"
git push

# Create and push the tag
git tag v1.1.0
git push origin v1.1.0
```

### 4. GitHub Does the Rest
The release workflow automatically:
- Builds the Windows executable
- Creates a ZIP with all files
- Generates SHA256 checksum
- Publishes to GitHub Releases

### 5. Download Your Release
Go to: `https://github.com/YOUR_USERNAME/PdfSigner/releases`

## Troubleshooting

### Build Fails on GitHub
- Check the Actions tab for error details
- Usually a formatting issue: run `dotnet format` locally and push

### Smart Card Not Detected
- Ensure card reader is connected
- Check Windows Device Manager for the reader
- Try `.\PdfSigner.exe --list` to see available certs

### Certificate Not Showing
The tool filters certificates. Your cert must have:
- Digital Signature key usage
- Email Protection or Document Signing EKU
- Not be expired

Run `.\PdfSigner.exe --list` to see all certs with their status.

## File Quick Reference

| File | Purpose |
|------|---------|
| `Program.cs` | All application code |
| `PdfSigner.csproj` | Build config and version |
| `README.md` | User documentation |
| `CHANGELOG.md` | Version history |
| `sign.bat` | Drag-and-drop helper |
| `.github/workflows/` | CI/CD automation |

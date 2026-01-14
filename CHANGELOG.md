# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-01-14

### Fixed
- sign.bat now has Windows line endings (CRLF) so drag-and-drop works

## [1.0.1] - 2026-01-14

### Fixed
- Sample PDF now works with iText append mode (rebuilt with LaTeX)

## [1.0.0] - 2026-01-14

### Added
- PDF digital signing using Windows Certificate Store
- PIV/CAC smart card support (DOD, NASA, FPKI, etc.)
- Multi-signature support - add multiple signatures to a single PDF
- Two certificate selection modes:
  - Console: Text-based picker with certificate grouping
  - GUI: Native Windows certificate selection dialog (`--gui`)
- Signature verification with `--verify` command
- Certificate listing with `--list` command
- Intelligent certificate filtering:
  - Filters by Email Protection or Document Signing EKU
  - Excludes expired certificates
  - Excludes VPN/network security vendor certs (Palo Alto, Cisco, Zscaler, etc.)
  - Excludes device/machine certificates
- Self-contained Windows executable (~72MB, no .NET runtime required)
- Cross-platform build support (build on macOS/Linux for Windows)
- Drag-and-drop signing via `sign.bat`
- Example PDF for testing

### Technical Details
- Built with .NET 6.0 targeting Windows x64
- Uses iText7 for PDF manipulation and signing
- Uses BouncyCastle for cryptographic operations
- Uses Windows CNG for smart card PIN prompts

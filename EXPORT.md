# Export Compliance Notice

## Classification

This software is classified under Export Control Classification Number (ECCN) **5D002** - Information Security Software.

## License Exception

PdfSigner is exported under **License Exception TSU** (Technology and Software Unrestricted) per [15 CFR § 740.13(e)](https://www.law.cornell.edu/cfr/text/15/740.13) of the Export Administration Regulations (EAR).

This exception applies because:

1. **Publicly Available**: The source code is publicly available on GitHub
2. **Open Source**: Released under MIT License with no payment required for commercial use
3. **No Custom Cryptography**: Uses standard cryptographic libraries (BouncyCastle, .NET)

## Cryptographic Functionality

PdfSigner performs **digital signing** operations only. It does not perform encryption for data confidentiality.

Cryptographic operations used:
- SHA-256 hashing for signature digests
- RSA/ECDSA signature generation (via Windows Certificate Store)
- CMS (Cryptographic Message Syntax) signature embedding

## BIS Notification

Per 15 CFR § 740.13(e)(3), notification of publicly available encryption source code has been submitted to:

- Bureau of Industry and Security (BIS): crypt@bis.doc.gov
- ENC Encryption Request Coordinator: enc@nsa.gov

Source code location: https://github.com/brucedombrowski/PdfSigner

Notification submitted: 2026-01-14

## Restrictions

This software may not be exported or re-exported to:

- Countries under U.S. embargo (currently: Cuba, Iran, North Korea, Syria, and the Crimea, Donetsk, and Luhansk regions of Ukraine)
- Denied persons or entities on the BIS Entity List
- End-users involved in weapons of mass destruction proliferation

## Disclaimer

This export compliance notice is provided for informational purposes. Users are responsible for ensuring their use complies with applicable export control laws.

## References

- [EAR Part 740 - License Exceptions](https://www.bis.gov/ear/title-15/subtitle-b/chapter-vii/subchapter-c/part-740)
- [15 CFR § 740.13 - TSU](https://www.law.cornell.edu/cfr/text/15/740.13)
- [BIS Encryption Policy Guidance](https://www.bis.doc.gov/index.php/policy-guidance/encryption)

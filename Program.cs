using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using iText.Kernel.Pdf;
using iText.Signatures;
using iText.Bouncycastle.X509;
using Org.BouncyCastle.X509;

namespace PdfSignerApp
{
    class Program
    {
        static int Main(string[] args)
        {
            Console.WriteLine("==========================================");
            Console.WriteLine("PDF Digital Signature Tool");
            Console.WriteLine("Uses Windows Certificate Store (PIV/CAC)");
            Console.WriteLine("==========================================");
            Console.WriteLine();

            if (args.Length == 0)
            {
                Console.WriteLine("Usage: PdfSigner.exe <input.pdf> [output.pdf] [options]");
                Console.WriteLine();
                Console.WriteLine("Options:");
                Console.WriteLine("  --list     List available signing certificates");
                Console.WriteLine("  --verify   Verify signatures on a PDF");
                Console.WriteLine("  --gui      Use graphical certificate picker dialog");
                Console.WriteLine("  --console  Use console certificate picker (default)");
                Console.WriteLine();
                return 1;
            }

            if (args[0] == "--list")
            {
                ListCertificates();
                return 0;
            }

            if (args[0] == "--verify")
            {
                if (args.Length < 2)
                {
                    Console.WriteLine("Usage: PdfSigner.exe --verify <document.pdf>");
                    return 1;
                }
                return VerifySignatures(args[1]);
            }

            // Parse arguments
            bool useGui = args.Contains("--gui");
            var fileArgs = args.Where(a => !a.StartsWith("--")).ToArray();

            string inputPdf = fileArgs[0];
            string outputPdf = fileArgs.Length > 1 ? fileArgs[1] : GetOutputPath(inputPdf);

            if (!File.Exists(inputPdf))
            {
                Console.WriteLine($"Error: Input file not found: {inputPdf}");
                return 1;
            }

            try
            {
                // Get signing certificate from Windows store (includes smart cards)
                X509Certificate2? cert = useGui ? SelectSigningCertificateGui() : SelectSigningCertificate();
                if (cert == null)
                {
                    Console.WriteLine("No certificate selected. Exiting.");
                    return 1;
                }

                Console.WriteLine();
                Console.WriteLine($"Selected: {cert.Subject}");
                Console.WriteLine();

                // Sign the PDF - Windows will prompt for PIN if smart card
                SignPdf(inputPdf, outputPdf, cert);

                Console.WriteLine();
                Console.WriteLine($"SUCCESS: Signed PDF saved to: {outputPdf}");
                return 0;
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine();
                Console.WriteLine($"Cryptographic error: {ex.Message}");
                Console.WriteLine("This may occur if PIN entry was cancelled or the smart card was removed.");
                return 1;
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine($"Error: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"Inner: {ex.InnerException.Message}");
                }
                return 1;
            }
        }

        static string GetOutputPath(string inputPath)
        {
            string dir = Path.GetDirectoryName(inputPath) ?? ".";
            string name = Path.GetFileNameWithoutExtension(inputPath);
            string ext = Path.GetExtension(inputPath);
            return Path.Combine(dir, $"{name}_signed{ext}");
        }

        // Known PIV/CAC/Government certificate issuers
        static readonly string[] GovernmentIssuers = new[]
        {
            "DOD", "Department of Defense", "NASA", "FPKI", "Federal PKI",
            "Entrust", "DigiCert Federal", "WidePoint", "Carillon",
            "Treasury", "HHS", "GSA", "USDA", "DOE", "DOJ", "DHS"
        };

        // Certificate CN patterns to exclude (device/system certs, not person certs)
        static readonly string[] ExcludedCnPatterns = new[]
        {
            "MS-Organization-Access",
            "Microsoft Intune",
            "Windows Hello",
            "YOURDEVICE",  // Common placeholder in device certs
            "TPM",
            "Device",
            "Machine",
            "Computer",
            "Workstation"
        };

        // Issuers to exclude (VPN, network security, etc. - not for document signing)
        static readonly string[] ExcludedIssuers = new[]
        {
            "Palo Alto",
            "GlobalProtect",
            "Cisco",
            "AnyConnect",
            "Zscaler",
            "Fortinet",
            "FortiClient",
            "Pulse Secure",
            "F5",
            "Citrix",
            "VMware",
            "Workspace ONE"
        };

        static List<X509Certificate2> GetSigningCertificates(bool filterForSigning = true)
        {
            var result = new List<X509Certificate2>();

            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            // We don't check HasPrivateKey here because that can trigger
            // smart card access and cause hangs
            foreach (var cert in store.Certificates)
            {
                if (!filterForSigning)
                {
                    result.Add(cert);
                    continue;
                }

                // Filter: Must not be expired
                if (cert.NotAfter < DateTime.Now)
                    continue;

                // Filter: Must have Digital Signature key usage
                if (!HasDigitalSignatureUsage(cert))
                    continue;

                // Filter: Must be a person certificate (not device/system)
                if (!IsPersonCertificate(cert))
                    continue;

                // Filter: Exclude VPN/network security certs
                if (IsExcludedIssuer(cert))
                    continue;

                result.Add(cert);
            }

            return result;
        }

        static bool HasDigitalSignatureUsage(X509Certificate2 cert)
        {
            // Must have Digital Signature in Key Usage extension
            bool hasDigitalSignatureKeyUsage = false;
            foreach (var ext in cert.Extensions)
            {
                if (ext is X509KeyUsageExtension keyUsage)
                {
                    if ((keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) != 0)
                    {
                        hasDigitalSignatureKeyUsage = true;
                        break;
                    }
                }
            }

            // If no Key Usage extension at all, be lenient for older certs
            if (!cert.Extensions.OfType<X509KeyUsageExtension>().Any())
            {
                hasDigitalSignatureKeyUsage = true;
            }

            if (!hasDigitalSignatureKeyUsage)
                return false;

            // Now check Enhanced Key Usage - must have Email Protection or Document Signing
            // Exclude Smart Card Logon and Client Authentication (those are for login, not signing)
            foreach (var ext in cert.Extensions)
            {
                if (ext is X509EnhancedKeyUsageExtension eku)
                {
                    foreach (var oid in eku.EnhancedKeyUsages)
                    {
                        // Only accept document signing related EKUs
                        if (oid.Value == "1.3.6.1.5.5.7.3.4" ||       // Email Protection (S/MIME signing)
                            oid.Value == "1.3.6.1.4.1.311.10.3.12")   // Document Signing
                        {
                            return true;
                        }
                    }
                    // Has EKU extension but none match signing - reject
                    return false;
                }
            }

            // No EKU extension = allow (older certs, self-signed test certs)
            return true;
        }

        static bool IsPersonCertificate(X509Certificate2 cert)
        {
            string cn = ExtractCommonName(cert.Subject);
            string cnUpper = cn.ToUpperInvariant();

            // Exclude known device/system certificate patterns
            foreach (var pattern in ExcludedCnPatterns)
            {
                if (cnUpper.Contains(pattern.ToUpperInvariant()))
                    return false;
            }

            // Check if CN looks like a person's name
            // Person names typically have spaces (First Last) or commas (Last, First)
            // and don't contain @ (email), \ (domain), or start with numbers/GUIDs

            // Exclude email addresses as CN
            if (cn.Contains("@"))
                return false;

            // Exclude domain\user format
            if (cn.Contains("\\"))
                return false;

            // Exclude GUIDs and hex strings (common in device certs)
            if (System.Text.RegularExpressions.Regex.IsMatch(cn, @"^[0-9a-fA-F-]{20,}$"))
                return false;

            // Person names usually have at least one space or comma
            // But PIV certs might have formats like "LASTNAME.FIRSTNAME.MIDDLE.1234567890"
            bool hasSpace = cn.Contains(" ");
            bool hasComma = cn.Contains(",");
            bool hasDotSeparatedName = System.Text.RegularExpressions.Regex.IsMatch(cn, @"^[A-Z]+\.[A-Z]+",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            // Accept if it looks like a name
            if (hasSpace || hasComma || hasDotSeparatedName)
                return true;

            // For government/PIV certs, be more lenient - they know what they're doing
            if (IsGovernmentCert(cert))
                return true;

            // Self-signed test certs - allow through
            if (cert.Subject == cert.Issuer)
                return true;

            // Default: reject if it doesn't look like a person name
            return false;
        }

        static bool IsGovernmentCert(X509Certificate2 cert)
        {
            string issuer = cert.Issuer.ToUpperInvariant();
            string subject = cert.Subject.ToUpperInvariant();

            foreach (var keyword in GovernmentIssuers)
            {
                if (issuer.Contains(keyword.ToUpperInvariant()) ||
                    subject.Contains(keyword.ToUpperInvariant()))
                    return true;
            }
            return false;
        }

        static bool IsExcludedIssuer(X509Certificate2 cert)
        {
            string issuer = cert.Issuer.ToUpperInvariant();

            foreach (var keyword in ExcludedIssuers)
            {
                if (issuer.Contains(keyword.ToUpperInvariant()))
                    return true;
            }
            return false;
        }

        static string GetCertCategory(X509Certificate2 cert)
        {
            if (IsGovernmentCert(cert))
                return "PIV/CAC";

            // Check for self-signed (test certs)
            if (cert.Subject == cert.Issuer)
                return "Self-signed";

            return "Other";
        }

        static string ExtractCommonName(string distinguishedName)
        {
            if (distinguishedName.StartsWith("CN="))
            {
                int comma = distinguishedName.IndexOf(',');
                if (comma > 0)
                    return distinguishedName.Substring(3, comma - 3);
                else
                    return distinguishedName.Substring(3);
            }
            return distinguishedName;
        }

        static void ListCertificates()
        {
            Console.WriteLine("All certificates in Windows Certificate Store:");
            Console.WriteLine();

            var certs = GetSigningCertificates(filterForSigning: false);

            if (certs.Count == 0)
            {
                Console.WriteLine("No certificates found.");
                return;
            }

            // Group by category
            var grouped = certs.GroupBy(c => GetCertCategory(c)).OrderBy(g => g.Key == "PIV/CAC" ? 0 : g.Key == "Other" ? 1 : 2);

            foreach (var group in grouped)
            {
                Console.WriteLine($"=== {group.Key} ===");
                foreach (var cert in group)
                {
                    string status = cert.NotAfter < DateTime.Now ? "[EXPIRED]" :
                                    HasDigitalSignatureUsage(cert) ? "[OK]" : "[No Sign]";
                    Console.WriteLine($"  {status} {ExtractCommonName(cert.Subject)}");
                    Console.WriteLine($"         Issuer: {ExtractCommonName(cert.Issuer)}");
                    Console.WriteLine($"         Expires: {cert.NotAfter:yyyy-MM-dd}");
                }
                Console.WriteLine();
            }
        }

        static X509Certificate2? SelectSigningCertificate()
        {
            // Get filtered certs (valid, with signing capability)
            var certs = GetSigningCertificates(filterForSigning: true);

            if (certs.Count == 0)
            {
                Console.WriteLine("No valid signing certificates found.");
                Console.WriteLine();
                Console.WriteLine("Certificates must be:");
                Console.WriteLine("  - Not expired");
                Console.WriteLine("  - Have Digital Signature key usage");
                Console.WriteLine();
                Console.WriteLine("Ensure your smart card is inserted and recognized by Windows.");
                Console.WriteLine("Run with --list to see all certificates.");
                return null;
            }

            // Sort: PIV/CAC first, then by expiration date (newest last = more time to use)
            var sortedCerts = certs
                .OrderByDescending(c => IsGovernmentCert(c))  // PIV/CAC first
                .ThenBy(c => c.NotAfter)  // Expiring soonest first
                .ToList();

            if (sortedCerts.Count == 1)
            {
                var cert = sortedCerts[0];
                string category = GetCertCategory(cert);
                Console.WriteLine($"Using certificate: {ExtractCommonName(cert.Subject)} [{category}]");
                return cert;
            }

            // Multiple certs - display nicely grouped
            Console.WriteLine("Select a certificate for signing:");
            Console.WriteLine();

            // Group by category for display
            var pivCerts = sortedCerts.Where(c => IsGovernmentCert(c)).ToList();
            var otherCerts = sortedCerts.Where(c => !IsGovernmentCert(c)).ToList();

            int index = 0;

            if (pivCerts.Any())
            {
                Console.WriteLine("  --- PIV/CAC (Smart Card) ---");
                foreach (var cert in pivCerts)
                {
                    index++;
                    string name = ExtractCommonName(cert.Subject);
                    string issuer = ExtractCommonName(cert.Issuer);
                    int daysLeft = (int)(cert.NotAfter - DateTime.Now).TotalDays;
                    Console.WriteLine($"  [{index}] {name}");
                    Console.WriteLine($"      Issuer: {issuer}");
                    Console.WriteLine($"      Expires: {cert.NotAfter:yyyy-MM-dd} ({daysLeft} days)");
                    Console.WriteLine();
                }
            }

            if (otherCerts.Any())
            {
                Console.WriteLine("  --- Other Certificates ---");
                foreach (var cert in otherCerts)
                {
                    index++;
                    string name = ExtractCommonName(cert.Subject);
                    string issuer = ExtractCommonName(cert.Issuer);
                    string selfSigned = cert.Subject == cert.Issuer ? " (self-signed)" : "";
                    int daysLeft = (int)(cert.NotAfter - DateTime.Now).TotalDays;
                    Console.WriteLine($"  [{index}] {name}{selfSigned}");
                    Console.WriteLine($"      Issuer: {issuer}");
                    Console.WriteLine($"      Expires: {cert.NotAfter:yyyy-MM-dd} ({daysLeft} days)");
                    Console.WriteLine();
                }
            }

            // Recommend PIV/CAC if available
            if (pivCerts.Any())
            {
                Console.WriteLine("  TIP: PIV/CAC certificates are recommended for official documents.");
                Console.WriteLine();
            }

            Console.Write($"Select certificate [1-{sortedCerts.Count}]: ");

            string? input = Console.ReadLine();
            if (int.TryParse(input, out int choice) && choice >= 1 && choice <= sortedCerts.Count)
            {
                return sortedCerts[choice - 1];
            }

            Console.WriteLine("Invalid selection.");
            return null;
        }

        static X509Certificate2? SelectSigningCertificateGui()
        {
            // Get filtered certs (valid, with signing capability)
            var certs = GetSigningCertificates(filterForSigning: true);

            if (certs.Count == 0)
            {
                Console.WriteLine("No valid signing certificates found.");
                Console.WriteLine();
                Console.WriteLine("Certificates must be:");
                Console.WriteLine("  - Not expired");
                Console.WriteLine("  - Have Digital Signature key usage");
                Console.WriteLine();
                Console.WriteLine("Ensure your smart card is inserted and recognized by Windows.");
                return null;
            }

            // Convert to X509Certificate2Collection for the UI
            var collection = new X509Certificate2Collection();
            foreach (var cert in certs)
            {
                collection.Add(cert);
            }

            Console.WriteLine("Opening certificate selection dialog...");
            Console.WriteLine();

            // Use the native Windows certificate picker dialog
            // This is part of System.Security.Cryptography.X509Certificates - no WinForms needed
            var selected = X509Certificate2UI.SelectFromCollection(
                collection,
                "Select Signing Certificate",
                "Choose a certificate to sign the PDF document.\nPIV/CAC certificates are recommended for official documents.",
                X509SelectionFlag.SingleSelection);

            if (selected.Count == 0)
            {
                return null;
            }

            return selected[0];
        }

        static int VerifySignatures(string pdfPath)
        {
            if (!File.Exists(pdfPath))
            {
                Console.WriteLine($"Error: File not found: {pdfPath}");
                return 1;
            }

            try
            {
                using var reader = new PdfReader(pdfPath);
                using var doc = new PdfDocument(reader);
                var signatureUtil = new SignatureUtil(doc);
                var signatureNames = signatureUtil.GetSignatureNames();

                if (signatureNames.Count == 0)
                {
                    Console.WriteLine("No signatures found in this document.");
                    return 0;
                }

                Console.WriteLine($"Found {signatureNames.Count} signature(s):");
                Console.WriteLine();

                bool allValid = true;
                int index = 0;

                foreach (var name in signatureNames)
                {
                    index++;
                    Console.WriteLine($"=== Signature {index}: {name} ===");

                    var pkcs7 = signatureUtil.ReadSignatureData(name);
                    if (pkcs7 == null)
                    {
                        Console.WriteLine("  Status: INVALID (could not read signature data)");
                        allValid = false;
                        Console.WriteLine();
                        continue;
                    }

                    // Get signer certificate info
                    var signerCert = pkcs7.GetSigningCertificate();
                    if (signerCert != null)
                    {
                        // Access certificate through iText's wrapper
                        string subject = signerCert.GetSubjectDN()?.ToString() ?? "Unknown";
                        string issuer = signerCert.GetIssuerDN()?.ToString() ?? "Unknown";

                        // Extract CN from subject
                        string cn = subject;
                        if (subject.Contains("CN="))
                        {
                            int start = subject.IndexOf("CN=") + 3;
                            int end = subject.IndexOf(',', start);
                            cn = end > 0 ? subject.Substring(start, end - start) : subject.Substring(start);
                        }

                        Console.WriteLine($"  Signer: {cn}");
                        Console.WriteLine($"  Issuer: {issuer}");
                    }

                    // Get signing time
                    var signDate = pkcs7.GetSignDate();
                    if (signDate != DateTime.MinValue)
                    {
                        Console.WriteLine($"  Signed: {signDate:yyyy-MM-dd HH:mm:ss}");
                    }

                    // Verify integrity (document not modified since signing)
                    bool integrityValid = pkcs7.VerifySignatureIntegrityAndAuthenticity();

                    // Check if signature covers whole document
                    bool coversWholeDoc = signatureUtil.SignatureCoversWholeDocument(name);

                    if (integrityValid && coversWholeDoc)
                    {
                        Console.WriteLine("  Status: VALID");
                        Console.WriteLine("  Integrity: Document has not been modified since signing");
                    }
                    else if (integrityValid && !coversWholeDoc)
                    {
                        Console.WriteLine("  Status: VALID (partial)");
                        Console.WriteLine("  Note: Document was modified after this signature (additional signatures added)");
                    }
                    else
                    {
                        Console.WriteLine("  Status: INVALID");
                        Console.WriteLine("  Warning: Signature integrity check failed");
                        allValid = false;
                    }

                    Console.WriteLine();
                }

                // Summary
                if (allValid)
                {
                    Console.WriteLine("All signatures are valid.");
                    return 0;
                }
                else
                {
                    Console.WriteLine("WARNING: One or more signatures failed validation.");
                    return 1;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error verifying signatures: {ex.Message}");
                return 1;
            }
        }

        static void SignPdf(string inputPath, string outputPath, X509Certificate2 cert)
        {
            Console.WriteLine("Signing PDF...");
            Console.WriteLine("(Windows Security will prompt for your PIN if using a smart card)");

            // Convert .NET cert to iText-wrapped BouncyCastle cert
            var bcCert = new X509CertificateParser().ReadCertificate(cert.RawData);
            var wrappedCert = new X509CertificateBC(bcCert);
            var chain = new iText.Commons.Bouncycastle.Cert.IX509Certificate[] { wrappedCert };

            // Create external signature using Windows CNG (triggers PIN dialog)
            var externalSignature = new X509Certificate2Signature(cert, "SHA256");

            using var reader = new PdfReader(inputPath);
            using var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write);

            // Use append mode for already-signed PDFs to preserve existing signatures
            var stampingProperties = new StampingProperties();
            stampingProperties.UseAppendMode();

            var signer = new iText.Signatures.PdfSigner(reader, outputStream, stampingProperties);

            // Generate unique signature field name
            // Check existing signatures and increment the number
            string fieldName = GetNextSignatureFieldName(inputPath);
            signer.SetFieldName(fieldName);

            Console.WriteLine($"Adding signature field: {fieldName}");

            // Perform the signature - this triggers the PIN dialog for smart cards
            signer.SignDetached(externalSignature, chain, null, null, null, 0,
                iText.Signatures.PdfSigner.CryptoStandard.CMS);
        }

        static string GetNextSignatureFieldName(string inputPath)
        {
            // Check for existing signature fields by opening a separate reader
            using var tempReader = new PdfReader(inputPath);
            using var tempDoc = new PdfDocument(tempReader);
            var signatureUtil = new SignatureUtil(tempDoc);
            var existingSignatures = signatureUtil.GetSignatureNames();

            // Find the next available signature number
            int nextNumber = 1;
            while (existingSignatures.Contains($"Signature{nextNumber}"))
            {
                nextNumber++;
            }

            return $"Signature{nextNumber}";
        }
    }

    /// <summary>
    /// External signature implementation using Windows Certificate Store.
    /// This bridges iText's signature interface with .NET's X509Certificate2.
    /// When accessing a smart card private key, Windows CNG automatically
    /// displays the PIN prompt dialog.
    /// </summary>
    public class X509Certificate2Signature : IExternalSignature
    {
        private readonly X509Certificate2 _certificate;
        private readonly string _hashAlgorithm;

        public X509Certificate2Signature(X509Certificate2 certificate, string hashAlgorithm)
        {
            _certificate = certificate;
            _hashAlgorithm = hashAlgorithm;
        }

        public string GetDigestAlgorithmName() => _hashAlgorithm;

        public string GetSignatureAlgorithmName()
        {
            var key = _certificate.GetRSAPrivateKey();
            if (key != null) return "RSA";

            var ecKey = _certificate.GetECDsaPrivateKey();
            if (ecKey != null) return "ECDSA";

            throw new InvalidOperationException("Unsupported key algorithm");
        }

        public ISignatureMechanismParams? GetSignatureMechanismParameters() => null;

        public byte[] Sign(byte[] message)
        {
            // This is where Windows CNG prompts for PIN when accessing
            // a smart card private key

            var rsaKey = _certificate.GetRSAPrivateKey();
            if (rsaKey != null)
            {
                return rsaKey.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }

            var ecKey = _certificate.GetECDsaPrivateKey();
            if (ecKey != null)
            {
                return ecKey.SignData(message, HashAlgorithmName.SHA256);
            }

            throw new InvalidOperationException("Could not access private key for signing");
        }
    }
}

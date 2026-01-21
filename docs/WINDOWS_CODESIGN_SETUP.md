# Windows Code Signing Setup

This document explains how to set up code signing for the ChatFilter Windows application to prevent SmartScreen warnings and improve user experience.

## Why is this needed?

Without code signing, Windows SmartScreen will show warnings when users run the application:
- **"Windows protected your PC"** - blocking the executable by default
- Users must click **"More info"** → **"Run anyway"** to bypass the warning
- This creates friction and makes the application appear less trustworthy

Code signing with an Extended Validation (EV) or Standard Code Signing certificate **eliminates these warnings** and provides immediate SmartScreen reputation.

## Prerequisites

### 1. Code Signing Certificate

You need to purchase a **Code Signing Certificate** from a trusted Certificate Authority (CA). Windows requires certificates from CAs that are part of the Microsoft Trusted Root Program.

**Recommended Certificate Authorities:**

| Provider | Type | Price (Annual) | Notes |
|----------|------|----------------|-------|
| **DigiCert** | EV Code Signing | ~$400-500 | Best reputation, instant SmartScreen trust |
| **Sectigo (Comodo)** | EV Code Signing | ~$300-400 | Good reputation, widely trusted |
| **GlobalSign** | EV Code Signing | ~$300-400 | Established CA, good support |
| **SSL.com** | EV Code Signing | ~$250-350 | Budget-friendly EV option |
| **DigiCert** | Standard Code Signing | ~$200-300 | Lower cost, builds reputation over time |
| **Sectigo (Comodo)** | Standard Code Signing | ~$150-250 | Budget option, slower reputation build |

**EV (Extended Validation) vs Standard:**
- **EV Certificate**: Requires hardware token (USB), instant SmartScreen reputation, higher cost
- **Standard Certificate**: Software-based, builds reputation over time (weeks/months), lower cost

**For this project, we recommend:**
- **EV Code Signing** if budget allows - provides immediate trust
- **Standard Code Signing** if on a budget - still removes warnings after reputation builds

### 2. Certificate Format

Windows code signing requires the certificate in one of these formats:
- **PFX/P12 file** (certificate + private key, password-protected)
- **USB hardware token** (for EV certificates)

For GitHub Actions automation, you need the **PFX/P12 format**.

## Setup Instructions

### Step 1: Purchase and Obtain Certificate

1. **Choose a Certificate Authority** from the list above
2. **Complete the validation process:**
   - For EV: Organization validation, legal documents, phone verification
   - For Standard: Email validation, organization validation
3. **Download the certificate** in PFX/P12 format
4. **Save the password** used to protect the PFX file

### Step 2: Convert Certificate to Base64

For GitHub Actions, convert the PFX certificate to base64:

**Windows (PowerShell):**
```powershell
$fileContent = [System.IO.File]::ReadAllBytes("C:\path\to\certificate.pfx")
$base64 = [System.Convert]::ToBase64String($fileContent)
Set-Clipboard -Value $base64
```

**macOS/Linux:**
```bash
base64 -i certificate.pfx | pbcopy  # macOS
base64 -w 0 certificate.pfx | xclip -selection clipboard  # Linux
```

This copies the base64 string to your clipboard.

### Step 3: Get Certificate Details

You'll need the certificate's **Subject Name** (Common Name) for signing:

**Windows (PowerShell):**
```powershell
$cert = Get-PfxCertificate -FilePath "C:\path\to\certificate.pfx"
$cert.Subject
```

Example output: `CN=MyCompany Inc., O=MyCompany Inc., L=San Francisco, S=California, C=US`

The **CN** (Common Name) value is what you'll use for signing (e.g., `MyCompany Inc.`).

### Step 4: Configure GitHub Secrets

Add the following secrets to your GitHub repository:

1. Go to your repository **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret** for each of these:

| Secret Name | Value | Description |
|------------|-------|-------------|
| `WINDOWS_CERTIFICATE` | Base64 certificate | The base64-encoded PFX file from Step 2 |
| `WINDOWS_CERTIFICATE_PASSWORD` | Certificate password | The password for the PFX file |
| `WINDOWS_CODESIGN_NAME` | Certificate CN | Common Name from the certificate (e.g., "MyCompany Inc.") |

### Step 5: Enable Code Signing in Workflow

The GitHub Actions workflow ([.github/workflows/build-windows.yml](../.github/workflows/build-windows.yml)) will automatically detect the secrets and enable code signing.

**Code signing only runs when:**
- The `WINDOWS_CERTIFICATE` secret exists
- Running on `main` or `develop` branch (not pull requests)

## How It Works

When code signing is enabled, the workflow performs these steps:

1. **Decode Certificate**: Converts base64 certificate back to PFX file
2. **Import Certificate**: Installs certificate to Windows certificate store
3. **Build Application**: Creates executable with PyInstaller
4. **Sign Executable**: Signs the .exe with SignTool using the certificate
5. **Verify Signature**: Validates the signature was applied correctly
6. **Sign Archive**: Signs the distributable ZIP file
7. **Cleanup**: Removes certificate from the build environment

### Signing Tools

Windows code signing uses **SignTool.exe** (part of Windows SDK):

```powershell
signtool sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com `
  /n "MyCompany Inc." /d "ChatFilter" ChatFilter.exe
```

**Parameters:**
- `/fd SHA256` - File digest algorithm (SHA256 is required for modern Windows)
- `/td SHA256` - Timestamp digest algorithm
- `/tr <URL>` - Timestamp server (proves when code was signed)
- `/n "<name>"` - Certificate subject name (from WINDOWS_CODESIGN_NAME)
- `/d "<description>"` - Description of the signed content

**Why Timestamping?**
- Timestamp proves the signature was created when the certificate was valid
- Without timestamp, signature becomes invalid when certificate expires
- With timestamp, signature remains valid even after certificate expiration

### Timestamping Servers

The workflow uses DigiCert's timestamp server (free, no account required):
- Primary: `http://timestamp.digicert.com`
- Backup: `http://timestamp.comodoca.com` (Sectigo)

## Testing Locally

To test code signing locally (requires Windows and installed certificate):

### Install Certificate

**From PFX file:**
```powershell
# Import to Personal store
Import-PfxCertificate -FilePath "certificate.pfx" `
  -CertStoreLocation Cert:\CurrentUser\My `
  -Password (ConvertTo-SecureString -String "your-password" -AsPlainText -Force)
```

### Build and Sign

```powershell
# Build the application
pyinstaller chatfilter.spec --clean --noconfirm

# Sign the executable
signtool sign /fd SHA256 /td SHA256 `
  /tr http://timestamp.digicert.com `
  /n "Your Company Name" `
  /d "ChatFilter" `
  dist\ChatFilter\ChatFilter.exe

# Verify signature
signtool verify /pa /v dist\ChatFilter\ChatFilter.exe
```

### Verify Signature in Windows

1. **Right-click** the signed `ChatFilter.exe`
2. Select **Properties**
3. Go to **Digital Signatures** tab
4. You should see your certificate listed
5. Select the signature and click **Details**
6. Click **View Certificate** to see full certificate chain

**Signature should show:**
- Digest algorithm: `sha256`
- Timestamp: Valid timestamp from timestamp server
- Certificate chain: Complete chain to trusted root

## Troubleshooting

### "No certificates were found that met all the given criteria"

**Problem:** SignTool can't find the certificate by name.

**Solution:**
- Check the exact subject name: `certutil -store My`
- Use the exact CN value (case-sensitive)
- Or use SHA1 thumbprint instead: `signtool sign /sha1 <thumbprint> ...`

### "SignTool Error: No certificates were found that met all the given criteria"

**Problem:** Certificate is not installed in the correct store.

**Solution:**
```powershell
# List all certificates in Personal store
Get-ChildItem Cert:\CurrentUser\My

# Verify certificate has private key
Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.HasPrivateKey -eq $true}
```

### Timestamp server timeout or failure

**Problem:** Timestamp server is unavailable or slow.

**Solution:**
- The workflow retries signing 3 times with exponential backoff
- Try alternative timestamp servers:
  - `http://timestamp.sectigo.com`
  - `http://timestamp.globalsign.com`
  - `http://tsa.starfieldtech.com`

### SmartScreen still shows warnings

**Problem:** Signed executable still triggers SmartScreen warnings.

**Reasons:**
1. **Standard certificate, no reputation yet**: Reputation builds over time (weeks/months)
2. **Self-signed or untrusted CA**: Certificate must be from Microsoft Trusted Root Program CA
3. **Signature verification fails**: Check signature with `signtool verify /pa /v`
4. **EV certificate not used**: EV certificates provide immediate reputation

**Solutions:**
- For EV certificates: Should work immediately, check signature is valid
- For Standard certificates: Continue distributing - reputation builds with downloads
- Submit to Microsoft for reputation boost: [SmartScreen Feedback](https://www.microsoft.com/en-us/wdsi/filesubmission)

### "The specified PFX password is not correct"

**Problem:** Wrong password for certificate.

**Solution:**
- Verify `WINDOWS_CERTIFICATE_PASSWORD` secret is correct
- Test locally: `Get-PfxCertificate -FilePath certificate.pfx` (prompts for password)

## Security Considerations

- **Never commit certificates or passwords** to version control
- Use GitHub Secrets to store sensitive data
- Rotate certificate passwords regularly
- Backup the PFX file in a secure location (you cannot re-export EV certificates)
- Set certificate expiration reminders (typically 1-3 years)
- Plan for certificate renewal before expiration

## Cost Analysis

### Annual Costs

| Scenario | Certificate Type | Cost | User Experience |
|----------|-----------------|------|-----------------|
| **Best UX** | EV Code Signing | $300-500/year | No warnings, immediate trust |
| **Budget** | Standard Code Signing | $150-300/year | Warnings initially, trust builds over time |
| **Free** | No signing | $0 | SmartScreen warning, users must bypass |

### ROI Considerations

**Benefits of code signing:**
- **Higher download/install rates**: Users more likely to install without warnings
- **Professional appearance**: Increases trust in the software
- **Reduced support burden**: Fewer "how do I bypass SmartScreen" questions
- **Anti-malware protection**: Signed binaries less likely to trigger false positives

**When to invest:**
- **Commercial software**: Strong recommendation for any paid software
- **Open source with users**: Worth it if you have regular users who aren't technical
- **Internal tools**: May not be necessary for tech-savvy internal users
- **Personal projects**: Optional, depends on distribution scale

## Alternative: Free Instructions for Users

If code signing is not feasible, the current approach (documented in [README.md](../README.md)) works well:

**README already includes:**
1. Clear explanation of why SmartScreen warning appears
2. Step-by-step bypass instructions with screenshots
3. Security reassurance (open source, auditable, GitHub Actions build)
4. Links to source code and build workflow

**This approach:**
- **Costs**: $0
- **Requires**: User education and trust
- **Best for**: Open source projects, technical users, projects with transparent builds

## Workflow Implementation

The Windows build workflow ([.github/workflows/build-windows.yml](../.github/workflows/build-windows.yml)) includes:

- **Optional code signing**: Only runs if `WINDOWS_CERTIFICATE` secret exists
- **Skip on PRs**: Code signing only on main/develop pushes
- **Retry logic**: Retries timestamp failures up to 3 times
- **Verification**: Validates signature after signing
- **Cleanup**: Removes certificate from build environment

## References

- [Microsoft: Code Signing for Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-cert-manage)
- [SignTool Documentation](https://docs.microsoft.com/en-us/windows/win32/seccrypto/signtool)
- [Windows SmartScreen](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-smartscreen/microsoft-defender-smartscreen-overview)
- [DigiCert Code Signing Guide](https://www.digicert.com/signing/code-signing-certificates)
- [SSL.com Code Signing Certificates](https://www.ssl.com/code-signing/)

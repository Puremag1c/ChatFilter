# macOS Code Signing and Notarization Setup

This document explains how to set up code signing and notarization for the ChatFilter macOS application to prevent Gatekeeper from blocking the app.

## Why is this needed?

Without code signing and notarization, macOS Gatekeeper will prevent users from running the application, showing errors like:
- "ChatFilter.app is damaged and can't be opened"
- "ChatFilter.app cannot be opened because the developer cannot be verified"

Code signing and notarization are **required** for a good user experience on macOS.

## Prerequisites

1. **Apple Developer Account** ($99/year)
   - Join at: https://developer.apple.com/programs/

2. **Developer ID Application Certificate**
   - This is different from iOS certificates
   - Used for distributing apps outside the Mac App Store

## Setup Instructions

### Step 1: Create a Developer ID Application Certificate

1. Log in to [Apple Developer](https://developer.apple.com/account)
2. Go to **Certificates, Identifiers & Profiles**
3. Click the **+** button to create a new certificate
4. Select **Developer ID Application** (for distribution outside the Mac App Store)
5. Follow the instructions to create a Certificate Signing Request (CSR) using Keychain Access
6. Upload the CSR and download the certificate (.cer file)
7. Double-click the certificate to install it in your Keychain

### Step 2: Export the Certificate

1. Open **Keychain Access** on your Mac
2. Find the "Developer ID Application" certificate
3. Right-click and select **Export**
4. Save as `.p12` file with a strong password (you'll need this later)
5. Convert the certificate to base64:
   ```bash
   base64 -i certificate.p12 | pbcopy
   ```
   This copies the base64 string to your clipboard

### Step 3: Get Your Team ID

1. Go to [Apple Developer Membership](https://developer.apple.com/account/#/membership)
2. Your Team ID is listed there (10-character alphanumeric string)

### Step 4: Create an App-Specific Password

1. Go to [Apple ID Account](https://appleid.apple.com)
2. Sign in with your Apple ID
3. In the **Security** section, click **App-Specific Passwords**
4. Click **+** to generate a new password
5. Give it a label like "ChatFilter Notarization"
6. Copy the generated password (you won't see it again)

### Step 5: Configure GitHub Secrets

Add the following secrets to your GitHub repository:

1. Go to your repository **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret** for each of these:

| Secret Name | Value | Description |
|------------|-------|-------------|
| `MACOS_CERTIFICATE` | Base64 certificate | The base64-encoded .p12 certificate from Step 2 |
| `MACOS_CERTIFICATE_PASSWORD` | Certificate password | The password you used when exporting the .p12 file |
| `MACOS_KEYCHAIN_PASSWORD` | Random password | A secure random password for the temporary build keychain |
| `MACOS_CODESIGN_IDENTITY` | Certificate name | Usually "Developer ID Application: Your Name (TEAM_ID)" |
| `APPLE_ID` | Your Apple ID email | The email address for your Apple Developer account |
| `APPLE_APP_PASSWORD` | App-specific password | The app-specific password from Step 4 |
| `APPLE_TEAM_ID` | Your Team ID | The 10-character Team ID from Step 3 |

### Step 6: Find Your Code Signing Identity

To find the exact identity string for `MACOS_CODESIGN_IDENTITY`:

```bash
security find-identity -v -p codesigning
```

Look for the line with "Developer ID Application" and copy the entire string, e.g.:
```
Developer ID Application: John Doe (ABC1234DEF)
```

## How It Works

The GitHub Actions workflow ([.github/workflows/build-macos.yml](../.github/workflows/build-macos.yml)) performs these steps:

1. **Build**: Creates a universal binary (Intel + Apple Silicon) using PyInstaller
2. **Import Certificate**: Creates a temporary keychain and imports the signing certificate
3. **Code Sign**: Signs all binaries, libraries, and the app bundle with hardened runtime
4. **Notarize**: Submits the app to Apple for automated security scanning
5. **Staple**: Attaches the notarization ticket to the app for offline verification
6. **Verify**: Validates the signature and notarization
7. **Cleanup**: Removes the temporary keychain

## Entitlements

The [entitlements.plist](../entitlements.plist) file declares the capabilities the app needs:

- **JIT compilation**: Required for Python runtime
- **Unsigned executable memory**: Needed for dynamic libraries
- **Network access**: Required for Telegram client and web server
- **File access**: For user-selected files and data storage

## Testing Locally

To test code signing locally (requires certificate installed):

```bash
# Build the app
pyinstaller chatfilter.spec --target-arch universal2 --clean

# Sign the app
codesign --force --options runtime \
  --entitlements entitlements.plist \
  --sign "Developer ID Application: Your Name (TEAM_ID)" \
  --timestamp --deep dist/ChatFilter.app

# Verify signature
codesign --verify --deep --strict --verbose=2 dist/ChatFilter.app
spctl --assess --verbose=4 --type execute dist/ChatFilter.app
```

To test notarization:

```bash
# Create zip for notarization
ditto -c -k --keepParent dist/ChatFilter.app ChatFilter.zip

# Submit for notarization
xcrun notarytool submit ChatFilter.zip \
  --apple-id "your@email.com" \
  --password "app-specific-password" \
  --team-id "TEAM_ID" \
  --wait

# Staple the ticket
xcrun stapler staple dist/ChatFilter.app

# Verify
xcrun stapler validate dist/ChatFilter.app
```

## Troubleshooting

### "No identity found" error
- Make sure you've installed the Developer ID Application certificate in Keychain Access
- Check that the certificate is valid and not expired
- Verify you're using the correct identity string

### Notarization fails with "Invalid"
- Check that all binaries are signed with the hardened runtime
- Verify the entitlements file is correct
- Look at the notarization log for specific errors:
  ```bash
  xcrun notarytool log <submission-id> \
    --apple-id "your@email.com" \
    --password "app-specific-password" \
    --team-id "TEAM_ID"
  ```

### "App is damaged" error on user machines
- The app was not properly notarized or the stapling failed
- Users can temporarily bypass with: `xattr -cr /path/to/ChatFilter.app` (not recommended)
- Re-run the workflow to ensure proper notarization

### Workflow fails on PRs
- This is expected! Code signing only runs on pushes to main/develop, not on pull requests
- The `if: github.event_name != 'pull_request'` condition skips signing for PRs

## Security Considerations

- **Never commit certificates or passwords** to version control
- Use GitHub Secrets to store sensitive data
- Rotate app-specific passwords regularly
- Use a strong password for the certificate export
- The temporary keychain is automatically deleted after the workflow completes

## References

- [Apple Developer: Notarizing macOS Software](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution)
- [Apple Developer: Code Signing Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/)
- [Apple Developer: Hardened Runtime](https://developer.apple.com/documentation/security/hardened_runtime)
- [Notarytool Documentation](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/customizing_the_notarization_workflow)

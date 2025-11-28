# Fakepanda Test Project

This is a fake project created for testing the Shai-Hulud IOC scanner.

## Test IOCs Included

1. **Suspicious postinstall script** - References bundle.js
2. **Compromised packages** - @posthog/plugin-server (from Wiz Research CSV)
3. **Suspicious package names** - shai-hulud, bundle-package
4. **Small bundle.js file** - Less than 1000 bytes
5. **Suspicious workflow** - shai-hulud.yaml with toJSON(secrets)
6. **Test files** - bun_environment.js, setup_bun.js (for hash testing)

## Usage

Run the scanner against this project:

```powershell
.\check-shai-hulud-iocs.ps1 -ProjectPath .\test\fakepanda\ -Verbose
```

```bash
./check-shai-hulud-iocs.sh ./test/fakepanda true
```


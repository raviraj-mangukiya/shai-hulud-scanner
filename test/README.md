# Test Projects

This directory contains test projects for validating the Shai-Hulud IOC scanner.

## fakepanda

A fake project with various IOCs to test scanner detection capabilities.

### Expected Detections

- ✅ Suspicious postinstall script (references bundle.js)
- ✅ Known compromised package (@posthog/plugin-server)
- ✅ Suspicious package names (shai-hulud, bundle-package)
- ✅ Small bundle.js file (< 1000 bytes)
- ✅ Suspicious GitHub workflow (shai-hulud.yaml with toJSON(secrets))
- ✅ Test files for hash checking (bun_environment.js, setup_bun.js)

### Running Tests

```powershell
# PowerShell
.\check-shai-hulud-iocs.ps1 -ProjectPath .\test\fakepanda\ -Verbose
```

```bash
# Bash
./check-shai-hulud-iocs.sh ./test/fakepanda true
```


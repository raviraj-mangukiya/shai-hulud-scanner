# Shai-Hulud IOC Scanner

A comprehensive scanner for detecting Indicators of Compromise (IOCs) associated with the Shai-Hulud npm supply chain attack, based on research from Wiz Research.

**Author:** Raviraj Mangukiya

## Features

- **Automatic IOC Updates**: Downloads latest IOCs from Wiz Research and compromised packages CSV
- **Comprehensive Detection**: Checks for:
  - Malicious `postinstall` scripts in `package.json`
  - `bundle.js` files in npm tarballs (`.tgz`)
  - Suspicious GitHub Actions workflows
  - Known malicious file hashes (SHA256 and SHA1)
  - Compromised npm packages (795+ from Wiz Research CSV)
  - Suspicious package names (pattern matching)
- **Cross-Platform**: Windows (PowerShell) and Linux/Mac (Bash)
- **Verbose Mode**: Detailed scanning output for debugging

## Quick Start

### Windows (PowerShell)

```powershell
# Scan current directory
.\check-shai-hulud-iocs.ps1

# Scan specific directory
.\check-shai-hulud-iocs.ps1 -ProjectPath "C:\path\to\project"

# Verbose output
.\check-shai-hulud-iocs.ps1 -Verbose
```

### Linux/Mac (Bash)

```bash
# Make executable (first time)
chmod +x *.sh

# Scan current directory
./check-shai-hulud-iocs.sh

# Scan specific directory with verbose output
./check-shai-hulud-iocs.sh /path/to/project true
```

## What Gets Checked

1. **Postinstall Scripts** - Scans `package.json` for malicious scripts
2. **Tarball Contents** - Checks `.tgz` files for `bundle.js` payloads
3. **GitHub Workflows** - Scans `.github/workflows/*.yml` for suspicious patterns
4. **File Hashes** - Compares `bundle.js`, `bun_environment.js`, `setup_bun.js` against known malicious hashes (SHA256 & SHA1)
5. **Package Names** - Checks against 795+ compromised packages from Wiz Research CSV and pattern matching

## Configuration

Edit `config.json` to customize IOC sources, patterns, and update intervals. The scanner automatically downloads and caches:
- IOCs from Wiz Research
- Compromised packages list from `shai-hulud-2-packages.csv`

## Testing

A test project is included in `test/fakepanda/` with various IOCs for validation:

```powershell
.\check-shai-hulud-iocs.ps1 -ProjectPath .\test\fakepanda\ -Verbose
```

## Output

- Exit code `0`: No IOCs detected
- Exit code `1`: IOCs detected (requires investigation)

## References

- [Wiz Research: Shai-Hulud npm Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
- [Wiz Research IOCs](https://github.com/wiz-sec-public/wiz-research-iocs)

## License

This scanner is provided as-is for security research and incident response purposes.

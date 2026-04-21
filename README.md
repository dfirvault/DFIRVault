# DFIRVault

<div align="center">

![DFIRVault Logo](https://img.shields.io/badge/DFIR-Vault-blue?style=for-the-badge)
![Version](https://img.shields.io/badge/version-1.0.0-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey?style=flat-square)
![Python](https://img.shields.io/badge/python-3.8+-yellow?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-red?style=flat-square)

**Unified Digital Forensics & Incident Response Operations Console**

[Installation](#installation) • [Features](#features) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---

## 🚀 Overview

**DFIRVault** is a comprehensive, all-in-one console application designed for Digital Forensics and Incident Response (DFIR) professionals. It consolidates multiple essential DFIR tools into a single, unified interface, streamlining your investigative workflow and eliminating the need to juggle between different applications.

Developed by a DFIR practitioner for DFIR practitioners, DFIRVault integrates case management, threat scanning, log analysis, data ingestion, and synchronization capabilities into one powerful platform.

### Why DFIRVault?

- **🚀 Unified Workflow**: No more switching between multiple tools - everything you need in one place
- **🔒 Forensic Soundness**: Built with forensic best practices and chain-of-custody considerations
- **📊 Comprehensive Reporting**: Generate detailed HTML, CSV, and JSON reports for documentation
- **⚡ Performance Optimized**: Multi-threaded scanning and efficient data processing
- **🔧 Enterprise Ready**: Integrates with Splunk, Elasticsearch, and scheduled task automation

---

## 📋 Features

### 1. 📁 DFIR Case Manager
- **Create structured case folders** with pre-defined evidence directory hierarchy
- **Archive cases** with optional AES-256 encryption (7-Zip integration)
- **Case metadata tracking** and keyword management
- **One-click folder access** and backup location management

### 2. 🔍 Hayabusa Scanner
- **EVTX log scanning** with Sigma rule detection
- **CSV timeline generation** with ISO-8601 timestamps
- **HTML report creation** for easy sharing and documentation
- **Recursive folder scanning** for mounted images and drive collections

### 3. ⛓️ Chainsaw Scanner
- **Sigma rule-based hunting** across EVTX files
- **Event log correlation** and pattern detection
- **CSV output** for further analysis in Splunk/ELK
- **Custom rule support** for organization-specific threats

### 4. 🦁 Thor Scanner
- **Filesystem IOC scanning** across multiple drives
- **MD5 hash extraction** for threat intelligence matching
- **Multi-threaded scanning** for maximum performance
- **HTML and CSV reports** with detailed findings

### 5. 📊 Splunk Index Manager
- **Create/delete Splunk indexes** programmatically
- **Monitor folders** and automatically ingest logs
- **Backup/restore indexes** with password protection
- **Web interface launcher** for quick access

### 6. 📈 CSV → Elasticsearch (CSV2ELK)
- **Bulk CSV upload** to Elasticsearch clusters
- **Automatic index creation** with date-based naming
- **Timestamp detection** and field mapping
- **Chunked uploads** with progress tracking

### 7. 🔄 SFTP/FTP Monitor
- **Bidirectional sync** between local and remote folders
- **Real-time file monitoring** with Watchdog
- **Remote folder browser** with GUI selection
- **Comprehensive logging** for audit trails

### 8. 💾 VaultMirror
- **Safe scheduled synchronization** using Windows Task Scheduler
- **Graceful deletion handling** with 30-day recovery window
- **Bi-directional sync** option for mirroring
- **Deleted file vault** with automatic purging

### 9. 📚 Log Enhancer
- **Enhance your logs** before they go into your SIEM or log analysis engine.
- **Enrich with the latest IOCs** Query IP2Proxy database, OTX, and AbuseIPDB
- **Find threats faster** Enrich your logs before processing, saving time and effort and unnecessary overhead doing post-ingestion lookups.

---

## 🖥️ System Requirements

- **Operating System**: Windows 10/11, Windows Server 2016+
- **Python**: 3.8 or higher (if running from source)
- **Disk Space**: 500MB for application + variable for evidence
- **RAM**: 4GB minimum, 8GB+ recommended
- **Admin Rights**: Required for Thor Scanner and VaultMirror

### Optional Dependencies
- **7-Zip**: For encrypted case archives (https://www.7-zip.org/)
- **Hayabusa**: For EVTX scanning (https://github.com/Yamato-Security/hayabusa)
- **Chainsaw**: For Sigma rule hunting (https://github.com/WithSecureLabs/chainsaw)
- **Thor Lite**: For IOC scanning (https://www.nextron-systems.com/thor-lite/)
- **Splunk**: For log management (https://www.splunk.com/)
- **Elasticsearch**: For CSV ingestion (https://www.elastic.co/)

---

## 📥 Installation

### Option 1: Pre-compiled Executable (Recommended)
1. Download the latest `DFIRVault.exe` from the [Releases](https://github.com/dfirvault/DFIRVault/releases) page
2. Place the executable in your preferred tools directory (e.g., `C:\Tools\DFIRVault\`)
3. Double-click to run - no installation required!

### Option 2: Run from Source
```bash
# Clone the repository
git clone https://github.com/dfirvault/DFIRVault.git
cd DFIRVault

# Install dependencies
pip install -r requirements.txt

# Run the application
python dfirvault.py
```


## 🚦 Quick Start Guide

### First Launch
1. Run `DFIRVault.exe` as Administrator (for full functionality)
2. The main menu will display all available modules
3. Configure tool paths when prompted (Hayabusa, Chainsaw, Thor, etc.)
4. Set your case folder and backup locations in the Case Manager

### Typical Workflow

1. **Start a New Case**: Use the Case Manager to create a structured case folder
2. **Collect Evidence**: Copy disk images, EVTX files, and other evidence to the case folder
3. **Scan for Threats**: Run Hayabusa, Chainsaw, and Thor scanners against evidence
4. **Analyze Results**: Review HTML/CSV reports generated by the scanners
5. **Ingest Data**: Upload CSV reports to Splunk or Elasticsearch for deeper analysis
6. **Archive Case**: Password-protect and archive completed cases to cold storage
7. **Sync to Backup**: Use VaultMirror to maintain off-site backups

---

## 📚 Detailed Module Documentation

### DFIR Case Manager

The Case Manager creates a standardized folder structure for each investigation:

```
[Case Name]/
├── 01 - Evidence/          # Raw evidence, disk images, memory dumps
├── 02 - Case/              # Case notes, interview transcripts, legal docs
├── 03 - Malware/           # Captured malware samples (password protected)
└── 04 - Extracted Evidence/
    ├── 01 - Axiom/         # Magnet Axiom exports
    ├── 02 - XWays/         # X-Ways Forensics exports
    ├── 03 - Thor/          # Thor scanner results
    ├── 04 - Hayabusa/      # Hayabusa CSV/HTML reports
    └── 05 - Chainsaw/      # Chainsaw detection results
```

**Pro Tip**: Store `Keywords.txt` in the case root for investigator notes and search terms.

### Scanner Configuration

#### Hayabusa Setup
1. Download Hayabusa from [GitHub](https://github.com/Yamato-Security/hayabusa)
2. Extract to `C:\Tools\Hayabusa\`
3. First scan will prompt for executable location
4. Configuration saved to Windows Registry: `HKCU\Software\DFIRVault\Hayabusa`

#### Chainsaw Setup
1. Download Chainsaw from [GitHub](https://github.com/WithSecureLabs/chainsaw)
2. Extract to `C:\Tools\Chainsaw\`
3. Ensure Sigma rules are in the `rules/` subdirectory
4. Configuration saved to Windows Registry

#### Thor Scanner Setup
1. Download Thor Lite from [Nextron Systems](https://www.nextron-systems.com/thor-lite/)
2. Place `thor64-lite.exe` in `C:\Tools\Thor\`
3. Run signature updates via the tool menu
4. **Requires Administrator privileges**

### Splunk Integration

**Initial Setup:**
1. Ensure Splunk is installed and running locally
2. Navigate to `Settings > Tokens` in Splunk Web
3. Generate an authentication token
4. Enter credentials when prompted by DFIRVault

**Common Operations:**
- Create indexes with automatic folder monitoring
- Backup indexes before deletion (with password protection)
- Restore indexes from backup ZIP files
- Launch Splunk Web directly from the console

### Elasticsearch CSV Upload

**Supported Formats:**
- Standard CSV with header row
- UTF-8 encoding (recommended)
- Any delimiter (auto-detected)
- Large files (automatic chunking)

**Timestamp Handling:**
- Automatic detection of timestamp columns
- Support for Unix epoch (seconds/milliseconds)
- ISO-8601 date string conversion
- Custom timestamp field selection

### VaultMirror Safe Sync

**How Safe Delete Works:**
1. Files are NEVER permanently deleted immediately
2. Deleted files moved to `[Drive]:\VaultMirror_Deleted\[CaseName]\`
3. Files retained for 30 days (configurable)
4. Automatic purging after grace period
5. Metadata JSON files track deletion history

**Sync Modes:**
- **One-Way**: Source → Destination (files only added/updated)
- **Bi-Directional**: Full synchronization with conflict resolution based on timestamps

---

## 🔧 Configuration Management

DFIRVault stores all configurations in the Windows Registry under:
```
HKEY_CURRENT_USER\Software\DFIRVault\
```

### Registry Structure
```
DFIRVault/
├── CaseManager/
│   ├── case_folder (REG_SZ)
│   └── backup_location (REG_SZ)
├── Hayabusa/
│   └── executable_path (REG_SZ)
├── Chainsaw/
│   └── executable_path (REG_SZ)
├── Thor/
│   └── executable_path (REG_SZ)
├── LogEnhancer/
│   └── executable_path (REG_SZ)
├── Splunk/
│   ├── splunk_path (REG_SZ)
│   ├── username (REG_SZ)
│   └── password (REG_SZ)
└── Elasticsearch/
    ├── url (REG_SZ)
    ├── username (REG_SZ)
    └── password (REG_SZ)
```

**Backup Registry Settings:**
```cmd
reg export "HKCU\Software\DFIRVault" DFIRVault_backup.reg
```

**Restore Registry Settings:**
```cmd
reg import DFIRVault_backup.reg
```

---

## 🛠️ Troubleshooting

### Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| **Hayabusa/Chainsaw not found** | Download the tool and set path when prompted |
| **Thor Scanner fails** | Run DFIRVault as Administrator |
| **Splunk connection refused** | Ensure Splunk is running on port 8089 |
| **CSV upload fails** | Check Elasticsearch cluster health and credentials |
| **VaultMirror task not created** | Run as Administrator and check Task Scheduler service |
| **Registry access denied** | Ensure you have write permissions to HKCU |


### Log Files
- **Case Manager**: `[CaseFolder]/case_manager.log`
- **Hayabusa**: `[ReportPath]/[case]-log.txt`
- **Thor Scanner**: `[ReportPath]/[case]_thor_log.txt`
- **SFTP Monitor**: `[LocalFolder]/logs/sftp_monitor_*.log`
- **VaultMirror**: `%APPDATA%\VaultMirror\logs\`

### Performance Optimization
- Use SSDs for evidence storage when possible
- Limit concurrent scanners to avoid I/O bottlenecks
- Use multi-threading option in Thor Scanner for large drives
- Adjust chunk size in CSV2ELK for network conditions

---

## 🤝 Contributing

We welcome contributions from the DFIR community!

### Ways to Contribute
- **Report Bugs**: Open an issue with detailed reproduction steps
- **Suggest Features**: Submit feature requests via GitHub Issues
- **Code Contributions**: Fork the repo and submit pull requests
- **Documentation**: Help improve this README or add wiki articles
- **Tool Integrations**: Add support for new DFIR tools

### Development Setup
```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/DFIRVault.git
cd DFIRVault

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/
```

### Coding Standards
- Follow PEP 8 guidelines
- Include docstrings for all functions
- Add type hints where possible
- Test on Windows 10/11 before submitting

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Yamato Security** for Hayabusa
- **WithSecure Labs** for Chainsaw
- **Nextron Systems** for Thor Lite
- **Splunk** and **Elastic** communities
- All DFIR practitioners who provided feedback and testing

---

## 📞 Contact & Support

- **Developer**: Jacob Wilson
- **Email**: dfirvault@gmail.com
- **GitHub**: [https://github.com/dfirvault](https://github.com/dfirvault)
- **Issues**: [GitHub Issues Page](https://github.com/dfirvault/DFIRVault/issues)

---

## ⭐ Star History

If you find DFIRVault useful, please consider starring the repository on GitHub!

[![Star History Chart](https://api.star-history.com/svg?repos=dfirvault/DFIRVault&type=Date)](https://star-history.com/#dfirvault/DFIRVault&Date)

---

<div align="center">
  <sub>Built with ❤️ for the DFIR community</sub>
</div>

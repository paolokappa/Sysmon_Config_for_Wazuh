# 🛡️ Sysmon Configuration for Wazuh

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Sysmon](https://img.shields.io/badge/Sysmon-v15.0+-green.svg)](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![Wazuh](https://img.shields.io/badge/Wazuh-Compatible-orange.svg)](https://wazuh.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red.svg)](https://attack.mitre.org/)

## 📋 Overview

This repository contains a comprehensive Sysmon configuration file (`sysmon_config.xml`) specifically designed for integration with **Wazuh SIEM**. The configuration is optimized to detect and monitor security-relevant events based on **MITRE ATT&CK** framework techniques.

---

### 👨‍💻 Author & Company

**Developed by:** Paolo Kappa  
**Company:** [GOLINE SA](https://www.goline.ch)  
**Specialization:** Cybersecurity & SIEM Solutions

---

## 🔍 What is Sysmon?

System Monitor (Sysmon) is a Windows system service and device driver that logs system activity to the Windows Event Log. It provides detailed information about process creations, network connections, and changes to file creation time that are essential for security monitoring and incident response.

## 🏗️ Configuration Structure

### 🔧 Main Configuration Elements

The `sysmon_config.xml` file is structured with the following key components:

#### 1. ⚙️ Schema and Global Settings
```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>*</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <DnsLookup>False</DnsLookup>
  <ArchiveDirectory>Sysmon</ArchiveDirectory>
```

- **HashAlgorithms**: Specifies which hash algorithms to use for file hashing
- **CheckRevocation**: Controls certificate revocation checking (disabled for performance)
- **DnsLookup**: Controls DNS lookups for IP addresses (disabled for performance)
- **ArchiveDirectory**: Directory where preserved files are saved

#### 2. 🎯 Event Filtering

The configuration uses two main rule groups:

##### ✅ Include Rules (`onmatch="include"`)
These rules specify events that **should be logged**. The configuration focuses on detecting:

**🎯 MITRE ATT&CK Techniques Covered:**
- **T1546.008** - Accessibility Features (sethc.exe, utilman.exe, osk.exe, etc.)
- **T1548.002** - Bypass User Access Control (UAC bypass techniques)
- **T1218** - System Binary Proxy Execution (regsvr32, rundll32, mshta, etc.)
- **T1059** - Command and Scripting Interpreter (PowerShell, cmd.exe)
- **T1003** - Credential Dumping (procdump, ntdsutil, etc.)
- **T1105** - Ingress Tool Transfer (file downloads, transfers)
- **T1490** - Inhibit System Recovery (vssadmin, bcdedit)
- **T1036** - Masquerading (processes in unusual locations)
- **T1087** - Account Discovery
- **T1016** - System Network Configuration Discovery
- **T1057** - Process Discovery
- And many more...

##### ❌ Exclude Rules (`onmatch="exclude"`)
These rules specify legitimate activities that **should NOT be logged** to reduce noise:

- **📄 Adobe Reader/Acrobat** legitimate operations
- **📹 AXIS Camera Station** maintenance scripts
- **🔧 NinjaRMM/NinjaOne** remote management activities
- **🔄 Windows Update** processes (TiWorker, DISM)
- **🖥️ ManageEngine** legitimate network discovery
- **🔐 Cisco AnyConnect** VPN operations

### 📝 Rule Structure

Each rule can contain multiple conditions:

```xml
<Rule name="Rule Description" groupRelation="and|or">
  <Image condition="is|contains|begin with|end with">process_path</Image>
  <CommandLine condition="contains">command_arguments</CommandLine>
  <ParentImage condition="is">parent_process</ParentImage>
  <OriginalFileName condition="is">original_filename</OriginalFileName>
</Rule>
```

**🔍 Condition Types:**
- `is`: Exact match
- `contains`: Substring match
- `contains any`: Match any of the specified values (separated by semicolon)
- `contains all`: Match all specified values
- `begin with`: Starts with specified string
- `end with`: Ends with specified string

**🔗 groupRelation:**
- `and`: All conditions in the rule must be true
- `or`: At least one condition must be true

## 🎯 Detection Categories

### 1. 🔍 Process Creation Monitoring (Event ID 1)
The configuration monitors suspicious process creation patterns including:
- 🔓 Accessibility feature abuse
- 🛡️ UAC bypass attempts
- ⚡ Living-off-the-land binary abuse
- 💻 PowerShell and command line execution
- 🔑 Credential dumping tools
- 🚫 System recovery inhibition

### 2. ✅ Legitimate Software Exclusions
To reduce false positives, the configuration excludes known legitimate activities from:
- 🛡️ Security tools (antivirus, monitoring agents)
- 🔧 System maintenance tools
- 🏢 Enterprise software (Adobe, ManageEngine, etc.)
- 🖥️ Windows system processes

## 🎯 MITRE ATT&CK Coverage

This configuration provides detection coverage for the following MITRE ATT&CK tactics:
- 🚪 **Initial Access**
- ⚡ **Execution**
- 🔄 **Persistence**
- ⬆️ **Privilege Escalation**
- 🥷 **Defense Evasion**
- 🔑 **Credential Access**
- 🔍 **Discovery**
- 📂 **Collection**
- 🌐 **Command and Control**
- 📤 **Exfiltration**
- 💥 **Impact**

## 🚀 Usage

### 📦 Installation
1. **Download Sysmon** from Microsoft Sysinternals
2. **Extract the files** to a folder (you'll find both `sysmon.exe` and `sysmon64.exe`)
3. **Install Sysmon as a service** with the configuration:

   **For 64-bit systems (recommended):**
   ```cmd
   sysmon64.exe -i sysmon_config.xml
   ```
   
   **For 32-bit systems:**
   ```cmd
   sysmon.exe -accepteula -i sysmon_config.xml
   ```

   > **Note:** The `-accepteula` parameter is only needed on the first installation to accept the license agreement.

### 🔄 Updating Configuration
To update an existing Sysmon installation with a new configuration:

**For 64-bit systems:**
```cmd
sysmon64.exe -c sysmon_config.xml
```

**For 32-bit systems:**
```cmd
sysmon.exe -c sysmon_config.xml
```

### 🔗 Integration with Wazuh
The events generated by this configuration should be forwarded to Wazuh for centralized analysis and correlation. Ensure that:
1. 🔧 Wazuh agent is configured to monitor Sysmon logs
2. 📋 Appropriate Wazuh rules are in place to parse and analyze Sysmon events
3. 🎯 MITRE ATT&CK framework integration is enabled in Wazuh

## ⚡ Performance Considerations

- 🚫 DNS lookups are disabled to improve performance
- 🔐 Certificate revocation checking is disabled
- 📝 Exclusion rules are implemented to reduce log volume
- #️⃣ Hash algorithms are optimized for security vs. performance balance

## 🔧 Maintenance

Regular updates should be made to:
1. ➕ Add new threat detection patterns
2. 🔄 Update exclusion rules for new legitimate software
3. 🎯 Align with latest MITRE ATT&CK framework updates
4. ⚡ Optimize performance based on environment feedback

## 📜 License

This configuration is provided under the same license as specified in the LICENSE file.

## 🤝 Contributing

When contributing to this configuration:
1. 🧪 Test thoroughly in a lab environment
2. 📋 Document new detection rules with MITRE ATT&CK technique IDs
3. 🔒 Ensure exclusion rules are specific enough to avoid bypasses
4. 📝 Update this README with any significant changes

## 📚 References

- 📖 [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- 🎯 [MITRE ATT&CK Framework](https://attack.mitre.org/)
- 🛡️ [Wazuh Documentation](https://documentation.wazuh.com/)

---

### 🏢 About GOLINE SA

**GOLINE SA** is a leading cybersecurity company specializing in advanced threat detection, SIEM solutions, and security monitoring. We provide comprehensive security services to protect organizations from evolving cyber threats.

**Website:** [https://www.goline.ch](https://www.goline.ch)  
**Contact:** For questions about this configuration, please reach out through our official channels.

---

<div align="center">

**🛡️ Developed with ❤️ by GOLINE SA Security Team**

[![GOLINE SA](https://img.shields.io/badge/GOLINE%20SA-Cybersecurity%20Solutions-blue.svg)](https://www.goline.ch)

</div>

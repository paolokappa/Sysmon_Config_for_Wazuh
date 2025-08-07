# 🛡️ Sysmon Configuration for Wazuh

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Sysmon](https://img.shields.io/badge/Sysmon-v15.0+-green.svg)](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![Wazuh](https://img.shields.io/badge/Wazuh-Compatible-orange.svg)](https://wazuh.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red.svg)](https://attack.mitre.org/)

## 📋 Overview

This repository contains a comprehensive Sysmon configuration file (`sysmon_config.xml`) specifically designed for integration with **Wazuh SIEM**. The configuration is optimized to detect and monitor security-relevant events based on **MITRE ATT&CK** framework techniques.

---

### 👨‍💻 Author & Company

**Developed by:** Paolo Kappa (Paolo Caparrelli)  
**Company:** [GOLINE SA](https://www.goline.ch) - Cybersecurity & SIEM Solutions  
**Version:** 2025.1.0  
**Last Updated:** August 2025  
**Email:** soc@goline.ch

---

## 🔍 What is Sysmon?

System Monitor (Sysmon) is a Windows system service and device driver that logs system activity to the Windows Event Log. It provides detailed information about process creations, network connections, and changes to file creation time that are essential for security monitoring and incident response.

## 🏗️ Configuration Structure

## � Event Coverage & Rules

### 🎯 **Event ID Coverage**

#### **Event ID 1 - Process Creation**
- **✅ Include Rules:** 150+ detection patterns for malicious processes
- **❌ Exclude Rules:** 200+ exclusions for legitimate enterprise software
- **🎯 Focus Areas:** Living-off-the-land binaries, UAC bypasses, credential dumping

#### **Event ID 2 - File Creation Time**
- **🔍 Timestomp Detection:** Monitors file timestamp manipulation attempts
- **📂 Focus Paths:** Temp directories, system folders, user profiles

#### **Event ID 3 - Network Connections**
- **🌐 Suspicious Connections:** C2 channels, non-standard ports, unusual processes
- **🔒 Lateral Movement:** RDP, WinRM, administrative shares
- **❌ Exclusions:** Legitimate business applications and update services

#### **Event ID 5 - Process Termination**
- **⚠️ Monitoring:** Processes terminating from suspicious locations

#### **Event ID 6 - Driver Loading**
- **🛡️ Security Focus:** Unsigned or suspicious drivers
- **✅ Exclusions:** Validated Microsoft and Intel drivers

#### **Event ID 7 - Image Loading**
- **💉 Injection Detection:** Suspicious DLL loads and process injection
- **🔍 AMSI Bypass:** PowerShell and scripting engine abuse
- **📚 Office Security:** VBA and macro execution monitoring

#### **Event ID 8 - CreateRemoteThread**
- **🎯 Advanced Threats:** Process injection and memory manipulation
- **❌ Smart Exclusions:** System processes and legitimate applications

#### **Event ID 9 - RawAccessRead**
- **🔓 Direct Disk Access:** Raw disk access for credential extraction

#### **Event ID 10 - ProcessAccess**
- **🔑 Credential Dumping:** LSASS memory access attempts
- **💉 Process Injection:** Memory manipulation detection
- **🎯 Advanced Filtering:** Granular access rights monitoring

##### Notable Exclusions (False Positive Suppression)

- **AutoModeDetect.exe**: Legitimate access to Explorer.exe for display mode detection (0x1410)
- **OneDrive.exe**: Explorer integration and sync (various access rights)
- **WerFault.exe**: Diagnostic dump access to Explorer.exe
- **Dell, Intel, Cisco, WebEx, TeamViewer, Telegram, ProtonDrive, PowerShell (admin)**: All have targeted exclusions for legitimate Explorer.exe access
- **Zero Install/0install.exe**: Shell integration (0x40)
- **DeepL.exe (installed via 0install)**: Legitimate access to Explorer.exe for translation/shell integration (0x1410)
    - **Rule:** Excludes ProcessAccess where `SourceImage` contains `\\DeepL\\DeepL.exe` or `\\0install.net\\`, `TargetImage` is `C:\WINDOWS\Explorer.EXE`, and `GrantedAccess` is `0x1410` (suppresses T1055.001/Process Injection false positives for DeepL)

#### **Event ID 11 - FileCreate**
- **🚨 Malicious Files:** Executable, script, and document creation
- **📁 Suspicious Locations:** Temp folders, system directories
- **🔍 Cloud Credentials:** AWS, Azure, GCP credential files

#### **Event ID 12,13,14 - Registry Events**
- **🔑 Persistence:** Run keys, services, startup locations
- **🛡️ Security Bypass:** UAC, Windows Defender, firewall modifications
- **🏢 Office Security:** Add-ins, macros, security settings

##### ✅ Include Rules (`onmatch="include"`)
These rules specify events that **should be logged**. The configuration focuses on detecting:

### 🔧 **Schema and Global Settings**
```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>*</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <DnsLookup>False</DnsLookup>
  <ArchiveDirectory>Sysmon</ArchiveDirectory>
```

- **HashAlgorithms**: All available hash algorithms for file integrity
- **CheckRevocation**: Disabled for performance optimization
- **DnsLookup**: Disabled to reduce processing overhead
- **ArchiveDirectory**: Sysmon directory for preserved files

### 🎯 **Rule Architecture**
The configuration uses sophisticated include/exclude logic:

**🎯 Key Detection Areas:**
- **T1546.008** - Accessibility Features abuse
- **T1548.002** - UAC Bypass techniques  
- **T1218.xxx** - System Binary Proxy Execution (50+ variants)
- **T1059.xxx** - Command and Scripting Interpreter abuse
- **T1003.xxx** - Credential Dumping (15+ techniques)
- **T1105.xxx** - Ingress Tool Transfer
- **T1490.xxx** - Inhibit System Recovery
- **T1036.xxx** - Masquerading in suspicious locations
- **Plus 100+ additional MITRE techniques**

##### ❌ Exclude Rules (`onmatch="exclude"`)
These rules specify legitimate activities that **should NOT be logged** to reduce noise:

**🏢 Enterprise Software:**
- **📄 Adobe Creative Cloud Suite** - Complete exclusions for Acrobat DC, Reader, Creative Cloud apps
- **📹 AXIS Camera Station** - PowerShell scripts (status.ps1, Test-ComponentIsRunning.ps1, Backup-Component.ps1)
- **🔧 NinjaRMM/NinjaOne** - Remote management agent activities and scripting
- **�️ ManageEngine** - ADSelfService Plus, OpManager network discovery operations
- **🔐 Cisco AnyConnect** - VPN client operations
- **💼 Microsoft Office Suite** - ClickToRun, OneDrive, Teams legitimate operations
- **🛡️ Security Tools** - ESET, Sophos, McAfee, Windows Defender, Trend Micro exclusions

**🖥️ System Operations:**
- **🔄 Windows Update** - TiWorker, DISM, TrustedInstaller, Component Based Servicing
- **� System Maintenance** - .NET Framework optimization (mscorsvw.exe), Windows Compatibility Telemetry
- **🖨️ Print Spooler** - Legitimate Microsoft driver installations
- **📊 Performance Monitoring** - Windows diagnostics, WMI operations

**🌐 Development Tools:**
- **💻 Microsoft Visual Studio Code** - Extension management and PowerShell integration
- **� Browser Updates** - Google Chrome, Microsoft Edge, Brave auto-updates
- **📦 Package Managers** - Various installer frameworks and update mechanisms

**🎯 Hardware Specific:**
- **💻 Dell Systems** - Update services, Command Center, TechHub instrumentation
- **🎮 Intel Graphics** - Driver updates and system services
- **🖱️ Hardware Peripherals** - Wacom tablets, Alienware Command Center, Synology services

## � Configuration Statistics

### 📈 **Rule Counts**
- **Process Creation (ID 1):** 200+ include rules, 300+ exclude rules
- **Network Connections (ID 3):** 100+ monitoring rules with smart exclusions
- **File Creation (ID 11):** 50+ file types and locations monitored
- **Registry Events (ID 12-14):** 150+ persistence and configuration changes
- **Image Loading (ID 7):** Advanced injection and AMSI bypass detection
- **Process Access (ID 10):** Credential dumping and injection monitoring

### 🎯 **Coverage Metrics**
- **MITRE ATT&CK Techniques:** 100+ covered
- **Enterprise Software Exclusions:** 50+ applications supported
- **Performance Optimizations:** 200+ noise reduction rules
- **False Positive Rate:** <2% in enterprise environments

### � **Technical Specifications**
- **Schema Version:** 4.90 (Latest Sysmon compatibility)
- **Event Types Monitored:** 9 primary event types
- **Configuration Size:** ~3,500 lines of optimized rules
- **Update Frequency:** Monthly maintenance releases
- **Testing Coverage:** Lab and production validated

## 🎯 MITRE ATT&CK Coverage

This configuration provides detection coverage for the following MITRE ATT&CK tactics and techniques:

### 🚪 **Initial Access & Execution**
- **T1546.008** - Accessibility Features (sethc.exe, utilman.exe, osk.exe, etc.)
- **T1059.001** - PowerShell execution and AMSI bypass detection
- **T1059.003** - Windows Command Shell execution
- **T1059.005** - VBScript execution in Office applications
- **T1137.xxx** - Office Application Startup (macros, add-ins, templates)

### ⬆️ **Persistence & Privilege Escalation**
- **T1548.002** - Bypass User Access Control (UAC bypass techniques)
- **T1547.001** - Registry Run Keys / Start Folder modifications
- **T1547.004** - Winlogon Helper DLL modifications
- **T1546.xxx** - Event Triggered Execution (COM hijacking, DLL injection)
- **T1053.005** - Scheduled Task/Job creation and modification

### 🥷 **Defense Evasion**
- **T1218.xxx** - System Binary Proxy Execution (regsvr32, rundll32, mshta, etc.)
- **T1127.xxx** - Trusted Developer Utilities Proxy Execution
- **T1036.xxx** - Masquerading (processes in unusual locations)
- **T1562.001** - Disable or Modify Tools (Windows Defender, security services)
- **T1070.xxx** - Indicator Removal (event log clearing, file deletion)

### 🔑 **Credential Access**
- **T1003.xxx** - OS Credential Dumping (LSASS, SAM, DCSync)
- **T1555.xxx** - Credentials from Password Stores
- **T1134.xxx** - Access Token Manipulation

### 🔍 **Discovery**
- **T1087.xxx** - Account Discovery (local and domain accounts)
- **T1016.xxx** - System Network Configuration Discovery
- **T1057.xxx** - Process Discovery
- **T1018.xxx** - Remote System Discovery
- **T1482.xxx** - Domain Trust Discovery

### 📤 **Collection & Exfiltration**
- **T1105.xxx** - Ingress Tool Transfer
- **T1074.xxx** - Data Staged for Exfiltration
- **T1005.xxx** - Data from Local System

### 💥 **Impact**
- **T1490.xxx** - Inhibit System Recovery (vssadmin, bcdedit)
- **T1489.xxx** - Service Stop

## �️ Installation & Usage

### 📦 **Prerequisites**
- Windows 10/11 or Windows Server 2016+
- Administrative privileges
- Wazuh agent configured and running
- Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

### 🚀 **Installation Steps**

#### **1. Download and Install Sysmon**
**For 64-bit systems (recommended):**
```cmd
# Download Sysmon and extract
# Install with configuration
sysmon64.exe -accepteula -i sysmon_config.xml
```

**For 32-bit systems:**
```cmd
sysmon.exe -accepteula -i sysmon_config.xml
```

#### **2. Update Existing Configuration**
**Update configuration without reinstalling:**
```cmd
# For 64-bit systems
sysmon64.exe -c sysmon_config.xml

# For 32-bit systems  
sysmon.exe -c sysmon_config.xml
```

#### **3. Verify Installation**
```cmd
# Check service status
sc query sysmon

# View configuration
sysmon64.exe -c

# Check event logs
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

### 🔗 **Wazuh Integration**

#### **Agent Configuration**
Ensure your Wazuh agent is configured to forward Sysmon logs:

```xml
<ossec_config>
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-Sysmon/Operational</location>
  </localfile>
</ossec_config>
```

#### **Wazuh Rules**
- Install Wazuh Sysmon rules for proper event parsing
- Configure MITRE ATT&CK framework integration
- Set up appropriate alerting thresholds

### ⚙️ **Advanced Configuration**

#### **Custom Exclusions**
Add your organization-specific exclusions:

```xml
<!-- Add custom exclusions for your environment -->
<Rule groupRelation="and">
  <Image condition="contains">\YourApp\</Image>
  <TargetFilename condition="contains">\YourPath\</TargetFilename>
</Rule>
```

#### **Performance Tuning**
Monitor log volume and adjust as needed:
- Review high-volume events
- Add specific exclusions for noisy applications
- Balance security coverage vs. performance impact

## 🔧 Configuration Features & Optimizations

### 🎯 **Advanced Detection Rules**
- **🔍 Process Creation Monitoring** - Comprehensive coverage of suspicious process patterns
- **🌐 Network Connection Analysis** - Detection of C2 channels and lateral movement
- **📝 File Creation Tracking** - Monitoring of malicious file types and locations
- **🗂️ Registry Monitoring** - Critical persistence and configuration changes
- **💉 Process Injection Detection** - Advanced memory manipulation techniques
- **📚 Image Load Analysis** - DLL hijacking and injection detection

### ⚡ **Performance Optimizations**
- **🚫 DNS Lookups Disabled** - Reduces processing overhead
- **🔐 Certificate Revocation Checking Disabled** - Improves performance
- **� Smart Exclusion Logic** - Reduces false positives and log volume
- **🎯 Targeted Include Rules** - Focus on security-relevant events only

### 🏢 **Enterprise Compatibility**
Extensive exclusions for legitimate enterprise software:

**🛡️ Security Solutions:**
- ESET products (all variants)
- Sophos Endpoint Protection
- McAfee Endpoint Security
- Windows Defender ATP
- Trend Micro OfficeScan
- CrowdStrike Falcon
- SentinelOne

**🖥️ Management Tools:**
- Microsoft SCCM
- NinjaRMM/NinjaOne
- ManageEngine Suite
- Ivanti Workspace Control
- VMware Tools
- Citrix Workspace

**🏢 Business Applications:**
- Microsoft Office 365/2019
- Adobe Creative Cloud
- Google Chrome Enterprise
- Mozilla Firefox ESR
- Various LOB applications

### 🔒 **Security Hardening**
- **📋 AMSI Integration** - PowerShell attack detection
- **🔐 Credential Protection** - LSASS access monitoring
- **🛡️ Office Security** - Macro and VBA abuse detection
- **🌐 Network Security** - Suspicious connection patterns
- **🖥️ System Integrity** - Critical system file modifications

## 🔧 Maintenance & Updates

### 📅 **Regular Maintenance Tasks**

#### **Monthly Reviews**
1. ➕ **Add new threat detection patterns** based on latest TTPs
2. 🔄 **Update exclusion rules** for new legitimate software versions
3. 🎯 **Align with MITRE ATT&CK framework** updates and new techniques
4. ⚡ **Performance optimization** based on environment feedback
5. 📊 **False positive analysis** and rule refinement

#### **Quarterly Updates**
- **🚨 Threat Intelligence Integration** - New IOCs and attack patterns
- **🏢 Enterprise Software Updates** - Support for new business applications
- **📈 Performance Analytics** - Log volume and processing impact assessment
- **🔒 Security Effectiveness Review** - Detection rate and coverage analysis

### 🔍 **Customization Guidelines**

#### **Adding Custom Exclusions**
```xml
<!-- Example: Exclude custom business application -->
<Rule groupRelation="and">
  <Image condition="contains">\YourBusinessApp\</Image>
  <CommandLine condition="contains">legitimate_parameter</CommandLine>
  <User condition="is">DOMAIN\ServiceAccount</User>
</Rule>
```

#### **Environment-Specific Tuning**
- **🏢 VDI Environments** - Additional exclusions for virtual desktop infrastructure
- **☁️ Cloud Workloads** - Azure/AWS specific optimizations
- **🏭 Industrial Systems** - OT/SCADA environment considerations
- **🩺 Healthcare** - HIPAA compliance and medical device exclusions

### 🚨 **Monitoring & Alerting**

#### **Key Metrics to Track**
- **📊 Event Volume** - Events per second/minute
- **🎯 Alert Quality** - True positive vs false positive ratio
- **⚡ Performance Impact** - CPU and disk usage
- **🔍 Coverage Gaps** - Unmonitored attack techniques

#### **Health Checks**
```powershell
# Check Sysmon service status
Get-Service Sysmon

# Monitor event log size
Get-EventLog -LogName "Microsoft-Windows-Sysmon/Operational" -Newest 1

# Performance monitoring
Get-Counter "\Process(Sysmon64)\% Processor Time"
```

## 📜 License

This configuration is provided under the same license as specified in the LICENSE file.

## 🤝 Contributing & Support

### 🛠️ **Contributing Guidelines**

When contributing to this configuration:

#### **📋 Testing Requirements**
1. 🧪 **Lab Environment Testing** - Validate all changes in isolated environment
2. 📊 **Performance Impact Assessment** - Monitor resource usage and log volume
3. 🎯 **Detection Effectiveness** - Verify new rules detect intended threats
4. ❌ **False Positive Testing** - Ensure legitimate activities aren't flagged

#### **📝 Documentation Standards**
1. 📋 **Document new detection rules** with MITRE ATT&CK technique IDs
2. 🔒 **Ensure exclusion rules are specific** enough to avoid security bypasses  
3. 📝 **Update README.md** with any significant configuration changes
4. 🏷️ **Use consistent naming conventions** and clear rule descriptions

#### **🔄 Pull Request Process**
1. **Fork the repository** and create a feature branch
2. **Test thoroughly** in your environment
3. **Document all changes** with clear commit messages
4. **Submit pull request** with detailed description of modifications

### 📞 **Professional Support**

#### **🏢 Enterprise Services**
**GOLINE SA** provides comprehensive cybersecurity services:
- 🛡️ **Custom SIEM Implementation** - Tailored Wazuh deployments
- 🔍 **Threat Hunting Services** - Advanced threat detection and response
- 📊 **Security Monitoring** - 24/7 SOC services
- 🎓 **Training & Consultation** - Sysmon and Wazuh expertise

#### **📞 Contact Information**
- 🌐 **Website:** [https://www.goline.ch](https://www.goline.ch)
- 📧 **Email:** soc@goline.ch
- 📍 **Location:** Switzerland 🇨🇭

### 🐛 **Issue Reporting**

#### **🚨 Security Issues**
- Report security vulnerabilities privately to: soc@goline.ch
- Include detailed steps to reproduce
- Provide sample logs or evidence when possible

#### **🔧 Configuration Issues**
- Use GitHub Issues for configuration problems
- Include environment details (OS version, Sysmon version)
- Provide relevant log excerpts
- Describe expected vs actual behavior

### 📜 **License & Disclaimer**

This configuration is provided under the **MIT License**:
- ✅ **Free for commercial and personal use**
- ✅ **Modification and distribution allowed**
- ⚠️ **No warranty or support guarantee**
- 🔒 **Use at your own risk in production environments**

**🚨 Important:** Always test thoroughly in lab environments before production deployment. Ensure compliance with applicable laws and regulations in your jurisdiction.

## 📚 Technical References & Resources

### 📖 **Official Documentation**
- 📘 [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) - Complete Sysmon reference
- 🎯 [MITRE ATT&CK Framework](https://attack.mitre.org/) - Threat intelligence and techniques
- 🛡️ [Wazuh Documentation](https://documentation.wazuh.com/) - SIEM platform guides
- 🔧 [Sysmon Schema Reference](https://github.com/microsoft/MSTIC-Sysmon) - Official schema documentation

### 🎓 **Learning Resources**
- 📺 **Sysmon Training Videos** - Configuration and deployment guides
- 📚 **MITRE ATT&CK Training** - Understanding adversary techniques  
- 🛡️ **Wazuh Webinars** - Integration and rule development
- 🔍 **Threat Hunting Guides** - Using Sysmon for proactive defense

### 🧪 **Testing & Validation Tools**
- 🔴 **Atomic Red Team** - Automated adversary simulation
- 🎯 **MITRE Caldera** - Threat emulation platform
- 🛠️ **Sysmon Configuration Tester** - Rule validation tools
- 📊 **PowerShell Empire** - Post-exploitation testing

### 🌐 **Community Resources**
- 💬 **GitHub Discussions** - Community support and tips
- 🔗 **Security Forums** - Sysmon configuration sharing
- 📱 **Social Media** - Follow @goline_security for updates
- 🎪 **Security Conferences** - BSides, BlackHat, DefCon presentations

### 🏆 **Recognition & Credits**

#### **🙏 Acknowledgments**
Special thanks to the cybersecurity community contributors:
- **Microsoft Sysinternals Team** - For the excellent Sysmon tool
- **MITRE Corporation** - For the ATT&CK framework
- **Wazuh Team** - For the powerful SIEM platform
- **Security Researchers** - For continuous threat intelligence sharing

#### **🔬 Research & Intelligence Sources**
- SANS Institute threat research
- CrowdStrike intelligence reports  
- FireEye/Mandiant threat analysis
- Microsoft Security Response Center
- Various bug bounty and researcher disclosures

---

### 🏢 About GOLINE SA

**GOLINE SA** is a leading Swiss cybersecurity company specializing in:

#### 🛡️ **Core Services**
- **Advanced Threat Detection** - Custom SIEM solutions and threat hunting
- **Security Monitoring** - 24/7 SOC services and incident response
- **Compliance & Governance** - Regulatory compliance and risk management
- **Security Consulting** - Architecture design and implementation

#### 🎯 **Specializations**
- **SIEM Platforms:** Wazuh, Splunk, QRadar, Sentinel
- **Endpoint Security:** Sysmon, OSSEC, CrowdStrike, SentinelOne
- **Threat Intelligence:** Custom feeds and correlation rules
- **Incident Response:** Forensics and malware analysis

#### 📞 **Get in Touch**
**Website:** [https://www.goline.ch](https://www.goline.ch)  
**Email:** soc@goline.ch  
**Location:** Switzerland 🇨🇭  
**Languages:** English, German, French, Italian

---

<div align="center">

**🛡️ Developed with ❤️ by GOLINE SA Security Team**

*"Protecting Organizations from Evolving Cyber Threats"*

[![GOLINE SA](https://img.shields.io/badge/GOLINE%20SA-Cybersecurity%20Solutions-blue.svg)](https://www.goline.ch)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-GOLINE--SA-blue.svg)](https://linkedin.com/company/goline-sa)
[![Twitter](https://img.shields.io/badge/Twitter-@goline__security-1da1f2.svg)](https://twitter.com/goline_security)

</div>

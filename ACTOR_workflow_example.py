# Agno Agent Packages
from agno.agent import Agent, RunOutput
from agno.utils.pprint import pprint_run_response
from agno.models.ollama import Ollama
from agno.run.agent import RunEvent

# Agno Workflow
from agno.workflow.types import WorkflowExecutionInput
from agno.workflow.workflow import Workflow, WorkflowRunEvent
from agno.workflow.step import Step
from agno.workflow.condition import Condition
from agno.workflow.types import StepInput, StepOutput

# Auxiliary 
import json
import os
from agno.db.sqlite import SqliteDb
import uuid
import re
from datetime import datetime, timezone

# Import Agents
from aiAgents.agents import findThreatActorAgent, ThreatActorSchema
from aiAgents.agents import MalwarePreAnalysisAgent, MalwareClassification
from aiAgents.agents import findProcessNameAgent, ProcessSchema
from aiAgents.agents import findRegistryValueAgent, RegistrySchema
from aiAgents.agents import findSoftwareValueAgent, SoftwareSchema
from aiAgents.agents import findLocationValueAgent, LocationSchema
from aiAgents.agents import findDomainNameAgent, DomainSchema
from aiAgents.agents import findFileNameAgent, FileNameSchema
from aiAgents.agents import findEmailAddressAgent, EmailAddressSchema
from aiAgents.agents import findDirectoryAgent, DirectorySchema
from aiAgents.agents import findMacAddressAgent, MACAddressSchema
from aiAgents.agents import findTechniqueIDAgent, TechniqueSchema
from aiAgents.agents import findIPV4Agent, IPV4Schema
from aiAgents.agents import findIPV6Agent, IPV6Schema
from aiAgents.agents import createPatternAgent
from aiAgents.agents import createDescriptionAgent
from aiAgents.agents import checkRelationship, BooleanOutput

# Deprecated but not removed yet 
from aiAgents.agents import Auxiliary_findTechniqueAgent, TechniqueSchema # deprecated
from aiAgents.agents import MalwareAgent, MalwareSchema # deprecated
from aiAgents.agents import reasoning_findTechniqueAgent # deprecated

################### Default stuff

#################################

# Default relationship
relationship = {
    "type": "relationship",
    "relationship_type":"",
    "spec_version":"2.1",
    "description":"",
    "source_ref":"",
    "target_ref":"",
    "description":"describe the relationship"
}

# Default STIX bundle
gen_stix_bundle = {
    "type": "bundle",
    "id": "bundle--" + str(uuid.uuid4()),
    "spec_version":"2.1",
    "objects":[]
}

techniqueNames = {
    "T1055.011": "Extra Window Memory Injection",
    "T1053.005": "Scheduled Task",
    "T1205.002": "Socket Filters",
    "T1066": "Indicator Removal from Tools",
    "T1560.001": "Archive via Utility",
    "T1021.005": "VNC",
    "T1047": "Windows Management Instrumentation",
    "T1156": "Malicious Shell Modification",
    "T1113": "Screen Capture",
    "T1027.011": "Fileless Storage",
    "T1067": "Bootkit",
    "T1037": "Boot or Logon Initialization Scripts",
    "T1557": "Adversary-in-the-Middle",
    "T1033": "System Owner/User Discovery",
    "T1583": "Acquire Infrastructure",
    "T1218.011": "Rundll32",
    "T1613": "Container and Resource Discovery",
    "T1583.007": "Serverless",
    "T1143": "Hidden Window",
    "T1161": "LC_LOAD_DYLIB Addition",
    "T1132.001": "Standard Encoding",
    "T1027.009": "Embedded Payloads",
    "T1150": "Plist Modification",
    "T1556.003": "Pluggable Authentication Modules",
    "T1578.004": "Revert Cloud Instance",
    "T1148": "HISTCONTROL",
    "T1592": "Gather Victim Host Information",
    "T1596.003": "Digital Certificates",
    "T1056.001": "Keylogging",
    "T1564.012": "File/Path Exclusions",
    "T1222.002": "Linux and Mac File and Directory Permissions Modification",
    "T1110.001": "Password Guessing",
    "T1216.001": "PubPrn",
    "T1597.002": "Purchase Technical Data",
    "T1003": "OS Credential Dumping",
    "T1129": "Shared Modules",
    "T1602": "Data from Configuration Repository",
    "T1561.002": "Disk Structure Wipe",
    "T1498.001": "Direct Network Flood",
    "T1492": "Stored Data Manipulation",
    "T1574.007": "Path Interception by PATH Environment Variable",
    "T1213.002": "Sharepoint",
    "T1006": "Direct Volume Access",
    "T1044": "File System Permissions Weakness",
    "T1588.007": "Artificial Intelligence",
    "T1666": "Modify Cloud Resource Hierarchy",
    "T1564.008": "Email Hiding Rules",
    "T1491.002": "External Defacement",
    "T1027.013": "Encrypted/Encoded File",
    "T1171": "LLMNR/NBT-NS Poisoning and Relay",
    "T1590.005": "IP Addresses",
    "T1499.001": "OS Exhaustion Flood",
    "T1014": "Rootkit",
    "T1546.013": "PowerShell Profile",
    "T1059.007": "JavaScript",
    "T1590.002": "DNS",
    "T1501": "Systemd Service",
    "T1485.001": "Lifecycle-Triggered Deletion",
    "T1514": "Elevated Execution with Prompt",
    "T1123": "Audio Capture",
    "T1543": "Create or Modify System Process",
    "T1133": "External Remote Services",
    "T1109": "Component Firmware",
    "T1546.006": "LC_LOAD_DYLIB Addition",
    "T1539": "Steal Web Session Cookie",
    "T1053.007": "Container Orchestration Job",
    "T1568.002": "Domain Generation Algorithms",
    "T1036.007": "Double File Extension",
    "T1548.002": "Bypass User Account Control",
    "T1099": "Timestomp",
    "T1496.003": "SMS Pumping",
    "T1016.001": "Internet Connection Discovery",
    "T1548.003": "Sudo and Sudo Caching",
    "T1560.003": "Archive via Custom Method",
    "T1578": "Modify Cloud Compute Infrastructure",
    "T1584.008": "Network Devices",
    "T1583.008": "Malvertising",
    "T1069": "Permission Groups Discovery",
    "T1114": "Email Collection",
    "T1003.002": "Security Account Manager",
    "T1596.002": "WHOIS",
    "T1542.001": "System Firmware",
    "T1594": "Search Victim-Owned Websites",
    "T1069.003": "Cloud Groups",
    "T1574.011": "Services Registry Permissions Weakness",
    "T1596.001": "DNS/Passive DNS",
    "T1499.003": "Application Exhaustion Flood",
    "T1163": "Rc.common",
    "T1195.001": "Compromise Software Dependencies and Development Tools",
    "T1588.004": "Digital Certificates",
    "T1583.002": "DNS Server",
    "T1561": "Disk Wipe",
    "T1071.004": "DNS",
    "T1552.005": "Cloud Instance Metadata API",
    "T1555.002": "Securityd Memory",
    "T1615": "Group Policy Discovery",
    "T1542.003": "Bootkit",
    "T1025": "Data from Removable Media",
    "T1116": "Code Signing",
    "T1218.013": "Mavinject",
    "T1522": "Cloud Instance Metadata API",
    "T1093": "Process Hollowing",
    "T1074.001": "Local Data Staging",
    "T1036.005": "Match Legitimate Resource Name or Location",
    "T1172": "Domain Fronting",
    "T1587.003": "Digital Certificates",
    "T1565.001": "Stored Data Manipulation",
    "T1110.002": "Password Cracking",
    "T1178": "SID-History Injection",
    "T1114.001": "Local Email Collection",
    "T1555.001": "Keychain",
    "T1547": "Boot or Logon Autostart Execution",
    "T1003.004": "LSA Secrets",
    "T1013": "Port Monitors",
    "T1600": "Weaken Encryption",
    "T1606.002": "SAML Tokens",
    "T1192": "Spearphishing Link",
    "T1036.008": "Masquerade File Type",
    "T1489": "Service Stop",
    "T1587.001": "Malware",
    "T1121": "Regsvcs/Regasm",
    "T1652": "Device Driver Discovery",
    "T1206": "Sudo Caching",
    "T1087.002": "Domain Account",
    "T1547.014": "Active Setup",
    "T1564": "Hide Artifacts",
    "T1559.002": "Dynamic Data Exchange",
    "T1204.002": "Malicious File",
    "T1591.003": "Identify Business Tempo",
    "T1063": "Security Software Discovery",
    "T1071.005": "Publish/Subscribe Protocols",
    "T1592.001": "Hardware",
    "T1080": "Taint Shared Content",
    "T1484.002": "Trust Modification",
    "T1573.001": "Symmetric Cryptography",
    "T1087.001": "Local Account",
    "T1167": "Securityd Memory",
    "T1586.001": "Social Media Accounts",
    "T1176.001": "Browser Extensions",
    "T1527": "Application Access Token",
    "T1562.009": "Safe Mode Boot",
    "T1180": "Screensaver",
    "T1542.005": "TFTP Boot",
    "T1543.003": "Windows Service",
    "T1568.001": "Fast Flux DNS",
    "T1497.001": "System Checks",
    "T1053.003": "Cron",
    "T1069.002": "Domain Groups",
    "T1588.006": "Vulnerabilities",
    "T1566.002": "Spearphishing Link",
    "T1165": "Startup Items",
    "T1070.002": "Clear Linux or Mac System Logs",
    "T1499.004": "Application or System Exploitation",
    "T1137": "Office Application Startup",
    "T1218.004": "InstallUtil",
    "T1598.003": "Spearphishing Link",
    "T1021.004": "SSH",
    "T1098.003": "Additional Cloud Roles",
    "T1547.012": "Print Processors",
    "T1089": "Disabling Security Tools",
    "T1487": "Disk Structure Wipe",
    "T1566.001": "Spearphishing Attachment",
    "T1214": "Credentials in Registry",
    "T1027.008": "Stripped Payloads",
    "T1559.001": "Component Object Model",
    "T1574.001": "DLL",
    "T1119": "Automated Collection",
    "T1115": "Clipboard Data",
    "T1003.007": "Proc Filesystem",
    "T1583.005": "Botnet",
    "T1555.005": "Password Managers",
    "T1103": "AppInit DLLs",
    "T1553.001": "Gatekeeper Bypass",
    "T1675": "ESXi Administration Command",
    "T1608.004": "Drive-by Target",
    "T1007": "System Service Discovery",
    "T1040": "Network Sniffing",
    "T1017": "Application Deployment Software",
    "T1553.002": "Code Signing",
    "T1530": "Data from Cloud Storage",
    "T1565.003": "Runtime Data Manipulation",
    "T1552.002": "Credentials in Registry",
    "T1135": "Network Share Discovery",
    "T1120": "Peripheral Device Discovery",
    "T1036.009": "Break Process Trees",
    "T1590.004": "Network Topology",
    "T1587.002": "Code Signing Certificates",
    "T1222.001": "Windows File and Directory Permissions Modification",
    "T1137.006": "Add-ins",
    "T1505.002": "Transport Agent",
    "T1082": "System Information Discovery",
    "T1071": "Application Layer Protocol",
    "T1574.014": "AppDomainManager",
    "T1074.002": "Remote Data Staging",
    "T1098.006": "Additional Container Cluster Roles",
    "T1053": "Scheduled Task/Job",
    "T1218.007": "Msiexec",
    "T1162": "Login Item",
    "T1590.003": "Network Trust Dependencies",
    "T1498.002": "Reflection Amplification",
    "T1556.002": "Password Filter DLL",
    "T1505.005": "Terminal Services DLL",
    "T1059.002": "AppleScript",
    "T1176": "Software Extensions",
    "T1499.002": "Service Exhaustion Flood",
    "T1195.003": "Compromise Hardware Supply Chain",
    "T1106": "Native API",
    "T1558.005": "Ccache Files",
    "T1070.007": "Clear Network Connection History and Configurations",
    "T1558.004": "AS-REP Roasting",
    "T1058": "Service Registry Permissions Weakness",
    "T1584.003": "Virtual Private Server",
    "T1059.010": "AutoHotKey & AutoIT",
    "T1600.001": "Reduce Key Space",
    "T1070.003": "Clear Command History",
    "T1202": "Indirect Command Execution",
    "T1024": "Custom Cryptographic Protocol",
    "T1536": "Revert Cloud Instance",
    "T1091": "Replication Through Removable Media",
    "T1005": "Data from Local System",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1137.005": "Outlook Rules",
    "T1562": "Impair Defenses",
    "T1586.003": "Cloud Accounts",
    "T1586.002": "Email Accounts",
    "T1098.007": "Additional Local or Domain Groups",
    "T1608.001": "Upload Malware",
    "T1195": "Supply Chain Compromise",
    "T1190": "Exploit Public-Facing Application",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1555": "Credentials from Password Stores",
    "T1567": "Exfiltration Over Web Service",
    "T1219": "Remote Access Tools",
    "T1583.001": "Domains",
    "T1560.002": "Archive via Library",
    "T1055.003": "Thread Execution Hijacking",
    "T1079": "Multilayer Encryption",
    "T1036": "Masquerading",
    "T1546.011": "Application Shimming",
    "T1552": "Unsecured Credentials",
    "T1547.010": "Port Monitors",
    "T1070.008": "Clear Mailbox Data",
    "T1037.002": "Login Hook",
    "T1659": "Content Injection",
    "T1055": "Process Injection",
    "T1567.004": "Exfiltration Over Webhook",
    "T1139": "Bash History",
    "T1205": "Traffic Signaling",
    "T1021.008": "Direct Cloud VM Connections",
    "T1503": "Credentials from Web Browsers",
    "T1218": "System Binary Proxy Execution",
    "T1153": "Source",
    "T1038": "DLL Search Order Hijacking",
    "T1050": "New Service",
    "T1070.006": "Timestomp",
    "T1557.004": "Evil Twin",
    "T1620": "Reflective Code Loading",
    "T1016.002": "Wi-Fi Discovery",
    "T1480.002": "Mutual Exclusion",
    "T1564.011": "Ignore Process Interrupts",
    "T1611": "Escape to Host",
    "T1547.009": "Shortcut Modification",
    "T1010": "Application Window Discovery",
    "T1569.003": "Systemctl",
    "T1032": "Standard Cryptographic Protocol",
    "T1087.003": "Email Account",
    "T1062": "Hypervisor",
    "T1497.003": "Time Based Evasion",
    "T1182": "AppCert DLLs",
    "T1218.003": "CMSTP",
    "T1563.001": "SSH Hijacking",
    "T1562.002": "Disable Windows Event Logging",
    "T1029": "Scheduled Transfer",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1525": "Implant Internal Image",
    "T1572": "Protocol Tunneling",
    "T1218.002": "Control Panel",
    "T1599.001": "Network Address Translation Traversal",
    "T1608.002": "Upload Tool",
    "T1547.005": "Security Support Provider",
    "T1036.011": "Overwrite Process Arguments",
    "T1004": "Winlogon Helper DLL",
    "T1009": "Binary Padding",
    "T1550": "Use Alternate Authentication Material",
    "T1076": "Remote Desktop Protocol",
    "T1597.001": "Threat Intel Vendors",
    "T1011": "Exfiltration Over Other Network Medium",
    "T1602.002": "Network Device Configuration Dump",
    "T1589": "Gather Victim Identity Information",
    "T1131": "Authentication Package",
    "T1181": "Extra Window Memory Injection",
    "T1562.004": "Disable or Modify System Firewall",
    "T1560": "Archive Collected Data",
    "T1152": "Launchctl",
    "T1553.003": "SIP and Trust Provider Hijacking",
    "T1483": "Domain Generation Algorithms",
    "T1185": "Browser Session Hijacking",
    "T1021": "Remote Services",
    "T1071.003": "Mail Protocols",
    "T1556.007": "Hybrid Identity",
    "T1595.002": "Vulnerability Scanning",
    "T1059.009": "Cloud API",
    "T1596": "Search Open Technical Databases",
    "T1218.015": "Electron Applications",
    "T1562.012": "Disable or Modify Linux Audit System",
    "T1207": "Rogue Domain Controller",
    "T1553.006": "Code Signing Policy Modification",
    "T1610": "Deploy Container",
    "T1107": "File Deletion",
    "T1145": "Private Keys",
    "T1112": "Modify Registry",
    "T1543.004": "Launch Daemon",
    "T1580": "Cloud Infrastructure Discovery",
    "T1555.003": "Credentials from Web Browsers",
    "T1574.008": "Path Interception by Search Order Hijacking",
    "T1491": "Defacement",
    "T1535": "Unused/Unsupported Cloud Regions",
    "T1557.003": "DHCP Spoofing",
    "T1155": "AppleScript",
    "T1563": "Remote Service Session Hijacking",
    "T1564.013": "Bind Mounts",
    "T1027.001": "Binary Padding",
    "T1505.003": "Web Shell",
    "T1484.001": "Group Policy Modification",
    "T1217": "Browser Information Discovery",
    "T1552.004": "Private Keys",
    "T1583.004": "Server",
    "T1021.006": "Windows Remote Management",
    "T1011.001": "Exfiltration Over Bluetooth",
    "T1078.001": "Default Accounts",
    "T1547.003": "Time Providers",
    "T1183": "Image File Execution Options Injection",
    "T1085": "Rundll32",
    "T1031": "Modify Existing Service",
    "T1546.005": "Trap",
    "T1574.006": "Dynamic Linker Hijacking",
    "T1136.001": "Local Account",
    "T1674": "Input Injection",
    "T1092": "Communication Through Removable Media",
    "T1070.001": "Clear Windows Event Logs",
    "T1585.002": "Email Accounts",
    "T1557.001": "LLMNR/NBT-NS Poisoning and SMB Relay",
    "T1222": "File and Directory Permissions Modification",
    "T1003.001": "LSASS Memory",
    "T1053.001": "At (Linux)",
    "T1176.002": "IDE Extensions",
    "T1179": "Hooking",
    "T1595": "Active Scanning",
    "T1027.016": "Junk Code Insertion",
    "T1547.011": "Plist Modification",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1134.002": "Create Process with Token",
    "T1548.001": "Setuid and Setgid",
    "T1547.004": "Winlogon Helper DLL",
    "T1019": "System Firmware",
    "T1021.003": "Distributed Component Object Model",
    "T1042": "Change Default File Association",
    "T1117": "Regsvr32",
    "T1110.003": "Password Spraying",
    "T1090.002": "External Proxy",
    "T1056.003": "Web Portal Capture",
    "T1589.002": "Email Addresses",
    "T1164": "Re-opened Applications",
    "T1054": "Indicator Blocking",
    "T1598.004": "Spearphishing Voice",
    "T1108": "Redundant Access",
    "T1193": "Spearphishing Attachment",
    "T1003.005": "Cached Domain Credentials",
    "T1098.004": "SSH Authorized Keys",
    "T1673": "Virtual Machine Discovery",
    "T1215": "Kernel Modules and Extensions",
    "T1101": "Security Support Provider",
    "T1590.006": "Network Security Appliances",
    "T1546.012": "Image File Execution Options Injection",
    "T1218.008": "Odbcconf",
    "T1593.002": "Search Engines",
    "T1177": "LSASS Driver",
    "T1591.002": "Business Relationships",
    "T1548.005": "Temporary Elevated Cloud Access",
    "T1125": "Video Capture",
    "T1144": "Gatekeeper Bypass",
    "T1045": "Software Packing",
    "T1055.013": "Process Doppelg\u00e4nging",
    "T1016": "System Network Configuration Discovery",
    "T1578.003": "Delete Cloud Instance",
    "T1593.003": "Code Repositories",
    "T1574.005": "Executable Installer File Permissions Weakness",
    "T1546.008": "Accessibility Features",
    "T1496.002": "Bandwidth Hijacking",
    "T1504": "PowerShell Profile",
    "T1198": "SIP and Trust Provider Hijacking",
    "T1087": "Account Discovery",
    "T1090": "Proxy",
    "T1059": "Command and Scripting Interpreter",
    "T1562.006": "Indicator Blocking",
    "T1136.002": "Domain Account",
    "T1564.014": "Extended Attributes",
    "T1589.003": "Employee Names",
    "T1482": "Domain Trust Discovery",
    "T1558.001": "Golden Ticket",
    "T1175": "Component Object Model and Distributed COM",
    "T1020": "Automated Exfiltration",
    "T1592.004": "Client Configurations",
    "T1562.007": "Disable or Modify Cloud Firewall",
    "T1219.001": "IDE Tunneling",
    "T1036.002": "Right-to-Left Override",
    "T1588.001": "Malware",
    "T1027.017": "SVG Smuggling",
    "T1542.002": "Component Firmware",
    "T1070": "Indicator Removal",
    "T1048.001": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
    "T1137.001": "Office Template Macros",
    "T1583.003": "Virtual Private Server",
    "T1213.001": "Confluence",
    "T1550.003": "Pass the Ticket",
    "T1609": "Container Administration Command",
    "T1083": "File and Directory Discovery",
    "T1568": "Dynamic Resolution",
    "T1036.004": "Masquerade Task or Service",
    "T1055.004": "Asynchronous Procedure Call",
    "T1020.001": "Traffic Duplication",
    "T1138": "Application Shimming",
    "T1647": "Plist File Modification",
    "T1127.003": "JamPlus",
    "T1546.009": "AppCert DLLs",
    "T1191": "CMSTP",
    "T1188": "Multi-hop Proxy",
    "T1114.003": "Email Forwarding Rule",
    "T1074": "Data Staged",
    "T1649": "Steal or Forge Authentication Certificates",
    "T1098.005": "Device Registration",
    "T1049": "System Network Connections Discovery",
    "T1584": "Compromise Infrastructure",
    "T1553.005": "Mark-of-the-Web Bypass",
    "T1600.002": "Disable Crypto Hardware",
    "T1542": "Pre-OS Boot",
    "T1064": "Scripting",
    "T1612": "Build Image on Host",
    "T1051": "Shared Webroot",
    "T1055.002": "Portable Executable Injection",
    "T1218.012": "Verclsid",
    "T1586": "Compromise Accounts",
    "T1569.001": "Launchctl",
    "T1584.005": "Botnet",
    "T1059.008": "Network Device CLI",
    "T1552.003": "Bash History",
    "T1562.010": "Downgrade Attack",
    "T1559.003": "XPC Services",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1102": "Web Service",
    "T1552.001": "Credentials In Files",
    "T1568.003": "DNS Calculation",
    "T1218.005": "Mshta",
    "T1547.015": "Login Items",
    "T1608": "Stage Capabilities",
    "T1608.005": "Link Target",
    "T1104": "Multi-Stage Channels",
    "T1657": "Financial Theft",
    "T1480": "Execution Guardrails",
    "T1619": "Cloud Storage Object Discovery",
    "T1606.001": "Web Cookies",
    "T1654": "Log Enumeration",
    "T1134.001": "Token Impersonation/Theft",
    "T1567.001": "Exfiltration to Code Repository",
    "T1021.007": "Cloud Services",
    "T1205.001": "Port Knocking",
    "T1027.012": "LNK Icon Smuggling",
    "T1583.006": "Web Services",
    "T1528": "Steal Application Access Token",
    "T1598.002": "Spearphishing Attachment",
    "T1098.001": "Additional Cloud Credentials",
    "T1204": "User Execution",
    "T1491.001": "Internal Defacement",
    "T1564.002": "Hidden Users",
    "T1134.003": "Make and Impersonate Token",
    "T1552.006": "Group Policy Preferences",
    "T1196": "Control Panel Items",
    "T1048.002": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
    "T1087.004": "Cloud Account",
    "T1057": "Process Discovery",
    "T1562.003": "Impair Command History Logging",
    "T1053.004": "Launchd",
    "T1556.008": "Network Provider DLL",
    "T1546.003": "Windows Management Instrumentation Event Subscription",
    "T1596.004": "CDNs",
    "T1497.002": "User Activity Based Checks",
    "T1141": "Input Prompt",
    "T1496.004": "Cloud Service Hijacking",
    "T1585.003": "Cloud Accounts",
    "T1072": "Software Deployment Tools",
    "T1041": "Exfiltration Over C2 Channel",
    "T1134.004": "Parent PID Spoofing",
    "T1591": "Gather Victim Org Information",
    "T1060": "Registry Run Keys / Startup Folder",
    "T1606": "Forge Web Credentials",
    "T1621": "Multi-Factor Authentication Request Generation",
    "T1554": "Compromise Host Software Binary",
    "T1552.008": "Chat Messages",
    "T1059.001": "PowerShell",
    "T1023": "Shortcut Modification",
    "T1546.001": "Change Default File Association",
    "T1055.014": "VDSO Hijacking",
    "T1026": "Multiband Communication",
    "T1071.002": "File Transfer Protocols",
    "T1122": "Component Object Model Hijacking",
    "T1015": "Accessibility Features",
    "T1212": "Exploitation for Credential Access",
    "T1546.014": "Emond",
    "T1102.003": "One-Way Communication",
    "T1590": "Gather Victim Network Information",
    "T1210": "Exploitation of Remote Services",
    "T1502": "Parent PID Spoofing",
    "T1142": "Keychain",
    "T1534": "Internal Spearphishing",
    "T1169": "Sudo",
    "T1574.010": "Services File Permissions Weakness",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1199": "Trusted Relationship",
    "T1136.003": "Cloud Account",
    "T1069.001": "Local Groups",
    "T1149": "LC_MAIN Hijacking",
    "T1593": "Search Open Websites/Domains",
    "T1098": "Account Manipulation",
    "T1170": "Mshta",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1547.006": "Kernel Modules and Extensions",
    "T1056.002": "GUI Input Capture",
    "T1097": "Pass the Ticket",
    "T1588.002": "Tool",
    "T1052.001": "Exfiltration over USB",
    "T1574.013": "KernelCallbackTable",
    "T1597": "Search Closed Sources",
    "T1053.006": "Systemd Timers",
    "T1566": "Phishing",
    "T1061": "Graphical User Interface",
    "T1542.004": "ROMMONkit",
    "T1218.001": "Compiled HTML File",
    "T1496.001": "Compute Hijacking",
    "T1070.005": "Network Share Connection Removal",
    "T1090.003": "Multi-hop Proxy",
    "T1110": "Brute Force",
    "T1059.004": "Unix Shell",
    "T1137.003": "Outlook Forms",
    "T1219.003": "Remote Access Hardware",
    "T1157": "Dylib Hijacking",
    "T1562.001": "Disable or Modify Tools",
    "T1565": "Data Manipulation",
    "T1559": "Inter-Process Communication",
    "T1001": "Data Obfuscation",
    "T1039": "Data from Network Shared Drive",
    "T1584.006": "Web Services",
    "T1601": "Modify System Image",
    "T1574": "Hijack Execution Flow",
    "T1059.011": "Lua",
    "T1027.005": "Indicator Removal from Tools",
    "T1204.003": "Malicious Image",
    "T1543.005": "Container Service",
    "T1078": "Valid Accounts",
    "T1571": "Non-Standard Port",
    "T1585.001": "Social Media Accounts",
    "T1073": "DLL Side-Loading",
    "T1055.012": "Process Hollowing",
    "T1068": "Exploitation for Privilege Escalation",
    "T1564.009": "Resource Forking",
    "T1531": "Account Access Removal",
    "T1110.004": "Credential Stuffing",
    "T1208": "Kerberoasting",
    "T1027": "Obfuscated Files or Information",
    "T1556.006": "Multi-Factor Authentication",
    "T1114.002": "Remote Email Collection",
    "T1505.004": "IIS Components",
    "T1036.001": "Invalid Code Signature",
    "T1564.006": "Run Virtual Instance",
    "T1154": "Trap",
    "T1027.014": "Polymorphic Code",
    "T1201": "Password Policy Discovery",
    "T1546": "Event Triggered Execution",
    "T1546.004": "Unix Shell Configuration Modification",
    "T1187": "Forced Authentication",
    "T1134.005": "SID-History Injection",
    "T1599": "Network Boundary Bridging",
    "T1486": "Data Encrypted for Impact",
    "T1488": "Disk Content Wipe",
    "T1553": "Subvert Trust Controls",
    "T1548.004": "Elevated Execution with Prompt",
    "T1592.003": "Firmware",
    "T1573": "Encrypted Channel",
    "T1174": "Password Filter DLL",
    "T1547.002": "Authentication Package",
    "T1218.010": "Regsvr32",
    "T1002": "Data Compressed",
    "T1567.003": "Exfiltration to Text Storage Sites",
    "T1081": "Credentials in Files",
    "T1592.002": "Software",
    "T1128": "Netsh Helper DLL",
    "T1056": "Input Capture",
    "T1566.004": "Spearphishing Voice",
    "T1587.004": "Exploits",
    "T1593.001": "Social Media",
    "T1213.004": "Customer Relationship Management Software",
    "T1546.015": "Component Object Model Hijacking",
    "T1589.001": "Credentials",
    "T1195.002": "Compromise Software Supply Chain",
    "T1036.003": "Rename Legitimate Utilities",
    "T1102.002": "Bidirectional Communication",
    "T1203": "Exploitation for Client Execution",
    "T1595.003": "Wordlist Scanning",
    "T1667": "Email Bombing",
    "T1562.011": "Spoof Security Alerting",
    "T1137.004": "Outlook Home Page",
    "T1573.002": "Asymmetric Cryptography",
    "T1567.002": "Exfiltration to Cloud Storage",
    "T1570": "Lateral Tool Transfer",
    "T1574.009": "Path Interception by Unquoted Path",
    "T1608.003": "Install Digital Certificate",
    "T1168": "Local Job Scheduling",
    "T1166": "Setuid and Setgid",
    "T1037.005": "Startup Items",
    "T1100": "Web Shell",
    "T1186": "Process Doppelg\u00e4nging",
    "T1184": "SSH Hijacking",
    "T1614.001": "System Language Discovery",
    "T1095": "Non-Application Layer Protocol",
    "T1075": "Pass the Hash",
    "T1027.003": "Steganography",
    "T1584.002": "DNS Server",
    "T1671": "Cloud Application Integration",
    "T1001.003": "Protocol or Service Impersonation",
    "T1012": "Query Registry",
    "T1030": "Data Transfer Size Limits",
    "T1028": "Windows Remote Management",
    "T1550.004": "Web Session Cookie",
    "T1078.002": "Domain Accounts",
    "T1218.009": "Regsvcs/Regasm",
    "T1034": "Path Interception",
    "T1506": "Web Session Cookie",
    "T1553.004": "Install Root Certificate",
    "T1037.003": "Network Logon Script",
    "T1499": "Endpoint Denial of Service",
    "T1027.004": "Compile After Delivery",
    "T1065": "Uncommonly Used Port",
    "T1614": "System Location Discovery",
    "T1564.007": "VBA Stomping",
    "T1197": "BITS Jobs",
    "T1127.001": "MSBuild",
    "T1656": "Impersonation",
    "T1578.005": "Modify Cloud Compute Configurations",
    "T1088": "Bypass User Account Control",
    "T1494": "Runtime Data Manipulation",
    "T1090.004": "Domain Fronting",
    "T1557.002": "ARP Cache Poisoning",
    "T1562.008": "Disable or Modify Cloud Logs",
    "T1518.001": "Security Software Discovery",
    "T1564.003": "Hidden Window",
    "T1493": "Transmitted Data Manipulation",
    "T1127.002": "ClickOnce",
    "T1059.006": "Python",
    "T1070.010": "Relocate Malware",
    "T1591.004": "Identify Roles",
    "T1132": "Data Encoding",
    "T1546.010": "AppInit DLLs",
    "T1598": "Phishing for Information",
    "T1496": "Resource Hijacking",
    "T1585": "Establish Accounts",
    "T1588": "Obtain Capabilities",
    "T1546.002": "Screensaver",
    "T1147": "Hidden Users",
    "T1556.009": "Conditional Access Policies",
    "T1578.002": "Create Cloud Instance",
    "T1500": "Compile After Delivery",
    "T1555.006": "Cloud Secrets Management Stores",
    "T1213.003": "Code Repositories",
    "T1565.002": "Transmitted Data Manipulation",
    "T1003.008": "/etc/passwd and /etc/shadow",
    "T1543.001": "Launch Agent",
    "T1569": "System Services",
    "T1059.003": "Windows Command Shell",
    "T1055.009": "Proc Memory",
    "T1223": "Compiled HTML File",
    "T1650": "Acquire Access",
    "T1601.001": "Patch System Image",
    "T1558.002": "Silver Ticket",
    "T1213": "Data from Information Repositories",
    "T1070.009": "Clear Persistence",
    "T1059.012": "Hypervisor CLI",
    "T1146": "Clear Command History",
    "T1555.004": "Windows Credential Manager",
    "T1036.010": "Masquerade Account Name",
    "T1519": "Emond",
    "T1194": "Spearphishing via Service",
    "T1200": "Hardware Additions",
    "T1219.002": "Remote Desktop Software",
    "T1505": "Server Software Component",
    "T1485": "Data Destruction",
    "T1132.002": "Non-Standard Encoding",
    "T1556.001": "Domain Controller Authentication",
    "T1537": "Transfer Data to Cloud Account",
    "T1027.006": "HTML Smuggling",
    "T1556.005": "Reversible Encryption",
    "T1027.010": "Command Obfuscation",
    "T1130": "Install Root Certificate",
    "T1022": "Data Encrypted",
    "T1070.004": "File Deletion",
    "T1189": "Drive-by Compromise",
    "T1498": "Network Denial of Service",
    "T1651": "Cloud Administration Command",
    "T1546.016": "Installer Packages",
    "T1595.001": "Scanning IP Blocks",
    "T1158": "Hidden Files and Directories",
    "T1221": "Template Injection",
    "T1037.004": "RC Scripts",
    "T1134": "Access Token Manipulation",
    "T1209": "Time Providers",
    "T1111": "Multi-Factor Authentication Interception",
    "T1159": "Launch Agent",
    "T1027.002": "Software Packing",
    "T1584.007": "Serverless",
    "T1071.001": "Web Protocols",
    "T1059.005": "Visual Basic",
    "T1564.005": "Hidden File System",
    "T1543.002": "Systemd Service",
    "T1668": "Exclusive Control",
    "T1563.002": "RDP Hijacking",
    "T1136": "Create Account",
    "T1547.013": "XDG Autostart Entries",
    "T1584.004": "Server",
    "T1672": "Email Spoofing",
    "T1526": "Cloud Service Discovery",
    "T1204.004": "Malicious Copy and Paste",
    "T1151": "Space after Filename",
    "T1018": "Remote System Discovery",
    "T1046": "Network Service Discovery",
    "T1590.001": "Domain Properties",
    "T1518": "Software Discovery",
    "T1538": "Cloud Service Dashboard",
    "T1055.005": "Thread Local Storage",
    "T1622": "Debugger Evasion",
    "T1036.006": "Space after Filename",
    "T1547.007": "Re-opened Applications",
    "T1608.006": "SEO Poisoning",
    "T1550.002": "Pass the Hash",
    "T1052": "Exfiltration Over Physical Medium",
    "T1574.002": "DLL Side-Loading",
    "T1105": "Ingress Tool Transfer",
    "T1216.002": "SyncAppvPublishingServer",
    "T1098.002": "Additional Email Delegate Permissions",
    "T1588.003": "Code Signing Certificates",
    "T1126": "Network Share Connection Removal",
    "T1648": "Serverless Execution",
    "T1548.006": "TCC Manipulation",
    "T1084": "Windows Management Instrumentation Event Subscription",
    "T1160": "Launch Daemon",
    "T1055.008": "Ptrace System Calls",
    "T1653": "Power Settings",
    "T1027.007": "Dynamic API Resolution",
    "T1021.001": "Remote Desktop Protocol",
    "T1037.001": "Logon Script (Windows)",
    "T1055.015": "ListPlanting",
    "T1665": "Hide Infrastructure",
    "T1484": "Domain or Tenant Policy Modification",
    "T1220": "XSL Script Processing",
    "T1596.005": "Scan Databases",
    "T1564.001": "Hidden Files and Directories",
    "T1578.001": "Create Snapshot",
    "T1591.001": "Determine Physical Locations",
    "T1137.002": "Office Test",
    "T1587": "Develop Capabilities",
    "T1173": "Dynamic Data Exchange",
    "T1003.003": "NTDS",
    "T1602.001": "SNMP (MIB Dump)",
    "T1001.002": "Steganography",
    "T1204.001": "Malicious Link",
    "T1550.001": "Application Access Token",
    "T1547.008": "LSASS Driver",
    "T1569.002": "Service Execution",
    "T1078.004": "Cloud Accounts",
    "T1480.001": "Environmental Keying",
    "T1008": "Fallback Channels",
    "T1564.004": "NTFS File Attributes",
    "T1558.003": "Kerberoasting",
    "T1096": "NTFS File Attributes",
    "T1003.006": "DCSync",
    "T1124": "System Time Discovery",
    "T1053.002": "At",
    "T1035": "Service Execution",
    "T1055.001": "Dynamic-link Library Injection",
    "T1086": "PowerShell",
    "T1588.005": "Exploits",
    "T1556": "Modify Authentication Process",
    "T1546.017": "Udev Rules",
    "T1056.004": "Credential API Hooking",
    "T1495": "Firmware Corruption",
    "T1490": "Inhibit System Recovery",
    "T1546.007": "Netsh Helper DLL",
    "T1566.003": "Spearphishing via Service",
    "T1090.001": "Internal Proxy",
    "T1216": "System Script Proxy Execution",
    "T1094": "Custom Command and Control Protocol",
    "T1102.001": "Dead Drop Resolver",
    "T1118": "InstallUtil",
    "T1001.001": "Junk Data",
    "T1598.001": "Spearphishing Service",
    "T1043": "Commonly Used Port",
    "T1505.006": "vSphere Installation Bundles",
    "T1552.007": "Container API",
    "T1584.001": "Domains",
    "T1505.001": "SQL Stored Procedures",
    "T1556.004": "Network Device Authentication",
    "T1561.001": "Disk Content Wipe",
    "T1213.005": "Messaging Applications",
    "T1048.003": "Exfiltration Over Unencrypted Non-C2 Protocol",
    "T1027.015": "Compression",
    "T1574.004": "Dylib Hijacking",
    "T1601.002": "Downgrade System Image",
    "T1078.003": "Local Accounts",
    "T1669": "Wi-Fi Networks",
    "T1211": "Exploitation for Defense Evasion",
    "T1127": "Trusted Developer Utilities Proxy Execution",
    "T1529": "System Shutdown/Reboot",
    "T1218.014": "MMC",
    "T1564.010": "Process Argument Spoofing",
    "T1077": "Windows Admin Shares",
    "T1574.012": "COR_PROFILER"
}


# Default author identity
ACTOR_identity = {"type": "identity", "spec_version":"2.1", "id": f"identity--{str(uuid.uuid4())}", "name": "ACTOR Extractor", "description": "LLM driven CTI extractor", "identity_class":"organization", "sectors":["education"], "contact_information": "Digital Security Group, University of Oslo"}
ACTOR_id = ACTOR_identity["id"]

# Add default author identity to bundle
gen_stix_bundle["objects"].append(ACTOR_identity)


# Default created / modified timestamp in RFC 3389 format
timestamp = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


# Default generic intrusion set
gen_stix_intrusion_set = {
    "type":"intrusion-set",
    "spec_version":"2.1",
    "id":"intrusion-set--"+str(uuid.uuid4()),
    "created":timestamp,
    "modified":timestamp,
    "created_by_ref":ACTOR_id,
    "name":"An intrusion set", #TODO fix this generic title
    "description":"Modify as seen fit"}

# Add the default intrusion set to the stix bundle
gen_stix_bundle["objects"].append(gen_stix_intrusion_set)


# Default ID for intrusion set
intrusion_set_id = gen_stix_intrusion_set["id"]

###############################################
#
#
#       BEGIN WORKFLOW STUFF HERE
#
#
#
################################################

#   OVERRIDE LLM MODEL HERE
# for example
#ThreatAgent.model=Ollama(id="gemma3:12b-it-qat", options={"num_ctx":3000, "temperature":0.1}, keep_alive=0)
#

retry_value = 1     # change the max amount of retries globally for each step. Alternatively in the workflow (bottom of file change each step manually)

#### Functions for each workflow step

def getAnnotations(step_input: StepInput): # change to step input
    
    threat_report = step_input.input
    
    # Get the file name so we can add it to the Report SDO we create later
    filename_regex = r"[^\\/]+$"
    reportFind = re.search(filename_regex, str(threat_report))
    reportName = reportFind.group(0)
    
    # Generate a STIX Report SDO
    if reportName:
        report_dict = {
            "type": "report",
            "id": "report--" + str(uuid.uuid4()),
            "spec_version": "2.1",
            "name": reportName,
            "created":timestamp,
            "modified":timestamp,
            "report_type":["threat-report"],
            "object_refs": []
            }

        report_id = report_dict["id"]
        
        derivation_RDO = {
            "type": "relationship",
            "id": "relationship--" + str(uuid.uuid4()),
            "spec_version": "2.1",
            "created_by_ref": ACTOR_id,
            "created": timestamp,
            "modified": timestamp,
            "relationship_type": "derived-from",
            "source_ref": gen_stix_intrusion_set["id"],
            "target_ref": report_id,
            "description": "This intrusion set was generated by the ACTOR LLM Workflow, by processing the threat report text and transforming it into STIX 2.1"
        }
        
        
        report_dict["object_refs"].append(intrusion_set_id)
        gen_stix_bundle["objects"].append(report_dict)
        gen_stix_bundle["objects"].append(derivation_RDO)
    
    # Get the metadata topics and text
    with open(threat_report, 'r', encoding='utf-8') as file:
        data = json.load(file)
    
    # Return the metadata topics and text 
    return StepOutput(content={"data": data, "report_dict": report_dict})



def getAnnotatedMetadata(step_input: StepInput):
    
    # Get the entire threat report JSON with annotations and text
    previous_data = step_input.previous_step_content
    threat_report = previous_data["data"]  # Extract the data portion

    
    
    
    threat_actor_text_collated = ""
    threat_actor_exists = False
    
    malware_text_collated = ""
    malware_exists = False
    
    process_text_collated = ""
    process_exists = False
    
    tool_text_collated = ""
    tool_exists = False
    
    technique_text_collated = ""
    technique_exists = False
    
    domain_text_collated = ""
    domain_exists = False
    
    email_text_collated = ""
    email_exists = False
    
    filename_text_collated = ""
    filename_exists = False
    
    directory_text_collated = ""
    directory_exists = False
    
    registry_text_collated = ""
    registry_exists = False
    
    IPV4_text_collated = ""
    IPV4_exists = False
    
    IPV6_text_collated = ""
    IPV6_exists = False
    
    
    
    for doc in threat_report.get("documents", []):
        for page in doc.get("pages", []):
            
            # Check if Threat Actor metadata exists, collate the text for each Threat Actor annotated text
            topics = set(page.get("topics", []))
            if "Threat Actor" in topics:
                
                threat_actor_exists = True
                threat_actor_text_collated += "\n" + page['text']

            if "Malware" in topics:
                
                malware_exists = True
                malware_text_collated += "\n" + page['text']
                

            if "Process" in topics:
                
                process_exists = True
                process_text_collated += "\n" + page['text']
                
            # Treat "Tool" and "Software" as the same - logic workaround #TODO revision layer to scope 'tool' 'malware' and 'software' exclusivity 
            if any(t in topics for t in ("Tool", "Software")):
                tool_exists = True
                tool_text_collated += "\n" + page["text"]
                
            
            if "TTPs" in topics:
                
                technique_exists = True
                technique_text_collated += "\n" + page['text']
                
            if "Domain" in topics:
                
                domain_exists = True
                domain_text_collated += "\n" + page['text']
                
            if "Email" in topics:
                
                email_exists = True
                email_text_collated += "\n" + page['text']
                
            if "Filename" in topics:
                
                filename_exists = True
                filename_text_collated += "\n" + page['text']
                
            if "Directory" in topics:
                
                directory_exists = True
                directory_text_collated += "\n" + page['text']
                
            if "Registry" in topics:
                
                registry_exists = True
                registry_text_collated += "\n" + page['text']
                
                
            if "IPV4" in topics:
                
                IPV4_exists = True
                IPV4_text_collated += "\n" + page['text']
                
            if "IPV6" in topics:
                
                IPV6_exists = True
                IPV6_text_collated += "\n" + page['text']
                
            
                            
            
                
    return StepOutput(
        content={
            "threat_actor_exists": threat_actor_exists,
            "threat_actor_text": threat_actor_text_collated,
            "malware_exists": malware_exists,
            "malware_text": malware_text_collated,
            "process_exists": process_exists,
            "process_text": process_text_collated,
            "tool_exists": tool_exists,
            "tool_text": tool_text_collated,
            "technique_exists": technique_exists,
            "technique_text": technique_text_collated,
            "domain_exists": domain_exists,
            "domain_text": domain_text_collated,
            "email_exists": email_exists,
            "email_text": email_text_collated,
            "filename_exists": filename_exists,
            "filename_text": filename_text_collated,
            "directory_exists": directory_exists,
            "directory_text": directory_text_collated,
            "registry_exists": registry_exists,
            "registry_text": registry_text_collated,
            "IPV4_exists": IPV4_exists,
            "IPV4_text": IPV4_text_collated,
            "IPV6_exists": IPV6_exists,
            "IPV6_text": IPV6_text_collated,
        }
    )
    
def check_threat_actor(step_input: StepInput) -> bool:
    test_content = step_input.get_step_content("Get Annotated Data")
    return test_content["threat_actor_exists"]


def processThreatActor(step_input: StepInput):
    content = step_input.get_step_content("Get Annotated Data")
    threat_actor_text = content["threat_actor_text"]
    
    # Get the initial report SDO created in the first step.
    # We will use the Report SDO to Threat Actor object_refs  
    metadata = step_input.get_step_content("Get Metadata")
    report_dict = metadata["report_dict"]
    
    # Process the relevent threat actor text with the Threat Actor Agent
    ThreatActorResponse = findThreatActorAgent.run(fr"This is the excerpt: '{threat_actor_text}'")
    
    print("DEBUGGING THREAT ACTOR RESPONSE: ", ThreatActorResponse.content)
    

    # If something exists create a Threat Actor SDO
    if "NO THREAT ACTOR" not in str(ThreatActorResponse.content).upper():
        if ThreatActorResponse.content.found == True:
            for threatActor in ThreatActorResponse.content.threat_actors:
                threatActorOutput = ThreatActorSchema(
                    type="threat-actor",
                    id=fr"threat-actor--{uuid.uuid4()}",
                    created_by_ref=ACTOR_id,
                    created=timestamp,
                    modified=timestamp,
                    name=threatActor,
                    aliases=[threatActor]
                )
                threatActorSDO_dict = threatActorOutput.model_dump()
                
                # Create the relationship between an instrusion set and the threat actor
                
                relationship_sdo = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--" + str(uuid.uuid4()),
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type":"attributed-to",
                    "source_ref":gen_stix_intrusion_set["id"],
                    "target_ref": threatActorSDO_dict["id"],
                    "created_by_ref":ACTOR_id
                }
                
                # Add the threat actor ID to the report object_refs
                report_dict["object_refs"].append(threatActorSDO_dict["id"])
                gen_stix_bundle["objects"].append(threatActorSDO_dict)
                gen_stix_bundle["objects"].append(relationship_sdo)
                #report_dict["object_refs"].append(relationship_sdo["id"])
                

    return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": report_dict})
    
def check_malware(step_input: StepInput) -> bool:
    malware_content = step_input.get_step_content("Get Annotated Data")
    return malware_content["malware_exists"]

def check_tool(step_input: StepInput) -> bool:
    tool_content = step_input.get_step_content("Get Annotated Data")
    return tool_content["tool_exists"]

def check_process(step_input: StepInput) -> bool:
    process_content = step_input.get_step_content("Get Annotated Data")
    return process_content["process_exists"]

def processMalware(step_input: StepInput):
    content = step_input.get_step_content("Get Annotated Data")
    malware_text = content["malware_text"]
    threat_actor_exists = content["threat_actor_exists"]
    
    print("######################################")
    print(threat_actor_exists)
    print("######################################")
    
    previous_step = step_input.previous_step_content
    bundle = previous_step["bundle"]
    report = previous_step["report_sdo"]
    
    # Get the initial report SDO created in the first step.
    # We will use the Report SDO to Threat Actor object_refs  
    metadata = step_input.get_step_content("Get Metadata")
    report_dict = metadata["report_dict"]
    
    # Process the relevent threat actor text with the Threat Actor Agent
    # TODO Evaluate the two agents
    # Agent 1 
    #MalwareResponse = MalwareAgent.run(fr"This is the excerpt: '{malware_text}'")
    # Agent 2
    MalwareResponse = MalwarePreAnalysisAgent.run(fr"This is the excerpt: '{malware_text}'")

    # If something exists create a Threat Actor SDO
    if "NO MALWARE" not in str(MalwareResponse.content).upper():
        if MalwareResponse.content.found == True:
            for malware in MalwareResponse.content.malwares:
                malwareOutput = MalwareSchema(
                    type="malware",
                    id=fr"malware--{uuid.uuid4()}",
                    created_by_ref=ACTOR_id,
                    created=timestamp,
                    modified=timestamp,
                    name=malware,
                    
                )
                
                malwareSDO_dict = malwareOutput.model_dump()
                gen_stix_bundle["objects"].append(malwareSDO_dict)
                report_dict["object_refs"].append(malwareSDO_dict["id"])
                

                
                
                # Create the relationship between an instrusion set and the threat actor
                '''
                if threat_actor_exists:
                    threat_actors = [obj for obj in bundle.get("objects", [])
                    if obj.get("type") == "threat-actor"]
                    
                    for ta in threat_actors:
                        checkRelationshipResponse = checkRelationship.run(
                            f"Threat Actor: {ta.get('name')}\n"
                            f"Malware: {malware}\n"
                            f"Relationship: uses\n\n"
                            f"Text: {malware_text}\n\n"
                            f"Does the text state that {ta.get('name')} uses {malware}?"
                        )
                        print("#"*12)
                        print("Debugging")
                        print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {malware} ")
                        print("#"*12)
                        
                        if checkRelationshipResponse.content.result == "True":

                            
                            print("#"*12)
                            print("Debugging")
                            print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {malware} ")
                            print("#"*12)
                            
                            relationship_TA_to_Malware = {
                                "type":"relationship",
                                "id": "relationship--" + str(uuid.uuid4()),
                                "spec_version": "2.1",
                                "created": timestamp,
                                "modified": timestamp,
                                "relationship_type": "uses",
                                "source_ref": ta.get("id"),
                                "target_ref": malwareSDO_dict["id"]
                            }
                            gen_stix_bundle["objects"].append(relationship_TA_to_Malware)
                '''
                describeRelationship = createDescriptionAgent.run(fr"Please describe the relationship between the intrusion set and {malware} in the following threat report: {malware_text}")                
                relationshipDescription = describeRelationship.content.description
                relationshipDescription = str(relationshipDescription)
                
                relationship_sdo = {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": "relationship--" + str(uuid.uuid4()),
                        "created": timestamp,
                        "modified": timestamp,
                        "relationship_type":"uses",
                        "source_ref":gen_stix_intrusion_set["id"],
                        "target_ref": malwareSDO_dict["id"],
                        "created_by_ref":ACTOR_id,
                        "description": relationshipDescription
                    }
                gen_stix_bundle["objects"].append(relationship_sdo)
                #report_dict["object_refs"].append(relationship_sdo["id"])
                
                genPattern = createPatternAgent.run(f"Please create a STIX pattern for this STIX object: {malwareOutput} ") 
                
                pattern_obj = {
                        "type": "indicator",
                        "name": f"Indicator for {malware}",
                        "spec_version": "2.1",
                        "id": "indicator--" + str(uuid.uuid4()),
                        "created": timestamp,
                        "modified": timestamp,
                        "pattern": genPattern.content.pattern
                    }
                
                gen_stix_bundle["objects"].append(pattern_obj)
                report_dict["object_refs"].append(pattern_obj["id"])
                
                pattern_relationship = {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": "relationship--" + str(uuid.uuid4()),
                        "created": timestamp,
                        "modified": timestamp,
                        "relationship_type":"indicates",
                        "source_ref":pattern_obj["id"],
                        "target_ref": malwareSDO_dict["id"],
                        "created_by_ref":ACTOR_id
                    }
            
                
                gen_stix_bundle["objects"].append(pattern_relationship)
                report_dict["object_refs"].append(pattern_relationship["id"])


    return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": report_dict})

def processTool(step_input: StepInput):
    content = step_input.get_step_content("Get Annotated Data")
    tool_text = content["tool_text"]
    threat_actor_exists = content["threat_actor_exists"]
    
    print("######################################")
    print(threat_actor_exists)
    print("######################################")
    
    previous_step = step_input.previous_step_content
    bundle = previous_step["bundle"]
    report = previous_step["report_sdo"]
    
    # Get the initial report SDO created in the first step.
    # We will use the Report SDO to Threat Actor object_refs  
    metadata = step_input.get_step_content("Get Metadata")
    report_dict = metadata["report_dict"]
    
    # Process the relevent threat actor text with the Threat Actor Agent
    SoftwareResponse = findSoftwareValueAgent.run(fr"This is the excerpt: '{tool_text}'")

    # If something exists create a Threat Actor SDO
    if "NO SOFT" not in str(SoftwareResponse.content).upper(): # TODO create logic that changes software to tool
        if SoftwareResponse.content.found == True:
            for software in SoftwareResponse.content.softwares:
                toolOutput = SoftwareSchema(
                    type="tool",
                    id=fr"tool--{uuid.uuid4()}",
                    created_by_ref=ACTOR_id,
                    created=timestamp,
                    modified=timestamp,
                    name=software,
                    
                )
                
                toolSDO_dict = toolOutput.model_dump()
                gen_stix_bundle["objects"].append(toolSDO_dict)
                report_dict["object_refs"].append(toolSDO_dict["id"])
                

                
                
                # Create the relationship between an instrusion set and the threat actor
                '''
                if threat_actor_exists:
                    threat_actors = [obj for obj in bundle.get("objects", [])
                    if obj.get("type") == "threat-actor"]
                    
                    for ta in threat_actors:
                        checkRelationshipResponse = checkRelationship.run(
                            f"Threat Actor: {ta.get('name')}\n"
                            f"Software: {software}\n"
                            f"Relationship: uses\n\n"
                            f"Text: {tool_text}\n\n"
                            f"Does the text state that {ta.get('name')} uses {software}? Only return True if the text explicitly says that {ta.get('name')} executed, leveraged, or employed {software}"
                        )
                        
                        if checkRelationshipResponse.content.result == "True":

                            
                            print("#"*12)
                            print("Debugging")
                            print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {software} ")
                            print("#"*12)
                            
                            relationship_TA_to_Malware = {
                                "type":"relationship",
                                "id": "relationship--" + str(uuid.uuid4()),
                                "spec_version": "2.1",
                                "created": timestamp,
                                "modified": timestamp,
                                "relationship_type": "uses",
                                "source_ref": ta.get("id"),
                                "target_ref": toolSDO_dict["id"]
                            }
                            gen_stix_bundle["objects"].append(relationship_TA_to_Malware)
                
                # create indicator object
                
                processIndicator = {
                                    "type": "indicator",
                                    "spec_version": "2.1",
                                    "id": "indicator--" + str(uuid.uuid4()),
                                    "created": timestamp,
                                    "modified": timestamp,
                                    "indicator_types": ["malicious-activity"],
                                    "name": "Malicious Activity Indicator",
                                    "description": "Automatically generated indicator for a malicious process -- placeholder",
                                    "pattern": f"[file:name MATCHES '{software}']",
                                    "pattern_type": "stix"
                                    #"valid_from": "2010-01-01T00:00:00Z"
                                    }
                # Append indicator to bundles and report
                gen_stix_bundle["objects"].append(processIndicator)
                report_dict["object_refs"].append(processIndicator["id"])
                
                processIndicator_relationship = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--" + str(uuid.uuid4()),
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type": "indicates",
                    "source_ref": processIndicator.get("id"),
                    "target_ref": toolSDO_dict["id"]
                    #"valid_from": "2010-01-01T00:00:00Z"
                    }
                
                gen_stix_bundle["objects"].append(processIndicator_relationship)
                report_dict["object_refs"].append(processIndicator_relationship["id"])
            '''
            
                describeRelationship = createDescriptionAgent.run(fr"Please describe the relationship between the intrusion set and {software} in the following threat report: {tool_text}")                
                relationshipDescription = describeRelationship.content.description
                relationshipDescription = str(relationshipDescription)
            
                relationship_sdo = {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": "relationship--" + str(uuid.uuid4()),
                        "created": timestamp,
                        "modified": timestamp,
                        "relationship_type":"uses",
                        "source_ref":gen_stix_intrusion_set["id"],
                        "target_ref": toolSDO_dict["id"],
                        "created_by_ref":ACTOR_id,
                        "description":relationshipDescription
                    }
                gen_stix_bundle["objects"].append(relationship_sdo)
                #report_dict["object_refs"].append(relationship_sdo["id"])
                
                # create pattern
                
                genPattern = createPatternAgent.run(f"Please create a STIX pattern for this STIX object: {toolOutput} ") 
                
                pattern_obj = {
                        "type": "indicator",
                        "name": f"Indicator for {software}",
                        "spec_version": "2.1",
                        "id": "indicator--" + str(uuid.uuid4()),
                        "created": timestamp,
                        "modified": timestamp,
                        "pattern": genPattern.content.pattern
                    }
                
                gen_stix_bundle["objects"].append(pattern_obj)
                report_dict["object_refs"].append(pattern_obj["id"])
                
                pattern_relationship = {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": "relationship--" + str(uuid.uuid4()),
                        "created": timestamp,
                        "modified": timestamp,
                        "relationship_type":"indicates",
                        "source_ref":pattern_obj["id"],
                        "target_ref": toolSDO_dict["id"],
                        "created_by_ref":ACTOR_id
                    }
            
                
                gen_stix_bundle["objects"].append(pattern_relationship)
                report_dict["object_refs"].append(pattern_relationship["id"])

    return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": report_dict})
                    
                    
def processProcess(step_input: StepInput):
    content = step_input.get_step_content("Get Annotated Data")
    process_text = content["process_text"]
    threat_actor_exists = content["threat_actor_exists"]
    
    print("######################################")
    print(threat_actor_exists)
    print("######################################")
    
    previous_step = step_input.previous_step_content
    bundle = previous_step["bundle"]
    report = previous_step["report_sdo"]
    
    # Get the initial report SDO created in the first step.
    # We will use the Report SDO to Threat Actor object_refs  
    metadata = step_input.get_step_content("Get Metadata")
    report_dict = metadata["report_dict"]
    
    # Process the relevent threat actor text with the Threat Actor Agent
    ProcessResponse = findProcessNameAgent.run(fr"This is the excerpt: '{process_text}'")

    # If something exists create a Threat Actor SDO
    if "NO PROCESS" not in str(ProcessResponse.content).upper():
        if ProcessResponse.content.found == True:
            for process in ProcessResponse.content.processes:
                processOutput = ProcessSchema(
                    type="process",
                    id=fr"process--{uuid.uuid4()}",
                    created_by_ref=ACTOR_id,
                    created=timestamp,
                    modified=timestamp,
                    name=process,
                )
                
                processSDO_dict = processOutput.model_dump()
                gen_stix_bundle["objects"].append(processSDO_dict)
                report_dict["object_refs"].append(processSDO_dict["id"])
                

                
                
                # Create the relationship between an instrusion set and the threat actor
                '''
                if threat_actor_exists:
                    threat_actors = [obj for obj in bundle.get("objects", [])
                    if obj.get("type") == "threat-actor"]
                    
                    for ta in threat_actors:
                        checkRelationshipResponse = checkRelationship.run(
                            f"Threat Actor: {ta.get('name')}\n"
                            f"Process: {process}\n"
                            f"Relationship: uses\n\n"
                            f"Text: {process_text}\n\n"
                            f"Does the text state that {ta.get('name')} uses or has used {process}?"
                        )
                        print("#"*12)
                        print("Debugging")
                        print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                        print("#"*12)
                        
                        if checkRelationshipResponse.content.result == "True":

                            
                            print("#"*12)
                            print("Debugging")
                            print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                            print("#"*12)
                            
                            relationship_TA_to_Malware = {
                                "type":"relationship",
                                "id": "relationship--" + str(uuid.uuid4()),
                                "spec_version": "2.1",
                                "created": timestamp,
                                "modified": timestamp,
                                "relationship_type": "uses",
                                "source_ref": ta.get("id"),
                                "target_ref": processSDO_dict["id"]
                            }
                            gen_stix_bundle["objects"].append(relationship_TA_to_Malware)
                           '''
                           
                describeRelationship = createDescriptionAgent.run(fr"Please describe the relationship between the intrusion set and {process} in the following threat report: {process_text}")                
                relationshipDescription = describeRelationship.content.description
                relationshipDescription = str(relationshipDescription)
                
                relationship_sdo = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--" + str(uuid.uuid4()),
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type":"uses",
                    "source_ref":gen_stix_intrusion_set["id"],
                    "target_ref": processSDO_dict["id"],
                    "created_by_ref":ACTOR_id,
                    "description":relationshipDescription
                }
                gen_stix_bundle["objects"].append(relationship_sdo)
                #report_dict["object_refs"].append(relationship_sdo["id"])
                

    return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": report_dict})
                    
                    #return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": report_dict})
                    
def check_technique(step_input: StepInput) -> bool:
    technique_content = step_input.get_step_content("Get Annotated Data")
    return technique_content["technique_exists"]


def processTechnique(step_input: StepInput):
    content = step_input.get_step_content("Get Annotated Data")
    technique_text = content["technique_text"]
    threat_actor_exists = content["threat_actor_exists"]
    
    # Get the initial report SDO created in the first step.
    # We will use the Report SDO to Threat Actor object_refs  
    metadata = step_input.get_step_content("Get Metadata")
    report_dict = metadata["report_dict"]
    
    previous_step = step_input.previous_step_content
    bundle = previous_step["bundle"]
    report = previous_step["report_sdo"]
    
    # Process the relevent threat actor text with the Threat Actor Agent
    TechniqueResponse = findTechniqueIDAgent.run(fr"This is the excerpt: '{technique_text}'")
    
    print("Debugging technique response: ", TechniqueResponse.content)

    # If something exists create a Threat Actor SDO
    if "NO TECHN" not in str(TechniqueResponse.content).upper():
        if TechniqueResponse.content.found == True:
            for technique in TechniqueResponse.content.techniques:
                
                # Avoid fake techniques
                if technique in techniqueNames:
                
                    techniqueOutput = TechniqueSchema(
                        type="attack-pattern",
                        id=fr"attack-pattern--{uuid.uuid4()}",
                        created_by_ref=ACTOR_id,
                        created=timestamp,
                        modified=timestamp,
                        name=techniqueNames[technique], ## todo fix
                        external_references=[
                        {
                        "source_name": "mitre-attack", 
                        "external_id": f"{technique}"
                        }
                        ]
                    )
                    techniqueSDO_dict = techniqueOutput.model_dump()
                    
                    # Create the relationship between an instrusion set and the threat actor
                    
                    # TODO deprecated remove
                    '''
                    if threat_actor_exists:
                        pass
                        threat_actors = [obj for obj in bundle.get("objects", [])
                        if obj.get("type") == "threat-actor"]
                        
                        for ta in threat_actors:
                            
                            
                            checkRelationshipResponse = checkRelationship.run(
                                f"Threat Actor: {ta.get('name')}\n"
                                f"Process: {process}\n"
                                f"Relationship: uses\n\n"
                                f"Text: {process_text}\n\n"
                                f"Does the text state that {ta.get('name')} uses or has used {process}?"
                            )
                            print("#"*12)
                            print("Debugging")
                            print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                            print("#"*12)
                            
                            if checkRelationshipResponse.content.result == "True":

                                
                                print("#"*12)
                                print("Debugging")
                                print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                                print("#"*12)
                                
                            relationship_TA_to_Malware = {
                                    "type":"relationship",
                                    "id": "relationship--" + str(uuid.uuid4()),
                                    "spec_version": "2.1",
                                    "created": timestamp,
                                    "modified": timestamp,
                                    "relationship_type": "uses",
                                    "source_ref": ta.get("id"),
                                    "target_ref": techniqueSDO_dict["id"]
                                }
                            gen_stix_bundle["objects"].append(relationship_TA_to_Malware)
                    
                    '''
                    describeRelationship = createDescriptionAgent.run(fr"Please describe the relationship between the intrusion set and {technique} in the following threat report: {technique_text}")                
                    relationshipDescription = describeRelationship.content.description
                    relationshipDescription = str(relationshipDescription)
                    relationship_sdo = {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": "relationship--" + str(uuid.uuid4()),
                        "created": timestamp,
                        "modified": timestamp,
                        "relationship_type":"uses",
                        "source_ref":gen_stix_intrusion_set["id"],
                        "target_ref": techniqueSDO_dict["id"],
                        "created_by_ref":ACTOR_id,
                        "description":relationshipDescription
                    }
                    
                    
                    # Add the technique ID to the report object_refs
                    report_dict["object_refs"].append(techniqueSDO_dict["id"])
                    gen_stix_bundle["objects"].append(techniqueSDO_dict)
                    gen_stix_bundle["objects"].append(relationship_sdo)
                    #report_dict["object_refs"].append(relationship_sdo["id"])
                

    return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": report_dict})
    
def check_domain(step_input: StepInput) -> bool:
    domain_content = step_input.get_step_content("Get Annotated Data")
    return domain_content["domain_exists"]


def processDomain(step_input: StepInput):
    content = step_input.get_step_content("Get Annotated Data")
    domain_text = content["domain_text"]
    threat_actor_exists = content["threat_actor_exists"]
    
    # Get the initial report SDO created in the first step.
    # We will use the Report SDO to Threat Actor object_refs  
    metadata = step_input.get_step_content("Get Metadata")
    report_dict = metadata["report_dict"]
    
    previous_step = step_input.previous_step_content
    bundle = previous_step["bundle"]
    report = previous_step["report_sdo"]
    
    # Process the relevent threat actor text with the Threat Actor Agent
    DomainResponse = findDomainNameAgent.run(fr"This is the excerpt: '{domain_text}'")
    

    # If something exists create a Threat Actor SDO
    if "NO DOMAIN" not in str(DomainResponse.content).upper():
        if DomainResponse.content.found == True:
            for domain in DomainResponse.content.domains:
                domainOutput = DomainSchema(
                    type="domain-name",
                    id=fr"domain-name--{uuid.uuid4()}",
                    created_by_ref=ACTOR_id,
                    created=timestamp,
                    modified=timestamp,
                    value=domain,
                )
                domainSDO_dict = domainOutput.model_dump()
                
                # Create the relationship between an instrusion set and the threat actor
                
                ''''
                if threat_actor_exists:
                    threat_actors = [obj for obj in bundle.get("objects", [])
                    if obj.get("type") == "threat-actor"]
                    
                    for ta in threat_actors:
                        
                        
                        checkRelationshipResponse = checkRelationship.run(
                            f"Threat Actor: {ta.get('name')}\n"
                            f"Process: {process}\n"
                            f"Relationship: uses\n\n"
                            f"Text: {process_text}\n\n"
                            f"Does the text state that {ta.get('name')} uses or has used {process}?"
                        )
                        print("#"*12)
                        print("Debugging")
                        print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                        print("#"*12)
                        
                        if checkRelationshipResponse.content.result == "True":

                            
                            print("#"*12)
                            print("Debugging")
                            print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                            print("#"*12)
                            
                        relationship_TA_to_Malware = {
                                "type":"relationship",
                                "id": "relationship--" + str(uuid.uuid4()),
                                "spec_version": "2.1",
                                "created": timestamp,
                                "modified": timestamp,
                                "relationship_type": "uses",
                                "source_ref": ta.get("id"),
                                "target_ref": domainSDO_dict["id"]
                            }
                        gen_stix_bundle["objects"].append(relationship_TA_to_Malware)
                
                '''
                describeRelationship = createDescriptionAgent.run(fr"Please describe the relationship between the intrusion set and {domain} in the following threat report: {domain_text}")                
                relationshipDescription = describeRelationship.content.description
                relationshipDescription = str(relationshipDescription)
                relationship_sdo = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--" + str(uuid.uuid4()),
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type":"uses",
                    "source_ref":gen_stix_intrusion_set["id"],
                    "target_ref": domainSDO_dict["id"],
                    "created_by_ref":ACTOR_id,
                    "description":relationshipDescription
                }
                
                
                # Add the technique ID to the report object_refs
                report_dict["object_refs"].append(domainSDO_dict["id"])
                gen_stix_bundle["objects"].append(domainSDO_dict)
                gen_stix_bundle["objects"].append(relationship_sdo)
                #report_dict["object_refs"].append(relationship_sdo["id"])
                


    return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": report_dict})
    
def check_email(step_input: StepInput) -> bool:
    email_content = step_input.get_step_content("Get Annotated Data")
    return email_content["email_exists"]


def processEmail(step_input: StepInput):
    content = step_input.get_step_content("Get Annotated Data")
    email_text = content["email_text"]
    threat_actor_exists = content["threat_actor_exists"]
    
    # Get the initial report SDO created in the first step.
    # We will use the Report SDO to Threat Actor object_refs  
    metadata = step_input.get_step_content("Get Metadata")
    report_dict = metadata["report_dict"]
    
    previous_step = step_input.previous_step_content
    bundle = previous_step["bundle"]
    report = previous_step["report_sdo"]
    
    # Process the relevent threat actor text with the Threat Actor Agent
    EmailResponse = findEmailAddressAgent.run(fr"This is the excerpt: '{email_text}'")
    

    # If something exists create a Threat Actor SDO
    if "NO EMAIL" not in str(EmailResponse.content).upper():
        if EmailResponse.content.found == True:
            for email in EmailResponse.content.emails:
                EmailOutput = EmailAddressSchema(
                    type="email-addr",
                    id=fr"email-addr--{uuid.uuid4()}",
                    created_by_ref=ACTOR_id,
                    created=timestamp,
                    modified=timestamp,
                    value=email,
                )
                EmailSDO_dict = EmailOutput.model_dump()
                
                # Create the relationship between an instrusion set and the threat actor
                
                '''
                if threat_actor_exists:
                    threat_actors = [obj for obj in bundle.get("objects", [])
                    if obj.get("type") == "threat-actor"]
                    
                    for ta in threat_actors:
                        
                        
                        checkRelationshipResponse = checkRelationship.run(
                            f"Threat Actor: {ta.get('name')}\n"
                            f"Process: {process}\n"
                            f"Relationship: uses\n\n"
                            f"Text: {process_text}\n\n"
                            f"Does the text state that {ta.get('name')} uses or has used {process}?"
                        )
                        print("#"*12)
                        print("Debugging")
                        print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                        print("#"*12)
                        
                        if checkRelationshipResponse.content.result == "True":

                            
                            print("#"*12)
                            print("Debugging")
                            print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                            print("#"*12)
                            
                        relationship_TA_to_Malware = {
                                "type":"relationship",
                                "id": "relationship--" + str(uuid.uuid4()),
                                "spec_version": "2.1",
                                "created": timestamp,
                                "modified": timestamp,
                                "relationship_type": "uses",
                                "source_ref": ta.get("id"),
                                "target_ref": EmailSDO_dict["id"]
                            }
                        gen_stix_bundle["objects"].append(relationship_TA_to_Malware)
                
                '''
                describeRelationship = createDescriptionAgent.run(fr"Please describe the relationship between the intrusion set and {email} in the following threat report: {email_text}")                
                relationshipDescription = describeRelationship.content.description
                relationshipDescription = str(relationshipDescription)
                relationship_sdo = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--" + str(uuid.uuid4()),
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type":"uses",
                    "source_ref":gen_stix_intrusion_set["id"],
                    "target_ref": EmailSDO_dict["id"],
                    "created_by_ref":ACTOR_id,
                    "description":email_text
                }
                
                
                # Add the technique ID to the report object_refs
                report_dict["object_refs"].append(EmailSDO_dict["id"])
                gen_stix_bundle["objects"].append(EmailSDO_dict)
                gen_stix_bundle["objects"].append(relationship_sdo)
                #report_dict["object_refs"].append(relationship_sdo["id"])
                

    return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": report_dict})
                
def check_filename(step_input: StepInput) -> bool:
    filename_content = step_input.get_step_content("Get Annotated Data")
    return filename_content["filename_exists"]


def processFilename(step_input: StepInput):
    content = step_input.get_step_content("Get Annotated Data")
    filename_text = content["filename_text"]
    threat_actor_exists = content["threat_actor_exists"]
    
    # Get the initial report SDO created in the first step.
    # We will use the Report SDO to Threat Actor object_refs  
    metadata = step_input.get_step_content("Get Metadata")
    report_dict = metadata["report_dict"]
    
    previous_step = step_input.previous_step_content
    bundle = previous_step["bundle"]
    report = previous_step["report_sdo"]
    
    # Process the relevent threat actor text with the Threat Actor Agent
    FilenameResponse = findFileNameAgent.run(fr"This is the excerpt: '{filename_text}'")
    

    # If something exists create a Threat Actor SDO
    if "NO FILE" not in str(FilenameResponse.content).upper():
        if FilenameResponse.content.found == True:
            for filename in FilenameResponse.content.files:
                FilenameOutput = FileNameSchema(
                    type="file",
                    id=fr"file--{uuid.uuid4()}",
                    created_by_ref=ACTOR_id,
                    created=timestamp,
                    modified=timestamp,
                    name=filename,
                )
                FilenameSDO_dict = FilenameOutput.model_dump()
                
                # Create the relationship between an instrusion set and the threat actor
                
                '''
                if threat_actor_exists:
                    threat_actors = [obj for obj in bundle.get("objects", [])
                    if obj.get("type") == "threat-actor"]
                    
                    for ta in threat_actors:
                        
                        
                        checkRelationshipResponse = checkRelationship.run(
                            f"Threat Actor: {ta.get('name')}\n"
                            f"Process: {process}\n"
                            f"Relationship: uses\n\n"
                            f"Text: {process_text}\n\n"
                            f"Does the text state that {ta.get('name')} uses or has used {process}?"
                        )
                        print("#"*12)
                        print("Debugging")
                        print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                        print("#"*12)
                        
                        if checkRelationshipResponse.content.result == "True":

                            
                            print("#"*12)
                            print("Debugging")
                            print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                            print("#"*12)
                            
                        relationship_TA_to_Malware = {
                                "type":"relationship",
                                "id": "relationship--" + str(uuid.uuid4()),
                                "spec_version": "2.1",
                                "created": timestamp,
                                "modified": timestamp,
                                "relationship_type": "uses",
                                "source_ref": ta.get("id"),
                                "target_ref": FilenameSDO_dict["id"]
                            }
                        gen_stix_bundle["objects"].append(relationship_TA_to_Malware)
                
                '''
                describeRelationship = createDescriptionAgent.run(fr"Please describe the relationship between the intrusion set and {filename} in the following threat report: {filename_text}")                
                relationshipDescription = describeRelationship.content.description
                relationshipDescription = str(relationshipDescription)
                relationship_sdo = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--" + str(uuid.uuid4()),
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type":"uses",
                    "source_ref":gen_stix_intrusion_set["id"],
                    "target_ref": FilenameSDO_dict["id"],
                    "created_by_ref":ACTOR_id,
                    "description":relationshipDescription
                }
                
                
                # Add the technique ID to the report object_refs
                report_dict["object_refs"].append(FilenameSDO_dict["id"])
                gen_stix_bundle["objects"].append(FilenameSDO_dict)
                gen_stix_bundle["objects"].append(relationship_sdo)
                #report_dict["object_refs"].append(relationship_sdo["id"])
                

    return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": report_dict})
    
def check_directory(step_input: StepInput) -> bool:
    directory_content = step_input.get_step_content("Get Annotated Data")
    return directory_content["directory_exists"]


def processDirectory(step_input: StepInput):
    content = step_input.get_step_content("Get Annotated Data")
    directory_text = content["directory_text"]
    threat_actor_exists = content["threat_actor_exists"]
    
    # Get the initial report SDO created in the first step.
    # We will use the Report SDO to Threat Actor object_refs  
    metadata = step_input.get_step_content("Get Metadata")
    report_dict = metadata["report_dict"]
    
    previous_step = step_input.previous_step_content
    bundle = previous_step["bundle"]
    report = previous_step["report_sdo"]
    
    # Process the relevent threat actor text with the Threat Actor Agent
    DirectoryResponse = findDirectoryAgent.run(fr"This is the excerpt: '{directory_text}'")
    

    # If something exists create a Threat Actor SDO
    if "NO DIRECTORY" not in str(DirectoryResponse.content).upper():
        if DirectoryResponse.content.found == True:
            for directory in DirectoryResponse.content.directories:
                DirectoryOutput = DirectorySchema(
                    type="directory",
                    id=fr"directory--{uuid.uuid4()}",
                    created_by_ref=ACTOR_id,
                    created=timestamp,
                    modified=timestamp,
                    name=directory,
                )
                DirectorySDO_dict = DirectoryOutput.model_dump()
                
                # Create the relationship between an instrusion set and the threat actor
                
                '''
                if threat_actor_exists:
                    threat_actors = [obj for obj in bundle.get("objects", [])
                    if obj.get("type") == "threat-actor"]
                    
                    for ta in threat_actors:
                        
                        
                        checkRelationshipResponse = checkRelationship.run(
                            f"Threat Actor: {ta.get('name')}\n"
                            f"Process: {process}\n"
                            f"Relationship: uses\n\n"
                            f"Text: {process_text}\n\n"
                            f"Does the text state that {ta.get('name')} uses or has used {process}?"
                        )
                        print("#"*12)
                        print("Debugging")
                        print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                        print("#"*12)
                        
                        if checkRelationshipResponse.content.result == "True":

                            
                            print("#"*12)
                            print("Debugging")
                            print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                            print("#"*12)
                            
                        relationship_TA_to_Malware = {
                                "type":"relationship",
                                "id": "relationship--" + str(uuid.uuid4()),
                                "spec_version": "2.1",
                                "created": timestamp,
                                "modified": timestamp,
                                "relationship_type": "uses",
                                "source_ref": ta.get("id"),
                                "target_ref": FilenameSDO_dict["id"]
                            }
                        gen_stix_bundle["objects"].append(relationship_TA_to_Malware)
                
                '''
                describeRelationship = createDescriptionAgent.run(fr"Please describe the relationship between the intrusion set and {directory} in the following threat report: {directory_text}")                
                relationshipDescription = describeRelationship.content.description
                relationshipDescription = str(relationshipDescription)
                relationship_sdo = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--" + str(uuid.uuid4()),
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type":"uses",
                    "source_ref":gen_stix_intrusion_set["id"],
                    "target_ref": DirectorySDO_dict["id"],
                    "created_by_ref":ACTOR_id,
                    "description":relationshipDescription
                }
                
                
                # Add the technique ID to the report object_refs
                report_dict["object_refs"].append(DirectorySDO_dict["id"])
                gen_stix_bundle["objects"].append(DirectorySDO_dict)
                gen_stix_bundle["objects"].append(relationship_sdo)
                #report_dict["object_refs"].append(relationship_sdo["id"])
                

    return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": report_dict})
    
    
def check_registry(step_input: StepInput) -> bool:
    registry_content = step_input.get_step_content("Get Annotated Data")
    return registry_content["registry_exists"]


def processRegistry(step_input: StepInput):
    content = step_input.get_step_content("Get Annotated Data")
    registry_text = content["registry_text"]
    threat_actor_exists = content["threat_actor_exists"]
    
    # Get the initial report SDO created in the first step.
    # We will use the Report SDO to Threat Actor object_refs  
    metadata = step_input.get_step_content("Get Metadata")
    report_dict = metadata["report_dict"]
    
    previous_step = step_input.previous_step_content
    bundle = previous_step["bundle"]
    report = previous_step["report_sdo"]
    
    # Process the relevent threat actor text with the Threat Actor Agent
    RegistryResponse = findRegistryValueAgent.run(fr"This is the excerpt: '{registry_text}'")
    

    # If something exists create a Threat Actor SDO
    if "NO REGIS" not in str(RegistryResponse.content).upper():
        if RegistryResponse.content.found == True:
            for registry in RegistryResponse.content.registries:
                RegistryOutput = RegistrySchema(
                    type="registry",
                    id=fr"registry--{uuid.uuid4()}",
                    created_by_ref=ACTOR_id,
                    created=timestamp,
                    modified=timestamp,
                    value=registry,
                )
                RegistrySDO_dict = RegistryOutput.model_dump()
                
                # Create the relationship between an instrusion set and the threat actor
                
                '''
                if threat_actor_exists:
                    threat_actors = [obj for obj in bundle.get("objects", [])
                    if obj.get("type") == "threat-actor"]
                    
                    for ta in threat_actors:
                        
                        
                        checkRelationshipResponse = checkRelationship.run(
                            f"Threat Actor: {ta.get('name')}\n"
                            f"Process: {process}\n"
                            f"Relationship: uses\n\n"
                            f"Text: {process_text}\n\n"
                            f"Does the text state that {ta.get('name')} uses or has used {process}?"
                        )
                        print("#"*12)
                        print("Debugging")
                        print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                        print("#"*12)
                        
                        if checkRelationshipResponse.content.result == "True":

                            
                            print("#"*12)
                            print("Debugging")
                            print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                            print("#"*12)
                            
                        relationship_TA_to_Malware = {
                                "type":"relationship",
                                "id": "relationship--" + str(uuid.uuid4()),
                                "spec_version": "2.1",
                                "created": timestamp,
                                "modified": timestamp,
                                "relationship_type": "uses",
                                "source_ref": ta.get("id"),
                                "target_ref": FilenameSDO_dict["id"]
                            }
                        gen_stix_bundle["objects"].append(relationship_TA_to_Malware)
                
                '''
                describeRelationship = createDescriptionAgent.run(fr"Please describe the relationship between the intrusion set and {registry} in the following threat report: {registry_text}")                
                relationshipDescription = describeRelationship.content.description
                relationshipDescription = str(relationshipDescription)
                relationship_sdo = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--" + str(uuid.uuid4()),
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type":"uses",
                    "source_ref":gen_stix_intrusion_set["id"],
                    "target_ref": RegistrySDO_dict["id"],
                    "created_by_ref":ACTOR_id,
                    "description": relationshipDescription
                }
                
                
                # Add the technique ID to the report object_refs
                report_dict["object_refs"].append(RegistrySDO_dict["id"])
                gen_stix_bundle["objects"].append(RegistrySDO_dict)
                gen_stix_bundle["objects"].append(relationship_sdo)
                #report_dict["object_refs"].append(relationship_sdo["id"])
                

    return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": report_dict})
    
    
def check_IPV4(step_input: StepInput) -> bool:
    IPV4_content = step_input.get_step_content("Get Annotated Data")
    return IPV4_content["IPV4_exists"]


def processIPV4(step_input: StepInput):
    content = step_input.get_step_content("Get Annotated Data")
    IPV4_text = content["IPV4_text"]
    threat_actor_exists = content["threat_actor_exists"]
    
    # Get the initial report SDO created in the first step.
    # We will use the Report SDO to Threat Actor object_refs  
    metadata = step_input.get_step_content("Get Metadata")
    report_dict = metadata["report_dict"]
    
    previous_step = step_input.previous_step_content
    bundle = previous_step["bundle"]
    report = previous_step["report_sdo"]
    
    # Process the relevent threat actor text with the Threat Actor Agent
    IPV4Response = findIPV4Agent.run(fr"This is the excerpt: '{IPV4_text}'")
    
    print(f"########### DEBUGGING IPV4 RESPONSE: {IPV4Response.content}")

    # If something exists create a Threat Actor SDO
    if "NO IP" not in str(IPV4Response.content).upper():
        if IPV4Response.content.found == True:
            for IPV4 in IPV4Response.content.ips:
                IPV4Output = IPV4Schema(
                    type="ipv4-addr",
                    id=fr"ipv4-addr--{uuid.uuid4()}",
                    created_by_ref=ACTOR_id,
                    created=timestamp,
                    modified=timestamp,
                    value=IPV4,
                )
                IPV4SDO_dict = IPV4Output.model_dump()
                
                # Create the relationship between an instrusion set and the threat actor
                
                '''
                if threat_actor_exists:
                    threat_actors = [obj for obj in bundle.get("objects", [])
                    if obj.get("type") == "threat-actor"]
                    
                    for ta in threat_actors:
                        
                        
                        checkRelationshipResponse = checkRelationship.run(
                            f"Threat Actor: {ta.get('name')}\n"
                            f"Process: {process}\n"
                            f"Relationship: uses\n\n"
                            f"Text: {process_text}\n\n"
                            f"Does the text state that {ta.get('name')} uses or has used {process}?"
                        )
                        print("#"*12)
                        print("Debugging")
                        print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                        print("#"*12)
                        
                        if checkRelationshipResponse.content.result == "True":

                            
                            print("#"*12)
                            print("Debugging")
                            print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                            print("#"*12)
                            
                        relationship_TA_to_Malware = {
                                "type":"relationship",
                                "id": "relationship--" + str(uuid.uuid4()),
                                "spec_version": "2.1",
                                "created": timestamp,
                                "modified": timestamp,
                                "relationship_type": "uses",
                                "source_ref": ta.get("id"),
                                "target_ref": FilenameSDO_dict["id"]
                            }
                        gen_stix_bundle["objects"].append(relationship_TA_to_Malware)
                
                '''
                describeRelationship = createDescriptionAgent.run(fr"Please describe the relationship between the intrusion set and {IPV4} in the following threat report: {IPV4_text}")                
                relationshipDescription = describeRelationship.content.description
                relationshipDescription = str(relationshipDescription)
                relationship_sdo = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--" + str(uuid.uuid4()),
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type":"uses",
                    "source_ref":gen_stix_intrusion_set["id"],
                    "target_ref": IPV4SDO_dict["id"],
                    "created_by_ref":ACTOR_id,
                    "description":relationshipDescription
                }
                
                
                # Add the technique ID to the report object_refs
                report_dict["object_refs"].append(IPV4SDO_dict["id"])
                gen_stix_bundle["objects"].append(IPV4SDO_dict)
                gen_stix_bundle["objects"].append(relationship_sdo)
                #report_dict["object_refs"].append(relationship_sdo["id"])
                

    return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": report_dict})
    
def check_IPV6(step_input: StepInput) -> bool:
    IPV6_content = step_input.get_step_content("Get Annotated Data")
    return IPV6_content["IPV6_exists"]


def processIPV6(step_input: StepInput):
    content = step_input.get_step_content("Get Annotated Data")
    IPV6_text = content["IPV6_text"]
    threat_actor_exists = content["threat_actor_exists"]
    
    # Get the initial report SDO created in the first step.
    # We will use the Report SDO to Threat Actor object_refs  
    metadata = step_input.get_step_content("Get Metadata")
    report_dict = metadata["report_dict"]
    
    previous_step = step_input.previous_step_content
    bundle = previous_step["bundle"]
    report = previous_step["report_sdo"]
    
    # Process the relevent threat actor text with the Threat Actor Agent
    IPV6Response = findIPV6Agent.run(fr"This is the excerpt: '{IPV6_text}'")
    

    # If something exists create a Threat Actor SDO
    if "NO IP" not in str(IPV6Response.content).upper():
        if IPV6Response.content.found == True:
            for IPV6 in IPV6Response.content.ips:
                IPV6Output = IPV6Schema(
                    type="ipv6-addr",
                    id=fr"ipv6-addr--{uuid.uuid4()}",
                    created_by_ref=ACTOR_id,
                    created=timestamp,
                    modified=timestamp,
                    value=IPV6,
                )
                IPV6SDO_dict = IPV6Output.model_dump()
                
                # Create the relationship between an instrusion set and the threat actor
                
                '''
                if threat_actor_exists:
                    threat_actors = [obj for obj in bundle.get("objects", [])
                    if obj.get("type") == "threat-actor"]
                    
                    for ta in threat_actors:
                        
                        
                        checkRelationshipResponse = checkRelationship.run(
                            f"Threat Actor: {ta.get('name')}\n"
                            f"Process: {process}\n"
                            f"Relationship: uses\n\n"
                            f"Text: {process_text}\n\n"
                            f"Does the text state that {ta.get('name')} uses or has used {process}?"
                        )
                        print("#"*12)
                        print("Debugging")
                        print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                        print("#"*12)
                        
                        if checkRelationshipResponse.content.result == "True":

                            
                            print("#"*12)
                            print("Debugging")
                            print(fr"{checkRelationshipResponse.content}:: {ta.get("name")} {checkRelationshipResponse.content} {process} ")
                            print("#"*12)
                            
                        relationship_TA_to_Malware = {
                                "type":"relationship",
                                "id": "relationship--" + str(uuid.uuid4()),
                                "spec_version": "2.1",
                                "created": timestamp,
                                "modified": timestamp,
                                "relationship_type": "uses",
                                "source_ref": ta.get("id"),
                                "target_ref": FilenameSDO_dict["id"]
                            }
                        gen_stix_bundle["objects"].append(relationship_TA_to_Malware)
                
                '''
                describeRelationship = createDescriptionAgent.run(fr"Please describe the relationship between the intrusion set and {IPV6} in the following threat report: {IPV6_text}")                
                relationshipDescription = describeRelationship.content.description
                relationshipDescription = str(relationshipDescription)
                relationship_sdo = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--" + str(uuid.uuid4()),
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type":"uses",
                    "source_ref":gen_stix_intrusion_set["id"],
                    "target_ref": IPV6SDO_dict["id"],
                    "created_by_ref":ACTOR_id,
                    "description":relationshipDescription
                }
                
                
                # Add the technique ID to the report object_refs
                report_dict["object_refs"].append(IPV6SDO_dict["id"])
                gen_stix_bundle["objects"].append(IPV6SDO_dict)
                gen_stix_bundle["objects"].append(relationship_sdo)
                #report_dict["object_refs"].append(relationship_sdo["id"])
                

    return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": report_dict})

                
def refreshContent(step_input: StepInput):
    # Check in reverse order - most recent first
    IPV6_output = step_input.get_step_content("Process IPV6 SDO")
    IPV4_output = step_input.get_step_content("Process IPV4 SDO")
    registry_output = step_input.get_step_content("Process Registry SDO")
    directory_output = step_input.get_step_content("Process Directory SDO")
    filename_output = step_input.get_step_content("Process Filename SDO")
    email_output = step_input.get_step_content("Process Email SDO")
    domain_output = step_input.get_step_content("Process Domain SDO")
    technique_output = step_input.get_step_content("Process Technique SDO")
    tool_output = step_input.get_step_content("Process Software SDO")
    process_output = step_input.get_step_content("Process Process SDO")
    malware_output = step_input.get_step_content("Process Malware SDO")
    threat_actor_output = step_input.get_step_content("Process Threat Actor SDO")
        
    if IPV6_output and isinstance(IPV6_output, dict):
        bundle = tool_output["bundle"]
        report = tool_output["report_sdo"]
        
    elif IPV4_output and isinstance(IPV4_output, dict):
        bundle = tool_output["bundle"]
        report = tool_output["report_sdo"]
    elif registry_output and isinstance(registry_output, dict):
        bundle = tool_output["bundle"]
        report = tool_output["report_sdo"]
    elif directory_output and isinstance(directory_output, dict):
        bundle = tool_output["bundle"]
        report = tool_output["report_sdo"]
    elif filename_output and isinstance(filename_output, dict):
        bundle = tool_output["bundle"]
        report = tool_output["report_sdo"]   
    elif email_output and isinstance(email_output, dict):
        bundle = tool_output["bundle"]
        report = tool_output["report_sdo"]   
    elif domain_output and isinstance(domain_output, dict):
        bundle = tool_output["bundle"]
        report = tool_output["report_sdo"]    
    elif technique_output and isinstance(technique_output, dict):
        bundle = tool_output["bundle"]
        report = tool_output["report_sdo"] 
    elif tool_output and isinstance(tool_output, dict):
        bundle = tool_output["bundle"]
        report = tool_output["report_sdo"]    
    elif process_output and isinstance(process_output, dict):
        bundle = process_output["bundle"]
        report = process_output["report_sdo"]
    elif malware_output and isinstance(malware_output, dict):
        bundle = malware_output["bundle"]
        report = malware_output["report_sdo"]
    elif threat_actor_output and isinstance(threat_actor_output, dict):
        bundle = threat_actor_output["bundle"]
        report = threat_actor_output["report_sdo"]
    else:
        bundle = gen_stix_bundle
        metadata = step_input.get_step_content("Get Metadata")
        report = metadata["report_dict"]
    
    '''
    if process_output and isinstance(process_output, dict):
        bundle = malware_output["bundle"]
        report = malware_output["report_sdo"]    
    elif process_output and isinstance(process_output, dict):
        bundle = malware_output["bundle"]
        report = malware_output["report_sdo"]
    elif malware_output and isinstance(malware_output, dict):
        bundle = malware_output["bundle"]
        report = malware_output["report_sdo"]
    elif threat_actor_output and isinstance(threat_actor_output, dict):
        bundle = threat_actor_output["bundle"]
        report = threat_actor_output["report_sdo"]
    else:
        bundle = gen_stix_bundle
        metadata = step_input.get_step_content("Get Metadata")
        report = metadata["report_dict"]
    '''
    return StepOutput(content={"bundle": bundle, "report_sdo": report})
        
'''
def refreshContent(step_input: StepInput):
    previous_step = step_input.previous_step_content
    
    # If previous step is None or not a dict, get from earlier step
    if not isinstance(previous_step, dict) or "bundle" not in previous_step:
        # Get from the last step that had the bundle
        previous_step = step_input.get_step_content("Process Threat Actor SDO")
        if not previous_step:
            # If threat actor step didn't run, initialize with empty bundle
            return StepOutput(content={"bundle": gen_stix_bundle, "report_sdo": step_input.get_step_content("Get Metadata")["report_dict"]})
    
    bundle = previous_step["bundle"]
    report = previous_step["report_sdo"]
    
    return StepOutput(content={"bundle": bundle, "report_sdo": report})
'''
    
def next(step_input: StepInput) -> StepOutput:
    previous_step = step_input.previous_step_content
    bundle = previous_step["bundle"]
    report = previous_step["report_sdo"]
    
    return StepOutput(content={"bundle": bundle, "report_sdo": report})
    
    
def writeToJSON(step_input: StepInput) -> StepOutput:
    refresh_output = step_input.get_step_content("Refresh Bundle")

    
    bundle = refresh_output["bundle"]
    report = refresh_output["report_sdo"]
    
    filename = "sampleOutput.json"
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(bundle, f, indent=4, ensure_ascii=False)
    
    
    return StepOutput(content="Written to JSON file")



 
###########################
#
#           STEPS
#
###########################    
STEP_getMetadata = Step(
    name="Get Metadata",
    executor=getAnnotations,
    max_retries=retry_value
)

STEP_getAnnotatedData = Step(
    name="Get Annotated Data",
    executor=getAnnotatedMetadata,
    max_retries=retry_value
)

STEP_createSoftware = Step(
    name="Process Software SDO",
    executor=processTool,
    max_retries=1
)


STEP_createThreatActor = Step(
    name="Process Threat Actor SDO",
    executor=processThreatActor,
    max_retries=1
)

STEP_createMalware = Step(
    name="Process Malware SDO",
    executor=processMalware,
    max_retries=1
)

STEP_createProcess = Step(
    name="Process Process SDO",
    executor=processProcess,
    max_retries=1
)

STEP_createTechnique = Step(
    name="Process Technique SDO",
    executor=processTechnique,
    max_retries=1
)

STEP_createDomain = Step(
    name="Process Domain SDO",
    executor=processDomain,
    max_retries=1
)

STEP_createEmail = Step(
    name="Process Email SDO",
    executor=processEmail,
    max_retries=1
)

STEP_createFilename = Step(
    name="Process Filename SDO",
    executor=processFilename,
    max_retries=1
)

STEP_createDirectory = Step(
    name="Process Directory SDO",
    executor=processDirectory,
    max_retries=1
)

STEP_createRegistry = Step(
    name="Process Registry SDO",
    executor=processRegistry,
    max_retries=1
)

STEP_createIPV4 = Step(
    name="Process IPV4 SDO",
    executor=processIPV4,
    max_retries=1
)

STEP_createIPV6 = Step(
    name="Process IPV6 SDO",
    executor=processIPV6,
    max_retries=1
)

STEP_writeBundle = Step(
    name="Write STIX Bundle",
    executor=writeToJSON,
    max_retries=1
)

STEP_refreshBundle = Step(
    name = "Refresh Bundle",
    executor=refreshContent,
    max_retries=1
)

STEP_next = Step(
    name="next",
    executor=next,
    max_retries=1
)


if __name__ == "__main__":
    analyse_report_workflow = Workflow(
        name="CTI Extraction Workflow",
        description="Automated extraction of CTI from a provided threat report",
        # Define the sequence of steps
        # First run the research_step, then the content_planning_step
        # You can mix and match agents, teams, and even regular python functions directly as steps
        steps=[STEP_getMetadata, STEP_getAnnotatedData,
                Condition(
                name="Check threat actor exists",
                evaluator=check_threat_actor,
                steps=[STEP_createThreatActor]
            ),
            STEP_refreshBundle,
            Condition(
                name="Check malware exists",
                evaluator=check_malware,
                steps=[STEP_createMalware]
            ),
            STEP_refreshBundle,
            Condition(
                name="Check process exists",
                evaluator=check_process,
                steps=[STEP_createProcess]
            ),
            STEP_refreshBundle,
            Condition(
                name="Check software exists",
                evaluator=check_tool,
                steps=[STEP_createSoftware]
            ),
            Condition(
                name="Check technique exists",
                evaluator=check_technique,
                steps=[STEP_createTechnique]
            ),
            STEP_refreshBundle,
            Condition(
                name="Check domain exists",
                evaluator=check_domain,
                steps=[STEP_createDomain]
            ),
            STEP_refreshBundle,
            Condition(
                name="Check email exists",
                evaluator=check_email,
                steps=[STEP_createEmail]
            ),
            STEP_refreshBundle,
            Condition(
                name="Check filename exists",
                evaluator=check_filename,
                steps=[STEP_createFilename]
            ),
            STEP_refreshBundle,
            Condition(
                name="Check directory exists",
                evaluator=check_directory,
                steps=[STEP_createDirectory]
            ),
            STEP_refreshBundle,
            Condition(
                name="Check registry exists",
                evaluator=check_registry,
                steps=[STEP_createRegistry]
            ),
            STEP_refreshBundle,
            Condition(
                name="Check IPV4 exists",
                evaluator=check_IPV4,
                steps=[STEP_createIPV4]
            ),
            STEP_refreshBundle,
            Condition(
                name="Check IPV6 exists",
                evaluator=check_IPV6,
                steps=[STEP_createIPV6]
            ),
            #STEP_next,
            STEP_refreshBundle,
            STEP_writeBundle],
    )
    analyse_report_workflow.print_response(
        #input="datasets/outputs/STIXnet/annotations/testAnnotations/0_metadata_output.json",
        #input="datasets/outputs/STIXnet/annotations/testAnnotations/0_metadata_output_test2.json",
        input="datasets/outputs/STIXnet/annotations/sample/gemma3-12b/test1_0_metadata_output.json",
        markdown=True,
        stream=True,
        debug_mode=True # enabled for testing. #TODO disable if implemented in GUI
    )
    
# TODO fix bottlenecks, clear up comments and redundant junk

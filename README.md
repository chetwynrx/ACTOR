# ACTOR

# Agentic CTI Extraction Tool 🕵️‍♂️🛡️

An early-stage prototype for an **Agentic Workflow** that automates the extraction of **Cyber Threat Intelligence (CTI)** from unstructured threat reports and converts them into standardized **STIX 2.1 Bundles**.

---

## 📖 Overview
This project transforms narrative threat report text into machine-readable intelligence. By utilizing local AI agents, it parses annotated excerpts to identify entities (Threat Actors, Malware, etc.) and establishes relationships between them, outputting a final JSON bundle.

### Core Objectives
- **Standardization:** Map raw text to the STIX 2.1 data model.
- **Agentic Logic:** Use specialized AI agents for high-accuracy extraction.
- **Local Sovereignty:** Powered by **Ollama** and **Agno** to ensure all data stays local.

---

## ⚙️ How It Works
The workflow is a deterministic pipeline orchestrated by the **Agno** framework:

1.  **Metadata Ingestion:** Reads a report file containing "Annotations" (semantic labels).
2.  **Conditional Routing:** The workflow activates specific agents only if their corresponding entity type (e.g., Malware) is tagged in the report.
3.  **Entity Extraction:** Specialized AI agents process the text to identify specific values (IPs, MD5s, Actor names).
4.  **STIX Creation:** Generates STIX Domain Objects (SDOs) and Cyber Observable Objects (SCOs).
5.  **Relational Mapping:** Links entities (e.g., *Threat Actor -> uses -> Malware*).
6.  **JSON Output:** Saves the final result as a validated STIX bundle.

---

## 🤖 Specialized AI Agents
The system features a robust library of over 20 specialized agents.

### 👥 Threat Actor & Behavioral Agents
| Agent Name | Description |
| :--- | :--- |
| `findThreatActorAgent` | Extracts names of APT groups, cybercriminal gangs, etc. |
| `createDescriptionAgent` | Creates a summary of why an entity is relevant to an intrusion set. |
| `findTechniqueIDAgent` | Extracts and validates MITRE ATT&CK technique identifiers. |
| `checkRelationship` | Identifies if a relationship exists between an actor and an entity. |

### ☣️ Malware & Technical Agents
| Agent Name | Description |
| :--- | :--- |
| `MalwareAgent` | Extracts explicitly mentioned malware family names. |
| `findSoftwareValueAgent` | Identifies utilities, frameworks, and C2 tools. |
| `findProcessNameAgent` | Identifies process names (e.g., `.exe` files) in suspicious contexts. |

### 🌐 Infrastructure & Network Agents
| Agent Name | Description |
| :--- | :--- |
| `findDomainNameAgent` | Identifies apex domains, subdomains, wildcards, and IDNs. |
| `findIPV4Agent` / `findIPV6Agent` | Extracts and validates IPv4 and IPv6 addresses. |
| `findEmailAddressAgent` | Extracts email addresses from the intelligence report. |

### 📂 Forensic & System Agents
| Agent Name | Description |
| :--- | :--- |
| `findFileNameAgent` | Identifies filenames and full system paths. |
| `findDirectoryAgent` | Identifies Windows and Unix file system directories. |
| `findRegistryValueAgent` | Extracts Windows Registry keys and specific value names. |

### 🛠 Utility Agents
| Agent Name | Description |
| :--- | :--- |
| `createPatternAgent` | Generates STIX 2.1 patterns for cyber observable objects. |

---

## 🛠 Tech Stack
* **Framework:** [Agno](https://docs.agno.com) (Multi-agent orchestration)
* **LLM Runtime:** [Ollama](https://ollama.com) (Local model hosting)
* **Language:** Python 3.x

---

## 🚀 Usage Guide

### 1. Annotating a Document
Reports must be "annotated" (tagged with semantic labels) before processing.
* **Script:** `annotateMetadata_example.py`
* **Action:** Assigns labels like "Threat Actor" or "Malware" to the file.

### 2. Generating the STIX Bundle
Once annotated, run the main orchestrator.
* **Script:** `ACTOR_workflow_example.py`
* **Output:** A STIX 2.1 Bundle JSON file in the root directory.

### 🔧 Modifications & Settings
* **Change Model:** Update `user_defined_model` in the scripts or `aiAgents/agents.py`.
* **Adjust Context:** Modify the `num_ctx` value for token window management.
* **Change Files:** Update `reportFile` or `exportAnnotations` in the annotation script.

---

## 📊 Supported STIX Objects
The tool currently implements the following SDOs and COOs:
> Threat Actor, Malware, Process, Attack Pattern, Software, Tool, Domain Name, Email, Filename, Directory, Registry, IPv4, IPv6, Identity, Indicator, Intrusion Set, and Relationships.

---

## ⚠️ Known Limitations
* **Attack Patterns:** Limited to explicit ID extraction (T1234). A GraphRAG pipeline for semantic similarity is in development.
* **Infrastructure:** Infrastructure objects are not yet fully modeled.
* **Performance:** The workflow is sequential (not parallel) due to local hardware limitations. Bottlenecks are known and a a fix is in progress to make the processing more efficient.
* **Patterns:** Indicator pattern logic is currently basic and undergoing refinement.
* **UI:** Terminal-based execution only.

---

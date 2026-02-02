from agno.agent import Agent, RunOutput
from agno.models.ollama import Ollama

from pydantic import BaseModel, Field
from typing import List, Optional

from agno.utils.pprint import pprint_run_response

class Metadata(BaseModel):
    page_number: int = Field(
        ..., description="This is the current page number."
    )
    topics: List[str] = Field(..., description="The identified topics for this text excerpt.")

class MetadataReview(BaseModel):
    page_number: int = Field(
        ..., description="This is the current page number."
    )
    topics: List[str] = Field(..., description="The reviewed topics for this text excerpt.")



class Page(BaseModel):
    page_number: int = Field(..., description="The page number")
    topics: List[str] = Field(..., description="Topics identified in this page")
    text: str = Field(..., description="The text content of the page")

class Document(BaseModel):
    document_id: str = Field(..., description="Unique identifier for the document")
    title: str = Field(..., description="Title of the document")
    pages: List[Page] = Field(..., description="List of pages in the document")

class DocumentContainer(BaseModel):
    documents: List[Document] = Field(..., description="List of documents")




topicsDict = {
    "Campaign": "Threat intelligence that refers to threat intelligence about a higher-level view of adversarial activity that connects lower-level details.",
    "Identity": "Threat intelligence that refers to individuals, targets, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, systems or groups (e.g., the finance sector). Not the threat actor itself though.",
    "Location": "Refers to threat intelligence identifying a geographic location. The location may be described as any, some or all of the following: region (e.g., North America), civic address (e.g. New York, US), latitude and longitude. Locations are primarily used to give context to other SDOs. For example, a Location could be used in a relationship to describe that the Bourgeois Swallow intrusion set originates from Eastern Europe.",
    "CVEs": "Threat intelligence that refers to threat intelligence that contains a CVE ID. The common vulnerabilities and exposures (CVE) system are specific vulnerabilities with a cve ID such as CVE-1234.",
    "Email": "Threat intelligence that refers to any mention of an email address.",
    "Artifact": "Threat intelligence that refers to any reference that includes an array of bytes, base64-encoded strings, or links to file-like payloads.",
    "AS Object": "Threat intelligence that refers to properties of an Autonomous System.",
    "Directory": "Threat intelligence that refers to properties common to a file system directory.",
    "Domain": "Threat intelligence that refers to properties of a network domain name.",
    "Hash": "Threat intelligence that refers to hash values such as MD5, SHA256, SHA-1 and other hashes.",
    "File": "Threat intelligence that refers to the properties of a file.",
    "Infrastructure": "Threat intelligence that refers to computing resources involved in a threat (e.g., C2 servers).",
    "IPV4": "Threat intelligence that refers to respective addresses.",
    "IPV6": "Threat intelligence that refers to respective addresses.",
    "MAC": "Threat intelligence that refers to a Media Access Control address.",
    "Malware": "Threat intelligence that refers to harmful software.",
    "Mutex": "Threat intelligence that refers to properties of mutual exclusion objects.",
    "Network Traffic": "Threat intelligence that refers to source and destination network traffic.",
    "Process": "Threat intelligence that refers to properties of executed computer programs.",
    "Software": "Threat intelligence that refers to general properties associated with software.",
    "Tool": "Any threat intelligence that refers to a legitimate software that can be used by threat actors to perform attacks. Unlike malware, these tools or software packages are often found on a system and have legitimate purposes for power users, system administrators, network administrators, or even normal users. Remote access tools (e.g., RDP) and network scanning tools (e.g., Nmap) are examples of Tools that may be used by a Threat Actor during an attack.",
    "URL": "Threat intelligence that refers to properties of URLs.",
    "User Account": "Threat intelligence that refers to instances of user accounts across platforms.",
    "Registry": "Threat intelligence that refers to Windows registry key properties.",
    "X.509": "Threat intelligence that refers to the properties of an X.509 certificate.",
    "Threat Actor": "Threat intelligence that refers to individuals or groups with malicious intent.",
    "TTPs": "Threat intelligence that refers to tactics, techniques, and procedures used by threat actors."
}

# Convert to a prompt string
topics = topicsDict.keys()
topicDescriptionPrompt = ""
topicKeyPrompt = ""

# Convert to a prompt string
for key, value in topicsDict.items():
    topic = (f"{key}: {value} \n")
    topicKeys = (f"{key}, ")

    
    
    topicDescriptionPrompt += topic
    topicKeyPrompt += topicKeys



tagger: Agent = Agent(
        model=Ollama(id="llama3", options={"temperature": 0.1, "num_ctx":3000}, keep_alive=0),

        description=f"""
        SUMMARY:
        You are a document analysis assistant designed to identify and tag key topics in the provided text. The provided text is taken from a cyber threat intelligence report
        that documents threat actor activities. The cyber threat intelligence in this provided text will refer to key topics that you MUST identify. 
        Your task is to analyze the text thoroughly and select the relevant topic types from the provided list of topics.
        """,
        instructions=["""TASK INSTRUCTIONS: You MUST ONLY use topics from the following list:
                            Campaign
                            Identity
                            CVEs
                            Email
                            Artifact
                            AS Object
                            Directory
                            Domain
                            Hash
                            File
                            Infrastructure
                            IPV4
                            IPV6
                            Location
                            MAC
                            Malware
                            Mutex
                            Network Traffic
                            Process
                            Software
                            Tool
                            URL
                            User Account
                            Registry
                            X.509
                            Threat Actor
                            TTPs""",
                            """You MUST use the following topic descriptions as context and guidance for choosing the correct topics:
                            Campaign: Threat intelligence that refers to threat intelligence about a higher-level view of adversarial activity that connects lower-level details.
                            Identity: Threat intelligence that refers to individuals, targets, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, systems or groups (e.g., the finance sector). Not the threat actor itself though.
                            Location: Refers to threat intelligence identifying a geographic location. The location may be described as any, some or all of the following: region (e.g., North America), civic address (e.g. New York, US), latitude and longitude. Locations are primarily used to give context to other SDOs. For example, a Location could be used in a relationship to describe that the Bourgeois Swallow intrusion set originates from Eastern Europe.
                            CVEs: Threat intelligence that refers to threat intelligence that contains a CVE ID. The common vulnerabilities and exposures (CVE) system are specific vulnerabilities with a cve ID such as CVE-1234.
                            Email: Threat intelligence that refers to any mention of an email address.
                            Artifact: Threat intelligence that refers to any reference that includes an array of bytes, base64-encoded strings, or links to file-like payloads.
                            AS Object: Threat intelligence that refers to properties of an Autonomous System.
                            Directory: Threat intelligence that refers to properties common to a file system directory.
                            Domain: Threat intelligence that refers to properties of a network domain name.
                            Hash: Threat intelligence that refers to hash values such as MD5, SHA256, SHA-1 and other hashes.
                            File: Threat intelligence that refers to the properties of a file.
                            Infrastructure: Threat intelligence that refers to computing resources involved in a threat (e.g., C2 servers).
                            IPv4: "Threat intelligence that refers to respective addresses.
                            IPv6: "Threat intelligence that refers to respective addresses.
                            MAC: Threat intelligence that refers to a Media Access Control address.
                            Malware: Threat intelligence that refers to harmful software.
                            Mutex: Threat intelligence that refers to properties of mutual exclusion objects.
                            Network Traffic: Threat intelligence that refers to source and destination network traffic.
                            Process: Threat intelligence that refers to properties of executed computer programs.
                            Software: Threat intelligence that refers to general properties associated with software.
                            Tool: Any threat intelligence that refers to a legitimate software that can be used by threat actors to perform attacks. Unlike malware, these tools or software packages are often found on a system and have legitimate purposes for power users, system administrators, network administrators, or even normal users. Remote access tools (e.g., RDP) and network scanning tools (e.g., Nmap) are examples of Tools that may be used by a Threat Actor during an attack.
                            URL: Threat intelligence that refers to properties of URLs.
                            User Account: Threat intelligence that refers to instances of user accounts across platforms.
                            Registry: Threat intelligence that refers to Windows registry key properties.
                            X.509: Threat intelligence that refers to the properties of an X.509 certificate.
                            Threat Actor: Threat intelligence that refers to individuals or groups with malicious intent.
                            TTPs: Threat intelligence that refers to tactics, techniques, and procedures used by threat actors.""",
                            """TASK REQUIREMENTS:""",
                            "DO NOT create new topics or use any terms outside of the provided topic list.",
                            "Provide only the topic labels, do not include the values that justify a topic.",
                            "Do not include any named entities in the output",
                            "If a topic is referenced in the document, provide the appropriate topic tag(s) as per the list. Use commas to separate multiple topics if necessary (e.g., 'Threat Actor', 'Malware').",
                            "Do not include the document text, reasoning, or explanations in your output.",

                            """Examples Correct topic tagging: 
                            Input:
                            'Threat Actor A is responsible for the campaign targeting financial institutions and targetting google. The email addresses used were attack@example.com. The infrastructure consists of multiple C2 servers, including 192.168.1.100.'
                            Output:
                            Threat Actor, Campaign, Identity, Email, IPv4, Infrastructure

                            Input:
                            'The analysis of network traffic revealed unusual activity from the domain name malicious-actor.com.'
                            Output:
                            Domain, Network Traffic

                            Input:
                            'The malware identified as 'TrojanXYZ' was found to utilise a vulnerability referenced as CVE-2021-34527.'
                            Output:
                            Malware, CVEs
                            
                            Examples of incorrect topic tagging:
                            Input:
                            'The analysis of network traffic revealed unusual activity originating from a Powershell process'
                            Output:
                            Powershell, Powershell.exe
                            
                            Examples of incorrect topic tagging:
                            Input:
                            'script.dll was manipulated by soehe.ps to generate a series of keys'
                            Output:
                            script.dll, soehe.ps, KEYS
                            """
                        ],
        output_schema=DocumentContainer,
        markdown=True,
        debug_mode=False,
    )

reviewer: Agent = Agent(
        model=Ollama(id="qwen3:8b", options={"temperature": 0.05, "num_ctx":5000}, keep_alive=0),

        description=f"""
        SUMMARY:
        You are a reviewing assistant tasked with validating the tagging results of key topics identified in the provided text related to cyber threat intelligence. 
        Your role is to ensure that the output contains only valid topic tags from a specified list.

        You will receive a set of topic tags that have been generated from the analysis of a document
        """,
        instructions=["""TASK INSTRUCTIONS: You MUST ONLY use topics from the following list:
                            Campaign
                            Identity
                            CVEs
                            Email
                            Artifact
                            AS Object
                            Directory
                            Domain
                            Hash
                            File
                            Infrastructure
                            IPv4
                            IPv6
                            Location
                            MAC
                            Malware
                            Mutex
                            Network Traffic
                            Process
                            Software
                            Tool
                            URL
                            User Account
                            Registry
                            X.509
                            Threat Actor
                            TTPs""",
                            """You MUST use the following topic descriptions as context and guidance for choosing the correct topics:
                            Campaign: Threat intelligence that refers to threat intelligence about a higher-level view of adversarial activity that connects lower-level details.
                            Identity: Threat intelligence that refers to individuals, targets, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, systems or groups (e.g., the finance sector). Not the threat actor itself though.
                            Location: Refers to threat intelligence identifying a geographic location. The location may be described as any, some or all of the following: region (e.g., North America), civic address (e.g. New York, US), latitude and longitude. Locations are primarily used to give context to other SDOs. For example, a Location could be used in a relationship to describe that the Bourgeois Swallow intrusion set originates from Eastern Europe.
                            CVEs: Threat intelligence that refers to threat intelligence that contains a CVE ID. The common vulnerabilities and exposures (CVE) system are specific vulnerabilities with a cve ID such as CVE-1234.
                            Email: Threat intelligence that refers to any mention of an email address.
                            Artifact: Threat intelligence that refers to any reference that includes an array of bytes, base64-encoded strings, or links to file-like payloads.
                            AS Object: Threat intelligence that refers to properties of an Autonomous System.
                            Directory: Threat intelligence that refers to properties common to a file system directory.
                            Domain: Threat intelligence that refers to properties of a network domain name.
                            Hash: Threat intelligence that refers to hash values such as MD5, SHA256, SHA-1 and other hashes.
                            File: Threat intelligence that refers to the properties of a file.
                            Infrastructure: Threat intelligence that refers to computing resources involved in a threat (e.g., C2 servers).
                            IPv4: "Threat intelligence that refers to respective addresses.
                            IPv6: "Threat intelligence that refers to respective addresses.
                            MAC: Threat intelligence that refers to a Media Access Control address.
                            Malware: Threat intelligence that refers to harmful software.
                            Mutex: Threat intelligence that refers to properties of mutual exclusion objects.
                            Network Traffic: Threat intelligence that refers to source and destination network traffic.
                            Process: Threat intelligence that refers to properties of executed computer programs.
                            Software: Threat intelligence that refers to general properties associated with software.
                            Tool: Any threat intelligence that refers to a legitimate software that can be used by threat actors to perform attacks. Unlike malware, these tools or software packages are often found on a system and have legitimate purposes for power users, system administrators, network administrators, or even normal users. Remote access tools (e.g., RDP) and network scanning tools (e.g., Nmap) are examples of Tools that may be used by a Threat Actor during an attack.
                            URL: Threat intelligence that refers to properties of URLs.
                            User Account: Threat intelligence that refers to instances of user accounts across platforms.
                            Registry: Threat intelligence that refers to Windows registry key properties.
                            X.509: Threat intelligence that refers to the properties of an X.509 certificate.
                            Threat Actor: Threat intelligence that refers to individuals or groups with malicious intent.
                            TTPs: Threat intelligence that refers to tactics, techniques, and procedures used by threat actors.""",
                            """TASK REQUIREMENTS:""",
                            "DO NOT create new topics or use any terms outside of the provided topic list.",
                            "Provide only the topic labels, do not include the values that justify a topic.",
                            "Do not include any named entities in the output",
                            "If a topic is referenced in the document, provide the appropriate topic tag(s) as per the list. Use commas to separate multiple topics if necessary (e.g., 'Threat Actor', 'Malware').",
                            "Do not include the document text, reasoning, or explanations in your output.",

                            """Examples: 
                            Input:
                            'Threat Actor A is responsible for the campaign targeting financial institutions and targetting google. The email addresses used were attack@example.com. The infrastructure consists of multiple C2 servers, including 192.168.1.100.'
                            Output:
                            Threat Actor, Campaign, Identity, Email, IPv4, Infrastructure

                            Input:
                            'The analysis of network traffic revealed unusual activity from the domain name malicious-actor.com.'
                            Output:
                            Domain, Network Traffic

                            Input:
                            'The malware identified as 'TrojanXYZ' was found to utilise a vulnerability referenced as CVE-2021-34527.'
                            Output:
                            Malware, CVEs
                            """
                        ],
        output_schema=DocumentContainer, # for reviewing evaluation
        markdown=True,
        debug_mode=False,
    )

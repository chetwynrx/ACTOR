# This is a template of an ollama agent used as the baseline for other agents
# This agent contains an instruction set, a temperature of 0.1 a dynamic model
# The model is specified at runtime, the default is llama3.2

from agno.agent import Agent
from agno.models.ollama import Ollama

# For response model stuff
from typing import Iterator, Optional, List, Literal, Dict
from pydantic import BaseModel, Field


#user_specified_model = "qwen3:8b"
#user_specified_model = "phi4:14b"
user_specified_model = "gemma3:12b"

# Auxiliary stuff to be used in general
class BooleanOutput(BaseModel):
    result: Literal["True", "False", "Unknown"]
    
    
checkRelationship = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.3, "num_ctx": 8192}),
    description="This agent aims to identity if a relationship exists between a threat actor a specific entity in a cyber threat intelligence report.",
    instructions=[
        "The user will specify the the threat actor and entity to analyse. The user will also specify the relationship to check between the threat actor and the entity.",
        "If the threat report states that two entities are related by this relationship then output True",
        "If the threat report does not state that the two entities are related then output False",
        "If you are unsure then output Unknown",
        """GUARDRAILS: 
        If the relationship between the threat actor and the entity contains any of [disguised, masquerad*, mimic*, appear*, rename*], force False for “uses."
        """,
        
        "Output your answer only as True, False or Unknown"],
    markdown=True,
    debug_mode=False,
    output_schema=BooleanOutput
)


class DescribeRelationship(BaseModel):
    description: str = Field(description="The value of the STIX pattern that identifies the specific thing.")
   

createDescriptionAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.3, "num_ctx": 8192}),
    description="This agent creates describes the relationship between the intrusion set and a specified entity in a threat intelligence report.",
    instructions = ["In a single summarised sentence, describe why the entity is relevant to the intrusion set.",
                    "Do not explain your internal reasoning, only the facts presented in the report."],
    markdown=True,
    debug_mode=False,
    output_schema=DescribeRelationship
)


    
# Threat actor specifics

# THREAT ACTOR AGENT
class ThreatActorSchema(BaseModel):
    type: str = Field(description="The value of this property MUST be threat-actor.")
    id: str = Field(description="The idea value of this object. It MUST be threat-actor: follow by the provided ID value.")
    name: str = Field(description="A name used to identify this Threat Actor or Threat Actor group.")
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )
    created_by_ref: str=Field(
        default="identity--123456"
    )
    aliases: Optional[list[str]] = Field(
        default=None,
        description="values of any aliases of this threat actor. This should include the threat actor name in the report."
    )
    
class APTIdentify(BaseModel):
    found: bool = Field(description="True if APTs found, False otherwise")
    threat_actors: list[str] = Field(
        default_factory=list,  # Changed from Optional with default=None
        description="List of threat actors found in text. Return empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no threat_actors found, return: 'No threat actors found in the provided text.'"
    )    


'''    
class APTIdentify(BaseModel):
    found: bool = Field(description="True if APTs found, False otherwise")
    threat_actors: Optional[list[str]] = Field(
        default_factory=None,
        description="List of threat actors found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no threat_actors found, return: 'No threat actors found in the provided text.'"
    )
'''

# TEMP REMOVED testing a simplified agent instruction set
'''
findThreatActorAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.2, "num_ctx": 8192}),
    description="This agent identifies Threat Actor names within cyber threat intelligence reports. It strictly follows defined pattern-matching rules and only returns actual findings from the text.",
    instructions=[
        "DEFINITION AND REQUIREMENTS (aligned with STIX Threat Actor semantics):",
        "- A Threat Actor is an individual, group, or organization believed to be operating with malicious intent (e.g., APT groups, cybercriminal gangs, government agencies, espionage, groups, hacktivist collectives).",
        "- For extraction, at least one concrete threat actor name or alias MUST appear explicitly in the text.",
        "- Minimum to extract: a clearly identified actor name or handle used as an actor (e.g., 'APT29', 'Lazarus Group', 'FIN7', 'Scattered Spider', '@evil_actor' when explicitly described as an actor).",

        "WHAT QUALIFIES AS THREAT ACTOR NAMES (case-insensitive where applicable, preserve original case):",
        "- Well-known or pattern-like actor/group names and formats:",
        "  * APT-style names (e.g., 'APT29', 'APT41').",
        "  * FIN/TA/UNC-style identifiers (e.g., 'FIN7', 'TA505', 'UNC1878').",
        "  * Named groups (e.g., 'Lazarus Group', 'Cozy Bear', 'Sandworm', 'Carbanak', 'Scattered Spider').",
        "  * Ransomware gangs/brands when explicitly used as actor entities (e.g., 'Conti', 'LockBit', 'ALPHV/BlackCat', 'Clop').",
        "- Actor handles and collective names when clearly described as threat actors:",
        "  * Handles like '@evil_actor', '0xDarkLord', 'TeamX' explicitly labeled as an actor/group.",
        "- Aliases and synonyms explicitly linked to an actor (e.g., 'aka', 'also known as', 'tracked as', 'aliases').",
        "- External identifiers for actors when explicitly tied to a name:",
        "  * MITRE ATT&CK Group IDs (e.g., 'G0032') when linked to a group name in the same snippet.",
        "  * Vendor tracking tags (e.g., 'Mandiant UNCxxxx', 'CrowdStrike ' with named actor) when they explicitly refer to an actor.",

        "ADDITIONAL ATTRIBUTES TO CAPTURE WHEN PRESENT (no inference):",
        "- name: the primary actor name as shown in the snippet (exact formatting).",
        "- aliases: list of aliases if explicitly stated (e.g., 'aka', 'also known as', 'tracked as').",
        "- roles: list of roles only if explicitly stated (e.g., 'intrusion set', 'ransomware operator', 'initial access broker', 'information stealer affiliate').",
        "- sophistication: explicit descriptor if present (e.g., 'advanced', 'expert', 'novice', 'strategic').",
        "- resource_level: explicit descriptor if present (e.g., 'nation-state', 'organization', 'club', 'individual').",
        "- primary_motivation: explicit if present (e.g., 'financial', 'espionage', 'ideological').",
        "- secondary_motivations: list if present.",
        "- goals: list if explicitly stated.",
        "- country: country attribution only if explicitly stated (e.g., 'Russia', 'North Korea'); do not infer.",
        "- sectors: list of targeted sectors only if explicitly stated (e.g., 'energy', 'healthcare').",
        "- first_seen: date/time if present (verbatim).",
        "- last_seen: date/time if present (verbatim).",
        "- associated_groups: list of other groups explicitly associated/collaborating (e.g., 'affiliated with', 'partnered with').",
        "- external_references: list of explicit external IDs or references (e.g., 'MITRE Gxxx', vendor report IDs) tied to the actor.",
        "- notes: short snippet copied from the text for context (no inference).",

        "COMMON FORMATS TO RECOGNIZE (DO NOT extract these unless they appear in the provided text):",
        "- 'APT29 (aka Cozy Bear)'",
        "- 'FIN7, also known as Carbanak Group'",
        "- 'UNC1878 (tracked by Mandiant); associated with Conti ransomware operations'",
        "- 'Lazarus Group (MITRE ATT&CK: G0032)'",
        "- 'LockBit ransomware gang claimed responsibility'",
        "- 'Scattered Spider (aka Octo Tempest)'",
        "- 'TA505 targeted the financial sector in 2023'",

        "WHAT TO EXCLUDE - NOT THREAT ACTOR NAMES:",
        "- Organization/vendor names used only as sources (e.g., 'Microsoft', 'CISA', 'Mandiant') unless the text explicitly states they are the actor (rare).",
        "- Malware/family names when not used as actor entities (e.g., 'Emotet', 'TrickBot') unless the text explicitly frames them as a group/actor.",
        "- Campaign or operation names unless explicitly mapped as an actor (e.g., 'Operation Night Dragon' without a linked actor).",
        "- Individual person names without explicit threat actor context.",
        "- Generic roles or teams without a specific actor identity (e.g., 'the attackers', 'the intrusion team').",
        "- Country names alone without explicit actor naming (e.g., 'Russia' alone is not sufficient unless explicitly naming a state actor group).",
        "- Any properties inferred from context without explicit wording (e.g., do NOT assign country or motivation unless clearly stated).",

        "PARSING AND EXTRACTION GUIDELINES:",
        "- Preserve exact strings and case for names and aliases (e.g., 'ALPHV/BlackCat').",
        "- When aliases are listed, split into items and trim whitespace and punctuation while preserving original case.",
        "- Capture external references (e.g., 'G0032') only when directly tied to the actor in the snippet.",
        "- If multiple actor names appear but are clearly linked as aliases, return a single object with 'name' as the primary mention and 'aliases' including the others.",
        "- If unrelated actors appear, return separate objects per actor.",
        "- Avoid inferring relationships or attributes not explicitly stated.",
        "- If an actor is described only by a handle (e.g., '@xyz'), extract as name and include additional attributes only if explicitly stated.",

        "EXTRACTION PROCEDURE:",
        "1. Scan the text for explicit threat actor names, handles, or group identifiers in recognized formats.",
        "2. Validate that the mention is clearly used as a threat actor entity (group/individual with malicious activity).",
        "3. Extract additional attributes (aliases, motivations, country, sectors, dates, roles) only when explicitly present.",
        #"4. Construct a structured object per actor with fields:",
        #"   - name: string (required for extraction)",
        #"   - aliases: [list of strings] if present",
        #"   - roles: [list of strings] if present",
        ##"   - sophistication: string if present",
        #"   - resource_level: string if present",
        #"   - primary_motivation: string if present",
        #"   - secondary_motivations: [list of strings] if present",
        #"   - goals: [list of strings] if present",
        #"   - country: string if present",
        #"   - sectors: [list of strings] if present",
        #"   - first_seen: string if present",
        #"   - last_seen: string if present",
        #"   - associated_groups: [list of strings] if present",
        #"   - external_references: [list of strings] if present",
        #"   - notes: short snippet from the text for context (no inference)",
        "4. Return ONLY the list of structured Threat Actor objects found.",
        "5. Treat repeated mentions as separate objects unless the text clearly indicates they refer to the same actor and context.",
        "6. Do NOT invent, hallucinate, normalize, or transform properties; preserve exact strings and formatting from the text.",

        "OUTPUT FORMAT:",
        "- Return a JSON array of objects. Preserve case and exact formatting for all extracted strings.",
        #"- Example output shape (do NOT output this unless matching content is found):",
       # "{ \"name\": \"APT29\", \"aliases\": [\"Cozy Bear\"], \"country\": \"Russia\", \"external_references\": [\"G0016\"], \"notes\": \"APT29 (aka Cozy Bear) referenced with MITRE G0016.\" }",

        "WHEN NO THREAT ACTOR NAMES ARE FOUND:",
        "If no valid Threat Actor names are found in the text, respond with:",
        "\"No Threat Actor objects found in the provided text.\"",
        
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return objects from the instructions or training data.",

        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return Threat Actor objects that actually appear in the provided text.",
        "- If you cannot find any Threat Actor names in the text, ONLY return the exact message 'No Threat Actor objects found in the provided text.'",
        "- Do NOT infer, hallucinate, suggest, or generate properties that aren't explicitly present in the text."
    ],
    markdown=True,
    debug_mode=True,
    output_schema=APTIdentify
)
'''

findThreatActorAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.2, "num_ctx": 8192}),
    description="This agent identifies Threat Actor names within cyber threat intelligence reports. It strictly follows defined pattern-matching rules and only returns actual findings from the text.",
    instructions=[
        "You are a CTI analyst. Extract all Threat Actor names from the text.",
        "1. Identify entities like APT groups, cyber groups, cybercriminal gangs, or named actors (e.g., Lazarus Group, APT30, FIN7, Government agencies).",
        "2. Only extract names explicitly mentioned. Do not infer.",
        "3. If multiple groups are mentioned (e.g., APT1 and APT30), include both in the list.",
        "4. Return an empty list if no threat actors are present.",
        "5. Ignore IP addresses, file names, and registry keys."
    ],
    markdown=True,
    debug_mode=True,
    output_schema=APTIdentify
)




''' # TODO remove deprecated
ThreatAgent: Agent = Agent(  # This agent extracts the author/organisation who curated the threat report
    name="ThreatAgent",
    description="""You are a security analyst tasked with identifying the threat actor listed in the report.
    Similarly, you will identity additional attributes associated with the threat actor. Use the structured output to guide you
    in these attribute categories.""", 
    instructions=[
        "You need to identify the threat actors in the report and their affiliation.",
        #"What are the aliases of this threat actor?"
        #"Identify when this threat actor was first seen?",
        #"Identify when this threat actor was last seen?",
        "The type is 'threat-actor' all lower case.",
        "If no threat actor can be found in the provided text then output: 'No threat actors found'.",
        "Use the provided ID. The idea value MUST be 'threat-actor:' followed by the provided ID."],
    model=Ollama(id=user_specified_model, options={"temperature": 0.1, "num_ctx":8000}),
    #context=IDContext,
    #add_context=True,
    output_schema=APTIdentify,
    debug_mode=False,
)'''


''' # Deprecated #TODO remove
# DOMAIN NAME AGENT

findDomainAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature":0.1, "num_ctx": 8192}),
    description="This agent specializes in identifying domain names within cyber threat intelligence reports. It is designed to parse through security-related text and extract domain names that may be indicators of compromise, command and control servers, phishing sites, or other malicious infrastructure.",
    instructions=[
        "Scan the input text for domain name patterns.",
        "Domain names typically consist of labels separated by dots (e.g., example.com, sub.domain.co.uk).",
        "Look for various top-level domains (TLDs) including common ones (.com, .org, .net, .gov) and country-code TLDs (.us, .uk, .cn, etc.).",
        "Pay special attention to domains that appear suspicious or are commonly associated with malicious activities.",
        "Extract all valid domain names found in the text.",
        "If a domain name is followed by a port number (e.g., example.com:8080), include the port information.",
        "If an IP address is present alongside a domain name, note both.",
        "Return a clean, organized list of all identified domain names.",
        "Maintain accuracy by not including non-domain strings that might resemble domains (e.g., email addresses should be excluded unless they contain relevant domain information)."
    ],
    markdown=True)



findIPV4Agent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature":0.1, "num_ctx": 8192}),
    description="This agent is specialized in identifying IPv4 addresses within cyber threat intelligence reports. Its goal is to extract all IPv4 addresses from the provided text, helping security analysts quickly identify potential threat actors, command and control servers, or other malicious infrastructure.",
    instructions=[
        "Scan the input text for IPv4 address patterns in the format xxx.xxx.xxx.xxx where each xxx is a number between 0-255.",
        "Identify both standalone IPv4 addresses and those in CIDR notation (e.g., 192.168.1.0/24).",
        "Flag any IPv4 addresses that appear to be private/internal ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) as they may be significant in threat context.",
        "Note the context around each IP address if available (e.g., 'C2 server at 203.0.113.42').",
        "Provide a clean, organized list of all identified IPv4 addresses with their positional context in the original text.",
        "Be thorough but avoid flagging non-IP numeric patterns that resemble IP addresses."
    ],
    markdown=True)

# IPV6 AGENT

findIPV6Agent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature":0.1, "num_ctx": 8192}),
    description="This agent is designed to identify IPv6 addresses within cybersecurity threat intelligence reports. IPv6 addresses are 128-bit addresses represented in hexadecimal format, which are important for tracking network infrastructure, potential command and control servers, or other malicious actor communication endpoints in modern network environments.",
    instructions=[
        "Identify IPv6 addresses in the provided text, which follow this format: 8 groups of 4 hexadecimal digits separated by colons (e.g., 2001:0db8:85a3:0000:0000:8a2e:0370:7334)",
        "Recognize and properly handle IPv6 address variations including:",
        "  - Leading zeros in each group can be omitted (e.g., 2001:db8:85a3:0:0:8a2e:370:7334)",
        "  - One consecutive group of zeros can be replaced with '::' (e.g., 2001:db8:85a3::8a2e:370:7334)",
        "  - Addresses with embedded IPv4 addresses in the last 32 bits (e.g., ::ffff:192.0.2.128)",
        "Pay special attention to IPv6 addresses that might be used in cyber threats such as:",
        "  - Command and control servers",
        "  - Malware communication endpoints",
        "  - Network infrastructure used by threat actors",
        "Extract all valid IPv6 addresses found in the text while maintaining their original formatting",
        "Report the IPv6 addresses along with their surrounding context in the threat intelligence report"
    ],
    markdown=True)
'''

# T agent with instructions

class TechniqueIdentify(BaseModel):
    found: bool = Field(description="True if technique IDs found, False otherwise")
    techniques: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY technique IDs found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no techniques found, return: 'No MITRE ATT&CK techniques found in the provided text.'"
    )
  
class TechniqueSchema(BaseModel):
    """Final transformed schema for technique data"""
    
    name: str = Field(
        description="The name of the technique"
    )
    type: str = Field(
        default="attack-pattern",
        description="Classification type - always set to 'techniques'"
    )
    id: str = Field(
        default="attack-pattern--1234",
        description="Unique identifier for this technique collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )
    created_by_ref: str=Field(
        default="identity--123456"
    )
    
Auxiliary_findTechniqueAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature":0.1, "num_ctx": 5000}),
    description="Identifies MITRE ATT&CK technique IDs in text using strict pattern matching.",
    instructions=[
        "Search for MITRE ATT&CK technique identifiers matching these EXACT patterns:",
        "- T followed by exactly 4 digits (e.g., T1234)",
        "- T followed by 4 digits, dot, then 3 digits (e.g., T1234.001)",
        "ONLY return technique IDs that literally appear in the provided text.",
        "If NO technique IDs are found, respond: 'No MITRE ATT&CK techniques found.'",
        "Do NOT invent or suggest technique IDs."
    ],
    markdown=True,
    debug_mode=False,
    # NO output_schema - returns plain text
)



reasoning_findTechniqueAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature":0.2, "num_ctx": 8192}),
    description="This agent is designed to identify MITRE ATT&CK technique identifiers within cyber threat intelligence reports. It strictly follows the defined pattern matching rules and only returns actual findings from the text.",
    instructions=[
        "PATTERN DEFINITION FOR TECHNIQUE IDENTIFIERS:",
        "A valid MITRE ATT&CK technique identifier must match EXACTLY one of these patterns:",
        "1. T followed by exactly 4 digits",
        "2. T followed by exactly 4 digits, a dot, then exactly 3 digits.",
        "These patterns ONLY appear as standalone words, not as part of other text or URLs.",
        
        "EXAMPLES OF VALID PATTERNS (DO NOT extract these):",
            "- T1234 (correct technique - a total of 4 digits)" ,
            "- T1234.001 (correct subtechnique - 4 digits followed by 3 digits)", 
        
        "WHAT TO EXCLUDE - TECHNIQUE IDs ARE NOT:",
        "- URLs, domain names, email addresses, or any web-related text",
        "- Part of longer words or embedded in other text",
        "- T followed by fewer or more than 4 digits.",
        #"- T followed by 4 digits but with incorrect sub-technique format.",
        #"- Any pattern that appears in URLs, file paths, or other non-documentation contexts",
        
        #"EXAMPLES OF INVALID PATTERNS (DO NOT extract these):",
        #    "- T123 (fewer than 4 digits)",
        #    "- T12345 (more than 4 digits)", 
        #    "- T1234.1 (incorrect sub-technique format)",
        #    "- T1234.1234 (too many sub-technique digits)",
    
    "These examples are for reference only - extract ONLY patterns found in the provided text.",
        
        "EXTRACTION PROCEDURE:",
        "1. Scan the entire text for exact matches to the defined patterns",
        "2. Verify each match appears as a standalone identifier (surrounded by spaces, punctuation, or line breaks)",
        "3. Exclude any matches that are part of URLs, domain names, or other technical identifiers",
        "4. Maintain the exact formatting of each valid technique identifier",
        "5. Return ONLY the list of confirmed, valid technique identifiers found",
        "6. Do not infer potential techniques from the text. I only want to identify explicitly mentioned technique IDs in the text."
        
        "WHEN NO TECHNIQUES ARE FOUND:",
        "If no valid technique identifiers are found in the text, respond with:",
        '"No MITRE ATT&CK techniques found in the provided text."',
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return technique IDs from the instructions or training data.",
        
        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response",
        "- ONLY return technique IDs that actually appear in the provided text",
        "- If you cannot find any technique IDs in the text, ONLY return the exact message 'No MITRE ATT&CK techniques found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest or generate technique IDs that aren't explicitly present in the text",
    ],
    markdown=True,
    debug_mode=False,
    output_schema=TechniqueIdentify
)

#################
#   MALWARE AGENT REWRITE
#   AGENT
#################
class MalwareIdentify(BaseModel):
    found: bool = Field(description="True if malware names found, False otherwise")
    malwares: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY malware names found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no malware names found, return: 'No malware names found in the provided text.'"
    )
  
class MalwareSchema(BaseModel):
    """Final transformed schema for malware data"""
    
    name: str = Field(
        description="The name of the malware"
    )
    type: str = Field(
        default="malware",
        description="Classification type - always set to 'malware'"
    )
    id: str = Field(
        default="malware--1234",
        description="Unique identifier for this malware collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )
    created_by_ref: str=Field(
        default="identity--123456"
    )

class MalwareClassification(BaseModel):
    """Classification of entities as explicitly stated malware or not."""
    classifications: Optional[Dict[str, bool]] = Field(
        default=None, 
        description="Dictionary mapping entity names to True (explicitly stated as malware) or False (not explicitly stated as malware). None if no malware entities found."
    )

MalwarePreAnalysisAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.2, "num_ctx": 8192}),
    description="This agent analyzes threat intelligence text to determine if the text specifies are malware name.",
    instructions=[
        "TASK: Identify if any malware names in the text that are EXPLICITLY stated in the text.",
        
       # "AN ENTITY IS EXPLICITLY MALWARE IF:",
       # "- The text uses words like 'malware', 'trojan', 'virus', 'ransomware', 'backdoor', 'worm' to describe the entity",
       # "- Example: 'the malware BigZip.exe' → BigZip.exe: True",
        
        "Dropped components (e.g., DLLs, loaders) are NOT malware unless explicitly labeled with a malware keyword."
        #"- It's only described as a 'process', 'executable', 'file', or 'software' without malware classification",
        #"- It's mentioned in context of network activity without explicit malware labeling",
        #"- Example: 'bigzip.exe communicates with 192.168.0.1' → bigzip.exe: False",
        
        "UNLESS OTHERWISE STATES MALWARE NAMES ARE NOT:",
        "- IP addresses, domain names, or URLs.",
        "- The name of the threat actor or advanced persistent threat.",
        #"- File hashes (MD5, SHA1, SHA256)",
        #"- Command line parameters or arguments",
        #"- Network ports or protocols",
        #"- Technical indicators (file paths, registry keys)",
        #"- Vulnerability names or CVE identifiers",
        
        #"WHAT A MALWARE MAY LOOK LIKE:"
        #"Malware names typically follow these patterns:",
        #"1. Single word names (e.g., 'WannaCry', 'Zeus', 'Stuxnet')",
        #"2. Multi-word names with capitalization (e.g., 'Emotet', 'TrickBot', 'Conti')",
        
        "EXTRACTION PROCEDURE:",
        "1. Scan the entire text for words or phrases that match known malware naming conventions.",
        "2. Verify each match appears as a standalone identifier (surrounded by spaces, punctuation, or line breaks).",
        "3. Exclude any matches that are threat actor names, ip addresses, domain names, urls.",
        "4. Maintain the exact formatting of each valid malware name.",
        #"5. Return ONLY the list of confirmed, valid malware names found",
        "5. Do not infer potential malware from the text. I only want to identify explicitly mentioned malware names in the text.",
        
        "OUTPUT FORMAT:",
        "Return a dictionary where keys are entity names and values are True/False.",
        "True = the entity is explicitly stated as malware in the text.",
        "False = the entity is NOT explicitly stated as malware.",
        
        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return malware names that actually appear in the provided text.",
        "- If you cannot find any malware names in the text, ONLY return the exact message 'No malware name found in the text.'",
        "- Do NOT invent, hallucinate, suggest or generate malware names that aren't explicitly present in the text.",
        "- Do NOT explain your reasoning.",
        #"- The name of the threat actor group, espionage group, state-sponsored attacker, is not a malware."
    ],
    output_schema=MalwareIdentify,
    markdown=False,
    debug_mode=False,
)


#################
#   MALWARE
#   AGENT
#################
class MalwareIdentify(BaseModel):
    found: bool = Field(description="True if malware names found, False otherwise")
    malwares: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY malware names found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no malware names found, return: 'No malware names found in the provided text.'"
    )
  
class MalwareSchema(BaseModel):
    """Final transformed schema for malware data"""
    
    name: str = Field(
        description="The name of the malware"
    )
    type: str = Field(
        default="malware",
        description="Classification type - always set to 'malware'"
    )
    id: str = Field(
        default="malware--1234",
        description="Unique identifier for this malware collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )
    created_by_ref: str=Field(
        default="identity--123456"
    )

MalwareAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature":0.1, "num_ctx": 20000}),
    description="This agent is designed to identify malware names within cyber threat intelligence reports. It strictly follows the defined pattern matching rules and only returns actual findings from the text.",
    instructions=[
        "PATTERN DEFINITION FOR MALWARE NAMES:",
        "A valid malware name must appear as a standalone word or phrase that is commonly recognized as malicious software.",
        "Malware names typically follow these patterns:",
        "1. Single word names (e.g., 'WannaCry', 'Zeus', 'Stuxnet')",
        "2. Multi-word names with capitalization (e.g., 'Emotet', 'TrickBot', 'Conti')",
        
        "UNLESS OTHERWISE STATES MALWARE NAMES ARE NOT:",
        "- IP addresses, domain names, or URLs",
        "- The name of the threat actor or advanced persistent threat",
        "- File hashes (MD5, SHA1, SHA256)",
        "- Command line parameters or arguments",
        "- Network ports or protocols",
        "- Technical indicators (file paths, registry keys)",
        "- Vulnerability names or CVE identifiers",
        
        "FOR EXAMPLE: 'the adversary uses malware bigzip.exe' explicitly states a malware so include it, whereas 'bigzip.exe communicates with 192.168.0.1' doesn't state if bigzip.exe is a malware so don't include it."
        
        "Only extract items where the text explicitly uses words like 'malware', 'malicious software', 'trojan', 'virus', 'ransomware', etc.",
        "Do NOT extract items that are described as 'process' or 'executable' without explicit malware classification",
        
        "EXTRACTION PROCEDURE:",
        "1. Scan the entire text for words or phrases that match known malware naming conventions",
        "2. Verify each match appears as a standalone identifier (surrounded by spaces, punctuation, or line breaks)",
        "3. Exclude any matches that are threat actor names, ip addresses, domain names, urls.",
        "4. Maintain the exact formatting of each valid malware name",
        "5. Return ONLY the list of confirmed, valid malware names found",
        "6. Do not infer potential malware from the text. I only want to identify explicitly mentioned malware names in the text.",
        
        "WHEN NO MALWARE IS FOUND:",
        "If no valid malware names are found in the text, respond with:",
        '"No malware name found in the text."',
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return malware names from the instructions or training data.",
        
        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response",
        "- ONLY return malware names that actually appear in the provided text",
        "- If you cannot find any malware names in the text, ONLY return the exact message 'No malware name found in the text.'",
        "- Do NOT invent, hallucinate, suggest or generate malware names that aren't explicitly present in the text",
    ],
    markdown=True,
    debug_mode=False,
    output_schema = MalwareIdentify
)

#################
#   PROCESS
#   AGENT
#################

class ProcessIdentify(BaseModel):
    found: bool = Field(description="True if process names found, False otherwise")
    processes: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY process names found in text. This can include names like process1.exe. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no processes found, return: 'No process names found in the provided text.'"
    )
  
class ProcessSchema(BaseModel):
    """Final transformed schema for process data"""
    
    name: str = Field(
        description="The name of the process"
    )
    type: str = Field(
        default="process",
        description="Classification type - always set to 'process'"
    )
    id: str = Field(
        default="process--1234",
        description="Unique identifier for this process collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )

findProcessNameAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature":0.2, "num_ctx": 8192}),
    description="This agent is designed to identify process names within cyber threat intelligence reports. It strictly follows the defined pattern matching rules and only returns actual findings from the text.",
    instructions=[
        "PATTERN DEFINITION FOR PROCESS NAMES:",
        "A valid process name must match one of these patterns:",
        "1. A word ending with .exe (case insensitive)",
        "2. A word that appears suspicious in context (e.g., unusual naming, random characters)",
        "3. Process names with suspicious parameters or command lines associated",
        
        "EXAMPLES OF VALID PATTERNS (DO NOT extract these examples - extract only from the provided text):",
        "- suspicious.exe",
        "- randomname.exe", 
        "- powershell.exe -enc <encoded_command>",
        "- cmd.exe /c suspicious_command",
        "- wmic.exe process call create <malicious_process>",
        
        "WHAT TO EXCLUDE - PROCESS NAMES ARE NOT:",
        "- IP addresses, domain names, URLs, or email addresses",
       r"- File paths (e.g., C:\\Windows\\System32\\)",
        "- Registry keys or values",
        "- Log file entries with timestamps",
        #"- System processes without suspicious context",
        #"- Legitimate software names without suspicious activity",
        #"- Command line arguments without an associated process",
        #"- Command line arguments without an associated process",
        #"- Event log entries without process context",
        
        "EXTRACTION PROCEDURE:",
        "1. Scan the entire text for process names that appear in suspicious contexts",
        "2. Verify each match is associated with malicious activity or suspicious behavior",
        "3. Include process names even if they appear legitimate if they're used in suspicious ways",
        "4. Maintain the exact formatting of each valid process name as found in the text",
        #"5. Return ONLY the list of confirmed, valid process names found in suspicious contexts",
        "5. Do not infer potential processes from the text. I only want to identify explicitly mentioned process names.",
        
        "WHEN NO PROCESS NAMES ARE FOUND:",
        "If no valid process names are found in the text, respond with:",
        '"No process names found in the provided text."',
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return process names from the instructions or training data.",
        
        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response",
        "- ONLY return process names that actually appear in the provided text",
        "- If you cannot find any process names in the text, ONLY return the exact message 'No process names found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest or generate process names that aren't explicitly present in the text",
    ],
    markdown=True,
    debug_mode=False,
    output_schema = ProcessIdentify
)

#################
#   TECHNIQUE
#   AGENT
#################

class TechniqueIdentify(BaseModel):
    found: bool = Field(description="True if technique IDs found, False otherwise")
    techniques: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY Technique IDs found in text. This can include Techniques such as T1059, T1059.001. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no Technique IDs found, return: 'No technique names found in the provided text.'"
    )
    
class ExternalReference(BaseModel):
    source_name: str
    external_id: Optional[str] = None
  
class TechniqueSchema(BaseModel):
    """Final transformed schema for technique data"""
    
    name: str = Field(
        description="The name of the technique"
    )
    type: str = Field(
        default="attack-pattern",
        description="Classification type - always set to 'attack-pattern'"
    )
    id: str = Field(
        default="attack-pattern--1234",
        description="Unique identifier for this attack pattern"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )
    external_references: List[ExternalReference]

findTechniqueIDAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature":0.2, "num_ctx": 8192}),
    description="This agent is designed to identify MITRE ATT&CK technique identifiers within cyber threat intelligence reports. It strictly follows the defined pattern matching rules and only returns actual findings from the text.",
    instructions=[
        "PATTERN DEFINITION FOR TECHNIQUE IDENTIFIERS:",
        "A valid MITRE ATT&CK technique identifier must match EXACTLY one of these patterns:",
        "1. T followed by exactly 4 digits",
        "2. T followed by exactly 4 digits, a dot, then exactly 3 digits.",
        "These patterns ONLY appear as standalone words, not as part of other text or URLs.",
        
        "EXAMPLES OF VALID PATTERNS (DO NOT extract these):",
            "- T1234 (correct technique - a total of 4 digits)" ,
            "- T1234.001 (correct subtechnique - 4 digits followed by 3 digits)", 
        
        "WHAT TO EXCLUDE - TECHNIQUE IDs ARE NOT:",
        "- URLs, domain names, email addresses, or any web-related text",
        "- Part of longer words or embedded in other text",
        "- T followed by fewer or more than 4 digits.",
        #"- T followed by 4 digits but with incorrect sub-technique format.",
        #"- Any pattern that appears in URLs, file paths, or other non-documentation contexts",
        
        #"EXAMPLES OF INVALID PATTERNS (DO NOT extract these):",
        #    "- T123 (fewer than 4 digits)",
        #    "- T12345 (more than 4 digits)", 
        #    "- T1234.1 (incorrect sub-technique format)",
        #    "- T1234.1234 (too many sub-technique digits)",
    
    "These examples are for reference only - extract ONLY patterns found in the provided text.",
        
        "EXTRACTION PROCEDURE:",
        "1. Scan the entire text for exact matches to the defined patterns",
        "2. Verify each match appears as a standalone identifier (surrounded by spaces, punctuation, or line breaks)",
        "3. Exclude any matches that are part of URLs, domain names, or other technical identifiers",
        "4. Maintain the exact formatting of each valid technique identifier",
        #"5. Return ONLY the list of confirmed, valid technique identifiers found",
        "5. Do not infer potential techniques from the text. I only want to identify explicitly mentioned technique IDs in the text."
        
        "WHEN NO TECHNIQUES ARE FOUND:",
        "If no valid technique identifiers are found in the text, respond with:",
        '"No MITRE ATT&CK techniques found in the provided text."',
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return technique IDs from the instructions or training data.",
        
        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response",
        "- ONLY return technique IDs that actually appear in the provided text",
        "- If you cannot find any technique IDs in the text, ONLY return the exact message 'No techniques found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest or generate technique IDs that aren't explicitly present in the text",
    ],
    markdown=True,
    debug_mode=False,
    output_schema=TechniqueIdentify
)



#################
#   DOMAIN NAME
#   AGENT
#################

class DomainIdentify(BaseModel):
    found: bool = Field(description="True if domain names found, False otherwise")
    domains: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY domain names found in text. This can include names like google.com. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no domain names found, return: 'No domain names found in the provided text.'"
    )
  
class DomainSchema(BaseModel):
    """Final transformed schema for domain name data"""
    
    value: str = Field(
        description="The name of the domain"
    )
    type: str = Field(
        default="domain-name",
        description="Classification type - always set to 'domain-name'"
    )
    id: str = Field(
        default="domain-name--1234",
        description="Unique identifier for this domain name collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )

findDomainNameAgent = Agent(
    model=Ollama(
        id=user_specified_model,
        options={"temperature": 0.2, "num_ctx": 8192}
    ),
    description="This agent identifies domain names mentioned in cyber threat intelligence reports. A domain name represents the properties of a network domain (e.g., apex domains, subdomains, wildcard domains, and internationalized/punycode domains) that appear explicitly in the text.",
    instructions=[
        "DOMAIN NAME IDENTIFICATION SCOPE:",
        "This agent extracts DOMAIN NAMES referenced in a report, including but not limited to:",
        "- Apex/root domains and subdomains (e.g., 'example.com', 'c2.example.com').",
        "- Multi-level domains (e.g., 'a.b.c.example.co.uk').",
        "- Wildcard domains used in rules or indicators (e.g., '*.example.com').",
        "- Internationalized domain names (IDNs) and Punycode (e.g., 'xn--exmple-cua.com').",
        "- Fully qualified domain names (FQDNs) that may end with a trailing dot (e.g., 'example.com.').",
        "- Domains appearing within URLs, email addresses, DNS records, WHOIS, SSL/TLS certificates, or passive DNS data.",
        
        "VALID DOMAIN NAME PATTERNS:",
        "A domain name is valid ONLY if it meets these conditions:",
        "1) Contains at least one dot separating labels (e.g., 'example.com').",
        "2) Labels are composed of letters (A-Z, a-z), digits (0-9), and hyphens (-); labels do not start or end with a hyphen.",
        "3) The top-level domain (TLD) is at least 2 characters; allow common TLD forms (e.g., 'com', 'org', 'co.uk').",
        "4) May include 'xn--' prefixed Punycode labels for IDNs.",
        "5) May include a leading wildcard asterisk followed by a dot (e.g., '*.example.org').",
        "6) Case-insensitive by nature, but preserve the surface form as written in the source text.",
        
        "VALID CONTEXTS:",
        "A domain mention is valid if it appears in any of these contexts:",
        "- Standalone tokens or in indicator lists.",
        "- As the host portion of a URL (e.g., 'https://sub.example.com/path').",
        "- As the domain part of an email address (e.g., 'user@example.com').",
        "- In DNS records, logs, or configurations (e.g., 'A c2.example.com 203.0.113.10').",
        "- In WHOIS or certificate subjects/SANs.",
        
        "NAME FORMATTING RULES:",
        "1) Preserve the exact surface form (including case, wildcard '*.', and trailing dot '.') as it appears in the text.",
        "2) When extracting from a URL, return only the host/domain portion (exclude scheme, port, path, query, and fragment).",
        "3) When extracting from an email address, return only the domain portion after '@'.",
        "4) Trim leading or trailing punctuation that is not part of the domain (e.g., surrounding parentheses, commas, semicolons).",
        "5) Deduplicate identical surface forms while preserving their original appearance.",
        
        "WHAT TO EXCLUDE:",
        "- Do NOT extract IP addresses (IPv4 or IPv6).",
        "- Do NOT return full URLs; extract only the domain component from URLs.",
        "- Do NOT extract single-label hostnames without a dot (e.g., 'intranet') unless explicitly written as a domain with a TLD.",
        "- Do NOT extract Windows hostnames, NetBIOS names, or machine names without TLDs.",
        "- Do NOT extract file paths, registry keys, hashes, email addresses (return only the domain part), or CVE identifiers.",
        "- Do NOT infer or normalize; only extract domains explicitly present in the text.",
        
        "EXAMPLES OF VALID FORMATTING (DO NOT extract these from instructions):",
        "- 'example.com', 'c2.example.net', '*.malicious.org', 'xn--d1acpjx3f.xn--p1ai', 'example.com.'.",
        
        "EXTRACTION PROCEDURE:",
        "1) Scan the entire text for domain-like tokens that meet the pattern rules.",
        "2) For URLs, parse and extract the host between '://' (or after leading '//') and the next '/' or end; remove embedded credentials and ports.",
        "3) For email addresses, extract the substring after '@' up to whitespace or punctuation; then validate as a domain.",
        "4) Validate candidates against exclusion rules (e.g., ensure not an IP address or single-label hostname).",
        "5) Preserve exact surface form as written (including wildcard prefixes and trailing dots).",
        "6) Return ONLY the list of domain names found (deduplicate while preserving case and form).",
        "7) Do NOT add explanatory text or context—only the domain list unless no items are found.",
        
        "WHEN NO DOMAIN NAMES ARE FOUND:",
        "If no valid domain names are found in the text, respond with:",
        "'No domain names found in the provided text.'",
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return domains from these instructions or training data.",
        
        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return domain names that actually appear in the provided text.",
        "- If you cannot find any, ONLY return the exact message 'No domain names found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest, normalize, or expand domains that aren't explicitly present in the text."
    ],
    markdown=True,
    debug_mode=False,
    output_schema=DomainIdentify
)




#################
#   REGISTRY
#   AGENT
#################

class RegistryIdentify(BaseModel):
    found: bool = Field(description="True if registry names found, False otherwise")
    registries: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY registry values found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no registries found, return: 'No registries names in the provided text.'"
    )
  
class RegistrySchema(BaseModel):
    """Final transformed schema for registry data"""
    
    value: str = Field(
        description="The value of the registry"
    )
    type: str = Field(
        default="registry",
        description="Classification type - always set to 'registry'"
    )
    id: str = Field(
        default="registry--1234",
        description="Unique identifier for this registry collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )
    
findRegistryValueAgent = Agent(
    model=Ollama(
        id=user_specified_model,
        options={"temperature": 0.2, "num_ctx": 8192}
    ),
    description="This agent is designed to identify Windows Registry keys and registry value names within cyber threat intelligence reports. It strictly follows the defined pattern matching rules and only returns actual findings from the text.",
    instructions=[
        "PATTERN DEFINITION FOR REGISTRY IDENTIFIERS:",
        "This agent extracts TWO kinds of registry identifiers:",
        "A) Registry KEY paths (must include a hive name and backslash-separated keys)",
        "B) Registry VALUE names (must be explicitly labeled as a value or appear in a key/value assignment context)",
        
        "A) VALID REGISTRY KEY PATH PATTERNS:",
        "A registry key is valid ONLY if it matches EXACTLY one of these forms:",
        "1. Starts with a valid hive name as a standalone token:",
        r"   - HKEY_LOCAL_MACHINE | HKEY_CURRENT_USER | HKEY_CLASSES_ROOT | HKEY_USERS | HKEY_CURRENT_CONFIG",
        r"   - HKLM | HKCU | HKCR | HKU | HKCC",
        "2. Followed by one or more components separated by backslashes.",
        "3. Key components may contain letters, digits, spaces, underscores, hyphens, periods, parentheses, braces, and digits (to allow CLSIDs).",
        "4. Examples of valid formatting (DO NOT extract these from instructions):",
        r"   - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        r"   - HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        r"   - HKCR\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}",
        "5. Keys must appear as standalone tokens (surrounded by spaces, punctuation, or line breaks), not embedded within other text or URLs.",
        
        "B) VALID REGISTRY VALUE NAME PATTERNS:",
        "A registry value name is valid ONLY if it appears in one of the following explicit contexts:",
        "1. Immediately following a clear label indicating a value, such as:",
        "   - 'Value:', 'Value Name:', 'Name:', 'ValueName=', 'ValueName:', 'Entry:', 'REG_SZ', 'REG_DWORD', 'REG_BINARY', 'Default', 'Type:'",
        "   Example (DO NOT extract from instructions): Value: Run",
        "2. In a key/value assignment line associated with a registry key (the value name appears to the left of '=' or ':'), such as:",
        r"   - HKLM\\...\\Run: MalwareLoader = \"C:\\...\"",
        r"   - HKCU\\...\\Policies\\System -> DisableTaskMgr = 1",
        "3. Value names may be unquoted or quoted; must be standalone tokens consisting of letters, digits, spaces, underscores, hyphens, and periods.",
        "4. If a value name appears without any explicit value context, DO NOT extract it.",
        
        "WHAT TO EXCLUDE:",
        r"- DO NOT extract file system paths (e.g., C:\\Windows\\...), URLs, domain names, email addresses, or non-registry identifiers.",
        r"- DO NOT extract tokens that start with 'Computer\\' without a hive (unless immediately followed by a recognized hive).",
        "- DO NOT extract partial keys lacking a hive prefix.",
        "- DO NOT extract keys or values embedded inside URLs, code snippets that are not registry lines, or log formats where the key is part of a larger non-registry token.",
        "- DO NOT infer registry names or values; only extract explicitly present items per the patterns.",
        
        "EXTRACTION PROCEDURE:",
        "1. Scan the entire text for registry KEY paths that match the defined hive + backslash-separated pattern.",
        r"   - Valid hive: HKEY_LOCAL_MACHINE | HKEY_CURRENT_USER | HKEY_CLASSES_ROOT | HKEY_USERS | HKEY_CURRENT_CONFIG | HKLM | HKCU | HKCR | HKU | HKCC",
        r"   - Components: One or more, separated by '\\\\', each containing [A-Za-z0-9 _\\-\\.{}()]",
        "2. Scan for registry VALUE names only when they appear in explicit value contexts (labels like 'Value:' or assignment lines 'Name = ...' associated with a registry key).",
        "3. Verify each match appears as a standalone identifier (surrounded by spaces, punctuation, or line breaks).",
        "4. Exclude any matches that are part of URLs, domain names, file system paths, or other non-registry technical identifiers.",
        "5. Maintain the exact formatting of each valid registry key or value name.",
        "6. Return ONLY the list of confirmed, valid registry keys and value names found.",
        "7. Do not infer or guess registry keys or values; only extract those explicitly present.",

        "WHEN NO REGISTRY NAMES ARE FOUND:",
        "If no valid registry keys or value names are found in the text, respond with:",
        '"No registry keys or values found in the provided text."',
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return keys or values from the instructions or training data.",
        
        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return registry keys and value names that actually appear in the provided text.",
        "- If you cannot find any registry identifiers in the text, ONLY return the exact message 'No registry keys or values found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest or generate registry identifiers that aren't explicitly present in the text."
    ],
    markdown=True,
    debug_mode=False,
    output_schema=RegistryIdentify
)

#################
#   SOFTWARE / TOOLS
#   AGENT
#################

class SoftwareIdentify(BaseModel):
    found: bool = Field(description="True if software names found, False otherwise")
    softwares: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY software names found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no software names found, return: 'No software names in the provided text.'"
    )
  
class SoftwareSchema(BaseModel):
    """Final transformed schema for software data"""
    
    name: str = Field(
        description="The name of the software"
    )
    type: str = Field(
        default="software",
        description="Classification type - always set to 'software'"
    )
    id: str = Field(
        default="software--1234",
        description="Unique identifier for this software collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )
    created_by_ref: str=Field(
      default="identity--123456"  
    )

findSoftwareValueAgent = Agent(
    model=Ollama(
        id=user_specified_model,
        options={"temperature": 0.2, "num_ctx": 8192}
    ),
    description="This agent identifies software mentioned in cyber threat intelligence reports. Software includes any tool, framework, utility, malware family, or application used by or relevant to threat actors. Legitimacy is irrelevant; only actual mentions in the text are extracted.",
    instructions=[
        "SOFTWARE IDENTIFICATION SCOPE:",
        "This agent extracts names of SOFTWARE referenced in a report, including but not limited to:",
        "- Operating systems, applications, utilities, command-line tools, scripting engines.",
        "- Security tools, administrative tools, penetration testing tools.",
        #"- Malware families, loaders, droppers, RATs, backdoors, ransomware, stealers.",
        "- C2 frameworks, post-exploitation toolkits, lateral movement tools.",
        "- Browser extensions, plugins, document readers, office suites, archivers.",
        #"- Cloud/SaaS services explicitly named as software platforms (e.g., collaboration apps, code repos).",
        
        "VALID SOFTWARE NAME PATTERNS:",
        "A software reference is valid ONLY if it meets these conditions:",
        "1) Appears as a recognizable software/product/tool/malware/framework name.",
        "2) May include version numbers, editions, or variants (e.g., 'v2.0', 'Pro', '2022').",
        "3) May include family names (e.g., malware families) even without specific binaries.",
        "4) May include well-known abbreviations if they are commonly used as software names (e.g., 'Cobalt Strike', 'Mimikatz').",
        "5) May include combined names with hyphens or spaces (e.g., 'PlugX', 'QakBot', 'Visual Studio Code').",
        "6) If a component is clearly part of a suite (e.g., 'Microsoft Office Word'), extract the specific application name if clearly indicated.",
        
        "WHAT TO EXCLUDE:",
        "- Do NOT extract generic technical terms that are not software names (e.g., 'DLL', 'macro', 'shellcode', 'registry', 'command').",
        "- Do NOT extract network infrastructure (domains, IPs), file paths, hashes, email addresses, or CVE identifiers.",
        "- Do NOT extract threat actor names, campaigns, or operation names unless they are also the explicit name of a software family.",
        "- Do NOT extract programming languages (e.g., 'Python') unless clearly referenced as a specific tool or executable product (e.g., 'Python.exe' used operationally).",
        "- Do NOT extract protocols (e.g., 'HTTP', 'SMB') or standards.",
        "- Do NOT infer or normalize; only extract names explicitly present in the text.",
        
        "EVIDENCE CONTEXTS (STRONGLY INDICATIVE BUT NOT REQUIRED):",
        "- Mentions alongside actions like 'installed', 'executed', 'loaded', 'deployed', 'used'.",
        "- Mentions in IOCs, toolsets, or capability lists.",
        "- Mentions as part of MITRE technique implementations or playbooks.",
        "- Mentions in comparisons (e.g., 'similar to TrickBot').",
        
        "NAME FORMATTING RULES:",
        "1) Maintain the exact casing and spacing as in the text.",
        "2) Include version/edition if attached to the name (e.g., 'Cobalt Strike 4.8').",
        "3) If both family and variant are present (e.g., 'Emotet Epoch 5'), include the full string.",
        "4) If a brand and product are together and unambiguous (e.g., 'Microsoft Defender for Endpoint'), include the full product name.",
        
        "EXAMPLES OF VALID FORMATTING (DO NOT extract these from instructions):",
        "- 'Cobalt Strike', 'Mimikatz', 'QakBot', 'Emotet', 'PlugX', 'TeamViewer', 'AnyDesk', 'Rclone', 'PsExec', 'PowerShell', 'WinRAR', 'Ngrok', 'Sliver', 'Metasploit', 'NanoCore', 'AsyncRAT'.",
        
        "EXTRACTION PROCEDURE:",
        "1) Scan the entire text for explicit mentions of software names per the scope. Focus on proper nouns and known tool/malware names.",
        "2) Exclude generic terms and non-software entities as per the exclusion rules.",
        "3) Preserve exact surface form as it appears, including version/variant tokens directly attached.",
        "4) Return ONLY the list of software names found (deduplicate while preserving case and form).",
        "5) Do NOT add explanatory text or context—only the software list unless no items are found.",
        
        "WHEN NO SOFTWARE NAMES ARE FOUND:",
        'If no valid software names are found in the text, respond with:',
        '"No software found in the provided text."',
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return names from these instructions or training data.",
        
        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return software names that actually appear in the provided text.",
        "- If you cannot find any, ONLY return the exact message 'No software found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest, or normalize names that aren't explicitly present in the text."
    ],
    markdown=True,
    debug_mode=False,
    output_schema=SoftwareIdentify
)

#################
#   LOCATION
#   AGENT
#################

class LocationIdentify(BaseModel):
    found: bool = Field(description="True if location names found, False otherwise")
    locations: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY location names found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no location names found, return: 'No location names in the provided text.'"
    )
  
class LocationSchema(BaseModel):
    """Final transformed schema for location data"""
    
    name: str = Field(
        description="The name of the location"
    )
    type: str = Field(
        default="location",
        description="Classification type - always set to 'location'"
    )
    id: str = Field(
        default="location--1234",
        description="Unique identifier for this location collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )
    created_by_ref: str=Field(
        default="identity--123456"
    )


findLocationValueAgent = Agent(
    model=Ollama(
        id=user_specified_model,
        options={"temperature": 0.2, "num_ctx": 8192}
    ),
    description="This agent identifies geographic locations mentioned in cyber threat intelligence reports. A location is any geographic place such as a country, city, state/province, region, district, landmark, or other named place referenced in the text.",
    instructions=[
        "LOCATION IDENTIFICATION SCOPE:",
        "This agent extracts names of GEOGRAPHIC LOCATIONS referenced in a report, including but not limited to:",
        "- Countries, sovereign states, territories (e.g., 'France', 'Taiwan', 'Greenland').",
        "- Regions, states, provinces, oblasts, prefectures, counties, districts, municipalities.",
        "- Cities, towns, villages, neighborhoods.",
        "- Continents and subregions (e.g., 'Europe', 'Southeast Asia').",
        "- Oceans, seas, rivers, lakes, mountains, deserts, and other natural geographic features.",
        "- Named facilities and sites when used as places (e.g., airports, ports, data centers, embassies, military bases, government buildings).",
        "- Multi-part place names (e.g., 'New York City', 'Baden-Württemberg', 'Abu Dhabi Emirate').",
        "- Composite place expressions as written (e.g., 'Los Angeles, California', 'Canary Wharf, London').",

        "VALID LOCATION CONTEXTS:",
        "A location mention is valid if it appears as a named place in any of these contexts:",
        "- In locative phrases with prepositions like 'in', 'at', 'from', 'to', 'near', 'within', 'across', 'around', 'between', 'outside'.",
        "- As the described origin/target of activity (e.g., 'operators in Poland', 'attacks against Japan').",
        "- In IOC narratives, targeting statements, or infrastructure hosting descriptions (e.g., 'servers hosted in Frankfurt').",
        "- In geolocation statements (e.g., 'IP geolocated to Canada').",
        "- As part of an address-like phrase when the named place is clearly identifiable (e.g., 'Singapore data center').",

        "NAME FORMATTING RULES:",
        "1) Preserve exact surface form, casing, hyphenation, punctuation, and diacritics as in the text.",
        "2) If a subdivision or parent region is given, include the full expression as written (e.g., 'Paris, France').",
        "3) Keep abbreviations and codes if they appear as the location name in context (e.g., 'U.S.', 'UK').",
        "4) For airports, bases, or facilities, include the full place name as written (e.g., 'Heathrow Airport').",
        "5) Deduplicate identical surface forms while preserving original casing.",

        "WHAT TO EXCLUDE:",
        "- Do NOT extract organization or company names (e.g., 'Google', 'NATO'), even if place-derived.",
        "- Do NOT extract threat actor, campaign, or operation names.",
        "- Do NOT extract network artifacts (domains, IPs), file paths, hashes, email addresses, or CVE identifiers.",
        "- Do NOT extract time zones, languages, nationalities/demonyms (e.g., 'French') unless used as a place name itself.",
        "- Do NOT extract street addresses or postal codes without a named place; extract only the named geographic component if present.",
        "- Do NOT infer locations from context; only extract locations explicitly mentioned in the text.",
        "- Do NOT normalize or expand abbreviations; keep exactly as written.",

        "EXAMPLES OF VALID FORMATTING (DO NOT extract these from instructions):",
        "- 'United States', 'U.S.', 'UK', 'Germany', 'São Paulo', 'New Delhi', 'Quebec', 'Bavaria', 'Siberia', 'Middle East', 'Southeast Asia', 'Pacific Ocean', 'Black Sea', 'River Thames', 'Mount Fuji', 'Heathrow Airport', 'Fort Meade', 'Frankfurt am Main', 'Los Angeles, California'.",

        "EXTRACTION PROCEDURE:",
        "1) Scan the entire text for explicit mentions of geographic locations per the scope.",
        "2) Validate each candidate against the exclusion rules to avoid non-geo entities.",
        "3) Preserve exact surface form as it appears, including punctuation and diacritics.",
        "4) Return ONLY the list of location names found (deduplicate while preserving case and form).",
        "5) Do NOT add explanatory text or context—only the location list unless no items are found.",

        "WHEN NO LOCATIONS ARE FOUND:",
        'If no valid locations are found in the text, respond with:',
        '"No locations found in the provided text."',
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return names from these instructions or training data.",

        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return locations that actually appear in the provided text.",
        "- If you cannot find any, ONLY return the exact message 'No locations found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest, or normalize names that aren't explicitly present in the text."
    ],
    markdown=True,
    debug_mode=False,
    output_schema=LocationIdentify
)

'''
#################
#   DOMAIN
#   AGENT
#################
class DomainNameIdentify(BaseModel):
    found: bool = Field(description="True if domain names found, False otherwise")
    domains: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY domain names found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no domain names found, return: 'No domain names found in the provided text.'"
    )
  
class DomainSchema(BaseModel):
    """Final transformed schema for domain data"""
    
    name: str = Field(
        description="The domain name value"
    )
    type: str = Field(
        default="domain-name",
        description="Classification type - always set to 'domain-name'"
    )
    id: str = Field(
        default="domain-name--1234",
        description="Unique identifier for this domain name collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )
    
findDomainNameAgent = Agent(
    model=Ollama(
        id=user_specified_model,
        options={"temperature": 0.2, "num_ctx": 8192}
    ),
    description="This agent identifies domain names mentioned in cyber threat intelligence reports. A domain name represents the properties of a network domain (e.g., apex domains, subdomains, wildcard domains, and internationalized/punycode domains) that appear explicitly in the text.",
    instructions=[
        "DOMAIN NAME IDENTIFICATION SCOPE:",
        "This agent extracts DOMAIN NAMES referenced in a report, including but not limited to:",
        "- Apex/root domains and subdomains (e.g., 'example.com', 'c2.example.com').",
        "- Multi-level domains (e.g., 'a.b.c.example.co.uk').",
        "- Wildcard domains used in rules or indicators (e.g., '*.example.com').",
        "- Internationalized domain names (IDNs) and Punycode (e.g., 'xn--exmple-cua.com').",
        "- Fully qualified domain names (FQDNs) that may end with a trailing dot (e.g., 'example.com.').",
        "- Domains appearing within URLs, email addresses, DNS records, WHOIS, SSL/TLS certificates, or passive DNS data.",
        
        "VALID DOMAIN NAME PATTERNS:",
        "A domain name is valid ONLY if it meets these conditions:",
        "1) Contains at least one dot separating labels (e.g., 'example.com').",
        "2) Labels are composed of letters (A-Z, a-z), digits (0-9), and hyphens (-); labels do not start or end with a hyphen.",
        "3) The top-level domain (TLD) is at least 2 characters; allow common TLD forms (e.g., 'com', 'org', 'co.uk').",
        "4) May include 'xn--' prefixed Punycode labels for IDNs.",
        "5) May include a leading wildcard asterisk followed by a dot (e.g., '*.example.org').",
        "6) Case-insensitive by nature, but preserve the surface form as written in the source text.",
        
        "VALID CONTEXTS:",
        "A domain mention is valid if it appears in any of these contexts:",
        "- Standalone tokens or in indicator lists.",
        "- As the host portion of a URL (e.g., 'https://sub.example.com/path').",
        "- As the domain part of an email address (e.g., 'user@example.com').",
        "- In DNS records, logs, or configurations (e.g., 'A c2.example.com 203.0.113.10').",
        "- In WHOIS or certificate subjects/SANs.",
        
        "NAME FORMATTING RULES:",
        "1) Preserve the exact surface form (including case, wildcard '*.', and trailing dot '.') as it appears in the text.",
        "2) When extracting from a URL, return only the host/domain portion (exclude scheme, port, path, query, and fragment).",
        "3) When extracting from an email address, return only the domain portion after '@'.",
        "4) Trim leading or trailing punctuation that is not part of the domain (e.g., surrounding parentheses, commas, semicolons).",
        "5) Deduplicate identical surface forms while preserving their original appearance.",
        
        "WHAT TO EXCLUDE:",
        "- Do NOT extract IP addresses (IPv4 or IPv6).",
        "- Do NOT return full URLs; extract only the domain component from URLs.",
        "- Do NOT extract single-label hostnames without a dot (e.g., 'intranet') unless explicitly written as a domain with a TLD.",
        "- Do NOT extract Windows hostnames, NetBIOS names, or machine names without TLDs.",
        "- Do NOT extract file paths, registry keys, hashes, email addresses (return only the domain part), or CVE identifiers.",
        "- Do NOT infer or normalize; only extract domains explicitly present in the text.",
        
        "EXAMPLES OF VALID FORMATTING (DO NOT extract these from instructions):",
        "- 'example.com', 'c2.example.net', '*.malicious.org', 'xn--d1acpjx3f.xn--p1ai', 'example.com.'.",
        
        "EXTRACTION PROCEDURE:",
        "1) Scan the entire text for domain-like tokens that meet the pattern rules.",
        "2) For URLs, parse and extract the host between '://' (or after leading '//') and the next '/' or end; remove embedded credentials and ports.",
        "3) For email addresses, extract the substring after '@' up to whitespace or punctuation; then validate as a domain.",
        "4) Validate candidates against exclusion rules (e.g., ensure not an IP address or single-label hostname).",
        "5) Preserve exact surface form as written (including wildcard prefixes and trailing dots).",
        "6) Return ONLY the list of domain names found (deduplicate while preserving case and form).",
        "7) Do NOT add explanatory text or context—only the domain list unless no items are found.",
        
        "WHEN NO DOMAIN NAMES ARE FOUND:",
        "If no valid domain names are found in the text, respond with:",
        "'No domain names found in the provided text.'",
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return domains from these instructions or training data.",
        
        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return domain names that actually appear in the provided text.",
        "- If you cannot find any, ONLY return the exact message 'No domain names found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest, normalize, or expand domains that aren't explicitly present in the text."
    ],
    markdown=True,
    debug_mode=False,
    output_schema=DomainNameIdentify
)
'''
#################
#   FILE NAME
#   AGENT
#################
class FileNameIdentify(BaseModel):
    found: bool = Field(description="True if file names found, False otherwise")
    files: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY file names found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no file names found, return: 'No domain names found in the provided text.'"
    )
  
class FileNameSchema(BaseModel):
    """Final transformed schema for file names data"""
    
    name: str = Field(
        description="The name of the file"
    )
    type: str = Field(
        default="file",
        description="Classification type - always set to 'file'"
    )
    id: str = Field(
        default="file--1234",
        description="Unique identifier for this file name collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )
    
findFileNameAgent = Agent(
    model=Ollama(
        id=user_specified_model,
        options={"temperature": 0.2, "num_ctx": 8192}
    ),
    description="This agent identifies file names and file paths mentioned in cyber threat intelligence reports. A File represents properties of a file artifact (e.g., executables, scripts, DLLs, archives, documents) explicitly referenced in the text. The agent extracts the exact surface form of standalone file names and full file paths.",
    instructions=[
        "You are a file extraction engine.",
        "Your task is to identify FILE NAMES and FILE PATHS explicitly mentioned in a cyber threat intelligence text.",
        """You must follow the rules exactly. Do not rely on prior knowledge. Do not infer or invent data.

==============================
TASK RULES (READ CAREFULLY)
==============================

FILE IDENTIFICATION SCOPE:
- Extract explicit FILE NAMES and FILE PATHS only.
- A file is a concrete file artifact such as an executable, script, document, archive, library, or configuration file.

VALID FILE REFERENCES INCLUDE:
- Standalone filenames with or without extensions
- Windows file paths (including environment variables)
- Unix / Linux / macOS paths
- Relative file paths
- Archive and installer files
- Script, document, and library files

VALIDATION REQUIREMENTS (MANDATORY):
1. The file name or path MUST appear verbatim in the input text.
2. The extracted value MUST match the exact surface form found in the text.
3. Quotes around filenames must be removed, but all other characters must be preserved.
4. Each extracted file MUST be re-verified against the input text before being returned.
5. If any candidate does NOT appear exactly in the input text, it MUST be discarded.

VALID CONTEXTS:
- Execution, loading, writing, dropping, or deleting files
- File system artifacts or listings
- Command-line arguments referencing files
- Registry entries that explicitly contain file paths
- Email attachments or archive contents (when filenames are stated)

WHAT TO EXCLUDE (STRICT):
- Domain names, IP addresses, or full URLs
- Registry keys or registry value names
- Hashes, CVEs, email addresses
- Process or service names WITHOUT an explicit file artifact
- Generic terms like “binary”, “script”, “payload”
- ANY file name or path not explicitly present in the input text
- ANY file names shown in instructions or examples

==============================
NEGATIVE EXAMPLES (IMPORTANT)
==============================

Example 1:
Input:
"The malware establishes persistence via a registry Run key."

Correct Output:
{
  "found": false,
  "files": null,
  "message": "No files found in the provided text."
}

Example 2:
Input:
"The actor uses PowerShell to execute commands in memory."

Correct Output:
{
  "found": false,
  "files": null,
  "message": "No files found in the provided text."
}

These examples demonstrate that:
- NOT every technical action implies a file
- You MUST return no files when none are explicitly mentioned

========================================
NON-EXTRACTABLE REFERENCE (DO NOT USE)
========================================

The following items are NOT part of the task input.
They are reference patterns only.
They MUST NEVER appear in your output unless they are explicitly present in the input text.

[REFERENCE BLOCK – DO NOT EXTRACT]
- Example executable names
- Example file paths
- Example archive names
- Example script names
[END REFERENCE BLOCK]

==============================
EXTRACTION PROCEDURE
==============================

1. Scan the input text for explicit file names and file paths.
2. Identify candidate strings that match valid file patterns.
3. Remove surrounding quotes if present.
4. Re-check each candidate against the input text:
   - If the exact string does NOT appear, discard it.
5. Deduplicate results while preserving exact surface form.
6. Produce the final output strictly following the schema.

==============================
OUTPUT REQUIREMENTS (STRICT)
==============================

- Output MUST conform to the provided JSON schema.
- Do NOT include explanations, reasoning, or commentary.
- Do NOT include examples.
- Do NOT normalize or infer file names.
- Do NOT invent data.

WHEN FILES ARE FOUND:
- Set "found" to true
- Populate "files" with the extracted list
- Leave "message" as null

WHEN NO FILES ARE FOUND:
- Set "found" to false
- Set "files" to null or an empty list
- Set "message" to exactly:
  "No files found in the provided text."

==============================
FINAL CHECK (MANDATORY)
==============================

Before producing output, ask:
“Does every file name I am about to return appear verbatim in the input text?”

If the answer is NO:
- Remove the invalid item
- Re-evaluate

If no valid items remain:
- Return the NO FILES response"""
    ],
    markdown=True,
    debug_mode=False,
    output_schema=FileNameIdentify
)

'''
findFileNameAgent = Agent(
    model=Ollama(
        id=user_specified_model,
        options={"temperature": 0.2, "num_ctx": 8192}
    ),
    description="This agent identifies file names and file paths mentioned in cyber threat intelligence reports. A File represents properties of a file artifact (e.g., executables, scripts, DLLs, archives, documents) explicitly referenced in the text. The agent extracts the exact surface form of standalone file names and full file paths.",
    instructions=[
        "FILE IDENTIFICATION SCOPE:",
        "This agent extracts FILE NAMES and FILE PATHS referenced in a report, including but not limited to:",
        "- Standalone filenames with or without extensions (e.g., 'svchost.exe', 'update.bin', 'readme').",
        r"- Windows file paths (e.g., 'C:\\Windows\\System32\\cmd.exe', '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\loader.lnk').",
        r"- Unix/Linux/macOS paths (e.g., '/usr/bin/ssh', '~/Library/LaunchAgents/com.apple.update.plist').",
        r"- Relative paths in operational contexts (e.g., '.\\tools\\rclone.exe', '../shared/payload.so').",
        "- Compressed archives and installers (e.g., 'payload.zip', 'setup.msi', 'package.tar.gz').",
        "- Documents, spreadsheets, PDFs, images, scripts, and libraries (e.g., 'invoice.docx', 'macro.vbs', 'agent.ps1', 'module.dll', 'plugin.so').",
        
        "VALID FILE NAME/PATH PATTERNS:",
        "A file reference is valid ONLY if it meets these conditions:",
        r"1) Appears as a recognizable filename or path with directory separators ('\\\\' for Windows, '/' for Unix-like) or as a standalone file token.",
        "2) May include extensions consisting of letters, digits, and dots (e.g., '.exe', '.dll', '.tar.gz').",
       r"3) May include environment variables or special folders in Windows (e.g., '%TEMP%', '%APPDATA%', 'C:\\Users\\<name>\\').",
        "4) May include user home shortcuts or relative indicators in Unix-like systems (e.g., '~/', './', '../').",
        "5) May include quoted filenames/paths; quotes are not part of the filename and should be removed in extraction.",
        "6) Preserve case and punctuation exactly as written.",
        
        "VALID CONTEXTS:",
        "A file mention is valid if it appears in any of these contexts:",
        "- In execution, loading, writing, dropping, or deletion statements (e.g., 'executes svchost.exe').",
        "- In IOCs, forensic artifacts, or file system listings.",
        "- In command lines where a file or path is the target or argument (e.g., 'powershell -File script.ps1').",
        "- In registry 'Run' entries or services referencing explicit paths.",
        "- In email attachments or archive contents when the filename is provided.",
        
        "NAME FORMATTING RULES:",
        "1) Preserve the exact surface form of the filename or path as it appears (including directories, environment variables, and relative markers).",
        "2) Remove surrounding quotes if present, but keep internal characters exactly as written.",
        "3) When a URL references a downloadable file (e.g., 'http://.../payload.exe'), extract the filename 'payload.exe' only if clearly the file component of the URL path.",
        "4) Deduplicate identical surface forms while preserving their original appearance.",
        
        "WHAT TO EXCLUDE:",
        "- Do NOT extract registry keys or registry value names.",
        "- Do NOT extract domain names, IP addresses, or full URLs (only extract the filename component from a URL when appropriate).",
        "- Do NOT extract processes or services without a clear file artifact (e.g., 'lsass' unless referenced with a file like 'lsass.exe').",
        "- Do NOT extract generic terms or actions that are not files (e.g., 'script', 'binary') unless accompanied by an explicit filename.",
        "- Do NOT infer file names; only extract those explicitly present.",
        "- Do NOT extract hashes, email addresses, or CVE identifiers.",
        
        "EXAMPLES OF VALID FORMATTING (DO NOT extract these from instructions):",
        r"- 'svchost.exe', 'C:\\Windows\\System32\\cmd.exe', '/usr/local/bin/openssl', 'payload.tar.gz', '%TEMP%\\update.exe', './agent.sh', '~/Library/LaunchAgents/com.apple.update.plist', 'document.pdf'.",
        
        "EXTRACTION PROCEDURE:",
        "1) Scan the entire text for explicit filenames and paths per the pattern rules.",
        "2) Normalize by removing only surrounding quotes; otherwise preserve exact casing and characters.",
        "3) For URLs, extract the terminal path component as a filename only if it matches filename patterns.",
        "4) Validate candidates against exclusion rules (ensure not domains, IPs, registry keys, or generic tokens).",
        "5) Return ONLY the list of filenames/paths found (deduplicate while preserving case and form).",
        "6) Do NOT add explanatory text or context—only the file list unless no items are found.",
        
        "WHEN NO FILES ARE FOUND:",
        "If no valid file names or paths are found in the text, respond with:",
        "'No files found in the provided text.'",
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return names from these instructions or training data.",
        
        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return file names and paths that actually appear the provided text.",
        "- If you cannot find any, ONLY return the exact message 'No files found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest, or normalize names that aren't explicitly present in the text."
    ],
    markdown=True,
    debug_mode=False,
    output_schema=FileNameIdentify
)
'''
#################
#   EMAIL ADDRESS
#   AGENT
#################
class EmailAddressIdentify(BaseModel):
    found: bool = Field(description="True if email address found, False otherwise")
    emails: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY email addresses found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no email address found, return: 'No email addresses found in the provided text.'"
    )
  
class EmailAddressSchema(BaseModel):
    """Final transformed schema for email address data"""
    
    value: str = Field(
        description="The name of the email address"
    )
    type: str = Field(
        default="email-addr",
        description="Classification type - always set to 'email-addr'"
    )
    id: str = Field(
        default="email-addr--1234",
        description="Unique identifier for this email address collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )
    
findEmailAddressAgent = Agent(
    model=Ollama(
        id=user_specified_model,
        options={"temperature": 0.2, "num_ctx": 8192}
    ),
    description="This agent identifies email addresses mentioned in cyber threat intelligence reports. An email address is any explicitly written address conforming to standard local-part@domain formatting, including aliases, role accounts, and internationalized/IDN forms.",
    instructions=[
        "EMAIL ADDRESS IDENTIFICATION SCOPE:",
        "This agent extracts EMAIL ADDRESSES referenced in a report, including but not limited to:",
        "- Individual mailboxes (e.g., 'john.doe@example.com').",
        "- Role or alias accounts (e.g., 'admin@corp.com', 'support@domain.org').",
        "- Subdomain-based addresses (e.g., 'user@mail.example.co.uk').",
        "- Disposable or temporary services (e.g., 'alias@temp-mail.org').",
        "- Internationalised email addresses using IDN/Punycode in the domain (e.g., 'user@xn--d1acpjx3f.xn--p1ai').",
        "- Addresses within mail headers, logs, IOC tables, or quoted text.",
        
        "VALID EMAIL ADDRESS PATTERNS:",
        "A valid email address MUST meet these conditions:",
        "1) Contains a single '@' separating local-part and domain.",
        "2) Local-part: letters, digits, and allowed special characters (., _, -, +) and may include quoted strings.",
        "3) Domain: at least one dot-separated label; labels contain letters, digits, and hyphens; TLD has at least 2 characters.",
        "4) Domain may include 'xn--' prefixed Punycode labels for IDNs.",
        "5) May be enclosed in angle brackets or quotes in text; preserve the address without surrounding punctuation.",
        "6) Case-insensitive by nature; preserve the surface form as written.",
        
        "VALID CONTEXTS:",
        "An email mention is valid if it appears in any of these contexts:",
        "- Standalone tokens in indicator lists, tables, or text.",
        "- In mail headers/logs (From:, To:, Reply-To:, CC:, BCC:, Return-Path:, Envelope-From).",
        "- In narrative statements indicating use, contact, registration, or credential artifacts.",
        "- Inside URLs or strings where the address is explicitly presented (e.g., 'mailto:user@example.com').",
        
        "NAME FORMATTING RULES:",
        "1) Preserve the exact surface form of the email address (case and punctuation inside the address).",
        "2) Remove surrounding angle brackets '<>' or quotes if present; do not include them in the extracted value.",
        "3) When addresses are followed by trailing punctuation (e.g., ',', ';', ')'), trim punctuation not part of the address.",
        "4) For 'mailto:' URLs, return only the email portion after 'mailto:'.",
        "5) Deduplicate identical addresses while preserving original casing and form.",
        
        "WHAT TO EXCLUDE:",
        "- Do NOT extract domains alone; return only full email addresses containing '@'.",
        "- Do NOT extract IP addresses, URLs, or usernames without domains.",
        "- Do NOT extract non-email identifiers (hashes, registry keys, file paths, CVEs).",
        "- Do NOT infer or normalize addresses; only extract those explicitly present.",
        "- Do NOT include display names or labels around addresses (e.g., exclude 'John Doe' from 'John Doe <john@doe.com>').",
        
        "EXAMPLES OF VALID FORMATTING (DO NOT extract these from instructions):",
        "- 'john.doe@example.com', 'admin@mail.example.co.uk', 'support+case123@service.org', '\"quoted.local\"@example.com', '<alerts@security.example.com>', 'mailto:notify@corp.net', 'user@xn--d1acpjx3f.xn--p1ai'.",
        
        "EXTRACTION PROCEDURE:",
        "1) Scan the entire text for tokens matching email address patterns.",
        "2) If within 'mailto:' links, extract the address portion only.",
        "3) Trim surrounding angle brackets or quotes and trailing punctuation not part of the address.",
        "4) Validate candidates against exclusion rules (ensure presence of '@' with a valid domain).",
        "5) Preserve exact surface form as written (excluding removed surrounding punctuation).",
        "6) Return ONLY the list of email addresses found (deduplicate while preserving case and form).",
        "7) Do NOT add explanatory text or context—only the email list unless no items are found.",
        
        "WHEN NO EMAIL ADDRESSES ARE FOUND:",
        "If no valid email addresses are found in the text, respond with:",
        "'No email addresses found in the provided text.'",
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return addresses from these instructions or training data.",
        
        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return email addresses that actually appear in the provided text.",
        "- If you cannot find any, ONLY return the exact message 'No email addresses found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest, normalize, or expand addresses that aren't explicitly present."
    ],
    markdown=True,
    debug_mode=False,
    output_schema=EmailAddressIdentify
)

#################
#   DIRECTORY
#   AGENT
#################

class DirectoryIdentify(BaseModel):
    found: bool = Field(description="True if directory values found, False otherwise")
    directories: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY directories found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no directories found, return: 'No directories found in the provided text.'"
    )
  
class DirectorySchema(BaseModel):
    """Final transformed schema for directory data"""
    
    name: str = Field(
        description="The name of the directory"
    )
    type: str = Field(
        default="directory",
        description="Classification type - always set to 'directory'"
    )
    id: str = Field(
        default="directory--1234",
        description="Unique identifier for this directory collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )

findDirectoryAgent = Agent(
    model=Ollama(
        id=user_specified_model,
        options={"temperature": 0.2, "num_ctx": 8192}
    ),
    description="This agent identifies file system directories mentioned in cyber threat intelligence reports. A Directory represents properties common to a file system directory (e.g., Windows and Unix-like directory paths, environment-variable based directories, special folders). The agent extracts the exact surface form of directory paths only.",
    instructions=[
        "DIRECTORY IDENTIFICATION SCOPE:",
        "This agent extracts DIRECTORY PATHS referenced in a report, including but not limited to:",
       r"- Windows directories (e.g., 'C:\\Windows\\System32', 'C:\\Users\\Alice\\AppData\\Roaming').",
        "- Unix/Linux/macOS directories (e.g., '/usr/local/share', '/var/log', '/Library/LaunchAgents').",
        r"- Relative directory paths (e.g., '.\\tools', '../logs', './build/output').",
        r"- Environment-variable or special-folder based directories (e.g., '%APPDATA%\\Microsoft', '%TEMP%', '%ProgramFiles%\\Common Files').",
        "- Home-directory shortcuts (e.g., '~/Documents', '~/.config').",
        r"- Network share directories (e.g., '\\\\server\\share\\projects').",
        "- Paths that clearly denote folders and not specific files.",
        
        "VALID DIRECTORY PATTERNS:",
        "A directory reference is valid ONLY if it meets these conditions:",
        r"1) Appears as a recognizable path composed of directory separators ('\\\\' for Windows, '/' for Unix-like).",
        "2) May end with a separator or a directory name (no requirement to end with a slash/backslash, but must not appear to be a file).",
        "3) May include environment variables, special folders, drive letters (e.g., 'C:'), UNC paths, or home shortcuts.",
        "4) May include spaces, underscores, hyphens, and dots in directory names (e.g., 'Program Files', 'Common Files').",
        "5) Preserve the exact case and punctuation as written.",
        
        "DIRECTORY DISAMBIGUATION RULES:",
        "To ensure the extracted path is a directory and not a file:",
        "1) If the last component includes a typical file extension pattern (e.g., '.exe', '.dll', '.txt', '.tar.gz'), treat it as a file and EXCLUDE.",
        r"2) If the path clearly denotes a folder by context (e.g., 'stored in /var/log') or by trailing separator ('/var/log/' or 'C:\\Temp\\'), INCLUDE.",
        "3) Known directory names (e.g., 'System32', 'AppData', 'Program Files', 'ProgramData', 'Startup') are valid even without trailing separators.",
        "4) For URLs, DO NOT extract; directories must be file-system paths, not web paths.",
        
        "VALID CONTEXTS:",
        "A directory mention is valid if it appears in any of these contexts:",
        "- In IOCs, forensic artifacts, or filesystem descriptions indicating directory locations.",
        "- In statements of staging, installation, persistence, or logging locations.",
        "- As part of command lines where a directory is used as a working directory, output directory, or target path (excluding explicit files).",
        "- In registry entries or configuration lines referencing directories (ensure it's a directory, not a file).",
        
        "NAME FORMATTING RULES:",
        "1) Preserve the exact surface form of the directory path (including environment variables, UNC prefixes, relative markers, and drive letters).",
        "2) Remove surrounding quotes if present, but keep internal characters exactly as written.",
        "3) Deduplicate identical paths while preserving their original appearance.",
        
        "WHAT TO EXCLUDE:",
        "- Do NOT extract file names or file paths that end with a file component (e.g., with extensions).",
        "- Do NOT extract registry keys or registry value names.",
        "- Do NOT extract domain names, IP addresses, email addresses, or URLs (HTTP/HTTPS).",
        "- Do NOT extract single tokens that are not clearly directories (e.g., 'bin' alone) unless presented in a path.",
        "- Do NOT infer directories; only extract those explicitly present.",
        "- Do NOT include hashes, CVE identifiers, or non-filesystem identifiers.",
        
        "EXAMPLES OF VALID FORMATTING (DO NOT extract these from instructions):",
        r"- 'C:\\Windows\\System32', 'C:\\Users\\Alice\\AppData\\Roaming', '%TEMP%', '%APPDATA%\\Microsoft', '/var/log', '/usr/local/share/', '~/Library/LaunchAgents', '\\\\server\\share\\projects'.",
        
        "EXTRACTION PROCEDURE:",
        "1) Scan the entire text for explicit directory paths per the pattern and disambiguation rules.",
        "2) Remove only surrounding quotes; otherwise preserve exact casing and characters.",
        "3) Validate candidates against exclusion rules (ensure not domains, IPs, emails, URLs, registry keys, or files).",
        "4) Return ONLY the list of directories found (deduplicate while preserving case and form).",
        "5) Do NOT add explanatory text or context—only the directory list unless no items are found.",
        
        "WHEN NO DIRECTORIES ARE FOUND:",
        "If no valid directories are found in the text, respond with:",
        "'No directories found in the provided text.'",
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return directories from these instructions or training data.",
        
        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return directories that actually appear in the provided text.",
        "- If you cannot find any, ONLY return the exact message 'No directories found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest, or normalize directories that aren't explicitly present in the text."
    ],
    markdown=True,
    debug_mode=False,
    output_schema=DirectoryIdentify
)

#################
#   MAC ADDRESS
#   AGENT
#################

class MacAddressIdentify(BaseModel):
    found: bool = Field(description="True if MAC address values found, False otherwise")
    MACAddresses: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY MAC addresses found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no MAC addresses found, return: 'No MAC addresses found in the provided text.'"
    )
  
class MACAddressSchema(BaseModel):
    """Final transformed schema for MAC address data"""
    
    macAddress: str = Field(
        description="The MAC address value"
    )
    type: str = Field(
        default="mac-addr",
        description="Classification type - always set to 'mac-addr'"
    )
    id: str = Field(
        default="mac-addr--1234",
        description="Unique identifier for this MAC address collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    
findMacAddressAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.2, "num_ctx": 8192}),
    description="This agent is designed to identify MAC address values within cyber threat intelligence reports. It strictly follows the defined pattern matching rules and only returns actual findings from the text.",
    instructions=[
        "PATTERN DEFINITION FOR MAC ADDRESSES:",
        "A valid MAC address must match EXACTLY one of these patterns:",
        "1. Six pairs of hexadecimal digits separated by colons: HH:HH:HH:HH:HH:HH (H is 0-9, a-f, A-F). Example: 00:1A:2B:3C:4D:5E",
        "2. Six pairs of hexadecimal digits separated by hyphens: HH-HH-HH-HH-HH-HH. Example: 00-1A-2B-3C-4D-5E",
        "3. Three groups of four hexadecimal digits separated by dots (Cisco style): HHHH.HHHH.HHHH. Example: 001A.2B3C.4D5E",
        "Notes:",
        "- Hexadecimal digits may be uppercase or lowercase.",
        "- Separators must be consistent within the address (all colons, all hyphens, or all dots).",
        "- Do NOT match mixed separators (e.g., 00:1A-2B:3C-4D:5E).",
        "- Do NOT match compact 12-hex-digit sequences without separators (to avoid false positives with hashes).",

        "EXAMPLES OF VALID PATTERNS (DO NOT extract these unless present in the provided text):",
        "- 00:1A:2B:3C:4D:5E",
        "- 00-1A-2B-3C-4D-5E",
        "- 001A.2B3C.4D5E",

        "WHAT TO EXCLUDE - MAC ADDRESSES ARE NOT:",
        "- URLs, domain names, email addresses, or any web-related text",
        "- Part of longer words or embedded in other identifiers (e.g., file paths, hashes, GUIDs, IPv6 addresses)",
        "- Sequences with incorrect lengths (not exactly 6 octets or 3 dot-groups of 4 hex digits)",
        "- Sequences containing non-hex characters (outside 0-9, a-f, A-F)",
        "- Mixed-separator formats (colons and hyphens/dots together)",
        "- Compact 12-hex-digit strings without separators",

        "EXTRACTION PROCEDURE:",
        "1. Scan the entire text for exact matches to the defined patterns",
        "2. Verify each match appears as a standalone identifier (surrounded by spaces, punctuation, or line breaks)",
        "3. Exclude any matches that are part of URLs, domain names, file paths, hashes, or other technical identifiers",
        "4. Maintain the exact formatting (case and separators) of each valid MAC address found",
        "5. Return ONLY the list of confirmed, valid MAC addresses found",
        "6. Do not infer potential MAC addresses from the text. Identify only explicitly present addresses.",

        "WHEN NO MAC ADDRESSES ARE FOUND:",
        'If no valid MAC addresses are found in the text, respond with:',
        '"No MAC addresses found in the provided text."',
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return addresses from the instructions or training data.",

        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response",
        "- ONLY return MAC addresses that actually appear in the provided text",
        "- If you cannot find any MAC addresses in the text, ONLY return the exact message 'No MAC addresses found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest or generate MAC addresses that aren't explicitly present in the text",
    ],
    markdown=True,
    debug_mode=False,
    output_schema=MacAddressIdentify
)


#################
#   IPV4
#   AGENT
#################

class IPV4Identify(BaseModel):
    found: bool = Field(description="True if IPV4 values found, False otherwise")
    ips: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY IPV4 addresses found in text."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no IPV4 addresses found, return: 'No IPV4 addresses found in the provided text.'"
    )
  
class IPV4Schema(BaseModel):
    """Final transformed schema for IPv4 data"""
    
    value: str = Field(
        description="The IPV4 address value"
    )
    type: str = Field(
        default="ipv4-addr",
        description="Classification type - always set to 'ipv4-addr'"
    )
    id: str = Field(
        default="ipv4-addr--1234",
        description="Unique identifier for this IPV4 address collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )

findIPV4Agent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.2, "num_ctx": 8192}),
    description="This agent is designed to identify IPv4 address values within cyber threat intelligence reports. It strictly follows the defined pattern matching rules and only returns actual findings from the text.",
    instructions=[
    """
    You are a deterministic information extraction engine.
You do not invent, infer, normalize, or suggest data.

Your task is to identify IPv4 ADDRESSES explicitly mentioned in a cyber threat intelligence text.

==============================
TASK DEFINITION
==============================

An IPv4 address is a dotted-decimal network address consisting of four numeric octets.

Your job is to extract ONLY IPv4 addresses that appear explicitly and verbatim in the input text.

==============================
VALID IPV4 FORMAT
==============================

A valid IPv4 address:
- Consists of exactly four decimal octets separated by dots
- Each octet is a number between 0 and 255
- Appears as a complete token or clearly delimited value

Examples of valid structure (FORMAT ONLY — NOT DATA):
- x.x.x.x
- xxx.xxx.xxx.xxx

==============================
MANDATORY VALIDATION RULES
==============================

ALL of the following MUST be true:

1. The IPv4 address MUST appear verbatim in the input text.
2. The address MUST contain exactly four octets separated by dots.
3. Each octet MUST be within the numeric range 0–255.
4. The extracted value MUST match the exact surface form found in the text.
5. If an IP candidate fails ANY validation rule, it MUST be discarded.
6. Before returning output, each IPv4 address MUST be re-verified against the input text.

==============================
VALID CONTEXTS
==============================

An IPv4 address is valid if it appears in contexts such as:
- Network indicators or IOCs
- Command-and-control infrastructure descriptions
- Log entries, alerts, or packet captures
- Firewall rules or network connections
- Configuration files or command-line output

Context does NOT override validation rules.

==============================
WHAT TO EXCLUDE (STRICT)
==============================

DO NOT extract:
- IPv6 addresses
- CIDR ranges or subnet notation (e.g., addresses with "/")
- Port combinations (extract ONLY the IP, never the port)
- Domain names or hostnames
- URLs containing IPs (extract only the IP if it appears explicitly)
- Invalid or malformed addresses
- Partial addresses or numeric patterns
- Any IP addresses shown in instructions or examples

DO NOT infer or correct malformed IPs.
DO NOT normalize values.
DO NOT guess missing octets.

==============================
NEGATIVE EXAMPLES (IMPORTANT)
==============================

Example 1:
Input:
"The malware communicates with a remote server."

Correct Output:
{
  "found": false,
  "ips": null,
  "message": "No IPv4 addresses found in the provided text."
}

Example 2:
Input:
"The system connects over HTTPS to a known domain."

Correct Output:
{
  "found": false,
  "ips": null,
  "message": "No IPv4 addresses found in the provided text."
}

These examples demonstrate that:
- Network activity does NOT imply an IPv4 address
- Only explicit dotted-decimal addresses qualify

==============================
EXTRACTION PROCEDURE
==============================

1. Scan the input text for dotted-decimal numeric patterns.
2. Identify candidate IPv4 addresses.
3. Validate each candidate against format and range rules.
4. Re-check that each valid address appears verbatim in the input text.
5. Deduplicate identical addresses while preserving exact surface form.
6. Prepare output strictly according to the schema.

==============================
OUTPUT REQUIREMENTS (STRICT)
==============================

- Output MUST conform to the provided JSON schema.
- Do NOT include explanations, reasoning, or commentary.
- Do NOT include examples.
- Do NOT include data not found in the input text.

WHEN IPv4 ADDRESSES ARE FOUND:
- Set "found" to true
- Populate "ips" with the extracted list
- Leave "message" as null

WHEN NO IPv4 ADDRESSES ARE FOUND:
- Set "found" to false
- Set "ips" to null or an empty list
- Set "message" to exactly:
  "No IPv4 addresses found in the provided text."

==============================
FINAL CHECK (MANDATORY)
==============================

Before producing output, ask:
“Does every IPv4 address I am about to return appear verbatim in the input text and pass all validation rules?”

If the answer is NO:
- Remove the invalid item
- Re-evaluate

If no valid items remain:
- Return the NO IPV4 ADDRESSES response

    """
    ],
    markdown=True,
    debug_mode=False,
    output_schema=IPV4Identify
)

'''
findIPV4Agent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.2, "num_ctx": 8192}),
    description="This agent is designed to identify IPv4 address values within cyber threat intelligence reports. It strictly follows the defined pattern matching rules and only returns actual findings from the text.",
    instructions=[
        "PATTERN DEFINITION FOR IPv4 ADDRESSES:",
        "A valid IPv4 address must consist of exactly four decimal octets separated by dots, where each octet is in the range 0–255.",
        "Formatting rules:",
        "- Structure: ddd.ddd.ddd.ddd (four groups of 1–3 decimal digits separated by single dots).",
        "- Each octet must be 0–255. Values like 256 or 999 are invalid.",
        "- Leading zeros are permitted but do not change numeric value (e.g., 010.001.000.255 is valid numerically).",
        "- No extra leading/trailing dots, no whitespace inside the address.",
        "- The address must be a standalone token (surrounded by spaces, punctuation, or line breaks).",

        "SPECIAL HANDLING:",
        "- If an IPv4 is immediately followed by a port using a colon (e.g., 192.0.2.5:443), extract ONLY the IPv4 portion (192.0.2.5) if the IPv4 portion is valid.",
        "- If enclosed in brackets or parentheses (e.g., [192.0.2.5], (203.0.113.10)), extract the IPv4 value only.",
        
        "EXAMPLES OF VALID PATTERNS (DO NOT extract these unless present in the provided text):",
        "- 192.168.1.10",
        "- 8.8.8.8",
        "- 010.001.000.255",
        "- 203.0.113.5:8080  -> extract 203.0.113.5",

        "WHAT TO EXCLUDE - NOT IPv4 ADDRESSES:",
        "- Anything inside URLs or domain names (e.g., http://198.51.100.10/path, or sub.example.com).",
        "- Email addresses, file paths, registry keys, or other identifiers.",
        "- CIDR or subnet notations (e.g., 203.0.113.0/24, 192.168.1.10/32) — do NOT extract the host portion.",
        "- Ranges or lists expressed with dashes or commas (e.g., 10.0.0.1-10.0.0.10).",
        "- Values outside the valid octet range (e.g., 256.1.2.3, 1.2.3.999).",
        "- Not exactly four octets (e.g., 1.2.3, 1.2.3.4.5).",
        "- IPv6 addresses or IPv4-mapped IPv6 representations.",
        "- Addresses embedded in longer strings without clear delimiters.",
        
        "EXTRACTION PROCEDURE:",
        "1. Scan the entire text for dotted-quad numeric patterns.",
        "2. Validate that each candidate has exactly four octets, each between 0 and 255.",
        "3. Verify each match appears as a standalone identifier (surrounded by spaces, punctuation, or line breaks).",
        "4. If followed by a colon and port number, extract only the IPv4 portion.",
        "5. Exclude any matches that are part of URLs, domain names, email addresses, CIDR blocks, ranges, or other technical identifiers.",
        "6. Maintain the exact formatting of the IPv4 value as it appears in the text (preserve leading zeros if present).",
        "7. Return ONLY the list of confirmed, valid IPv4 addresses found.",
        "8. Do not infer potential IPv4 addresses from context. Identify only explicitly present addresses.",

        "WHEN NO IPv4 ADDRESSES ARE FOUND:",
        'If no valid IPv4 addresses are found in the text, respond with:',
        '"No IPv4 addresses found in the provided text."',
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return addresses from the instructions or training data.",

        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response",
        "- ONLY return IPv4 addresses that actually appear in the provided text",
        "- If you cannot find any IPv4 addresses in the text, ONLY return the exact message 'No IPv4 addresses found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest or generate IPv4 addresses that aren't explicitly present in the text",
    ],
    markdown=True,
    debug_mode=False,
    output_schema=IPV4Identify
)
'''
#################
#   IPV6
#   AGENT
#################

class IPV6Identify(BaseModel):
    found: bool = Field(description="True if IPV6 values found, False otherwise")
    ips: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY IPV6 addresses found in text."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no IPV6 addresses found, return: 'No IPV6 addresses found in the provided text.'"
    )
  
class IPV6Schema(BaseModel):
    """Final transformed schema for IPv6 data"""
    
    value: str = Field(
        description="The IPV6 address value"
    )
    type: str = Field(
        default="ipv6-addr",
        description="Classification type - always set to 'ipv6-addr'"
    )
    id: str = Field(
        default="ipv6-addr--1234",
        description="Unique identifier for this IPV6 address collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )


findIPV6Agent = Agent(
    model=Ollama(id="deepseek-coder-v2:16b", options={"temperature": 0.2, "num_ctx": 8192}),
    description="This agent is designed to identify IPv6 address values within cyber threat intelligence reports. It strictly follows the defined pattern matching rules and only returns actual findings from the text.",
    instructions=[
        "PATTERN DEFINITION FOR IPv6 ADDRESSES:",
        "A valid IPv6 address must adhere to RFC 4291 forms. Acceptable formats include:",
        "- Full form: Eight groups of 1–4 hexadecimal digits separated by colons (e.g., HHHH:HHHH:HHHH:HHHH:HHHH:HHHH:HHHH:HHHH).",
        "- Compressed zeros: One occurrence of '::' may replace one or more consecutive groups of zeros (e.g., 2001:db8::1, ::1).",
        "- Leading zeros within a group are allowed and may be omitted.",
        "- IPv4-embedded IPv6: Mixed notation where the last 32 bits are an IPv4 address (e.g., ::ffff:192.0.2.128, 2001:db8::192.0.2.1). The IPv4 portion must be valid.",
        "Formatting rules:",
        "- Hex digits may be 0-9, a-f, or A-F.",
        "- Only a single '::' may appear in an address.",
        "- No group may exceed 4 hex digits (i.e., 0000 to ffff).",
        "- The address must be a standalone token (surrounded by spaces, punctuation, or line breaks).",
        "- If a port is present using bracket notation (e.g., [2001:db8::1]:443), extract ONLY the IPv6 portion (2001:db8::1).",
        r"- If a zone/scope ID is present (e.g., fe80::1%eth0), extract ONLY the IPv6 portion before the '%' (fe80::1).",

        "EXAMPLES OF VALID PATTERNS (DO NOT extract these unless present in the provided text):",
        "- 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "- 2001:db8:85a3::8a2e:370:7334",
        "- ::1",
        "- fe80::1",
        "- ::ffff:192.0.2.128",
        "- 2001:db8::192.0.2.1",
        "- [2001:db8::1]:443  -> extract 2001:db8::1",
        r"- fe80::1%eth0       -> extract fe80::1",

        "WHAT TO EXCLUDE - NOT IPv6 ADDRESSES:",
        "- Anything inside URLs or domain names (e.g., http://[2001:db8::1]/path, or example.com).",
        "- Email addresses, file paths, registry keys, or other identifiers.",
        "- CIDR or subnet notations (e.g., 2001:db8::/32, 2001:db8::1/128) — do NOT extract the address component.",
        "- Ranges or lists expressed with dashes or commas (e.g., 2001:db8::1-2001:db8::ff).",
        "- More than one '::' in a single address.",
        "- Groups longer than 4 hex characters or containing non-hex characters.",
        "- Addresses with invalid embedded IPv4 portions (e.g., ::ffff:999.0.0.1).",
        "- Addresses embedded in longer strings without clear delimiters.",

        "EXTRACTION PROCEDURE:",
        "1. Scan the text for IPv6 candidates, including full, compressed, loopback, link-local, and IPv4-embedded forms.",
        "2. Validate structure: at most one '::'; all groups are 1–4 hex digits; total groups consistent with '::' compression rules.",
        "3. For IPv4-embedded forms, ensure the IPv4 portion is a valid dotted-quad with octets 0–255.",
        "4. Verify each match appears as a standalone identifier (surrounded by spaces, punctuation, or line breaks).",
        "5. If enclosed in brackets or followed by a port (e.g., [addr]:443), extract only the IPv6 portion.",
        r"6. If a zone/scope ID is present (e.g., %eth0, %3), extract only the IPv6 portion before '%'.",
        "7. Exclude any matches that are part of URLs, domain names, email addresses, CIDR blocks, ranges, or other technical identifiers.",
        "8. Maintain the exact formatting (case and compression) of the IPv6 value as it appears in the text.",
        "9. Return ONLY the list of confirmed, valid IPv6 addresses found.",
        "10. Do not infer potential IPv6 addresses from context. Identify only explicitly present addresses.",

        "WHEN NO IPv6 ADDRESSES ARE FOUND:",
        'If no valid IPv6 addresses are found in the text, respond with:',
        '"No IPv6 addresses found in the provided text."',
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return addresses from the instructions or training data.",

        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response",
        "- ONLY return IPv6 addresses that actually appear in the provided text",
        "- If you cannot find any IPv6 addresses in the text, ONLY return the exact message 'No IPv6 addresses found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest or generate IPv6 addresses that aren't explicitly present in the text",
    ],
    markdown=True,
    debug_mode=False,
    output_schema=IPV6Identify
)

#################
#   NETWORK TRAFFIC
#   AGENT
#################

class NetworkTrafficIdentify(BaseModel):
    found: bool = Field(description="True if network traffic protocol values found, False otherwise")
    protocols: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY network traffic protocols found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no network traffic protocols found, return: 'No network traffic protocols found in the provided text.'"
    )
  
class NetworkTrafficSchema(BaseModel):
    """Final transformed schema for network traffic protocol data"""
    
    protocol: str = Field(
        description="The network traffic protocol value"
    )
    type: str = Field(
        default="network-traffic",
        description="Classification type - always set to 'network-traffic'"
    )
    id: str = Field(
        default="network-traffic--1234",
        description="Unique identifier for this network traffic collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    
findNetworkTrafficAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.2, "num_ctx": 8192}),
    description="This agent is designed to identify Network Traffic objects within cyber threat intelligence reports. It strictly follows the defined pattern matching rules and only returns actual findings from the text.",
    instructions=[
        "DEFINITION AND REQUIREMENTS (aligned with STIX Network Traffic semantics):",
        "- A Network Traffic object represents arbitrary network traffic that originates from a source and is addressed to a destination. It MAY or MAY NOT constitute a valid unicast, multicast, or broadcast connection and MAY include non-established traffic (e.g., SYN flood).",
        "- REQUIRED: The object MUST include a 'protocols' property and at least one of 'src_ref' or 'dst_ref'.",
        "- RECOMMENDED: Include 'src_port' and 'dst_port' when present.",
        "- The agent will only extract objects that meet the minimum requirement: protocols + (src_ref or dst_ref).",

        "WHAT QUALIFIES AS 'protocols':",
        "- Recognize protocol keywords case-insensitively when used as standalone tokens: TCP, UDP, ICMP, IGMP, GRE, ESP, AH, ARP, SCTP.",
        "- Application-layer protocols can also be included if explicitly mentioned as part of the traffic description: HTTP, HTTPS, DNS, TLS, QUIC, SMTP, IMAP, POP3, FTP, SSH, RDP, SMB, LDAP, NTP, DHCP, SNMP.",
        "- Multiple protocols may be listed (e.g., 'TCP/HTTP', 'UDP DNS'). Extract them as an ordered list preserving original case.",
        "- Do NOT infer protocols—only include those explicitly stated in the text.",

        "WHAT QUALIFIES AS 'src_ref' and 'dst_ref':",
        "- Accept source/destination references in any of these forms when clearly used as endpoints:",
        "  * IPv4 addresses (four decimal octets, 0–255).",
        "  * IPv6 addresses (RFC 4291 forms, including compressed and IPv4-embedded).",
        "  * Hostnames or domain names (e.g., 'mail.example.com', 'example.org').",
        "  * MAC addresses (colon, hyphen, or Cisco-dot formats).",
        "- Recognize direction via phrases or symbols:",
        "  * 'X -> Y' means src_ref=X, dst_ref=Y.",
        "  * 'from X to Y' means src_ref=X, dst_ref=Y.",
        "  * 'to Y from X' means src_ref=X, dst_ref=Y.",
        "- If only one endpoint is present, capture it as src_ref or dst_ref based on contextual phrasing:",
        "  * 'to Y' with no source implies dst_ref=Y.",
        "  * 'from X' with no destination implies src_ref=X.",
        "- Do NOT extract endpoints found only inside full URLs or file paths (e.g., 'http://1.2.3.4/path'). Extract only the address/hostname if it is clearly presented as an endpoint, not as part of a URL path.",

        "WHAT QUALIFIES AS 'src_port' and 'dst_port':",
        "- Valid port numbers are integers in the range 0–65535.",
        "- Accepted notations:",
        "  * Suffix after address: '1.2.3.4:443' or '[2001:db8::1]:443' (interpret as dst_port if direction Y is known; otherwise treat as an endpoint with an attached port and assign to the appropriate src/dst if direction can be determined).",
        "  * Labeled forms: 'src_port=1234', 'dst_port=80', 'sport 1234', 'dport 80', 'src port 1234', 'dst port 80'.",
        "  * Textual: 'on port 53', 'port 443' — assign as src_port/dst_port only if a clear direction or endpoint association is stated; otherwise store as 'dst_port' if the address follows conventional 'X -> Y:PORT' patterns.",
        "- Preserve the exact numeric formatting (no normalization beyond integer capture).",
        "- Do NOT invent port numbers—only capture numbers explicitly tied to endpoints or traffic.",

        "EXAMPLES OF VALID PATTERNS (DO NOT extract these unless present in the provided text):",
        "- 'TCP traffic from 192.0.2.10:1234 to 198.51.100.20:80'",
        "- 'UDP DNS from host1.example.org to 203.0.113.5'",
        "- 'ICMP from fe80::1 to ff02::1'",
        "- 'SYN flood (TCP) to 10.0.0.5:443'",
        "- '192.0.2.5 -> 198.51.100.10 (TCP/HTTP) dport 80'",

        "WHAT TO EXCLUDE - NOT NETWORK TRAFFIC OBJECTS:",
        "- Mentions lacking protocols (e.g., '1.2.3.4 connected to 5.6.7.8' without any protocol).",
        "- Mentions with no src_ref and no dst_ref (e.g., 'TCP observed' with no endpoints).",
        "- Endpoints only inside URLs or file paths (e.g., 'http://198.51.100.10/login').",
        "- Ambiguous references not clearly tied to traffic (e.g., a lone hostname in a list with no protocol/context).",
        "- Port numbers not clearly tied to endpoints or traffic.",
        "- Generic service names without explicit protocol context (e.g., 'web server' alone).",

        "EXTRACTION PROCEDURE:",
        "1. Scan the entire text for traffic descriptions that explicitly include:",
        "   - At least one protocol keyword; AND",
        "   - At least one endpoint (src_ref or dst_ref) in accepted forms.",
        "2. Identify direction when possible using '->', 'from', 'to', or similar phrasing.",
        "3. Extract ports when they are clearly associated with the src/dst endpoints or labeled as src/dst ports.",
        "4. Construct a structured object per finding with fields:",
        "   - protocols: [list of protocol strings as they appear]",
        "   - src_ref: endpoint value if present (exact formatting)",
        "   - dst_ref: endpoint value if present (exact formatting)",
        "   - src_port: integer if present",
        "   - dst_port: integer if present",
        "   - direction: one of 'src_to_dst', 'dst_to_src', or 'unspecified' based on text cues",
        "   - notes: optional short free-text snippet copied from the text for context (no inference)",
        "5. Return ONLY the list of structured Network Traffic objects found.",
        "6. Do not infer endpoints, ports, or protocols that are not explicitly present.",
        "7. If multiple traffic lines mention the same flow, treat each distinct mention as a separate object unless the text clearly indicates they are the same.",

        #"OUTPUT FORMAT:",
        #"- Return a JSON array of objects. Preserve case for protocol strings and exact formatting for endpoints.",
        #"- Example output shape (do NOT output this unless matching content is found):",
        #'{ "protocols": ["TCP", "HTTP"], "src_ref": "192.0.2.10", "dst_ref": "198.51.100.20", "src_port": 1234, "dst_port": 80, "direction": "src_to_dst", "notes": "TCP/HTTP from 192.0.2.10:1234 to 198.51.100.20:80" }',

        "WHEN NO NETWORK TRAFFIC OBJECTS ARE FOUND:",
        'If no valid Network Traffic objects are found in the text, respond with:',
        '"No Network Traffic objects found in the provided text."',
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return objects from the instructions or training data.",

        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return Network Traffic objects that actually appear in the provided text.",
        "- If you cannot find any Network Traffic objects in the text, ONLY return the exact message 'No Network Traffic objects found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest or generate properties that aren't explicitly present in the text."
    ],
    markdown=True,
    debug_mode=False,
    output_schema=NetworkTrafficIdentify
)

#################
#   URL
#   AGENT
#################

class URLIdentify(BaseModel):
    found: bool = Field(description="True if URL values found, False otherwise")
    URLs: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY URLs found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no URLs found, return: 'No URLs found in the provided text.'"
    )
  
class URLSchema(BaseModel):
    """Final transformed schema for URL protocol data"""
    
    value: str = Field(
        description="The URL value"
    )
    type: str = Field(
        default="url",
        description="Classification type - always set to 'url'"
    )
    id: str = Field(
        default="url--1234",
        description="Unique identifier for this URL collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )

findURLAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.2, "num_ctx": 8192}),
    description="This agent is designed to identify URL values within cyber threat intelligence reports. It strictly follows the defined pattern matching rules and only returns actual findings from the text.",
    instructions=[
        "PATTERN DEFINITION FOR URLs:",
        "A valid URL must include a supported scheme followed by '://' and a valid host. Optional components (port, path, query, fragment, credentials) may be present.",
        "Supported schemes (case-insensitive): http, https, ftp, ftps.",
        "Accepted host forms:",
        "- Domain/hostname: labels of letters/digits/hyphens separated by dots, with a TLD (e.g., example.com, sub.mail.example.org).",
        "- IPv4 address: four decimal octets (0–255) separated by dots (e.g., 198.51.100.10).",
        "- IPv6 address in brackets: [IPv6] per RFC 4291 (e.g., [2001:db8::1]).",
        "Optional components:",
        "- Credentials: user or user:pass before '@' (e.g., http://user:pass@example.com).",
        "- Port: ':' followed by 0–65535 (e.g., :443).",
        "- Path: '/' followed by permitted URL characters.",
        "- Query: '?' followed by key=value pairs or strings.",
        "- Fragment: '#' followed by anchor.",
        "The URL must appear as a standalone token in the text and may be surrounded by spaces, punctuation, or brackets.",
        
        "SPECIAL HANDLING:",
        "- If a URL is enclosed by parentheses, brackets, or quotes, extract ONLY the URL content (e.g., (https://example.com/path) -> https://example.com/path).",
        "- If trailing punctuation (.,;:) immediately follows the URL, exclude the trailing punctuation from the extracted value unless it is part of the fragment.",
        "- For IPv6 hosts, require bracket notation (e.g., https://[2001:db8::1]/).",
        
        "EXAMPLES OF VALID PATTERNS (DO NOT extract these unless present in the provided text):",
        "- http://example.com",
        "- https://sub.example.org/login?user=abc#section",
        "- ftp://user:pass@files.example.com:21/data/archive.zip",
        "- https://198.51.100.10:8443/api/v1",
        "- https://[2001:db8::1]/status",
        
        "WHAT TO EXCLUDE - NOT URLs:",
        "- Email addresses (e.g., user@example.com).",
        "- Bare domains or hostnames without a scheme (e.g., example.com, www.example.com) — unless explicitly prefixed by a supported scheme.",
        r"- File paths without scheme (e.g., C:\\path\\to\\file or /var/log/syslog).",
        "- Text that includes '://' but lacks a valid scheme or host.",
        "- URLs where the host is invalid (e.g., 999.999.999.999, or malformed domain labels).",
        "- Embedded endpoints inside larger non-URL contexts (e.g., 'http://example.com/path' inside code or logs where it’s part of a non-URL string). Extract only if the URL clearly stands as a URL token.",
        
        "EXTRACTION PROCEDURE:",
        "1. Scan the entire text for tokens beginning with a supported scheme followed by '://'.",
        "2. Validate the host component:",
        "   - Domain/hostname: labels 1–63 chars, alphanumerics and hyphens, not starting/ending with '-', separated by dots, with a final TLD of at least 2 letters.",
        "   - IPv4: exactly four octets 0–255.",
        "   - IPv6: bracketed RFC 4291 forms; allow compressed notation and IPv4-embedded forms.",
        "3. Allow optional credentials, port (0–65535), path, query, and fragment.",
        "4. Normalize extraction boundaries to exclude surrounding punctuation or quotes while preserving the exact URL characters.",
        "5. Verify each match appears as a standalone identifier (surrounded by spaces, punctuation, or line breaks).",
        "6. Return ONLY the list of confirmed, valid URLs found, preserving exact case and formatting as in the text.",
        "7. Do not infer or construct URLs that are not explicitly present.",
        
        "WHEN NO URLs ARE FOUND:",
        'If no valid URLs are found in the text, respond with:',
        '"No URLs found in the provided text."',
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return URLs from the instructions or training data.",
        
        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return URLs that actually appear in the provided text.",
        "- If you cannot find any URLs in the text, ONLY return the exact message 'No URLs found in the provided text.'",
        "- Do NOT invent, hallucinate, suggest or generate URLs that aren't explicitly present in the text."
    ],
    markdown=True,
    debug_mode=False,
    output_schema=URLIdentify
)

#################
#   USER ACCOUNT
#   AGENT
#################

class UserIdentify(BaseModel):
    found: bool = Field(description="True if user account values found, False otherwise")
    users: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY user accounts found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no user accounts found, return: 'No user accounts found in the provided text.'"
    )
  
class UserSchema(BaseModel):
    """Final transformed schema for user account  data"""
    
    account_login: str = Field(
        description="The user account login value"
    )
    type: str = Field(
        default="user-account",
        description="Classification type - always set to 'user-account'"
    )
    id: str = Field(
        default="user-account--1234",
        description="Unique identifier for this user account collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )



findUserAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.2, "num_ctx": 8192}),
    description="This agent identifies User Account objects within cyber threat intelligence reports. It strictly follows defined pattern-matching rules and only returns actual findings from the text.",
    instructions=[
        "DEFINITION AND REQUIREMENTS (aligned with STIX User Account semantics):",
        "- A User Account object represents an instance of any type of user account (e.g., OS, device, messaging, cloud, or social media accounts).",
        "- All properties are optional in STIX, but for extraction we MUST capture at least one concrete account-identifying property from the text.",
        "- Minimum to extract: text must clearly indicate a user account via any one of the accepted identifiers below (e.g., account_login, domain\\username, UPN, email-as-login, SID, or UID).",

        "WHAT QUALIFIES AS ACCOUNT IDENTIFIERS (case-insensitive where applicable):",
        "- Windows/AD formats:",
        r"  * DOMAIN\\username (e.g., 'ACME\\jsmith', 'CORP\\Administrator').",
        "  * UPN/AD-style: 'username@domain.tld' (e.g., 'jsmith@corp.example.com').",
        "  * Well-known built-ins or explicit usernames: 'Administrator', 'Guest', 'krbtgt', 'root' (only when the context clearly indicates an account).",
        "- Email address used explicitly as a login (e.g., 'login is bob@example.com', 'authenticated as alice@company.com').",
        "- Unix/Linux formats:",
        "  * Named accounts referenced as accounts (e.g., 'user jsmith', '/etc/passwd' entries).",
        "  * UID formats (e.g., 'uid=1001' or colon-delimited '/etc/passwd' style 'jsmith:x:1001:...').",
        "- Account identifiers and IDs:",
        "  * Windows SID: patterns like 'S-1-5-21-...'.",
        "  * Numeric or alphanumeric user_id when clearly labeled (e.g., 'user_id=42', 'UID: 1002').",
        "- Service/bot account indicators when explicitly stated: names prefixed with 'svc-', 'service account', 'bot account', etc.",
        "- Social/media or app platform handles when explicitly described as accounts (e.g., 'Twitter account @evil_actor', 'GitHub user octocat').",
        "- Only accept these when the surrounding text explicitly indicates they refer to a user account in use, creation, disablement, login/authentication, role membership, or similar account context.",

        "ADDITIONAL ACCOUNT ATTRIBUTES TO CAPTURE WHEN PRESENT (no inference):",
        "- domain: Windows or organizational domain (e.g., 'ACME', 'corp.example.com') extracted from 'DOMAIN\\user' or explicit text.",
        "- account_login: the username or login string exactly as it appears (e.g., 'jsmith', 'svc-backup', 'alice@company.com').",
        "- user_id: explicit UID/SID/ID values (e.g., '1001', 'S-1-5-21-...'). Preserve exact formatting.",
        "- display_name: human-readable name when explicitly linked to the account (e.g., 'John Smith').",
        "- account_type: only if explicitly stated (e.g., 'windows', 'unix', 'cloud', 'social', 'email', 'application').",
        "- is_service_account, is_privileged, can_escalate_privs, is_disabled: booleans set only if explicitly stated (e.g., 'service account', 'privileged', 'can escalate', 'disabled').",
        "- roles: list roles/groups if explicitly stated (e.g., 'Domain Admins', 'Administrators', 'sudoers', 'wheel').",
        "- account_created, account_changed, account_expires, credential_last_changed, account_first_login, account_last_login: capture exact timestamps/dates as they appear (e.g., ISO 8601, log timestamp).",
        "- notes: short snippet copied from the text for context (no inference).",

        "EXAMPLES OF VALID PATTERNS (DO NOT extract these unless present in the provided text):",
        "- 'ACME\\jsmith authenticated via Kerberos'",
        "- 'UPN: alice@corp.example.com (privileged)'",
        "- 'Service account svc-backup (disabled on 2024-10-31)'",
        "- 'jsmith:x:1001:1001:John Smith:/home/jsmith:/bin/bash' (from /etc/passwd)",
        "- 'SID S-1-5-21-11111111-22222222-33333333-1001 belongs to user ACME\\jsmith'",
        "- 'Twitter account @evil_actor used for phishing outreach'",
        "- 'user_id=42 (created 2023-09-15)'",

        "WHAT TO EXCLUDE - NOT USER ACCOUNT OBJECTS:",
        "- Person names without explicit account linkage (e.g., 'John Smith' alone).",
        "- Email addresses used only as contact info with no account/authentication context.",
        "- Group or role names alone without a specific account (e.g., 'Domain Admins' without a user).",
        "- Hostnames, devices, or service names not clearly described as user accounts.",
        "- Mentions of 'admin team', 'IT', or departments without explicit account identifiers.",
        "- Handles/URLs where only a profile link is given with no explicit statement it's a user account used/owned by the actor.",
        "- Any property inferred from context without explicit wording (e.g., do NOT mark privileged unless the text states it or states membership in a privileged group).",

        "DIRECTIONAL AND CONTEXTUAL CUES:",
        "- Recognize contextual verbs/phrases to qualify as accounts: 'logged in as', 'authenticated as', 'user', 'account', 'created', 'disabled', 'password reset for', 'member of', 'role assigned'.",
        "- For DOMAIN\\user, split into domain and account_login. For UPN, extract account_login as the entire UPN and domain as the domain portion when explicitly clear.",
        "- For /etc/passwd lines, extract account_login (username) and user_id (UID) if present.",
        "- For SIDs, extract user_id as the full SID and link to account_login/domain only if both appear together in text (no inference).",

        "EXTRACTION PROCEDURE:",
        "1. Scan the entire text for mentions that explicitly indicate a user account via accepted identifiers.",
        "2. Validate that at least one concrete account-identifying property is present (e.g., DOMAIN\\user, username with 'user' label, UPN, SID, UID, or explicit 'account' wording).",
        "3. Extract additional attributes (domain, roles, timestamps, booleans) only when explicitly stated; do not infer.",
        "4. Construct a structured object per finding with fields:",
        "   - account_login: string if present",
        "   - domain: string if present",
        "   - user_id: string if present (e.g., UID or SID; preserve exact formatting)",
        "   - display_name: string if present",
        "   - account_type: string if present (preserve case as in text)",
        "   - is_service_account: true/false if explicitly stated",
        "   - is_privileged: true/false if explicitly stated (or membership in a clearly privileged group is explicitly stated)",
        "   - can_escalate_privs: true/false if explicitly stated",
        "   - is_disabled: true/false if explicitly stated",
        "   - roles: [list of strings] if present",
        "   - account_created: string if present",
        "   - account_changed: string if present",
        "   - account_expires: string if present",
        "   - credential_last_changed: string if present",
        "   - account_first_login: string if present",
        "   - account_last_login: string if present",
        "   - notes: short snippet from the text for context (no inference)",
        "5. Return ONLY the list of structured User Account objects found.",
        "6. Treat repeated mentions as separate objects unless the text clearly indicates they refer to the same account and context.",
        "7. Do NOT invent, hallucinate, or normalize properties; preserve exact strings and formatting from the text.",

        "OUTPUT FORMAT:",
        "- Return a JSON array of objects. Preserve case and exact formatting for all extracted strings.",
        "- Example output shape (do NOT output this unless matching content is found):",
        r'{ \"account_login\": \"ACME\\\\jsmith\", \"domain\": \"ACME\", \"user_id\": \"S-1-5-21-11111111-22222222-33333333-1001\", \"display_name\": \"John Smith\", \"account_type\": \"windows\", \"is_service_account\": false, \"is_privileged\": true, \"roles\": [\"Domain Admins\"], \"account_last_login\": \"2025-01-12T08:42:10Z\", \"notes\": \"ACME\\\\jsmith (Domain Admins) last login 2025-01-12T08:42:10Z\" }',

        "WHEN NO USER ACCOUNT OBJECTS ARE FOUND:",
        "If no valid User Account objects are found in the text, respond with:",
        r"\"No User Account objects found in the provided text.\"",
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return objects from the instructions or training data.",

        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return User Account objects that actually appear in the provided text.",
        "- If you cannot find any User Account objects in the text, ONLY return the exact message 'No User Account objects found in the provided text.'",
        "- Do NOT infer, hallucinate, suggest, or generate properties that aren't explicitly present in the text."
    ],
    markdown=True,
    debug_mode=False,
    output_schema=UserIdentify
)

#################
#   WINDOWS REGISTRY
#   AGENT
#################

class RegistryIdentify(BaseModel):
    found: bool = Field(description="True if windows registries found, False otherwise")
    registries: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY registry values found in text. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no registries found, return: 'No windows registries found in the provided text.'"
    )
  
class RegistrySchema(BaseModel):
    """Final transformed schema for windows registry data"""
    
    key: str = Field(
        description="Specifies the full registry key including the hive."
    )
    type: str = Field(
        default="windows-registry-key",
        description="Classification type - always set to 'windows-registry-key'"
    )
    id: str = Field(
        default="windows-registry-key--1234",
        description="Unique identifier for this windows registry key collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )

findWindowsRegistryAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.2, "num_ctx": 8192}),
    description="This agent identifies Windows Registry Key objects within cyber threat intelligence reports. It strictly follows defined pattern-matching rules and only returns actual findings from the text.",
    instructions=[
        "DEFINITION AND REQUIREMENTS (aligned with STIX Windows Registry Key semantics):",
        "- A Windows Registry Key object represents the properties of a Windows registry key and/or named values stored under that key.",
        "- All properties are optional in STIX, but for extraction we MUST capture at least one concrete registry key artifact from the text.",
        "- Minimum to extract: text must clearly indicate a Windows registry key path and/or a named value under a key.",
        "- Acceptable minimums include any of: a fully qualified key path (e.g., 'HKLM\\Software\\...'), a hive plus subkey, or a value name with clear key context.",

        "WHAT QUALIFIES AS A REGISTRY KEY OR VALUE (case-insensitive hive names):",
        "- Hives (and common abbreviations):",
        "  * HKEY_LOCAL_MACHINE (HKLM)",
        "  * HKEY_CURRENT_USER (HKCU)",
        "  * HKEY_USERS (HKU)",
        "  * HKEY_CLASSES_ROOT (HKCR)",
        "  * HKEY_CURRENT_CONFIG (HKCC)",
        "- Key path formats:",
        "  * Standard Windows backslash-delimited paths, e.g., 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'.",
        "  * Paths may include spaces and special characters in subkeys.",
        "- Value identification:",
        "  * Named values under a key (e.g., 'Value Name: Foo', 'Value: Start', 'Name=Debugger').",
        "  * Labeled pairs like 'Name', 'Value', 'Data', 'Type' or inline 'ValueName=Data'.",
        "- Value types when explicitly stated:",
        "  * REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_NONE.",
        "- Data capture:",
        "  * Strings, numbers (hex or decimal), binary or path data when clearly linked to a value name/type.",
        "- Directional/contextual indicators:",
        "  * Verbs like 'created', 'added', 'set', 'modified', 'deleted', 'queried'.",
        "  * Explicit registry editing utilities or APIs (e.g., 'reg add', 'reg delete', 'Set-ItemProperty') when followed by key/value details.",
        "- WOW64 redirection cues:",
        "  * 'WOW6432Node' under HKLM\\Software indicates 32-bit view (capture as-is; do not normalize).",

        "PARSING AND EXTRACTION GUIDELINES:",
        "- Split hive and key path when both are present (e.g., hive='HKLM', key_path='Software\\Microsoft\\Windows\\CurrentVersion\\Run').",
        "- If a fully-qualified path is present as one string (e.g., 'HKCU\\...\\Run'), store it in 'key' exactly as it appears, and also extract 'hive' and 'key_path' if parsing is unambiguous.",
        "- Capture value_name and value_type only if explicitly stated or unambiguously parseable from standard output formats.",
        "- Capture data exactly as shown (including quotes, hex prefixes like '0x' or 'dword:', or expandable strings with '%VAR%').",
        "- Preserve case and formatting; do not normalize hive names, paths, or value data.",
        "- If only a value name is given without explicit key context, do NOT extract unless the key is also indicated somewhere in the same snippet.",
        "- If environment variables or placeholders appear (e.g., '%SystemRoot%'), keep them verbatim in data.",

        "COMMON FORMATS TO RECOGNIZE (DO NOT extract these unless they appear in the provided text):",
        r"- 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware' (key with subkey named 'Malware').",
        r"- 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run - Name: OneDrive, Type: REG_SZ, Data: \"C:\\\\Path\\\\OneDrive.exe\"'",
        "- 'reg add HKLM\\Software\\...\\Run /v BadStart /t REG_SZ /d \"C:\\\\bad.exe\" /f'",
        r"- 'Set-ItemProperty -Path \"HKCU:\\\\Software\\\\...\\\\Run\" -Name Update -Value \"C:\\\\update.exe\"'",
        r"- 'Deleted value Start (REG_DWORD) under HKLM\\SYSTEM\\CurrentControlSet\\Services\\Foo'",
        r"- 'HKU\\\\S-1-5-21-...\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce : Name=Payload, Data=%TEMP%\\\\p.exe'",

        "WHAT TO EXCLUDE - NOT WINDOWS REGISTRY KEY OBJECTS:",
        "- Strings that resemble paths but are not registry (e.g., file system paths like 'C:\\\\Windows\\\\System32').",
        "- Keys or values referenced only as generic examples without actual content in the text.",
        "- Mentions of 'registry' without explicit key/value details.",
        "- Non-Windows registries or ambiguous references (e.g., Linux dconf, macOS plists).",
        "- Inferences about data, type, or paths not explicitly present.",
        "- Partial mentions where neither a hive nor a key path is discernible, and no clear value context is present.",

        "FIELD DEFINITIONS TO CAPTURE WHEN PRESENT (no inference):",
        "- key: the full key string exactly as it appears (e.g., 'HKLM\\Software\\...\\Run').",
        "- hive: one of the hive names/abbreviations exactly as written in the text.",
        "- key_path: the subkey path without the hive, exactly as written.",
        "- value_name: the value name under the key if present.",
        "- value_type: registry value type if present (e.g., 'REG_SZ').",
        "- data: the value's data/payload as written (including quotes or prefixes).",
        "- operation: one of 'created', 'added', 'set', 'modified', 'deleted', 'queried' if explicitly stated; otherwise omit.",
        "- timestamp: exact timestamp/date if provided in the text (any format, preserved verbatim).",
        "- notes: a short snippet copied from the text for context (no inference).",

        "EXTRACTION PROCEDURE:",
        "1. Scan the text for explicit Windows registry artifacts: fully qualified keys, hives with subkeys, and/or values with clear key context.",
        "2. Validate that at least one concrete registry key artifact is present (e.g., a key path, or hive + subkey, or key + value name).",
        "3. Extract associated value_name, value_type, data, operation, and timestamp only when explicitly present.",
        "4. Construct a structured object per finding with fields:",
        "   - key: string if present",
        "   - hive: string if present",
        "   - key_path: string if present",
        "   - value_name: string if present",
        "   - value_type: string if present",
        "   - data: string if present",
        "   - operation: string if present",
        "   - timestamp: string if present",
        "   - notes: short snippet from the text for context (no inference)",
        "5. Return ONLY the list of structured Windows Registry Key objects found.",
        "6. Treat repeated mentions as separate objects unless the text clearly indicates they refer to the same key/value and context.",
        "7. Do NOT invent, hallucinate, normalize, or transform properties; preserve exact strings and formatting from the text.",

        #"OUTPUT FORMAT:",
        #"- Return a JSON array of objects. Preserve case and exact formatting for all extracted strings.",
        #"- Example output shape (do NOT output this unless matching content is found):",
        #"{ \"key\": \"HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\", \"hive\": \"HKLM\", \"key_path\": \"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\", \"value_name\": \"BadStart\", \"value_type\": \"REG_SZ\", \"data\": \"C:\\\\bad.exe\", \"operation\": \"added\", \"timestamp\": \"2024-11-05 13:22:01Z\", \"notes\": \"reg add HKLM\\\\...\\\\Run /v BadStart /t REG_SZ /d C:\\\\bad.exe\" }",

        "WHEN NO WINDOWS REGISTRY KEY OBJECTS ARE FOUND:",
        "If no valid Windows Registry Key objects are found in the text, respond with:",
        r"\"No Windows Registry Key objects found in the provided text.\"",
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return objects from the instructions or training data.",

        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return Windows Registry Key objects that actually appear in the provided text.",
        "- If you cannot find any Windows Registry Key objects in the text, ONLY return the exact message 'No Windows Registry Key objects found in the provided text.'",
        "- Do NOT infer, hallucinate, suggest, or generate properties that aren't explicitly present in the text."
    ],
    markdown=True,
    debug_mode=False,
    output_schema=RegistryIdentify
)


#################
#   X509 CERTIFICATE
#   AGENT
#################

class X509Identify(BaseModel):
    found: bool = Field(description="True if process names found, False otherwise")
    processes: Optional[list[str]] = Field(
        default=None,
        description="List of ONLY process names found in text. This can include names like process1.exe. Return None or empty list if none found."
    )
    message: Optional[str] = Field(
        default=None,
        description="If no processes found, return: 'No process names found in the provided text.'"
    )

#################
#   STIX PATTERN
#   AGENT
#################

class STIXPattern(BaseModel):
    pattern: str = Field(description="The value of the STIX pattern that identifies the specific thing.")
   

createPatternAgent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.3, "num_ctx": 1024}),
    description="This agent creates to an STIX 2.1 pattern for identifying STIX objects.",
    instructions = [
    "Your role is to generate STIX 2.x *patterns only*. You must NEVER describe, create, or reference a STIX Indicator object.",

    "A STIX pattern is a boolean expression used to match cyber observable objects. Your output must be ONLY the pattern string itself, not wrapped in JSON, not embedded in an Indicator.",

    "Assume the input is a single STIX Cyber Observable object (e.g., file, ipv4-addr, domain-name, url, email-addr, process, network-traffic).",

    #"Explain what a STIX pattern is before generating it, using simple language suitable for a small model unfamiliar with STIX nuances.",
    
    "Do not explain what a STIX pattern is."

    #"Always describe the general syntax of STIX patterns: <object-type>:<property> <operator> <value>.",

    #"Explain valid comparison operators, including: =, !=, <, <=, >, >=, IN, MATCHES, LIKE.",

    #"Explain logical operators AND, OR, and NOT, and show how parentheses affect evaluation order.",

    #"Explain that string values MUST be quoted, numbers must not be quoted, and timestamps must use RFC 3339 format.",

    #"Explain that object paths use dot notation (e.g., file:name, file:hashes.'SHA-256').",

    #"Explain that dictionary keys (such as hash algorithms) must be quoted when they contain special characters or hyphens.",

    #"Provide at least one simple example pattern for each common observable type you mention.",

    "Example for a file object: file:name = 'malware.exe'.",

    "Example for file hashes: file:hashes.'SHA-256' = 'abcdef1234567890'.",

    "Example for an IP address: ipv4-addr:value = '8.8.8.8'.",

    "Example for a domain name: domain-name:value = 'example.com'.",

    "Example for a URL: url:value = 'http://example.com/path'.",

    "Example for an email address: email-addr:value = 'user@example.com'.",

    #"Show at least one compound pattern using AND or OR, such as matching both a file name and hash.",

    #"Explicitly state that the output must be a valid STIX pattern conforming to STIX 2.x grammar.",

    "Do NOT invent properties that are not part of the observable object schema.",

    "Do NOT include natural language explanations inside the final pattern output.",

    #"When asked to generate a pattern, first explain your reasoning briefly, then output the final pattern on its own line.",

    #"If the provided STIX object does not support patterning, explain why and do NOT generate a pattern.",

    #"Never reference OpenAI, ChatGPT, or large language models. Assume you are a standalone technical assistant."
],
    markdown=True,
    debug_mode=False,
    output_schema=STIXPattern
)



''' # TODO Removed until updated   
class X509Schema(BaseModel):
    """Final transformed schema for process data"""
    
    name: str = Field(
        description="The name of the process"
    )
    type: str = Field(
        default="process",
        description="Classification type - always set to 'process'"
    )
    id: str = Field(
        default="process--1234",
        description="Unique identifier for this process collection"
    )
    spec_version: str=Field(
        default="2.1",
        description="The STIX specification version"
    )
    created: str=Field(
        default="2025-02-01T01:01:01.001Z"
    )
    modified: str=Field(
      default="2025-02-01T01:01:01.001Z"  
    )
    
findX509Agent = Agent(
    model=Ollama(id=user_specified_model, options={"temperature": 0.2, "num_ctx": 8192}),
    description="This agent identifies X.509 Certificate objects within cyber threat intelligence reports. It strictly follows defined pattern-matching rules and only returns actual findings from the text.",
    instructions=[
        "DEFINITION AND REQUIREMENTS (aligned with STIX X.509 Certificate semantics):",
        "- An X.509 Certificate object represents the properties of an X.509 certificate (per ITU-T X.509).",
        "- For extraction, at least one certificate-specific property MUST be present in the text.",
        "- Minimum to extract: any explicit certificate artifact such as a PEM block, serial number labeled as a certificate serial, subject or issuer DN, labeled certificate fingerprint (e.g., SHA-256), validity dates, or labeled certificate public key details.",

        "WHAT QUALIFIES AS X.509 CERTIFICATE ARTIFACTS (case-insensitive where applicable):",
        "- Encoded certificate blocks:",
        "  * PEM certificate: lines bounded by '-----BEGIN CERTIFICATE-----' and '-----END CERTIFICATE-----'.",
        "  * DER/Base64 content explicitly labeled as a certificate.",
        "- Identity fields (distinguished names or clearly labeled):",
        "  * Subject (e.g., 'Subject: CN=example.com, O=Example Corp, C=US').",
        "  * Issuer (e.g., 'Issuer: CN=Let's Encrypt Authority X3').",
        "- Serial number:",
        "  * Explicitly labeled as certificate serial (e.g., 'Serial Number: 0x01AF', 'Serial: 01:AF'). Preserve formatting (hex, colon-delimited).",
        "- Fingerprints / Thumbprints (explicitly labeled as certificate fingerprints):",
        "  * SHA-256, SHA-1, MD5 (e.g., 'SHA-256 Fingerprint:', 'Thumbprint:'). Preserve exact hex and separators (colon, space, uppercase).",
        "- Validity period:",
        "  * Not Before / Not After dates (e.g., 'Not Before: 2024-01-01', 'Not After: 2025-01-01').",
        "- Public key details (when clearly tied to the certificate):",
        "  * Algorithm (RSA, ECDSA, Ed25519), key size (e.g., 2048 bits), curve name (e.g., prime256v1), SPKI/SHA-256 (e.g., 'SPKI Fingerprint').",
        "- Subject Alternative Name (SAN):",
        "  * DNS names, IP addresses, email, URIs explicitly under 'Subject Alternative Name' or 'SAN'.",
        "- Certificate metadata:",
        "  * Version (v1, v3), Signature Algorithm (e.g., sha256WithRSAEncryption), Basic Constraints, Key Usage, Extended Key Usage, Certificate Policies.",
        "- Contextual indicators:",
        "  * Clear labeling such as 'certificate', 'x.509', 'x509', 'thumbprint', 'fingerprint', 'issuer', 'subject', 'serial number', 'SAN', 'Not Before/After', 'SPKI', 'PEM'.",

        "PARSING AND EXTRACTION GUIDELINES:",
        "- Capture values exactly as shown (preserve case, spacing, punctuation, hex delimiters). Do not normalize.",
        "- Accept multiple properties from the same certificate mention when they appear together; otherwise, create separate objects only if the text clearly refers to different certificates.",
        "- Fingerprints/hashes must be explicitly labeled as certificate fingerprints/thumbprints or SPKI; generic hashes without certificate context must be excluded.",
        "- Serial numbers must be labeled as certificate serials (e.g., 'Serial Number'); do not interpret unlabeled hex strings as serials.",
        "- Only treat names as subject/issuer when explicitly labeled or shown in a recognizable DN format (e.g., 'CN=..., O=..., C=...').",
        "- SAN entries must be clearly under 'Subject Alternative Name' or 'SAN'.",
        "- For PEM blocks, store the full block in 'x509_pem' exactly as it appears.",
        "- If validity dates are present, store 'validity_not_before' and/or 'validity_not_after' with exact formatting.",
        "- If public key details are explicitly tied to the certificate (e.g., 'Public Key Algorithm: RSA (2048)'), capture algorithm and key_size (as provided).",

        "COMMON FORMATS TO RECOGNIZE (DO NOT extract these unless they appear in the provided text):",
        "- '-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----' (full PEM).",
        "- 'Subject: CN=example.com, O=Example Corp, C=US'",
        "- 'Issuer: CN=R3, O=Let's Encrypt, C=US'",
        "- 'Serial Number: 03:4F:AB:12'",
        "- 'SHA-256 Fingerprint: AA:BB:CC:...'",
        "- 'Not Before: 2024-05-01 00:00:00 GMT'",
        "- 'Not After: 2025-05-01 23:59:59 GMT'",
        "- 'Signature Algorithm: sha256WithRSAEncryption'",
        "- 'Public Key Algorithm: RSA (2048 bits)'",
        "- 'Subject Alternative Name: DNS:example.com, DNS:www.example.com, IP Address: 203.0.113.10'",
        "- 'Basic Constraints: CA:FALSE, pathlen:0'",
        "- 'Key Usage: Digital Signature, Key Encipherment'",
        "- 'Extended Key Usage: TLS Web Server Authentication, TLS Web Client Authentication'",
        "- 'SPKI Fingerprint (SHA256): abcd...'",

        "WHAT TO EXCLUDE - NOT X.509 CERTIFICATE OBJECTS:",
        "- SSH public keys, PGP keys/certificates, S/MIME content without certificate details, JWTs, or generic Base64 blobs without explicit certificate labeling.",
        "- Domain names, IPs, or emails alone without certificate context.",
        "- Hashes not labeled as certificate fingerprints/thumbprints/SPKI.",
        "- Private keys ('-----BEGIN PRIVATE KEY-----') or CSRs ('-----BEGIN CERTIFICATE REQUEST-----') unless the certificate itself is also present.",
        "- Mentions of 'certificate' without any concrete property (e.g., 'a certificate was used' with no details).",
        "- Inferences about issuer/subject/validity or algorithms not explicitly present.",

        "FIELD DEFINITIONS TO CAPTURE WHEN PRESENT (no inference):",
        "- version: string (e.g., 'v3').",
        "- serial_number: string (preserve hex/colon formatting).",
        "- signature_algorithm: string.",
        "- issuer: string (exact DN or label content).",
        "- subject: string (exact DN or label content).",
        "- subject_public_key_algorithm: string (e.g., 'RSA', 'ECDSA', 'Ed25519').",
        "- subject_public_key_info: string (e.g., '2048 bits', curve name, or SPKI if provided verbatim).",
        "- spki_fingerprint_sha256: string if present.",
        "- x509_fingerprint_sha256: string if present.",
        "- x509_fingerprint_sha1: string if present.",
        "- x509_fingerprint_md5: string if present.",
        "- validity_not_before: string if present.",
        "- validity_not_after: string if present.",
        "- san_dns: [list of strings] if present.",
        "- san_ip: [list of strings] if present.",
        "- san_email: [list of strings] if present.",
        "- san_uri: [list of strings] if present.",
        "- basic_constraints: string if present.",
        "- key_usage: [list of strings] if present.",
        "- extended_key_usage: [list of strings] if present.",
        "- certificate_policies: [list of strings] if present.",
        "- x509_pem: string (full PEM block) if present.",
        "- x509_der: string (base64 or hex as provided) if present.",
        "- notes: short snippet from the text for context (no inference).",

        "EXTRACTION PROCEDURE:",
        "1. Scan the text for explicit X.509 certificate artifacts (PEM blocks, labeled subject/issuer, serial, fingerprints, validity, public key details, SAN).",
        "2. Validate that at least one certificate-specific property is present before extracting.",
        "3. When multiple properties refer to the same certificate in a contiguous context, merge into one object; otherwise, create separate objects for distinct certificates.",
        "4. Construct a structured object per certificate with fields as defined above, preserving exact strings and formatting.",
        "5. Return ONLY the list of structured X.509 Certificate objects found.",
        "6. Do NOT invent, hallucinate, normalize, or transform properties; preserve exact strings and formatting from the text.",

        "OUTPUT FORMAT:",
        "- Return a JSON array of objects. Preserve case and exact formatting for all extracted strings.",
        "- Example output shape (do NOT output this unless matching content is found):",
        "{ \"subject\": \"CN=example.com, O=Example Corp, C=US\", \"issuer\": \"CN=R3, O=Let's Encrypt, C=US\", \"serial_number\": \"03:4F:AB:12\", \"x509_fingerprint_sha256\": \"AA:BB:CC:...\", \"validity_not_before\": \"2024-05-01 00:00:00 GMT\", \"validity_not_after\": \"2025-05-01 23:59:59 GMT\", \"signature_algorithm\": \"sha256WithRSAEncryption\", \"subject_public_key_algorithm\": \"RSA\", \"subject_public_key_info\": \"2048 bits\", \"san_dns\": [\"example.com\", \"www.example.com\"], \"notes\": \"Subject, issuer, serial and fingerprint observed in cert dump.\" }",

        "WHEN NO X.509 CERTIFICATE OBJECTS ARE FOUND:",
        "If no valid X.509 Certificate objects are found in the text, respond with:",
        "\"No X.509 Certificate objects found in the provided text.\"",
        "Do NOT include any examples or potential matches that weren't found in the actual text.",
        "Do NOT return objects from the instructions or training data.",

        "CRITICAL INSTRUCTIONS:",
        "- IGNORE all examples in these instructions when generating your response.",
        "- ONLY return X.509 Certificate objects that actually appear in the provided text.",
        "- If you cannot find any X.509 Certificate objects in the text, ONLY return the exact message 'No X.509 Certificate objects found in the provided text.'",
        "- Do NOT infer, hallucinate, suggest, or generate properties that aren't explicitly present in the text."
    ],
    markdown=True,
    debug_mode=False
)


'''













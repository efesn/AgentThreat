"""Threat Analyzer Agent implementation for analyzing CTI feed entries from BigQuery."""

import logging
import os
import re
from datetime import datetime
from typing import Dict, List, Any
import requests
from bs4 import BeautifulSoup
from google.cloud import bigquery
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool
from . import prompt
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IOCPatterns:
    """Regular expression patterns for IOC extraction."""
    IPV4 = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    DOMAIN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    MD5 = r'\b[a-fA-F0-9]{32}\b'
    SHA1 = r'\b[a-fA-F0-9]{40}\b'
    SHA256 = r'\b[a-fA-F0-9]{64}\b'
    CVE = r'CVE-\d{4}-\d{4,7}'
    EMAIL = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

def fetch_article_content(url: str) -> str:
    """Fetch and extract text content from article URL."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove script and style elements
        for element in soup(['script', 'style']):
            element.decompose()
            
        return soup.get_text()
        
    except Exception as e:
        logger.error(f"Error fetching content from {url}: {str(e)}")
        return ""

def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract IOCs from text content."""
    iocs = {
        "ipv4": list(set(re.findall(IOCPatterns.IPV4, text))),
        "domains": list(set(re.findall(IOCPatterns.DOMAIN, text))),
        "md5": list(set(re.findall(IOCPatterns.MD5, text))),
        "sha1": list(set(re.findall(IOCPatterns.SHA1, text))),
        "sha256": list(set(re.findall(IOCPatterns.SHA256, text))),
        "cves": list(set(re.findall(IOCPatterns.CVE, text))),
        "emails": list(set(re.findall(IOCPatterns.EMAIL, text)))
    }
    return {k: v for k, v in iocs.items() if v}  # Remove empty lists

def identify_threat_category(text: str) -> str:
    """Identify the threat category based on content analysis."""
    text = text.lower()
    
    categories = {
        'ransomware': ['ransomware', 'ransom', 'encryption', 'decrypt'],
        'phishing': ['phishing', 'credential', 'social engineering'],
        'malware': ['malware', 'trojan', 'backdoor', 'virus', 'worm'],
        'vulnerability': ['vulnerability', 'cve', 'exploit', 'zero-day'],
        'apt': ['apt', 'advanced persistent threat', 'nation-state'],
        'data_breach': ['breach', 'leak', 'exposed', 'stolen data']
    }
    
    for category, keywords in categories.items():
        if any(keyword in text for keyword in keywords):
            return category
            
    return 'unknown'

def generate_summary(text: str, max_length: int = 500) -> str:
    """Generate a concise summary of the threat intelligence."""
    try:
        # Extract first few sentences or paragraphs, will improve this later
        sentences = text.split('.')[:3]
        summary = '. '.join(sentences)
        return summary[:max_length].strip()
    except Exception as e:
        logger.error(f"Error generating summary: {str(e)}")
        return ""

def extract_threat_actor(text: str) -> str:
    """Extract threat actor names from content."""
    text = text.lower()
    # Common threat actor indicators
    actor_patterns = [
        r'attributed to ([^\.]+)',
        r'(apt\d+)',
        r'threat actor[s]? ([^\.]+)',
        r'group known as ([^\.]+)',
        r'([^ ]+) threat group'
    ]
    
    for pattern in actor_patterns:
        matches = re.findall(pattern, text)
        if matches:
            return matches[0].strip()
    return "unknown"

def identify_mitre_techniques(text: str) -> List[str]:
    """Identify MITRE ATT&CK techniques mentioned in the content."""
    # MITRE technique patterns
    technique_patterns = [
        r'T\d{4}(\.\d{3})?',  # Match technique IDs like T1234 or T1234.001
        r'(?:Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact)'
    ]
    
    techniques = []
    for pattern in technique_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        techniques.extend(matches)
    
    return list(set(techniques))  # Remove duplicates

def analyze_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze a single feed entry."""
    try:
        # Fetch and analyze content
        content = fetch_article_content(entry['link'])
        if not content:
            logger.error(f"Could not fetch content for {entry['link']}")
            return None
            
        # Extract and validate data
        iocs = extract_iocs(content)
        threat_category = identify_threat_category(content)
        summary = generate_summary(content)
        threat_actor = extract_threat_actor(content)
        mitre_techniques = identify_mitre_techniques(content)
        
        # Ensure proper data types and handle nulls
        published_date = entry.get('published')
        if isinstance(published_date, datetime):
            published_date = published_date.isoformat()
        elif not published_date:
            published_date = datetime.utcnow().isoformat()
            
        # Convert complex objects to strings for BigQuery
        try:
            iocs_str = json.dumps(iocs) if iocs else "{}"
            mitre_techniques_str = json.dumps(mitre_techniques) if mitre_techniques else "[]"
        except Exception as e:
            logger.error(f"Error converting data to JSON: {str(e)}")
            iocs_str = "{}"
            mitre_techniques_str = "[]"

        # Validate string lengths for BigQuery
        summary = (summary or "")[:1000]  # Limit summary length
        threat_actor = (threat_actor or "unknown")[:100]  # Limit actor name length
        threat_category = (threat_category or "unknown")[:50]  # Limit category length

        # Create analysis row with validated data
        analysis_row = {
            "title": entry['title'][:500],  # Limit title length
            "link": entry['link'],
            "published": published_date,
            "analyzed": True,
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "threat_category": threat_category,
            "iocs": iocs_str,
            "summary": summary,
            "threat_actor": threat_actor,
            "mitre_techniques": mitre_techniques_str
        }

        return analysis_row

    except Exception as e:
        logger.error(f"Error analyzing entry: {str(e)}")
        return None

def run_analysis(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze unanalyzed entries and save results to BigQuery."""
    try:
        if not entries:
            return {
                "status": "success",
                "message": "No new entries to analyze",
                "analyzed_count": 0
            }
        
        results = []
        
        for entry in entries:
            try:
                analysis_result = analyze_entry(entry)
                if analysis_result:
                    results.append(analysis_result)
            except Exception as e:
                logger.error(f"Error analyzing entry {entry.get('link')}: {str(e)}")
                continue

        # Save analyzed results to BigQuery
        if results:
            try:
                project_id = os.getenv('GOOGLE_CLOUD_PROJECT')
                table_name = os.getenv('BIGQUERY_TABLE')
                client = bigquery.Client()
                table_id = f"{project_id}.{table_name}"

                # Insert analyzed results
                errors = client.insert_rows_json(table_id, results)
                if errors:
                    raise Exception(f"Error inserting analyzed results: {errors}")

                logger.info(f"Successfully processed {len(results)} entries")

            except Exception as e:
                logger.error(f"Error saving analysis results: {str(e)}")
                return {
                    "status": "error",
                    "message": f"Error saving results: {str(e)}",
                    "analyzed_count": 0
                }

        return {
            "status": "success",
            "message": f"Successfully analyzed {len(results)} entries",
            "analyzed_count": len(results),
            "results": results
        }

    except Exception as e:
        logger.error(f"Error in threat analysis: {str(e)}")
        return {
            "status": "error",
            "message": str(e),
            "analyzed_count": 0
        }

# Create the threat analyzer agent
threat_analyzer_agent = LlmAgent(
    name="threat_analyzer",
    model="gemini-2.0-flash-001",
    description="Agent for analyzing and enriching CTI feed entries",
    instruction=prompt.threat_analyzer_agent,
    tools=[
        FunctionTool(func=run_analysis),
    ]
)
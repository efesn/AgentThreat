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

def fetch_unanalyzed_entries() -> List[Dict[str, Any]]:
    """Fetch unanalyzed entries from BigQuery."""
    try:
        project_id = os.getenv('GOOGLE_CLOUD_PROJECT')
        table_name = os.getenv('BIGQUERY_TABLE')
        client = bigquery.Client()
        table_id = f"{project_id}.{table_name}"

        query = f"""
        SELECT title, link, published
        FROM `{table_id}`
        WHERE analyzed IS NULL OR analyzed = FALSE
        LIMIT 10
        """

        query_job = client.query(query)
        entries = []
        for row in query_job:
            entries.append({
                "title": row.title,
                "link": row.link,
                "published": row.published
            })
        
        return entries
    
    except Exception as e:
        logger.error(f"Error fetching entries from BigQuery: {str(e)}")
        return []

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
        iocs = extract_iocs(content)
        threat_category = identify_threat_category(content)
        
        # Generate summary and extract threat actor
        summary = generate_summary(content)
        threat_actor = extract_threat_actor(content)
        mitre_techniques = identify_mitre_techniques(content)
        
        # Update BigQuery with analysis results
        project_id = os.getenv('GOOGLE_CLOUD_PROJECT')
        table_name = os.getenv('BIGQUERY_TABLE')
        client = bigquery.Client()
        table_id = f"{project_id}.{table_name}"
        
        # Convert lists to strings for BigQuery
        iocs_str = json.dumps(iocs)
        mitre_techniques_str = json.dumps(mitre_techniques)
        
        # Ensure published date is in ISO format string
        published_date = entry['published']
        if isinstance(published_date, datetime):
            published_date = published_date.isoformat()
        
        # Create analysis row with all dates as ISO format strings
        analysis_row = {
            "title": entry['title'],
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
        
        # Insert the analysis results
        errors = client.insert_rows_json(table_id, [analysis_row])
        
        if errors:
            logger.error(f"Error inserting analysis results: {errors}")
            return None
        
        analysis_result = {
            "title": entry['title'],
            "link": entry['link'],
            "published": published_date,
            "threat_category": threat_category,
            "iocs": iocs,
            "summary": summary,
            "threat_actor": threat_actor,
            "mitre_techniques": mitre_techniques,
            "analysis_timestamp": datetime.utcnow().isoformat()
        }
        
        # Enhanced logging
        logger.info(f"\n=== Analysis Results for {entry['title']} ===")
        logger.info(f"Category: {threat_category}")
        logger.info(f"Threat Actor: {threat_actor}")
        logger.info(f"MITRE Techniques: {mitre_techniques}")
        logger.info(f"IOCs found: {len(sum(iocs.values(), []))} indicators")
        logger.info("------------------------")
        
        return analysis_result
        
    except Exception as e:
        logger.error(f"Error analyzing entry {entry['link']}: {str(e)}")
        return None

def run_analysis() -> Dict[str, Any]:
    """Main function to run threat analysis on unanalyzed entries."""
    try:
        entries = fetch_unanalyzed_entries()
        if not entries:
            return {
                "status": "success",
                "message": "No new entries to analyze",
                "analyzed_count": 0
            }
        
        results = []
        for entry in entries:
            result = analyze_entry(entry)
            if result:
                results.append(result)
        
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
        FunctionTool(func=analyze_entry),
        FunctionTool(func=fetch_unanalyzed_entries)
    ]
)
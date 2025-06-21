"""Threat Analyzer Agent implementation for analyzing CTI feed entries from BigQuery."""
from . import prompt
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
import google.generativeai as genai
from . import prompt
import json

# Configure Gemini
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))  # Set your Gemini API key in env vars

# Load model
gemini_model = genai.GenerativeModel("gemini-2.0-flash")

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

def fetch_article_content(url: str) -> tuple[str, str]:
    """Fetch article content and generate its summary."""
    try:
        logger.info(f"Fetching content from: {url}")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove script and style elements
        for element in soup(['script', 'style']):
            element.decompose()
            
        content = soup.get_text()
        
        # Generate summary immediately after fetching content
        logger.info("Generating summary...")
        summary = generate_summary(content)
        logger.info(f"Summary generated ({len(summary)} chars)")
        
        return content, summary
        
    except Exception as e:
        logger.error(f"Error fetching/summarizing content from {url}: {str(e)}")
        return "", ""

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

def generate_summary(text: str) -> str:
    """Generate summary using Gemini via google-generativeai SDK."""
    try:
        if not text:
            return ""

        max_chars = 5000
        text_to_summarize = text[:max_chars]

        # get summarizer prompt from the dedicated prompt file 
        summarization_prompt = f"""
        {prompt.summarizer_agent_prompt}

        Article to summarize:
        {text_to_summarize}
        """

        response = gemini_model.generate_content(summarization_prompt)
        return response.text.strip()[:1000]

    except Exception as e:
        logger.error("Gemini summary generation failed", exc_info=True)
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
        # Fetch content and get summary in one call
        content, summary = fetch_article_content(entry['link'])
        if not content:
            logger.error(f"Could not fetch content for {entry['link']}")
            return None
            
        # Extract and validate other data
        iocs = extract_iocs(content)
        threat_category = identify_threat_category(content)
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
    """
    Analyzes entries, checks for duplicates in BigQuery based on 'link', 
    and saves only new, analyzed results.
    """
    if not entries:
        return {
            "status": "success",
            "message": "No entries to analyze.",
            "analyzed_count": 0,
            "saved_count": 0,
            "skipped_count": 0
        }

    logger.info(f"Starting analysis for {len(entries)} entries.")
    
    # 1. Analyze all incoming entries
    analysis_results = []
    for entry in entries:
        try:
            # Assuming analyze_entry returns the full, enriched entry object
            analyzed_entry = analyze_entry(entry)
            if analyzed_entry:
                analysis_results.append(analyzed_entry)
        except Exception as e:
            logger.error(f"Error analyzing entry {entry.get('link')}: {str(e)}")
            continue # Skip to the next entry

    if not analysis_results:
        logger.info("Analysis resulted in no valid entries to save.")
        return {
            "status": "success",
            "message": "Analysis completed, but no new data was generated to save.",
            "analyzed_count": 0,
            "saved_count": 0,
            "skipped_count": 0
        }

    # 2. Save new, analyzed results to BigQuery, checking for duplicates
    try:
        project_id = os.getenv('GOOGLE_CLOUD_PROJECT')
        table_name = os.getenv('BIGQUERY_TABLE')
        if not project_id or not table_name:
            raise ValueError("Google Cloud project ID and BigQuery table name must be set.")
            
        client = bigquery.Client()
        table_id = f"{project_id}.{table_name}"

        # Fetch existing links to avoid duplicates
        logger.info("Fetching existing links from BigQuery to prevent duplicates...")
        query = f"SELECT link FROM `{table_id}`"
        query_job = client.query(query)
        existing_links = {row.link for row in query_job}
        logger.info(f"Found {len(existing_links)} existing links in BigQuery.")

        # Filter out results that already exist in BigQuery
        new_results_to_insert = []
        skipped_count = 0
        for result in analysis_results:
            if result.get('link') not in existing_links:
                new_results_to_insert.append(result)
            else:
                skipped_count += 1
        
        logger.info(f"Analyzed {len(analysis_results)} entries. Found {len(new_results_to_insert)} new entries to save. Skipped {skipped_count} duplicates.")

        # Insert only the new results
        if new_results_to_insert:
            logger.info(f"Inserting {len(new_results_to_insert)} new analyzed entries into BigQuery...")
            errors = client.insert_rows_json(table_id, new_results_to_insert)
            if errors:
                # This error is critical, something is wrong with the data or table schema
                error_message = f"Encountered errors while inserting rows: {errors}"
                logger.error(error_message)
                raise Exception(error_message)
            logger.info("Successfully inserted new entries.")

        return {
            "status": "success",
            "message": f"Analysis complete. Saved {len(new_results_to_insert)} new entries. Skipped {skipped_count} duplicates.",
            "analyzed_count": len(analysis_results),
            "saved_count": len(new_results_to_insert),
            "skipped_count": skipped_count
        }

    except Exception as e:
        logger.error(f"An error occurred during BigQuery operation: {str(e)}")
        return {
            "status": "error",
            "message": str(e),
            "analyzed_count": len(analysis_results),
            "saved_count": 0,
            "skipped_count": 0
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
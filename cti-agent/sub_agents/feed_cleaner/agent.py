"""Feed Cleaner Agent implementation for filtering and deduplicating CTI feed entries."""
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, List, Set
import re
from google.cloud import bigquery
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool
from . import prompt

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Keywords and patterns for cybersecurity relevance
SECURITY_KEYWORDS = {
    'vulnerability', 'exploit', 'malware', 'ransomware', 'phishing', 'breach', 
    'threat', 'attack', 'cve', 'zero-day', 'security', 'hack', 'compromise',
    'botnet', 'backdoor', 'trojan', 'worm', 'ddos', 'injection', 'payload',
    'patch', 'advisory', 'disclosure', 'incident', 'threat actor', 'apt'
}

# Keywords indicating low-signal content
NOISE_KEYWORDS = {
    'webinar', 'conference', 'job', 'career', 'hire', 'hiring', 'position',
    'workshop', 'training', 'certification', 'subscribe', 'newsletter',
    'award', 'recognition', 'partner', 'partnership', 'press release'
}

def compute_content_hash(entry: Dict[str, str]) -> str:
    """Compute a hash of the entry content for deduplication.
    
    Args:
        entry: Dictionary containing feed entry data
        
    Returns:
        A string hash of the content
    """
    content = f"{entry.get('title', '')}{entry.get('link', '')}"
    return hashlib.md5(content.encode()).hexdigest()

def is_security_relevant(text: str) -> bool:
    """Check if text contains cybersecurity-related keywords.
    
    Args:
        text: Text to check for security relevance
        
    Returns:
        Boolean indicating if the text is security-relevant
    """
    text = text.lower()
    return any(keyword in text for keyword in SECURITY_KEYWORDS)

def is_noise(text: str) -> bool:
    """Check if text matches patterns indicating low-signal content.
    
    Args:
        text: Text to check for noise patterns
        
    Returns:
        Boolean indicating if the text is likely noise
    """
    text = text.lower()
    return any(keyword in text for keyword in NOISE_KEYWORDS)

def extract_text(entry: Dict[str, str]) -> str:
    """Extract combined text from title, summary, and description fields."""
    return " ".join([
        entry.get("title", ""),
      #  entry.get("summary", ""),
       # entry.get("description", "")
    ])

def filter_by_keywords(entries: List[Dict[str, str]]) -> Dict[str, any]:
    """Filter entries based on security relevance and noise keywords.
    
    Args:
        entries: List of feed entries to filter
        
    Returns:
        Dictionary containing filtered entries and stats
    """
    filtered_entries = []
    discarded_count = 0
    
    for entry in entries:
        text = extract_text(entry)
        if is_security_relevant(text) and not is_noise(text):
            filtered_entries.append(entry)
        else:
            discarded_count += 1
            logger.debug(f"Discarded entry: {entry.get('title', '')}")
    
    return {
        "status": "success",
        "filtered_entries": filtered_entries,
        "stats": {
            "input_count": len(entries),
            "filtered_count": len(filtered_entries),
            "discarded_count": discarded_count
        }
    }

def deduplicate_entries(entries: List[Dict[str, str]]) -> Dict[str, any]:
    """Remove duplicate entries based on content hash and similar titles.
    
    Args:
        entries: List of feed entries to deduplicate
        
    Returns:
        Dictionary containing deduplicated entries and stats
    """
    unique_entries = []
    seen_hashes = set()
    seen_urls = set()
    duplicate_count = 0
    
    for entry in entries:
        content_hash = compute_content_hash(entry)
        url = entry.get('link', '')
        
        if content_hash not in seen_hashes and url not in seen_urls:
            unique_entries.append(entry)
            seen_hashes.add(content_hash)
            seen_urls.add(url)
        else:
            duplicate_count += 1
            logger.debug(f"Duplicate entry found: {entry.get('title', '')}")
    
    return {
        "status": "success",
        "unique_entries": unique_entries,
        "stats": {
            "input_count": len(entries),
            "unique_count": len(unique_entries),
            "duplicate_count": duplicate_count
        }
    }

def pass_clean_entries(entries: List[Dict[str, str]]) -> Dict[str, any]:
    """Passes cleaned and deduplicated entries to the next agent without saving to BigQuery."""
    logger.info(f"Passing {len(entries)} cleaned entries to the next agent.")
    return {
        "status": "success",
        "message": f"Successfully prepared {len(entries)} entries for analysis.",
        "cleaned_entries": entries
    }

# Create the feed cleaner agent
feed_cleaner_agent = LlmAgent(
    name="feed_cleaner",
    model="gemini-2.0-flash-001",
    description="Agent for filtering, deduplicating, and validating cybersecurity threat feed entries",
    instruction=prompt.feed_cleaner_agent,
    tools=[
        FunctionTool(func=filter_by_keywords),
        FunctionTool(func=deduplicate_entries),
        FunctionTool(func=pass_clean_entries)
    ]
)
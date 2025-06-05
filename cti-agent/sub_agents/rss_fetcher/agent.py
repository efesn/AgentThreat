"""RSS Feed Fetcher Agent implementation."""

import json
import logging
import socket
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.error import URLError

import feedparser
from dateutil import parser
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool
from . import prompt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Default RSS feed sources
DEFAULT_FEEDS = [
    "https://blog.google/threat-analysis-group/rss",  
    "https://www.mandiant.com/resources/blog/rss.xml",  
    "https://www.microsoft.com/en-us/security/blog/feed",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://research.checkpoint.com/feed/"
]

class FeedEntry:
    """Represents a single RSS feed entry."""
    def __init__(self, title: str, link: str, published: str, source: str):
        self.title = title
        self.link = link
        self.published = published
        self.source = source

    def to_dict(self) -> Dict[str, str]:
        return {
            "title": self.title,
            "link": self.link,
            "published": self.published,
            "source": self.source
        }

def check_internet_connection() -> bool:
    """Check if there is an active internet connection."""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

def parse_feed(url: str) -> List[Dict[str, str]]:
    """Parse a single RSS feed and return a list of entries.
    
    Args:
        url: The URL of the RSS feed to parse
        
    Returns:
        A list of dictionaries containing feed entries
    """
    if not check_internet_connection():
        logger.error("No internet connection available")
        return []

    try:
        # Configure request headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Create request with headers and timeout
        request = urllib.request.Request(url, headers=headers)
        
        # Fetch the feed with timeout
        with urllib.request.urlopen(request, timeout=10) as response:
            feed_content = response.read()
            
            # Parse the feed content
            feed = feedparser.parse(feed_content)
            
            if not feed.entries:
                logger.warning(f"No entries found in feed: {url}")
                return []
                
            entries = []
            
            for entry in feed.entries:
                published = entry.get('published', entry.get('updated', str(datetime.now())))
                try:
                    parsed_date = parser.parse(published).isoformat()
                except Exception as e:
                    logger.warning(f"Error parsing date {published}: {str(e)}")
                    parsed_date = published

                entry_data = FeedEntry(
                    title=entry.get('title', 'No title'),
                    link=entry.get('link', ''),
                    published=parsed_date,
                    source=url
                ).to_dict()
                
                entries.append(entry_data)
            
            logger.info(f"Successfully parsed {len(entries)} entries from {url}")
            return entries
            
    except URLError as e:
        logger.error(f"Network error while parsing feed {url}: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"Error parsing feed {url}: {str(e)}")
        return []

def save_feed_data(entries: List[Dict[str, str]], filename: str = "fetched_feeds.json") -> str:
    """Save feed entries to a JSON file.
    
    Args:
        entries: List of feed entries to save
        filename: Name of the output file (default: fetched_feeds.json)
        
    Returns:
        A message indicating the result of the save operation
    """
    try:
        output_path = Path("data") / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(entries, f, indent=2)
        return f"Successfully saved {len(entries)} entries to {filename}"
    except Exception as e:
        return f"Failed to save entries: {str(e)}"

def fetch_feeds(urls: Optional[List[str]] = None) -> Dict[str, any]:
    """Fetch and parse RSS feeds from the given URLs.
    
    Args:
        urls: Optional list of feed URLs to fetch. If None, uses DEFAULT_FEEDS.
        
    Returns:
        Dictionary containing fetched entries and status information
    """
    if not check_internet_connection():
        return {
            "status": "error",
            "message": "No internet connection available",
            "entries": []
        }

    feed_urls = urls or DEFAULT_FEEDS
    all_entries = []
    failed_feeds = []

    for url in feed_urls:
        logger.info(f"Fetching feed: {url}")
        try:
            entries = parse_feed(url)
            if entries:
                all_entries.extend(entries)
                logger.info(f"Successfully fetched {len(entries)} entries from {url}")
            else:
                failed_feeds.append(url)
        except Exception as e:
            failed_feeds.append(url)
            logger.error(f"Failed to fetch feed {url}: {str(e)}")

    if not all_entries:
        return {
            "status": "error",
            "message": "No entries fetched",
            "failed_feeds": failed_feeds,
            "entries": []
        }

    # Save raw entries
    save_feed_data(all_entries)

    return {
        "status": "success",
        "message": f"Successfully fetched {len(all_entries)} entries from {len(feed_urls) - len(failed_feeds)} feeds",
        "failed_feeds": failed_feeds,
        "entries": all_entries
    }

def get_latest_entries(count: int = 20) -> Dict[str, any]:
    """Get the latest entries from saved data."""
    try:
        with open("data/fetched_feeds.json", 'r') as f:
            entries = json.load(f)

        sorted_entries = sorted(
            entries,
            key=lambda x: parser.parse(x['published']),
            reverse=True
        )[:count]

        return {
            "status": "success",
            "entries": sorted_entries
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "message": "No feed data found. Please fetch feeds first.",
            "entries": []
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error retrieving entries: {str(e)}",
            "entries": []
        }

# Create the RSS fetcher agent
rss_fetcher_agent = LlmAgent(
    name="rss_fetcher",
    model="gemini-2.0-flash-001",
    description="Agent for fetching and managing cybersecurity RSS feeds",
    instruction=prompt.rss_fetcher_agent,
    tools=[
        FunctionTool(func=fetch_feeds),
        FunctionTool(func=parse_feed),
        FunctionTool(func=save_feed_data),
        FunctionTool(func=get_latest_entries)
    ]
) 
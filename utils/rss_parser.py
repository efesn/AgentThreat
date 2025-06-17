"""Utility module for parsing RSS feeds."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import feedparser
from dateutil import parser

class FeedEntry:
    """Represents a single RSS feed entry."""
    def __init__(self, title: str, link: str, published: str):
        self.title = title
        self.link = link
        self.published = published
        #self.source = source

    def to_dict(self) -> Dict:
        return {
            "title": self.title,
            "link": self.link,
            "published": self.published,
            #"source": self.source
        }

class RSSParser:
    """Utility class for parsing RSS feeds."""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def parse_feed(self, feed_url: str) -> List[FeedEntry]:
        """Parse a single RSS feed and return a list of entries."""
        try:
            feed = feedparser.parse(feed_url, timeout=self.timeout)
            entries = []
            
            for entry in feed.entries:
                published = entry.get('published', entry.get('updated', str(datetime.now())))
                try:
                    parsed_date = parser.parse(published).isoformat()
                except Exception:
                    parsed_date = published

                feed_entry = FeedEntry(
                    title=entry.get('title', 'No title'),
                    link=entry.get('link', ''),
                    published=parsed_date,
                    #source=feed_url
                )
                entries.append(feed_entry)
            
            return entries
        except Exception as e:
            raise Exception(f"Error parsing feed {feed_url}: {str(e)}")

    @staticmethod
    def save_entries(entries: List[FeedEntry], output_path: Path):
        """Save feed entries to a JSON file."""
        data = [entry.to_dict() for entry in entries]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2) 
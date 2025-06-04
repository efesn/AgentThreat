"""Configuration file containing RSS feed URLs for threat intelligence sources."""

FEED_URLS = [
    "https://blog.google/threat-analysis-group/rss/",
    "https://www.mandiant.com/resources/rss.xml",
    "https://www.microsoft.com/en-us/security/blog/feed/",
    "https://www.cisa.gov/blog.xml",
    "https://research.checkpoint.com/feed/"
]

# Configuration for feed fetching
FETCH_CONFIG = {
    "output_directory": "data",
    "output_file": "fetched_feeds.json",
    "request_timeout": 30,  # seconds
    "max_entries_per_feed": 100
} 
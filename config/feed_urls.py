"""Configuration file containing RSS feed URLs for threat intelligence sources."""

FEED_URLS = [
    "https://news.sophos.com/en-us/category/threat-research/feed/",
    "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",
    "https://research.checkpoint.com/feed/",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",
    "https://blog.talosintelligence.com/rss/",
    "https://isc.sans.edu/rssfeed_full.xml",
    "https://www.sentinelone.com/feed/",
    


]

# Configuration for feed fetching
FETCH_CONFIG = {
    "output_directory": "data",
    "output_file": "fetched_feeds.json",
    "request_timeout": 30,  # seconds
    "max_entries_per_feed": 100
} 
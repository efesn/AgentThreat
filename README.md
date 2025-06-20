# AgentThreat: Multi-Agent CTI System with Google's ADK
[AgentThreat is currently in development]

## Overview

AgentThreat is an autonomous, AI-driven multi-agent system built with Google’s Agent Development Kit (ADK) to collect, clean, enrich, and analyze cyber threat intelligence (CTI) reports from various trusted sources in real time. Designed to handle noisy and unstructured threat feeds from trusted sources.

The project addresses the common challenge faced by security researchers: extracting meaningful data from the high volume of noisy, duplicate, and unstructured resources. Using LLM powered agents built with ADK, AgentThreat automatically filters, enriches, and classifies CTI entries.

By enabling AI-native workflows with the Agent Development Kit, AgentThreat automatically filters out irrelevant or duplicate content, extracts key indicators of compromise (IOCs), identifies threat actors and malware, maps attacks to MITRE ATT&CK techniques, and summarizes threat context, all without human intervention. AgentThreat empowers threat hunters & security researchers by significantly reducing manual workload.

## Key Features

### Intelligent Feed Processing
The system employs three specialized agents:

**1. RSS Fetcher Agent**
- Fetches feeds from trusted cybersecurity sources
- Handles feed parsing and validation

**2. Feed Cleaner Agent**
- Filters out non-security & CTI related content
- Removes duplicates
- Inserts filtered data to BigQuery

**3. Threat Analyzer Agent**
- Extracts IOCs (IPs, domains, hashes, CVEs etc.)
- Identifies threat actors and TTPs
- Maps to MITRE ATT&CK framework
- Generates human readable summaries
- Inserts analyzed data to BigQuery

## Tech Stack
- **Language**: Python
- **Framework**: Google Agent Development Kit (ADK)
- **Cloud Services**: Google Cloud BigQuery for data storage
- **LLM**: Gemini 2.0 Flash

## Requirements

- Python 3.9+
- Google Cloud project with Vertex AI API enabled
- BigQuery (required table schema & configs are provided below)
- Google ADK (Agent Development Kit)


## Installation

1. Clone the repository:
```bash
git clone https://github.com/efesn/AgentThreat.git
cd AgentThreat
```
2. Set up environment variables:
```bash
# Rename .env.example to .env. Then edit .env with proper settings
cp .env.example .env
```

3. (Recommended) Create a Virtual Environment

Prefer that to isolate project dependencies and avoid conflicts instead of using break system packages flag, create a virtual environment:

```bash
python -m venv agentthreat
```
#### Active the virtual environment:
Windows:
```bash
agentthreat\Scripts\activate
```
macOS/Linux:
```
source agentthreat/bin/activate
```
#### Install Python Dependencies:
```bash
pip install -r requirements.txt
```

4. Set up BigQuery:

Go to  **BigQuery Studio** in the [Google Cloud Console](https://console.cloud.google.com/bigquery)

In your BigQuery Studio on Google Cloud Console, create new SQL Query and insert this required table structure & run:
```sql
CREATE TABLE `your-project-id.your-dataset-name.your-table-name`
(
    -- Basic Feed Data
    title STRING NOT NULL,
    link STRING NOT NULL,
    published TIMESTAMP,
    
    -- Analysis Status
    analyzed BOOLEAN DEFAULT FALSE,
    analysis_timestamp TIMESTAMP,
    
    -- Threat Analysis Data
    threat_category STRING,
    iocs STRING,  --stores as JSON string of extracted IOCs
    summary STRING,
    threat_actor STRING,
    mitre_techniques STRING,  --stores as JSON array of technique IDs
    
    -- Time datas
    insertion_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP(),
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
)
CLUSTER BY link, published;

```

## Usage

Basic usage:
Interact with agents in a browser-based playground.
```python
adk web .
```

## Data Sources

- [Google Threat Intelligence](https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v)
- [Sophos Threat Research](https://news.sophos.com/en-us/category/threat-research/feed/)
- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/)
- [CheckPoint Research](https://research.checkpoint.com/feed/)
- [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/feed/)
- [Cisco Talos Intelligence](https://blog.talosintelligence.com/rss/)
- [SANS Internet Storm Center](https://isc.sans.edu/rssfeed_full.xml)
- [SentinelOne Research](https://www.sentinelone.com/feed/)

## Future Enhancements

- Running autonomous daily/weekly and provide weekly/monthly insights by analyzing them
-
-


*This project was developed specifically for the "Agent Development Kit Hackathon with Google Cloud"*
"""Main agent configuration for the CTI Agents system."""

from google.adk.agents import LlmAgent
from . import prompt
from .sub_agents.rss_fetcher.agent import rss_fetcher_agent
from .sub_agents.feed_cleaner.agent import feed_cleaner_agent
from .sub_agents.threat_analyzer.agent import threat_analyzer_agent

# Use the latest Gemini model
MODEL = "gemini-2.0-flash-001"

# Create the coordinator agent that will manage other agents
root_agent = LlmAgent(
    name="AgentThreat",
    model=MODEL,
    description="Coordinator agent that manages CTI sub-agents",
    instruction=prompt.COORDINATOR_PROMPT,
    sub_agents=[rss_fetcher_agent, feed_cleaner_agent, threat_analyzer_agent],
)

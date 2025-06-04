"""Main agent configuration for the CTI Agents system."""

from google.adk.agents import LlmAgent
from . import prompt
from .sub_agents.rss_fetcher.agent import root_agent as rss_agent

# Use the latest Gemini model
MODEL = "gemini-2.0-flash-001"

# Create the coordinator agent that will manage other agents
cti_coordinator = LlmAgent(
    name="cti_coordinator",
    model=MODEL,
    description="Coordinator agent that manages CTI sub-agents",
    instruction=prompt.COORDINATOR_PROMPT,
    sub_agents=[rss_agent]
)

# Export the coordinator as the root agent
root_agent = cti_coordinator

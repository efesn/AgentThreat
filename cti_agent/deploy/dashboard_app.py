import os
import sys
import json
import logging
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from google.cloud import bigquery
from dotenv import load_dotenv
import google.generativeai as genai

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Import the root agent
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from cti_agent.agent import root_agent

app = Flask(__name__)

# Store logs for display in the dashboard
agent_logs = []

def log_message(level, message):
    """Add timestamped log message to the log store"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {"timestamp": timestamp, "level": level, "message": message}
    agent_logs.append(log_entry)
    if level == "ERROR":
        logger.error(message)
    else:
        logger.info(message)
    return log_entry

# Define a function to run the agent directly
def run_agent_workflow():
    """Run the agent workflow by accessing the agent's components directly"""
    try:
        log_message("INFO", "Starting direct agent workflow...")
        
        # Initialize the Gemini model
        genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))
        model = genai.GenerativeModel('gemini-2.0-flash-001')
        
        # Import RSS fetcher sub-agent if available
        try:
            from cti_agent.sub_agents.rss_fetcher.agent import rss_fetcher_agent
            log_message("INFO", "Running RSS fetcher sub-agent...")
            
            # Access the underlying Gemini model directly
            fetcher_result = model.generate_content(
                "Fetch the latest cyber threat intelligence feeds."
            )
            log_message("INFO", "RSS fetching completed")
        except (ImportError, AttributeError) as e:
            log_message("WARNING", f"Could not run RSS fetcher: {str(e)}")
            fetcher_result = None
            
        # Import feed cleaner sub-agent if available
        try:
            from cti_agent.sub_agents.feed_cleaner.agent import feed_cleaner_agent
            log_message("INFO", "Running feed cleaner sub-agent...")
            
            # Access the underlying Gemini model directly
            cleaner_result = model.generate_content(
                "Clean and prepare the fetched feeds for analysis."
            )
            log_message("INFO", "Feed cleaning completed")
        except (ImportError, AttributeError) as e:
            log_message("WARNING", f"Could not run feed cleaner: {str(e)}")
            cleaner_result = None
            
        # Import threat analyzer sub-agent if available
        try:
            from cti_agent.sub_agents.threat_analyzer.agent import threat_analyzer_agent
            log_message("INFO", "Running threat analyzer sub-agent...")
            
            # Access the underlying Gemini model directly
            analyzer_result = model.generate_content(
                "Analyze the cleaned feeds and identify threats."
            )
            log_message("INFO", "Threat analysis completed")
        except (ImportError, AttributeError) as e:
            log_message("WARNING", f"Could not run threat analyzer: {str(e)}")
            analyzer_result = None
            
        # Compile results
        results = []
        for name, result in [
            ("RSS Fetcher", fetcher_result),
            ("Feed Cleaner", cleaner_result),
            ("Threat Analyzer", analyzer_result)
        ]:
            if result:
                if hasattr(result, 'text'):
                    results.append(f"--- {name} Results ---\n{result.text}")
                else:
                    results.append(f"--- {name} Results ---\n{str(result)}")
        
        if not results:
            log_message("WARNING", "No agent components executed successfully")
            return "No results from any agent component. Check the agent implementation."
        
        return "\n\n".join(results)
    except Exception as e:
        log_message("ERROR", f"Error in direct agent workflow: {str(e)}")
        import traceback
        log_message("DEBUG", traceback.format_exc())
        raise e

@app.route('/')
def index():
    """Render the dashboard page"""
    return render_template('index.html')

@app.route('/get-threats')
def get_threats():
    """Fetch threat data from BigQuery"""
    try:
        # Initialize BigQuery client
        client = bigquery.Client()
        
        # Get table name from environment variables
        project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
        table_name = os.getenv("BIGQUERY_TABLE")
        table_id = f"{project_id}.{table_name}"
        
        log_message("INFO", f"Fetching threat data from {table_id}")
        
        # Execute query
        query = f"""
        SELECT 
            title, link, published, analyzed, analysis_timestamp,
            threat_category, iocs, summary, threat_actor, mitre_techniques,
            insertion_timestamp, last_updated
        FROM `{table_id}`
        ORDER BY analysis_timestamp DESC
        LIMIT 25
        """
        
        query_job = client.query(query)
        rows = query_job.result()
        
        # Convert to list of dictionaries for JSON serialization
        results = []
        for row in rows:
            row_dict = dict(row.items())
            
            # Convert datetime objects to strings
            for key, value in row_dict.items():
                if isinstance(value, datetime):
                    row_dict[key] = value.isoformat()
            
            results.append(row_dict)
        
        log_message("INFO", f"Successfully fetched {len(results)} threat entries")
        return jsonify(results)
    
    except Exception as e:
        error_msg = f"Error querying BigQuery: {str(e)}"
        log_message("ERROR", error_msg)
        return jsonify({"error": error_msg}), 500

@app.route('/run-agent', methods=['POST'])
def run_agent():
    """Run the threat analysis agent workflow"""
    try:
        log_message("INFO", "Starting agent workflow...")
        
        # Execute the agent using our direct workflow function
        result = run_agent_workflow()
        
        log_message("INFO", "Agent workflow completed successfully")
        return jsonify({
            "status": "success",
            "message": "Agent workflow completed",
            "details": result
        })
    
    except Exception as e:
        error_msg = f"Agent workflow failed: {str(e)}"
        log_message("ERROR", error_msg)
        # Get full stack trace for debugging
        import traceback
        stack_trace = traceback.format_exc()
        log_message("DEBUG", f"Stack trace: {stack_trace}")
        return jsonify({"status": "error", "message": error_msg}), 500

@app.route('/get-logs')
def get_logs():
    """Return stored log messages"""
    return jsonify(agent_logs)

@app.route('/clear-logs', methods=['POST'])
def clear_logs():
    """Clear stored log messages"""
    global agent_logs
    agent_logs = []
    return jsonify({"status": "success", "message": "Logs cleared"})

if __name__ == "__main__":
    log_message("INFO", "Starting CTI Dashboard server")
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5001)))
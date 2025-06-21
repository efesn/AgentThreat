import os
import sys

# Add the project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(project_root)

# Import and run the dashboard app
from cti_agent.deploy.dashboard_app import app

if __name__ == "__main__":
    print("Starting CTI Dashboard server...")
    app.run(debug=True, host="0.0.0.0", port=5001)
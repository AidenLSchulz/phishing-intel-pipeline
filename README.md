Phishing Domain Detection Pipeline
Setup Instructions
1. Clone the repository
git clone <your-repo-url>
cd phishing-intel-pipeline
2. Go into the API folder
cd api
3. Install dependencies
pip install fastapi uvicorn sqlalchemy psycopg2-binary python-dotenv
4. Run the server
python -m uvicorn app.main:app --reload
5. Open in browser

http://127.0.0.1:8000/docs

What this project does

# Phishing Domain Detection Pipeline

This project is an automated system that analyzes suspicious domains, identifies phishing indicators, assigns a risk score, and stores results for reporting and review.

## Initial Goals
- Accept domain input
- Run basic phishing checks
- Score suspicious domains
- Store results
- Generate reports

##Technology Stack

Python – Primary programming language used to build the phishing detection pipeline and analysis logic.

FastAPI – Framework used to create the backend API for submitting domains and retrieving analysis results.

PostgreSQL – Database used to store submitted domains, analysis results, and calculated risk scores.

Visual Studio Code (VS Code) – Development environment used to write and test the application.

GitHub – Used for version control, backlog management, issue tracking, and team collaboration.

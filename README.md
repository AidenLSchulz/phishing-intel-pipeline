# Phishing Domain Detection Pipeline

# For Information Regarding how to run the integration_test.py please scroll to line 70 and on. 

## Overview
This project analyzes domains for phishing indicators and assigns a risk score based on suspicious patterns such as keywords, length, and structure.

## Features
- Analyze domain input
- Detect suspicious keywords
- Score domain risk
- Return results through the API
- Simple frontend for testing

## Project Structure
phishing-intel-pipeline/
├── api/      # FastAPI backend
├── web/      # Frontend (HTML/CSS/JS)
└── README.md

## Setup

### 1. Clone the repo
git clone <your-repo-url>  
cd phishing-intel-pipeline  

### 2. Install dependencies
cd api  
pip install fastapi uvicorn sqlalchemy psycopg2-binary python-dotenv  

### 3. Run the API
python -m uvicorn app.main:app --reload  

Open in browser:  
http://127.0.0.1:8000/docs  

## Frontend
Open web/index.html in your browser.

## Example Request
POST /analyze-domain

{
  "domain": "paypal-secure-login-update.com"
}

## Example Response
{
  "domain": "paypal-secure-login-update.com",
  "risk_score": 60,
  "reasons": [
    "Contains suspicious keyword: login",
    "Contains suspicious keyword: secure",
    "Contains suspicious keyword: update",
    "Contains hyphens"
  ]
}

## Tech Stack
- Python
- FastAPI
- PostgreSQL (planned)
- VS Code
- GitHub

## Notes
- API runs on port 8000 by default  
- Frontend calls the API locally  
- Use /docs to test endpoints directly  


## CLI Integration Testing (Before GUI Merge)

## Additional Required Dependencies
  - pip install requests beautifulsoup4 python-whois

## Purpose
  - This is a CLI testing program used to ensure all phishing indicators are functioning correctly before merging into the website GUI.

## How to Run

  - You must cd into the phishing-intel-pipeline\api\app directory inside of the phishing-intel-pipeline.

## (This is an example — use your actual file path)
  - Example: C:\Users\Cody\OneDrive - Mid-State Technical College\1 Secure Software Applications\Git-Repos\phishing-intel-pipeline-updated\phishing-intel-pipeline\api\app

## Then run:
  - python .\integration_test.py

## What the Script Does
  - Takes the test_url variable tests it against all implemented phishing indicators, applies a phishing score for each detection triggered, then determines whether the site is likely phishing based on total score

## CLI Output Includes
  - Which indicators were triggered
  - The score value of each triggered detection
  - Final phishing determination
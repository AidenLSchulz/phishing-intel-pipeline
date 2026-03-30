# Phishing Domain Detection Pipeline

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



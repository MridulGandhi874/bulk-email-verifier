# Bulk Email Verification System

## Architecture Overview
This application uses a Python FastAPI backend to process bulk email verification asynchronously. It implements a 3-tier verification system:
1. **Syntax Validation:** Regex checking for standard IETF formats.
2. **DNS/MX Lookup:** Asynchronous domain queries using `aiodns`.
3. **SMTP Simulation:** Connects to Port 25 to verify RCPT TO, then gracefully issues a QUIT command without sending data. 

The frontend is a lightweight HTML5/TailwindCSS single-page application served directly by the backend.

## Local Installation Instructions
1. Ensure Python 3.8+ is installed.
2. Install dependencies by running: 
   `pip install fastapi uvicorn pandas aiodns python-multipart`
3. Start the local server: 
   `python -m uvicorn main:app --reload`
4. Open a web browser and navigate to `http://127.0.0.1:8000`.

**Note on Port 25:** Cloud providers and residential ISPs often block Port 25. If SMTP fails due to network restrictions, the application gracefully catches the timeout and flags the email as "Unknown/Error".
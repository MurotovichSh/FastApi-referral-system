# FastApi-referral-system

This project is a FastAPI-based web application that provides endpoints for user authentication, user registration, referral code generation, referral code deletion, and retrieval of referral information. The application uses PostgreSQL as its database backend to store information about users, referral codes, and related data. It also includes functionality for in-memory caching generated referral codes and deleting expired referral codes.

# Features
 * Referral Code Expiry
 
 * Generate referral code
 
 * Check validity of referral Code
 
 * Register referral code
 
 * Check the validity of the user email with emailhunter.co
 
 * Get additional information about the user with Enrichment API


# Set up

1) Clone the repository
```
git clone https://github.com/MurotovichSh/FastApi-referral-system
```
3) Go to the project directory
cd fastapi-referral-system
4) Create and activate an environment and install the dependencies

```
python3 -m venv .venv/
source .venv/bin/activate
pip install -r requirements.txt
```
4) Set the environment variables:
   ``
   SQLALCHEMY_DATABASE_URL,
   SECRET_KEY,
   EMAIL_HUNTER_API_KEY,
   CLEARBIT_API_KEY
   ``
# Run the application

Run the following code in the terminal:
```
python3 app.py
```

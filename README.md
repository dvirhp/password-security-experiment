# Password Security Experiment – Stage 2

This project implements the server-side components required for Stage 2 of the assignment.  
It focuses on user management, password hashing, logging, and experimental configuration.

## Features Implemented

### 1. Configurable Hashing Modes
The system supports three hashing algorithms, as required:
- **SHA-256 + Salt + Pepper**
- **bcrypt** (configurable cost)
- **argon2id** (configurable time/memory/parallelism)

Hash mode and parameters are loaded from `config.json`.

### 2. Pepper Support
A global pepper value is added to every hashing mode.  
It is stored only in the configuration file and never in the database.

### 3. User Generation (Weak / Medium / Strong)
A deterministic seed is created using:
- Dvir ID
- Bar ID  
XOR’ed together

Based on this seed, 30 users are created:
- 10 weak passwords  
- 10 medium passwords  
- 10 strong passwords  

The passwords are generated deterministically (not fixed wordlists).

### 4. SQLite Database
Two tables are used:
- `users` – username, hash, salt (when applicable), strength  
- `logs` – every login attempt, with timing and metadata

### 5. Login & Register API
Using Flask:
- `/register` – creates a user  
- `/login` – verifies credentials and measures latency

### 6. Logging System
Every login attempt is written to:
- The database (`logs` table)
- A JSON-lines file (`attempts.log`)

Fields include:
- timestamp  
- group_seed  
- username  
- hash_mode  
- protection_flags  
- result  
- latency_ms  

### 7. Configurable Protections (Stage 3–4)
The config includes flags for:
- rate limit  
- lockout  
- CAPTCHA  
- TOTP  

These are currently disabled, as required for Stage 2.

---

## How to Run

1. Install dependencies:

2. Initialize database:

3. Start the server:

4. Test login attacks using scripts (e.g., `bruteforce_test.py`).

---

## Notes
This implementation follows exactly the requirements of Stage 2:
- Configurable hashing  
- Deterministic user generation  
- Full logging  
- No advanced protections yet  
- No password storage in plain text  
- No exposure of secrets  

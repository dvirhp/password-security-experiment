# Cybersecurity Experiments Framework

This repository contains a framework for simulating and testing authentication attacks and protections.
It allows running brute-force attacks against different password hash schemes, evaluating security protections,
and visualizing experiment results.

---

## Features

- **Authentication Server** (`AuthServer`)
  - Configurable password hash algorithms: SHA-256, bcrypt, Argon2id.
  - Supports multiple protections:
    - Rate limiting
    - Lockout policies
    - CAPTCHA
    - TOTP (Two-Factor Authentication)
- **Attack Simulation**
  - Brute-force attacks with configurable parameters:
    - Password strength
    - Alternate password guessing
    - IP switching
    - Lockout and CAPTCHA interaction
- **Experiment Management**
  - Automatically generates experiments with various hash, protection, and attack parameters.
  - Group experiments by hash type, password strength, or protections.
- **Logging**
  - Per-experiment logs
  - Global combined log file
- **Statistics & Visualization**
  - Scatter plots of latency per attempt
  - Average attempts for successful logins
  - Frequency of messages (errors, lockouts, success)
  
---

## Requirements

- Python 3.9+
- Required packages:

```bash
pip install matplotlib pyotp
# Flask Banking Application

This Flask Banking Application is a simple yet secure web application designed to handle basic banking operations such as account creation, balance checks, and transfers between accounts. It demonstrates robust security practices against common vulnerabilities like SQL injection, CSRF, XSS, and more.

## Features

- **User Authentication**: Secure login and logout processes.
- **Account Management**: Ability view balances, and transfer funds.
- **Security**: Implements defenses against SQL injection, CSRF, XSS, and user enumeration.
- **Database Integration**: Uses SQLite for database management, securely handling transactions and data storage.

## Security Features

- **SQL Injection Protection**: Uses parameterized queries to prevent SQL injection.
- **CSRF Protection**: Leverages Flask-WTF to manage CSRF protection securely.
- **Secure Password Storage**: Utilizes PBKDF2 with SHA-256 to hash passwords before storage.
- **Error Handling**: Robust error management to prevent leakage of sensitive information.

## Prerequisites

Before you can run this application, you will need the following:
- Python
- Flask
- Flask-WTF
- Passlib
- SQLite3


import sqlite3
from passlib.hash import pbkdf2_sha256

def setup_database():
    """
    Creates and populates a 'users' table within a SQLite database.

    Security Features:
    1. SQL Injection Defense:
       - Uses parameterized queries when inserting data, which prevents SQL injection.
         SQL injection is a common attack where attackers could execute arbitrary SQL code
         by manipulating inputs that are incorrectly concatenated into SQL commands.

    2. Secure Password Storage:
       - Uses PBKDF2 (password-based key derivation function 2) with SHA-256 hash to secure passwords.
         Storing hashed passwords instead of plain text enhances security by making it significantly harder
         for attackers to retrieve the original passwords even if they gain access to the database.

    Error Handling:
    - Implements try-except blocks to catch and handle SQL errors, such as issues with table creation or data insertion.

    Transaction Management:
    - Uses transactions to ensure that all database operations either complete fully or not at all,
      maintaining data integrity.
    """

    try:
        con = sqlite3.connect('bank.db')
        cur = con.cursor()

        # Securely creating the table with SQL parameters to avoid SQL injection vulnerabilities.
        cur.execute('''
            CREATE TABLE users (
                email text primary key,
                name text,
                password text)
        ''')

        # Insert user data securely using parameterized statements.
        users_data = [
            ('alice@example.com', 'Alice Xu', pbkdf2_sha256.hash("123456")),
            ('bob@example.com', 'Bobby Tables', pbkdf2_sha256.hash("123456"))
        ]
        for user in users_data:
            cur.execute("INSERT INTO users VALUES (?, ?, ?)", user)

        con.commit()  # Commit the changes securely to ensure all operations are saved.
    except sqlite3.IntegrityError as e:
        print(f"Database error related to data integrity: {e}")
    except sqlite3.OperationalError as e:
        print(f"Operational error related to SQLite database operations: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        con.close()  # Ensure the database connection is closed even if an error occurs.

if __name__ == "__main__":
    setup_database()

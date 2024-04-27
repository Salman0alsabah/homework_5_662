import sqlite3

def create_accounts():
    """
    Creates a database table for accounts and inserts initial data.
    
    SQL Injection Defense:
    - Uses parameterized queries to ensure data is bound correctly, avoiding SQL injection.
      This is crucial since SQL injection can allow attackers to alter queries, resulting in unauthorized data access or modification.
    
    Use of Transactions:
    - The use of transactions ensures that all or none of the commands execute successfully,
      maintaining database consistency.

    Error Handling:
    - Basic error handling should be added to manage any SQL errors that occur during the execution
      of commands, such as trying to insert duplicate keys or issues in connecting to the database.
    """
    try:
        # Connect to the SQLite database
        con = sqlite3.connect('bank.db')
        cur = con.cursor()

        # Safely create the accounts table if it does not already exist
        cur.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id text primary key,
                owner text,
                balance integer,
                FOREIGN KEY(owner) REFERENCES users(email)
            )''')

        # Insert initial data using parameterized queries to prevent SQL injection
        accounts_data = [
            ('100', 'alice@example.com', 7500),
            ('190', 'alice@example.com', 200),
            ('998', 'bob@example.com', 1000)
        ]
        for account in accounts_data:
            cur.execute("INSERT INTO accounts VALUES (?, ?, ?)", account)

        con.commit()  # Commit the transaction to save the changes
    except sqlite3.IntegrityError as e:
        print(f"Database error: {e}")  # Handle specific sqlite3 errors like unique constraint failure
    except Exception as e:
        print(f"An error occurred: {e}")  # Handle general errors
    finally:
        con.close()  # Ensure that the database connection is closed even if an error occurs

if __name__ == "__main__":
    create_accounts()

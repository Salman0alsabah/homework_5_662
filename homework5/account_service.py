import sqlite3

def get_balance(account_number, owner):
    """
    Retrieves the balance for a specific account owned by a user.
    
    Args:
    - account_number: The account number as a string or integer.
    - owner: The owner's identifier (e.g., email or user ID).

    Returns:
    - The balance of the account as an integer or None if the account does not exist.

    Defense against SQL Injection:
    - Uses parameterized queries with placeholders (?, ?) to separate code from data,
      preventing attackers from manipulating SQL queries by injecting malicious SQL.
    
    Handling of sensitive data:
    - Accesses only the balance related to the owner, ensuring data privacy and adherence
      to the principle of least privilege.
    """
    try:
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        # Parameterized query to prevent SQL injection.
        cur.execute('SELECT balance FROM accounts WHERE id=? AND owner=?', (account_number, owner))
        row = cur.fetchone()
        if row is None:
            # Proper handling of non-existent accounts.
            return None
        return row[0]
    finally:
        # Ensure database connection is closed even if an error occurs.
        con.close()

def do_transfer(source, target, amount):
    """
    Performs a balance transfer between two accounts.
    
    Args:
    - source: The source account ID.
    - target: The target account ID.
    - amount: The amount to transfer as an integer.

    Returns:
    - True if the transfer was successful, False otherwise.

    Defense against SQL Injection:
    - Uses parameterized queries to prevent SQL code injection.

    Transaction integrity:
    - Uses database transactions to ensure that the transfer operation is atomic.
      This means either both operations (debit and credit) succeed, or none do,
      maintaining the integrity of financial data.

    Error handling:
    - Handles cases where the target account does not exist or the source does not have enough balance.
    """
    try:
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        # Check for the existence of the target account to prevent transfers to non-existent accounts.
        cur.execute('SELECT id FROM accounts WHERE id=?', (target,))
        if cur.fetchone() is None:
            return False
        
        # Start a transaction explicitly to ensure atomicity.
        con.execute('BEGIN')
        cur.execute('UPDATE accounts SET balance=balance-? WHERE id=? AND balance>=?', (amount, source, amount))
        if cur.rowcount == 0:
            # Rollback if the source account does not have enough funds.
            con.rollback()
            return False
        
        cur.execute('UPDATE accounts SET balance=balance+? WHERE id=?', (amount, target))
        # Commit the transaction to finalize the transfer.
        con.commit()
        return True
    finally:
        # Ensure the database connection is closed properly.
        con.close()

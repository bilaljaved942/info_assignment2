"""SQLite users table + salted hashing."""
import os
import sqlite3
from pathlib import Path
from ..common.utils import sha256_hex

class Database:
    def __init__(self):
        self.db_path = Path("storage/users.db")
        self.db_path.parent.mkdir(exist_ok=True)
        self.connection = sqlite3.connect(str(self.db_path))
        self.cursor = self.connection.cursor()

    def initialize_tables(self):
        """Create the users table if it doesn't exist."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.connection.commit()

    def add_user(self, username: str, password: str):
        """Add a new user with salted password hash."""
        salt = os.urandom(32).hex()  # 32 bytes = 256 bits
        password_hash = sha256_hex(password + salt)
        
        try:
            self.cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash, salt)
            )
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_user(self, username: str, password: str) -> bool:
        """Verify user credentials."""
        try:
            self.cursor.execute(
                "SELECT password_hash, salt FROM users WHERE username = ?",
                (username,)
            )
            result = self.cursor.fetchone()
            
            if not result:
                print(f"User {username} not found")
                return False
                
            stored_hash, salt = result
            computed_hash = sha256_hex(password + salt)
            return computed_hash == stored_hash
            
        except Exception as e:
            print(f"Error verifying user: {e}")
            return False

    def close(self):
        """Close database connection."""
        self.cursor.close()
        self.connection.close()

def main():
    """Initialize database tables when run as a script."""
    db = Database()
    db.initialize_tables()
    print("Database tables initialized successfully!")
    db.close()

if __name__ == "__main__":
    main()

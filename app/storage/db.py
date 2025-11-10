"""MySQL users table + salted hashing (no chat storage)."""
import os
import sys
import mysql.connector
from dotenv import load_dotenv
from ..common.utils import sha256_hex

load_dotenv()

class Database:
    def __init__(self):
        self.connection = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            port=int(os.getenv('DB_PORT')),
            database=os.getenv('DB_NAME'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASS')
        )
        self.cursor = self.connection.cursor()

    def initialize_tables(self):
        """Create the users table if it doesn't exist."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(64) NOT NULL,
                salt VARCHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.connection.commit()

    def add_user(self, username: str, password: str):
        """Add a new user with salted password hash."""
        salt = os.urandom(int(os.getenv('PASSWORD_SALT_LENGTH', 32))).hex()
        password_hash = sha256_hex(password + salt)
        
        try:
            self.cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)",
                (username, password_hash, salt)
            )
            self.connection.commit()
            return True
        except mysql.connector.IntegrityError:
            return False

    def verify_user(self, username: str, password: str) -> bool:
        """Verify user credentials."""
        self.cursor.execute(
            "SELECT password_hash, salt FROM users WHERE username = %s",
            (username,)
        )
        result = self.cursor.fetchone()
        
        if not result:
            return False
            
        stored_hash, salt = result
        computed_hash = sha256_hex(password + salt)
        return computed_hash == stored_hash

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

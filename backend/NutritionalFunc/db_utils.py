"""
Database utilities for Azure SQL Database connection and operations
"""
import pyodbc
import os
import logging
from typing import Optional, Dict, List, Any

logger = logging.getLogger(__name__)


class DatabaseConnection:
    """Manages Azure SQL Database connections"""

    def __init__(self):
        self.server = os.environ.get('SQL_SERVER')
        self.database = os.environ.get('SQL_DATABASE')
        self.username = os.environ.get('SQL_USERNAME')
        self.password = os.environ.get('SQL_PASSWORD')
        # Azure Functions has ODBC Driver 17 pre-installed
        self.driver = os.environ.get('SQL_DRIVER', '{ODBC Driver 17 for SQL Server}')

    def get_connection(self):
        """Get a database connection"""
        try:
            # ODBC Driver 18 requires TrustServerCertificate=yes for Azure SQL
            conn_str = (
                f'DRIVER={self.driver};'
                f'SERVER={self.server};'
                f'DATABASE={self.database};'
                f'UID={self.username};'
                f'PWD={self.password};'
                f'Encrypt=yes;'
                f'TrustServerCertificate=yes;'
                f'Connection Timeout=30;'
            )
            logger.info(f"Attempting connection to {self.server}/{self.database}")
            conn = pyodbc.connect(conn_str)
            logger.info("Database connection successful")
            return conn
        except pyodbc.Error as e:
            logger.error(f"Database connection error: {e}")
            raise

    def execute_query(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Execute a SELECT query and return results as list of dicts"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)

            # Get column names
            columns = [column[0] for column in cursor.description]

            # Fetch all rows and convert to list of dicts
            results = []
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))

            return results
        except pyodbc.Error as e:
            logger.error(f"Query execution error: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def execute_non_query(self, query: str, params: tuple = ()) -> int:
        """Execute INSERT, UPDATE, DELETE query and return affected rows"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount
        except pyodbc.Error as e:
            logger.error(f"Non-query execution error: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

    def execute_scalar(self, query: str, params: tuple = ()) -> Any:
        """Execute query and return first column of first row"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            result = cursor.fetchone()
            conn.commit()  # Commit the transaction
            return result[0] if result else None
        except pyodbc.Error as e:
            logger.error(f"Scalar query execution error: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()


# User management functions
def create_user(email: str, password_hash: Optional[str], full_name: Optional[str] = None) -> int:
    """Create a new user and return user_id"""
    db = DatabaseConnection()
    conn = None
    try:
        conn = db.get_connection()
        cursor = conn.cursor()

        # Insert user and get the inserted user_id in one statement
        insert_query = """
            INSERT INTO Users (email, password_hash, full_name)
            OUTPUT INSERTED.user_id
            VALUES (?, ?, ?)
        """
        cursor.execute(insert_query, (email, password_hash, full_name))
        result = cursor.fetchone()
        user_id = int(result[0]) if result and result[0] is not None else None

        conn.commit()
        logger.info(f"Created user with email: {email}, user_id: {user_id}")
        return user_id
    except pyodbc.Error as e:
        logger.error(f"Create user error: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Get user by email"""
    db = DatabaseConnection()
    query = "SELECT * FROM Users WHERE email = ? AND is_active = 1"
    results = db.execute_query(query, (email,))
    return results[0] if results else None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Get user by user_id"""
    db = DatabaseConnection()
    query = "SELECT * FROM Users WHERE user_id = ? AND is_active = 1"
    results = db.execute_query(query, (user_id,))
    return results[0] if results else None


def create_oauth_provider(user_id: int, provider: str, provider_user_id: str,
                          provider_username: Optional[str] = None) -> int:
    """Link OAuth provider to user"""
    db = DatabaseConnection()
    conn = None
    try:
        conn = db.get_connection()
        cursor = conn.cursor()

        # Insert OAuth provider and get the inserted oauth_id in one statement
        insert_query = """
            INSERT INTO OAuthProviders (user_id, provider, provider_user_id, provider_username)
            OUTPUT INSERTED.oauth_id
            VALUES (?, ?, ?, ?)
        """
        cursor.execute(insert_query, (user_id, provider, provider_user_id, provider_username))
        result = cursor.fetchone()
        oauth_id = int(result[0]) if result and result[0] is not None else None

        conn.commit()
        logger.info(f"Created OAuth provider link: {provider} for user_id: {user_id}")
        return oauth_id
    except pyodbc.Error as e:
        logger.error(f"Create OAuth provider error: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()


def get_user_by_oauth(provider: str, provider_user_id: str) -> Optional[Dict[str, Any]]:
    """Get user by OAuth provider credentials"""
    db = DatabaseConnection()
    query = """
        SELECT u.* FROM Users u
        INNER JOIN OAuthProviders o ON u.user_id = o.user_id
        WHERE o.provider = ? AND o.provider_user_id = ? AND u.is_active = 1
    """
    results = db.execute_query(query, (provider, provider_user_id))
    return results[0] if results else None


def create_session(user_id: int, jwt_token_hash: str, expires_at) -> int:
    """Create a new session"""
    db = DatabaseConnection()
    conn = None
    try:
        conn = db.get_connection()
        cursor = conn.cursor()

        # Insert session and get the inserted session_id in one statement
        insert_query = """
            INSERT INTO UserSessions (user_id, jwt_token_hash, expires_at)
            OUTPUT INSERTED.session_id
            VALUES (?, ?, ?)
        """
        cursor.execute(insert_query, (user_id, jwt_token_hash, expires_at))
        result = cursor.fetchone()
        session_id = int(result[0]) if result and result[0] is not None else None

        conn.commit()
        return session_id
    except pyodbc.Error as e:
        logger.error(f"Create session error: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()


def revoke_session(jwt_token_hash: str) -> int:
    """Revoke a session"""
    db = DatabaseConnection()
    query = "UPDATE UserSessions SET is_revoked = 1 WHERE jwt_token_hash = ?"
    return db.execute_non_query(query, (jwt_token_hash,))


def is_session_valid(jwt_token_hash: str) -> bool:
    """Check if session is valid and not revoked"""
    db = DatabaseConnection()
    query = """
        SELECT COUNT(*) FROM UserSessions
        WHERE jwt_token_hash = ? AND is_revoked = 0 AND expires_at > GETDATE()
    """
    count = db.execute_scalar(query, (jwt_token_hash,))
    return count > 0

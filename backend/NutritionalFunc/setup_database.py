"""
Script to create database tables for Phase 3
Run this once to initialize the database schema
"""
import pyodbc
import os
import sys

def create_tables():
    """Create all necessary database tables"""

    # Connection parameters
    server = 'nutritionaldb-sidak-202512.database.windows.net'
    database = 'NutritionalDB'
    username = 'sqladmin'
    password = 'SqlPass2025Strong!'
    driver = '{ODBC Driver 18 for SQL Server}'

    conn_str = (
        f'DRIVER={driver};'
        f'SERVER={server};'
        f'DATABASE={database};'
        f'UID={username};'
        f'PWD={password};'
        f'Encrypt=yes;'
        f'TrustServerCertificate=no;'
        f'Connection Timeout=30;'
    )

    print(f"Connecting to {server}...")

    try:
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        print("Connected successfully!")

        # Check if tables exist
        cursor.execute("""
            SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_TYPE = 'BASE TABLE'
        """)
        existing_tables = [row[0] for row in cursor.fetchall()]
        print(f"Existing tables: {existing_tables}")

        if 'Users' in existing_tables:
            print("Tables already exist!")
            return

        print("Creating Users table...")
        cursor.execute("""
            CREATE TABLE Users (
                user_id INT IDENTITY(1,1) PRIMARY KEY,
                email NVARCHAR(255) UNIQUE NOT NULL,
                password_hash NVARCHAR(255) NULL,
                full_name NVARCHAR(255),
                created_at DATETIME2 DEFAULT GETDATE(),
                updated_at DATETIME2 DEFAULT GETDATE(),
                is_active BIT DEFAULT 1,
                CONSTRAINT chk_email_format CHECK (email LIKE '%_@__%.__%')
            )
        """)
        conn.commit()
        print("Users table created!")

        print("Creating OAuthProviders table...")
        cursor.execute("""
            CREATE TABLE OAuthProviders (
                oauth_id INT IDENTITY(1,1) PRIMARY KEY,
                user_id INT NOT NULL,
                provider NVARCHAR(50) NOT NULL,
                provider_user_id NVARCHAR(255) NOT NULL,
                provider_username NVARCHAR(255),
                access_token NVARCHAR(MAX),
                created_at DATETIME2 DEFAULT GETDATE(),
                updated_at DATETIME2 DEFAULT GETDATE(),
                FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
                CONSTRAINT uq_provider_user UNIQUE (provider, provider_user_id)
            )
        """)
        conn.commit()
        print("OAuthProviders table created!")

        print("Creating UserSessions table...")
        cursor.execute("""
            CREATE TABLE UserSessions (
                session_id INT IDENTITY(1,1) PRIMARY KEY,
                user_id INT NOT NULL,
                jwt_token_hash NVARCHAR(255) NOT NULL,
                created_at DATETIME2 DEFAULT GETDATE(),
                expires_at DATETIME2 NOT NULL,
                is_revoked BIT DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
            )
        """)
        conn.commit()
        print("UserSessions table created!")

        print("Creating indexes...")
        cursor.execute("CREATE INDEX idx_users_email ON Users(email)")
        cursor.execute("CREATE INDEX idx_oauth_provider_userid ON OAuthProviders(provider, provider_user_id)")
        cursor.execute("CREATE INDEX idx_sessions_token ON UserSessions(jwt_token_hash)")
        cursor.execute("CREATE INDEX idx_sessions_user ON UserSessions(user_id)")
        conn.commit()
        print("Indexes created!")

        print("\nDatabase setup complete!")
        cursor.close()
        conn.close()

    except pyodbc.Error as e:
        print(f"Database error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    create_tables()

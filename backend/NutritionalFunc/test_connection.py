"""
Test database and function connectivity
"""
import requests
import json

# Test 1: Check if function app is running
print("=" * 60)
print("TEST 1: Function App Status")
print("=" * 60)
try:
    response = requests.get("https://dietfuncae5348.azurewebsites.net", timeout=10)
    print(f"✅ Function app is up (Status: {response.status_code})")
except Exception as e:
    print(f"❌ Function app error: {e}")

# Test 2: Test GitHub OAuth (doesn't need database)
print("\n" + "=" * 60)
print("TEST 2: GitHub OAuth Endpoint (No DB required)")
print("=" * 60)
try:
    response = requests.get("https://dietfuncae5348.azurewebsites.net/api/auth/github",
                           allow_redirects=False, timeout=10)
    if response.status_code == 302:
        print(f"✅ GitHub OAuth working (Status: {response.status_code})")
        print(f"   Redirect to: {response.headers.get('Location', 'N/A')[:80]}...")
    else:
        print(f"⚠️  Unexpected status: {response.status_code}")
except Exception as e:
    print(f"❌ GitHub OAuth error: {e}")

# Test 3: Test Registration endpoint (needs database)
print("\n" + "=" * 60)
print("TEST 3: Registration Endpoint (Requires DB)")
print("=" * 60)
try:
    payload = {
        "email": "diagtest@example.com",
        "password": "TestPass123",
        "full_name": "Diagnostic Test"
    }
    response = requests.post(
        "https://dietfuncae5348.azurewebsites.net/api/auth/register",
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=15
    )
    print(f"Status Code: {response.status_code}")
    print(f"Headers: {dict(response.headers)}")

    if response.status_code == 500:
        print("❌ Registration failed with 500 error")
        print("   This indicates a server-side error, likely database connection issue")
    elif response.status_code == 201:
        print("✅ Registration successful!")
        try:
            print(f"   Response: {response.json()}")
        except:
            print(f"   Response: {response.text}")
    elif response.status_code == 409:
        print("⚠️  User already exists (this is actually good - means DB is working!)")
        try:
            print(f"   Response: {response.json()}")
        except:
            print(f"   Response: {response.text}")
    else:
        print(f"⚠️  Unexpected status: {response.status_code}")
        print(f"   Response: {response.text}")
except Exception as e:
    print(f"❌ Registration request error: {e}")

# Test 4: Test local database connection
print("\n" + "=" * 60)
print("TEST 4: Direct Database Connection Test")
print("=" * 60)
try:
    import pyodbc

    conn_str = (
        'DRIVER={ODBC Driver 17 for SQL Server};'
        'SERVER=nutritionaldb-sidak-202512.database.windows.net;'
        'DATABASE=NutritionalDB;'
        'UID=sqladmin;'
        'PWD=SqlPass2025Strong!;'
        'Encrypt=yes;'
        'TrustServerCertificate=no;'
        'Connection Timeout=30;'
    )

    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM Users")
    count = cursor.fetchone()[0]
    print(f"✅ Database connection successful!")
    print(f"   Users in database: {count}")
    cursor.close()
    conn.close()
except Exception as e:
    print(f"❌ Database connection failed: {e}")

print("\n" + "=" * 60)
print("DIAGNOSIS COMPLETE")
print("=" * 60)
print("\nRECOMMENDATIONS:")
print("1. If GitHub OAuth works but Registration fails:")
print("   → Database connection issue in Azure Functions")
print("   → ODBC driver may not be available in Azure")
print("   → Consider switching to Azure SQL using pymssql or sqlalchemy")
print("\n2. If local DB connection works but Azure doesn't:")
print("   → Check Azure Function environment variables")
print("   → Verify ODBC driver availability in Azure Linux")

# function_app.py - Phase 3 Implementation
# Includes: Caching, Authentication, OAuth, Protected Endpoints
import azure.functions as func
import logging, os, io, json, math
import pandas as pd
import numpy as np
from azure.storage.blob import BlobServiceClient
from math import ceil
from datetime import datetime, timedelta

# Phase 3 imports
from cache_utils import CacheManager, get_clean_data, get_insights_cache, set_insights_cache, get_clusters_cache, set_clusters_cache, invalidate_all_caches
from auth_utils import AuthManager, require_auth, extract_token_from_request, validate_email, validate_password_strength, GitHubOAuth
from db_utils import create_user, get_user_by_email, get_user_by_id, create_oauth_provider, get_user_by_oauth, create_session

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# ---------- Helper functions (from Phase 2) ----------
def _read_blob_csv(container_name="datasets", blob_name="All_Diets.csv"):
    """Read CSV from blob storage"""
    conn_str = os.environ.get('BLOB_STORAGE_CONNECTION_STRING') or os.environ.get('AzureWebJobsStorage')
    bsc = BlobServiceClient.from_connection_string(conn_str)
    container = bsc.get_container_client(container_name)
    blob = container.get_blob_client(blob_name)
    data = blob.download_blob().readall()
    df = pd.read_csv(io.BytesIO(data))
    df.columns = [c.strip() for c in df.columns]  # Strip whitespace from column names
    return df

def _parse_request(req: func.HttpRequest):
    """Parse request parameters"""
    params = {}
    params['diet'] = req.params.get('diet')
    params['search'] = req.params.get('search')
    page = req.params.get('page')
    per_page = req.params.get('per_page')

    try:
        body = req.get_json()
    except ValueError:
        body = {}

    if not params['diet']:
        params['diet'] = body.get('diet')
    if not params['search']:
        params['search'] = body.get('search')
    if not page:
        page = body.get('page')
    if not per_page:
        per_page = body.get('per_page')

    try:
        params['page'] = int(page) if page is not None else 1
    except Exception:
        params['page'] = 1

    try:
        params['per_page'] = int(per_page) if per_page is not None else 10
    except Exception:
        params['per_page'] = 10

    if params['page'] < 1:
        params['page'] = 1
    if params['per_page'] < 1:
        params['per_page'] = 10

    if params['diet'] is None or str(params['diet']).strip().lower() in ('', 'all', 'none', 'null'):
        params['diet'] = None
    else:
        params['diet'] = str(params['diet']).strip()

    # Clean up search parameter
    if params['search'] is None or str(params['search']).strip() == '':
        params['search'] = None
    else:
        params['search'] = str(params['search']).strip()

    return params

def _ensure_numeric(df, cols=('Protein(g)','Carbs(g)','Fat(g)')):
    """Convert columns to numeric and fill missing values"""
    numeric_cols = []
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors='coerce')
            numeric_cols.append(c)
    if numeric_cols:
        df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].mean())
    return numeric_cols

def _apply_diet_filter(df, diet_filter):
    """Filter dataframe by diet type"""
    df_filtered = df.copy()
    if diet_filter:
        df_filtered = df_filtered[
            df_filtered['Diet_type'].astype(str).str.strip().str.lower()
            == str(diet_filter).strip().lower()
        ]
    return df_filtered

def _apply_search_filter(df, search_term):
    """Filter dataframe by search term across multiple columns"""
    if not search_term:
        return df

    search_lower = search_term.lower()
    df_filtered = df.copy()

    # Search in Recipe_name, Cuisine_type, and Diet_type columns
    mask = pd.Series([False] * len(df_filtered))

    if 'Recipe_name' in df_filtered.columns:
        mask |= df_filtered['Recipe_name'].astype(str).str.lower().str.contains(search_lower, na=False)

    if 'Cuisine_type' in df_filtered.columns:
        mask |= df_filtered['Cuisine_type'].astype(str).str.lower().str.contains(search_lower, na=False)

    if 'Diet_type' in df_filtered.columns:
        mask |= df_filtered['Diet_type'].astype(str).str.lower().str.contains(search_lower, na=False)

    return df_filtered[mask]

def _paginate(items, page, per_page):
    """Paginate a list of items"""
    total = len(items)
    total_pages = ceil(total / per_page) if per_page else 1
    if total_pages == 0:
        total_pages = 1
    if page > total_pages:
        page = total_pages
    if page < 1:
        page = 1
    start = (page - 1) * per_page
    end = start + per_page
    return items[start:end], {
        "total_recipes": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages
    }

def _normalize_diet_lower_in_records(records):
    """Normalize diet type to lowercase in records"""
    out = []
    for r in records:
        rr = dict(r)
        if 'Diet_type' in rr and rr['Diet_type'] is not None:
            rr['Diet_type'] = str(rr['Diet_type']).strip().lower()
        out.append(rr)
    return out



# Blob trigger commented out for local development (requires Azurite)

@app.function_name(name="HealthCheck")
@app.route(route="health", methods=["GET"])
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Simple health check endpoint"""
    import sys
    return func.HttpResponse(
        json.dumps({
            "status": "healthy",
            "message": "Function app is running",
            "python_version": sys.version,
            "timestamp": str(datetime.utcnow())
        }),
        status_code=200,
        mimetype="application/json"
    )

@app.function_name(name="Register")
@app.route(route="auth/register", methods=["POST"])
def register(req: func.HttpRequest) -> func.HttpResponse:
    """
    User registration endpoint.
    Expects: { "email": "user@example.com", "password": "Password123", "full_name": "John Doe" }
    """
    logging.info("Register endpoint triggered")

    try:
        # Try to get JSON from request body
        body_bytes = req.get_body()
        logging.info(f"Received body (first 100 chars): {body_bytes[:100]}")
        body = json.loads(body_bytes.decode('utf-8'))
        logging.info(f"Parsed JSON successfully: {list(body.keys())}")
    except Exception as e:
        logging.error(f"JSON parsing error: {type(e).__name__}: {e}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        return func.HttpResponse(
            json.dumps({"error": f"Invalid JSON: {str(e)}"}),
            status_code=400,
            mimetype="application/json"
        )

    email = body.get('email', '').strip()
    password = body.get('password', '')
    full_name = body.get('full_name', '').strip()

    # Validate input
    if not email or not password:
        return func.HttpResponse(
            json.dumps({"error": "Email and password are required"}),
            status_code=400,
            mimetype="application/json"
        )

    if not validate_email(email):
        return func.HttpResponse(
            json.dumps({"error": "Invalid email format"}),
            status_code=400,
            mimetype="application/json"
        )

    is_valid, error_msg = validate_password_strength(password)
    if not is_valid:
        return func.HttpResponse(
            json.dumps({"error": error_msg}),
            status_code=400,
            mimetype="application/json"
        )

    # Check if user already exists
    existing_user = get_user_by_email(email)
    if existing_user:
        return func.HttpResponse(
            json.dumps({"error": "User with this email already exists"}),
            status_code=409,
            mimetype="application/json"
        )

    # Hash password and create user
    auth_mgr = AuthManager()
    password_hash = auth_mgr.hash_password(password)

    try:
        logging.info(f"Attempting to create user: {email}")
        user_id = create_user(email, password_hash, full_name)
        logging.info(f"User created with ID: {user_id}")

        # Generate JWT token
        token = auth_mgr.generate_jwt_token(user_id, email)
        logging.info("JWT token generated")

        # Create session
        token_hash = auth_mgr.hash_token(token)
        expires_at = datetime.utcnow() + timedelta(hours=auth_mgr.jwt_expiration_hours)
        create_session(user_id, token_hash, expires_at)
        logging.info("Session created")

        return func.HttpResponse(
            json.dumps({
                "message": "User registered successfully",
                "token": token,
                "user": {
                    "user_id": user_id,
                    "email": email,
                    "full_name": full_name
                }
            }),
            status_code=201,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"Registration error: {type(e).__name__}: {e}")
        import traceback
        logging.error(f"Full traceback: {traceback.format_exc()}")
        return func.HttpResponse(
            json.dumps({"error": "Registration failed", "details": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


@app.function_name(name="Login")
@app.route(route="auth/login", methods=["POST"])
def login(req: func.HttpRequest) -> func.HttpResponse:
    """
    User login endpoint.
    Expects: { "email": "user@example.com", "password": "Password123" }
    """
    logging.info("Login endpoint triggered")

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON"}),
            status_code=400,
            mimetype="application/json"
        )

    email = body.get('email', '').strip()
    password = body.get('password', '')

    if not email or not password:
        return func.HttpResponse(
            json.dumps({"error": "Email and password are required"}),
            status_code=400,
            mimetype="application/json"
        )

    # Get user from database
    user = get_user_by_email(email)
    if not user:
        return func.HttpResponse(
            json.dumps({"error": "Invalid email or password"}),
            status_code=401,
            mimetype="application/json"
        )

    # Verify password
    auth_mgr = AuthManager()
    if not user.get('password_hash') or not auth_mgr.verify_password(password, user['password_hash']):
        return func.HttpResponse(
            json.dumps({"error": "Invalid email or password"}),
            status_code=401,
            mimetype="application/json"
        )

    # Generate JWT token
    token = auth_mgr.generate_jwt_token(user['user_id'], email)

    # Create session
    token_hash = auth_mgr.hash_token(token)
    expires_at = datetime.utcnow() + timedelta(hours=auth_mgr.jwt_expiration_hours)
    create_session(user['user_id'], token_hash, expires_at)

    return func.HttpResponse(
        json.dumps({
            "message": "Login successful",
            "token": token,
            "user": {
                "user_id": user['user_id'],
                "email": user['email'],
                "full_name": user.get('full_name')
            }
        }),
        status_code=200,
        mimetype="application/json"
    )


@app.function_name(name="GitHubOAuthLogin")
@app.route(route="auth/github", methods=["GET"])
def github_oauth_login(req: func.HttpRequest) -> func.HttpResponse:
    """
    Initiates GitHub OAuth flow.
    Redirects user to GitHub authorization page.
    """
    logging.info("GitHub OAuth login initiated")

    github = GitHubOAuth()
    auth_url = github.get_authorization_url()

    # Redirect directly to GitHub authorization page
    return func.HttpResponse(
        status_code=302,
        headers={'Location': auth_url}
    )


@app.function_name(name="GitHubOAuthCallback")
@app.route(route="auth/github/callback", methods=["GET", "POST"])
def github_oauth_callback(req: func.HttpRequest) -> func.HttpResponse:
    """
    GitHub OAuth callback endpoint.
    Receives authorization code and exchanges it for user info.
    """
    logging.info("GitHub OAuth callback triggered")

    code = req.params.get('code')

    if not code:
        return func.HttpResponse(
            json.dumps({"error": "Authorization code not provided"}),
            status_code=400,
            mimetype="application/json"
        )

    github = GitHubOAuth()

    # Exchange code for access token
    access_token = github.exchange_code_for_token(code)
    if not access_token:
        return func.HttpResponse(
            json.dumps({"error": "Failed to obtain access token"}),
            status_code=500,
            mimetype="application/json"
        )

    # Get user info from GitHub
    user_info = github.get_user_info(access_token)
    if not user_info:
        return func.HttpResponse(
            json.dumps({"error": "Failed to obtain user information"}),
            status_code=500,
            mimetype="application/json"
        )

    # Get user email
    email = github.get_user_email(access_token)
    if not email:
        # Fallback to user_info email (might be null if private)
        email = user_info.get('email')

    if not email:
        # Final fallback: use GitHub's noreply email format
        github_user_id = str(user_info['id'])
        github_username = user_info.get('login')
        email = f"{github_user_id}+{github_username}@users.noreply.github.com"
        logging.info(f"Using GitHub noreply email: {email}")

    github_user_id = str(user_info['id'])
    github_username = user_info.get('login')
    full_name = user_info.get('name') or github_username

    # Check if user exists with this OAuth provider
    user = get_user_by_oauth('github', github_user_id)

    if not user:
        # Check if user exists with this email
        user = get_user_by_email(email)

        if user:
            # Link GitHub to existing user
            create_oauth_provider(user['user_id'], 'github', github_user_id, github_username)
        else:
            # Create new user
            user_id = create_user(email, None, full_name)  # No password for OAuth users
            create_oauth_provider(user_id, 'github', github_user_id, github_username)
            user = get_user_by_id(user_id)

    # Generate JWT token
    auth_mgr = AuthManager()
    token = auth_mgr.generate_jwt_token(user['user_id'], user['email'])

    # Create session
    token_hash = auth_mgr.hash_token(token)
    expires_at = datetime.utcnow() + timedelta(hours=auth_mgr.jwt_expiration_hours)
    create_session(user['user_id'], token_hash, expires_at)

    # Redirect to frontend with token and user info
    # For local development, redirect to localhost:8000
    # For production, this should be configured via environment variable
    frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:8000')
    redirect_url = f"{frontend_url}/index.html?token={token}&user_id={user['user_id']}&email={user['email']}&full_name={user.get('full_name', '')}"

    return func.HttpResponse(
        status_code=302,
        headers={'Location': redirect_url}
    )


@app.function_name(name="GetProfile")
@app.route(route="auth/profile", methods=["GET"])
@require_auth
def get_profile(req: func.HttpRequest) -> func.HttpResponse:
    """
    Get current user profile (protected endpoint).
    Requires: Authorization: Bearer <token>
    """
    logging.info("GetProfile endpoint triggered")

    user_id = req.context.user_id
    user = get_user_by_id(user_id)

    if not user:
        return func.HttpResponse(
            json.dumps({"error": "User not found"}),
            status_code=404,
            mimetype="application/json"
        )

    return func.HttpResponse(
        json.dumps({
            "user_id": user['user_id'],
            "email": user['email'],
            "full_name": user.get('full_name'),
            "created_at": str(user.get('created_at'))
        }),
        status_code=200,
        mimetype="application/json"
    )


# ---------- Phase 3: Updated API Endpoints (with caching and auth) ----------

@app.function_name(name="GetInsights")
@app.route(route="GetInsights", methods=["GET", "POST"])
@require_auth
def get_insights(req: func.HttpRequest) -> func.HttpResponse:
    """
    Get nutritional insights with caching.
    Now requires authentication.
    """
    logging.info("GetInsights triggered (Phase 3 with caching)")

    params = _parse_request(req)
    diet_filter = params['diet']
    search_term = params['search']
    page = params['page']
    per_page = params['per_page']

    # Try to get from cache first (only if no search filter)
    cached_insights = get_insights_cache(diet_filter) if not search_term else None

    if cached_insights:
        logging.info(f"Insights cache HIT for diet={diet_filter}")
        # Get clean data for pagination
        df = get_clean_data()
        df_filtered = _apply_diet_filter(df, diet_filter)
        df_filtered = _apply_search_filter(df_filtered, search_term)

        numeric_cols = [c for c in ['Protein(g)', 'Carbs(g)', 'Fat(g)'] if c in df_filtered.columns]
        sample_cols = ['Diet_type', 'Recipe_name', 'Cuisine_type'] + numeric_cols
        available_cols = [c for c in sample_cols if c in df_filtered.columns]
        recipes_all = df_filtered[available_cols].reset_index(drop=True).to_dict(orient='records')
        recipes_all = _normalize_diet_lower_in_records(recipes_all)

        recipes_page, pagination = _paginate(recipes_all, page, per_page)

        payload = {
            "averages": cached_insights['averages'],
            "correlation": cached_insights['correlation'],
            "recipes": recipes_page,
            "pagination": pagination,
            "requested": {
                "diet": (str(diet_filter).strip().lower() if diet_filter else None),
                "search": search_term
            },
            "cached": True
        }

        return func.HttpResponse(json.dumps(payload, ensure_ascii=False, default=str), mimetype="application/json")

    # Cache MISS - calculate and cache
    logging.info(f"Insights cache MISS for diet={diet_filter}")

    try:
        df = get_clean_data()
    except Exception as ex:
        logging.exception("Error reading clean data:")
        return func.HttpResponse(f"Data read error: {ex}", status_code=500)

    if 'Diet_type' not in df.columns:
        return func.HttpResponse(json.dumps({"error": "Dataset missing 'Diet_type' column"}), status_code=500, mimetype="application/json")

    df_filtered = _apply_diet_filter(df, diet_filter)
    df_filtered = _apply_search_filter(df_filtered, search_term)
    numeric_cols = [c for c in ['Protein(g)', 'Carbs(g)', 'Fat(g)'] if c in df_filtered.columns]

    # Calculate averages
    if not df_filtered.empty and numeric_cols:
        avg = df_filtered.groupby('Diet_type')[numeric_cols].mean().reset_index()
    else:
        avg = pd.DataFrame()

    # Calculate correlation
    corr = None
    try:
        if len(numeric_cols) > 1 and not avg.empty and 'Diet_type' in avg.columns:
            pivot = avg.set_index('Diet_type')[numeric_cols]
            corr_df = pivot.corr()
            corr_df = corr_df.round(3)
            matrix = corr_df.values.tolist()
            for i in range(len(matrix)):
                for j in range(len(matrix[i])):
                    v = matrix[i][j]
                    if isinstance(v, (float, np.floating)):
                        if math.isnan(v) or math.isinf(v):
                            matrix[i][j] = None
            corr = {
                "labels": corr_df.columns.tolist(),
                "matrix": matrix
            }
    except Exception:
        corr = None

    # Cache the results
    if not avg.empty:
        corr_df_for_cache = pd.DataFrame(corr['matrix'], columns=corr['labels'], index=corr['labels']) if corr else pd.DataFrame()
        set_insights_cache(diet_filter, avg, corr_df_for_cache)

    # Prepare recipes for pagination
    sample_cols = ['Diet_type', 'Recipe_name', 'Cuisine_type'] + numeric_cols
    available_cols = [c for c in sample_cols if c in df_filtered.columns]
    recipes_all = df_filtered[available_cols].reset_index(drop=True).to_dict(orient='records')
    recipes_all = _normalize_diet_lower_in_records(recipes_all)

    recipes_page, pagination = _paginate(recipes_all, page, per_page)

    if not avg.empty and 'Diet_type' in avg.columns:
        avg_records = avg.to_dict(orient='records')
        for a in avg_records:
            a['Diet_type'] = str(a.get('Diet_type','')).strip().lower()
    else:
        avg_records = []

    payload = {
        "averages": avg_records,
        "correlation": corr,
        "recipes": recipes_page,
        "pagination": pagination,
        "requested": {
            "diet": (str(diet_filter).strip().lower() if diet_filter else None),
            "search": search_term
        },
        "cached": False
    }

    return func.HttpResponse(json.dumps(payload, ensure_ascii=False, default=str), mimetype="application/json")


@app.function_name(name="GetRecipes")
@app.route(route="GetRecipes", methods=["GET", "POST"])
@require_auth
def get_recipes(req: func.HttpRequest) -> func.HttpResponse:
    """
    Get recipes with pagination (using cached clean data).
    Now requires authentication.
    """
    logging.info("GetRecipes triggered (Phase 3 with caching)")

    params = _parse_request(req)
    diet_filter = params['diet']
    search_term = params['search']
    page = params['page']
    per_page = params['per_page']

    try:
        df = get_clean_data()
    except Exception as ex:
        logging.exception("Error reading clean data:")
        return func.HttpResponse(f"Data read error: {ex}", status_code=500)

    if 'Diet_type' not in df.columns:
        return func.HttpResponse(json.dumps({"error": "Dataset missing 'Diet_type' column"}), status_code=500, mimetype="application/json")

    df_filtered = _apply_diet_filter(df, diet_filter)
    df_filtered = _apply_search_filter(df_filtered, search_term)
    numeric_cols = [c for c in ['Protein(g)', 'Carbs(g)', 'Fat(g)'] if c in df_filtered.columns]

    sample_cols = ['Diet_type', 'Recipe_name', 'Cuisine_type'] + numeric_cols
    available_cols = [c for c in sample_cols if c in df_filtered.columns]
    recipes_all = df_filtered[available_cols].reset_index(drop=True).to_dict(orient='records')
    recipes_all = _normalize_diet_lower_in_records(recipes_all)

    recipes_page, pagination = _paginate(recipes_all, page, per_page)

    payload = {
        "recipes": recipes_page,
        "pagination": pagination,
        "requested": {
            "diet": (str(diet_filter).strip().lower() if diet_filter else None),
            "search": search_term
        }
    }
    return func.HttpResponse(json.dumps(payload, ensure_ascii=False, default=str), mimetype="application/json")


@app.function_name(name="GetClusters")
@app.route(route="GetClusters", methods=["GET", "POST"])
@require_auth
def get_clusters(req: func.HttpRequest) -> func.HttpResponse:
    """
    Get diet clusters with caching.
    Now requires authentication.
    """
    logging.info("GetClusters triggered (Phase 3 with caching)")

    params = _parse_request(req)
    diet_filter = params['diet']
    search_term = params['search']

    # Try cache first (only if no search filter)
    cached_clusters = get_clusters_cache(diet_filter) if not search_term else None

    if cached_clusters is not None:
        logging.info(f"Clusters cache HIT for diet={diet_filter}")
        clusters = cached_clusters.to_dict(orient='records')
        for c in clusters:
            if 'Diet_type' in c:
                c['diet_type'] = str(c['Diet_type']).strip().lower()
                del c['Diet_type']

        payload = {
            "clusters": clusters,
            "requested": {
                "diet": (str(diet_filter).strip().lower() if diet_filter else None),
                "search": search_term
            },
            "cached": True
        }
        return func.HttpResponse(json.dumps(payload, ensure_ascii=False, default=str), mimetype="application/json")

    # Cache MISS - calculate and cache
    logging.info(f"Clusters cache MISS for diet={diet_filter}")

    try:
        df = get_clean_data()
    except Exception as ex:
        logging.exception("Error reading clean data:")
        return func.HttpResponse(f"Data read error: {ex}", status_code=500)

    if 'Diet_type' not in df.columns:
        return func.HttpResponse(json.dumps({"error": "Dataset missing 'Diet_type' column"}), status_code=500, mimetype="application/json")

    df_filtered = _apply_diet_filter(df, diet_filter)
    df_filtered = _apply_search_filter(df_filtered, search_term)
    numeric_cols = [c for c in ['Protein(g)', 'Carbs(g)', 'Fat(g)'] if c in df_filtered.columns]

    clusters = []
    if not df_filtered.empty and numeric_cols:
        grp = df_filtered.groupby('Diet_type')[numeric_cols].mean().reset_index()

        # Cache the results
        set_clusters_cache(diet_filter, grp)

        for _, row in grp.iterrows():
            c = {col: row[col] for col in numeric_cols}
            c['diet_type'] = str(row['Diet_type']).strip().lower()
            clusters.append(c)

    payload = {
        "clusters": clusters,
        "requested": {
            "diet": (str(diet_filter).strip().lower() if diet_filter else None),
            "search": search_term
        },
        "cached": False
    }
    return func.HttpResponse(json.dumps(payload, ensure_ascii=False, default=str), mimetype="application/json")

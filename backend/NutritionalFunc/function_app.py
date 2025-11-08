# function_app.py
import azure.functions as func
import logging, os, io, json, math
import pandas as pd
import numpy as np
from azure.storage.blob import BlobServiceClient
from math import ceil

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# ---------- helpers ----------
def _read_blob_csv(conn_str, container_name="datasets", blob_name="All_Diets.csv"):
    bsc = BlobServiceClient.from_connection_string(conn_str)
    container = bsc.get_container_client(container_name)
    blob = container.get_blob_client(blob_name)
    data = blob.download_blob().readall()
    df = pd.read_csv(io.BytesIO(data))
    return df

def _parse_request(req: func.HttpRequest):
    params = {}
    params['diet'] = req.params.get('diet')
    page = req.params.get('page')
    per_page = req.params.get('per_page')

    try:
        body = req.get_json()
    except ValueError:
        body = {}

    if not params['diet']:
        params['diet'] = body.get('diet')
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
    return params

def _ensure_numeric(df, cols=('Protein(g)','Carbs(g)','Fat(g)')):
    numeric_cols = []
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors='coerce')
            numeric_cols.append(c)
    if numeric_cols:
        df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].mean())
    return numeric_cols

def _apply_diet_filter(df, diet_filter):
    df_filtered = df.copy()
    if diet_filter:
        df_filtered = df_filtered[
            df_filtered['Diet_type'].astype(str).str.strip().str.lower()
            == str(diet_filter).strip().lower()
        ]
    return df_filtered

def _paginate(items, page, per_page):
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
    out = []
    for r in records:
        rr = dict(r)
        if 'Diet_type' in rr and rr['Diet_type'] is not None:
            rr['Diet_type'] = str(rr['Diet_type']).strip().lower()
        out.append(rr)
    return out

# ---------- endpoints ----------
@app.function_name(name="GetInsights")
@app.route(route="GetInsights", methods=["GET", "POST"])
def get_insights(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("GetInsights triggered")
    conn_str = os.getenv("AzureWebJobsStorage")
    if not conn_str:
        return func.HttpResponse("AzureWebJobsStorage not configured", status_code=500)
    try:
        df = _read_blob_csv(conn_str)
    except Exception as ex:
        logging.exception("Error reading blob:")
        return func.HttpResponse(f"Blob read error: {ex}", status_code=500)

    df.columns = [c.strip() for c in df.columns]

    params = _parse_request(req)
    diet_filter = params['diet']
    page = params['page']
    per_page = params['per_page']

    numeric_cols = _ensure_numeric(df)

    if 'Diet_type' not in df.columns:
        return func.HttpResponse(json.dumps({"error": "Dataset missing 'Diet_type' column"}), status_code=500, mimetype="application/json")
    df_filtered = _apply_diet_filter(df, diet_filter)

    if not df_filtered.empty and numeric_cols:
        avg = df_filtered.groupby('Diet_type')[numeric_cols].mean().reset_index()
    elif 'Diet_type' in df_filtered.columns and not df_filtered.empty:
        avg = df_filtered.groupby('Diet_type').size().reset_index(name='count')
    else:
        avg = pd.DataFrame()

    # build correlation matrix safely (replace NaN/inf with None)
    corr = None
    try:
        if len(numeric_cols) > 1 and not avg.empty and 'Diet_type' in avg.columns:
            pivot = avg.set_index('Diet_type')[numeric_cols]
            corr_df = pivot.corr()
            # round for readability
            corr_df = corr_df.round(3)
            matrix = corr_df.values.tolist()
            # replace nan/inf with None so json.dumps produces valid JSON (null)
            for i in range(len(matrix)):
                for j in range(len(matrix[i])):
                    v = matrix[i][j]
                    if isinstance(v, (float, np.floating)):
                        if math.isnan(v) or math.isinf(v):
                            matrix[i][j] = None
                    elif v is None:
                        matrix[i][j] = None
            corr = {
                "labels": corr_df.columns.tolist(),
                "matrix": matrix
            }
    except Exception:
        corr = None

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
            "diet": (str(diet_filter).strip().lower() if diet_filter else None)
        }
    }

    return func.HttpResponse(json.dumps(payload, ensure_ascii=False, default=str), mimetype="application/json")

@app.function_name(name="GetRecipes")
@app.route(route="GetRecipes", methods=["GET", "POST"])
def get_recipes(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("GetRecipes triggered")
    conn_str = os.getenv("AzureWebJobsStorage")
    if not conn_str:
        return func.HttpResponse("AzureWebJobsStorage not configured", status_code=500)
    try:
        df = _read_blob_csv(conn_str)
    except Exception as ex:
        logging.exception("Error reading blob:")
        return func.HttpResponse(f"Blob read error: {ex}", status_code=500)

    df.columns = [c.strip() for c in df.columns]
    params = _parse_request(req)
    diet_filter = params['diet']
    page = params['page']
    per_page = params['per_page']

    numeric_cols = _ensure_numeric(df)
    if 'Diet_type' not in df.columns:
        return func.HttpResponse(json.dumps({"error": "Dataset missing 'Diet_type' column"}), status_code=500, mimetype="application/json")

    df_filtered = _apply_diet_filter(df, diet_filter)

    sample_cols = ['Diet_type', 'Recipe_name', 'Cuisine_type'] + numeric_cols
    available_cols = [c for c in sample_cols if c in df_filtered.columns]
    recipes_all = df_filtered[available_cols].reset_index(drop=True).to_dict(orient='records')
    recipes_all = _normalize_diet_lower_in_records(recipes_all)

    recipes_page, pagination = _paginate(recipes_all, page, per_page)

    payload = {
        "recipes": recipes_page,
        "pagination": pagination,
        "requested": {
            "diet": (str(diet_filter).strip().lower() if diet_filter else None)
        }
    }
    return func.HttpResponse(json.dumps(payload, ensure_ascii=False, default=str), mimetype="application/json")

@app.function_name(name="GetClusters")
@app.route(route="GetClusters", methods=["GET", "POST"])
def get_clusters(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("GetClusters triggered")
    conn_str = os.getenv("AzureWebJobsStorage")
    if not conn_str:
        return func.HttpResponse("AzureWebJobsStorage not configured", status_code=500)
    try:
        df = _read_blob_csv(conn_str)
    except Exception as ex:
        logging.exception("Error reading blob:")
        return func.HttpResponse(f"Blob read error: {ex}", status_code=500)

    df.columns = [c.strip() for c in df.columns]
    params = _parse_request(req)
    diet_filter = params['diet']

    numeric_cols = _ensure_numeric(df)
    if 'Diet_type' not in df.columns:
        return func.HttpResponse(json.dumps({"error": "Dataset missing 'Diet_type' column"}), status_code=500, mimetype="application/json")

    df_filtered = _apply_diet_filter(df, diet_filter)

    clusters = []
    if not df_filtered.empty and numeric_cols:
        grp = df_filtered.groupby('Diet_type')[numeric_cols].mean().reset_index()
        for _, row in grp.iterrows():
            c = {col: row[col] for col in numeric_cols}
            c['diet_type'] = str(row['Diet_type']).strip().lower()
            clusters.append(c)

    payload = {
        "clusters": clusters,
        "requested": {
            "diet": (str(diet_filter).strip().lower() if diet_filter else None)
        }
    }
    return func.HttpResponse(json.dumps(payload, ensure_ascii=False, default=str), mimetype="application/json")

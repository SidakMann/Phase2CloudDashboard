"""
Caching utilities using Azure Blob Storage with CSV files
Implements caching strategy for Phase 3 requirements
"""
import pandas as pd
import numpy as np
import logging
import os
import io
from datetime import datetime
from azure.storage.blob import BlobServiceClient, ContentSettings
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class CacheManager:
    """Manages CSV-based caching in Azure Blob Storage"""

    def __init__(self):
        self.connection_string = os.environ.get('BLOB_STORAGE_CONNECTION_STRING') or os.environ.get('AzureWebJobsStorage')
        self.cache_container = os.environ.get('BLOB_CACHE_CONTAINER_NAME', 'cache')
        self.blob_service_client = BlobServiceClient.from_connection_string(self.connection_string)

        # Ensure cache container exists
        try:
            self.blob_service_client.get_container_client(self.cache_container).get_container_properties()
        except Exception:
            # Create container if it doesn't exist
            try:
                self.blob_service_client.create_container(self.cache_container)
                logger.info(f"Created cache container: {self.cache_container}")
            except Exception as e:
                logger.warning(f"Could not create cache container: {e}")

    def get_blob_client(self, blob_name: str):
        """Get a blob client for the cache container"""
        return self.blob_service_client.get_blob_client(
            container=self.cache_container,
            blob=blob_name
        )

    def read_cache(self, cache_key: str) -> Optional[pd.DataFrame]:
        """Read cached data from blob storage"""
        try:
            blob_client = self.get_blob_client(f"{cache_key}.csv")
            blob_data = blob_client.download_blob()
            csv_data = blob_data.readall()
            df = pd.read_csv(io.BytesIO(csv_data))
            logger.info(f"Cache HIT: {cache_key}")
            return df
        except Exception as e:
            logger.info(f"Cache MISS: {cache_key} - {e}")
            return None

    def write_cache(self, cache_key: str, df: pd.DataFrame, overwrite: bool = True):
        """Write DataFrame to cache as CSV"""
        try:
            blob_client = self.get_blob_client(f"{cache_key}.csv")
            csv_buffer = io.BytesIO()
            df.to_csv(csv_buffer, index=False)
            csv_buffer.seek(0)

            blob_client.upload_blob(
                csv_buffer,
                overwrite=overwrite,
                content_settings=ContentSettings(content_type='text/csv')
            )
            logger.info(f"Cache WRITE: {cache_key} ({len(df)} rows)")
        except Exception as e:
            logger.error(f"Cache write error for {cache_key}: {e}")
            raise

    def cache_exists(self, cache_key: str) -> bool:
        """Check if cache exists"""
        try:
            blob_client = self.get_blob_client(f"{cache_key}.csv")
            blob_client.get_blob_properties()
            return True
        except Exception:
            return False

    def get_cache_timestamp(self, cache_key: str) -> Optional[datetime]:
        """Get last modified timestamp of cache"""
        try:
            blob_client = self.get_blob_client(f"{cache_key}.csv")
            properties = blob_client.get_blob_properties()
            return properties.last_modified
        except Exception:
            return None

    def invalidate_cache(self, cache_key: str):
        """Delete cache"""
        try:
            blob_client = self.get_blob_client(f"{cache_key}.csv")
            blob_client.delete_blob()
            logger.info(f"Cache INVALIDATED: {cache_key}")
        except Exception as e:
            logger.warning(f"Cache invalidation error for {cache_key}: {e}")


# Specific cache functions for Phase 3 requirements

def get_clean_data() -> pd.DataFrame:
    """
    Get cleaned dataset from cache.
    This is the primary function for retrieving processed data.
    """
    cache_mgr = CacheManager()
    df = cache_mgr.read_cache('cleaned_diets')

    if df is None:
        logger.warning("Clean data cache not found. Triggering data cleaning...")
        # Fallback: trigger cleaning if cache doesn't exist
        from function_app import _read_blob_csv, _ensure_numeric
        df = _read_blob_csv()
        _ensure_numeric(df)  # Modifies df in place, returns list of columns
        cache_mgr.write_cache('cleaned_diets', df)

    return df


def get_insights_cache(diet_filter: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Get cached insights results (averages + correlation matrix).
    Returns None if cache doesn't exist or is invalid.
    """
    cache_mgr = CacheManager()
    cache_key = f"insights_{diet_filter}" if diet_filter else "insights_all"

    # Try to read both average and correlation caches
    try:
        avg_df = cache_mgr.read_cache(f"{cache_key}_averages")
        corr_df = cache_mgr.read_cache(f"{cache_key}_correlation")

        if avg_df is not None and corr_df is not None:
            return {
                'averages': avg_df.to_dict('records'),
                'correlation': corr_df.to_dict('records')
            }
    except Exception as e:
        logger.error(f"Error reading insights cache: {e}")

    return None


def set_insights_cache(diet_filter: Optional[str], averages_df: pd.DataFrame, correlation_df: pd.DataFrame):
    """
    Cache insights results (averages + correlation matrix).
    """
    cache_mgr = CacheManager()
    cache_key = f"insights_{diet_filter}" if diet_filter else "insights_all"

    try:
        cache_mgr.write_cache(f"{cache_key}_averages", averages_df)
        cache_mgr.write_cache(f"{cache_key}_correlation", correlation_df)
        logger.info(f"Insights cached: {cache_key}")
    except Exception as e:
        logger.error(f"Error caching insights: {e}")


def get_clusters_cache(diet_filter: Optional[str] = None) -> Optional[pd.DataFrame]:
    """Get cached cluster results"""
    cache_mgr = CacheManager()
    cache_key = f"clusters_{diet_filter}" if diet_filter else "clusters_all"
    return cache_mgr.read_cache(cache_key)


def set_clusters_cache(diet_filter: Optional[str], clusters_df: pd.DataFrame):
    """Cache cluster results"""
    cache_mgr = CacheManager()
    cache_key = f"clusters_{diet_filter}" if diet_filter else "clusters_all"
    cache_mgr.write_cache(cache_key, clusters_df)
    logger.info(f"Clusters cached: {cache_key}")


def invalidate_all_caches():
    """
    Invalidate all cached results.
    Called when source data (All_Diets.csv) changes.
    """
    cache_mgr = CacheManager()
    cache_keys = [
        'cleaned_diets',
        'insights_all_averages',
        'insights_all_correlation',
        'clusters_all'
    ]

    # Also invalidate diet-specific caches
    common_diets = ['mediterranean', 'dash', 'vegan', 'keto', 'paleo']
    for diet in common_diets:
        cache_keys.extend([
            f'insights_{diet}_averages',
            f'insights_{diet}_correlation',
            f'clusters_{diet}'
        ])

    for key in cache_keys:
        cache_mgr.invalidate_cache(key)

    logger.info("All caches invalidated")

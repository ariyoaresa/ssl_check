use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A cached certificate fingerprint entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub fingerprint_sha256: String,
    pub last_checked: DateTime<Utc>,
    pub domain: String,
}

/// Returns the path to the cache file: ~/.sslcheck/cache.json
fn cache_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".sslcheck").join("cache.json"))
}

/// Loads the fingerprint cache from disk.
pub fn load_cache() -> Result<HashMap<String, CacheEntry>, String> {
    let path = cache_path().ok_or_else(|| "Cannot determine home directory".to_string())?;

    if !path.exists() {
        return Ok(HashMap::new());
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read cache: {}", e))?;

    serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse cache: {}", e))
}

/// Saves the fingerprint cache to disk.
pub fn save_cache(cache: &HashMap<String, CacheEntry>) -> Result<(), String> {
    let path = cache_path().ok_or_else(|| "Cannot determine home directory".to_string())?;

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create cache directory: {}", e))?;
    }

    let content = serde_json::to_string_pretty(cache)
        .map_err(|e| format!("Failed to serialize cache: {}", e))?;

    std::fs::write(&path, content)
        .map_err(|e| format!("Failed to write cache: {}", e))?;

    Ok(())
}

/// Updates a single domain entry in the cache.
pub fn update_cache(domain: &str, fingerprint: &str) -> Result<(), String> {
    let mut cache = load_cache().unwrap_or_default();

    cache.insert(
        domain.to_string(),
        CacheEntry {
            fingerprint_sha256: fingerprint.to_string(),
            last_checked: Utc::now(),
            domain: domain.to_string(),
        },
    );

    save_cache(&cache)
}

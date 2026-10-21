//! OpenRouter Management API client for short-lived runtime keys.

use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::error::ServerError;

#[derive(Clone)]
pub struct CreatedKey {
    pub key: String,
    pub hash: String,
}

#[derive(Debug, Clone, Default)]
pub struct KeyUsage {
    pub usage_usd: f64,
    pub disabled: bool,
}

pub struct OpenRouterProvisioner {
    http: reqwest::Client,
    management_key: String,
    base: String,
}

#[derive(Deserialize)]
struct CreateKeyEnvelope {
    key: String,
    data: KeyData,
}

#[derive(Deserialize)]
struct GetKeyEnvelope {
    data: KeyData,
}

#[derive(Deserialize)]
struct ListKeysEnvelope {
    data: Vec<KeyData>,
}

#[derive(Deserialize, Default)]
struct KeyData {
    #[serde(default)]
    hash: String,
    #[serde(default)]
    usage: Option<f64>,
    #[serde(default)]
    byok_usage: Option<f64>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    limit: Option<f64>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    include_byok_in_limit: bool,
    #[serde(default)]
    disabled: bool,
}

impl OpenRouterProvisioner {
    pub fn new(management_key: String, base: String) -> Result<Self, ServerError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| {
                ServerError::Internal(format!("failed to build OpenRouter client: {error}"))
            })?;
        Ok(Self {
            http,
            management_key,
            base: base.trim_end_matches('/').to_string(),
        })
    }

    pub fn inference_base(&self) -> String {
        format!("{}/v1", self.base)
    }

    fn keys_url(&self) -> String {
        format!("{}/v1/keys", self.base)
    }

    fn key_url(&self, hash: &str) -> String {
        format!("{}/v1/keys/{hash}", self.base)
    }

    pub async fn create_key(
        &self,
        name: &str,
        limit_usd: f64,
        expires_at: u64,
    ) -> Result<CreatedKey, ServerError> {
        let expires_at_iso = unix_to_iso8601(expires_at);
        let body = json!({
            "name": name,
            "limit": limit_usd,
            "expires_at": expires_at_iso,
            // Prevent an account-level BYOK configuration from bypassing this
            // lease's zkAPI spending bound.
            "include_byok_in_limit": true,
        });
        let response = self
            .http
            .post(self.keys_url())
            .bearer_auth(&self.management_key)
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                ServerError::Internal(format!("OpenRouter key creation failed: {error}"))
            })?;
        let status = response.status();
        let text = response.text().await.map_err(|error| {
            ServerError::Internal(format!("OpenRouter key response failed: {error}"))
        })?;
        if !status.is_success() {
            return Err(ServerError::Internal(format!(
                "OpenRouter key creation returned {status}: {}",
                truncate(&text, 300)
            )));
        }
        let envelope: CreateKeyEnvelope = serde_json::from_str(&text).map_err(|error| {
            ServerError::Internal(format!("invalid OpenRouter key response: {error}"))
        })?;
        if envelope.key.is_empty() || envelope.data.hash.is_empty() {
            return Err(ServerError::Internal(
                "OpenRouter returned an incomplete key response".to_string(),
            ));
        }
        let limit_matches = envelope
            .data
            .limit
            .is_some_and(|limit| (limit - limit_usd).abs() <= f64::EPSILON.max(limit_usd * 1e-9));
        let expiry_matches = envelope
            .data
            .expires_at
            .as_deref()
            .is_some_and(|actual| openrouter_expiry_matches(actual, &expires_at_iso));
        if !limit_matches || !expiry_matches || !envelope.data.include_byok_in_limit {
            let hash = envelope.data.hash.clone();
            let _ = self.delete_key(&hash).await;
            return Err(ServerError::Internal(
                "OpenRouter did not apply the requested key limit and expiry".to_string(),
            ));
        }
        Ok(CreatedKey {
            key: envelope.key,
            hash: envelope.data.hash,
        })
    }

    pub async fn get_key_usage(&self, hash: &str) -> Result<KeyUsage, ServerError> {
        let response = self
            .http
            .get(self.key_url(hash))
            .bearer_auth(&self.management_key)
            .send()
            .await
            .map_err(|error| {
                ServerError::Internal(format!("OpenRouter usage read failed: {error}"))
            })?;
        let status = response.status();
        let text = response.text().await.map_err(|error| {
            ServerError::Internal(format!("OpenRouter usage response failed: {error}"))
        })?;
        if !status.is_success() {
            return Err(ServerError::Internal(format!(
                "OpenRouter usage read returned {status}: {}",
                truncate(&text, 300)
            )));
        }
        let envelope: GetKeyEnvelope = serde_json::from_str(&text).map_err(|error| {
            ServerError::Internal(format!("invalid OpenRouter usage response: {error}"))
        })?;
        let usage = envelope
            .data
            .usage
            .filter(|usage| usage.is_finite() && *usage >= 0.0);
        let byok_usage = envelope
            .data
            .byok_usage
            .filter(|usage| usage.is_finite() && *usage >= 0.0);
        let usage_usd = match (usage, byok_usage) {
            (Some(usage), Some(byok_usage)) if (usage + byok_usage).is_finite() => {
                usage + byok_usage
            }
            _ => {
                return Err(ServerError::Internal(
                    "OpenRouter returned incomplete or invalid usage".to_string(),
                ))
            }
        };
        Ok(KeyUsage {
            // `include_byok_in_limit` is true for these keys, and OpenRouter
            // reports BYOK usage separately from ordinary credit usage.
            usage_usd,
            disabled: envelope.data.disabled,
        })
    }

    /// Stop new spending while retaining the usage record for settlement.
    pub async fn disable_key(&self, hash: &str) -> Result<(), ServerError> {
        let response = self
            .http
            .patch(self.key_url(hash))
            .bearer_auth(&self.management_key)
            .json(&json!({ "disabled": true }))
            .send()
            .await
            .map_err(|error| {
                ServerError::Internal(format!("OpenRouter key disable failed: {error}"))
            })?;
        let status = response.status();
        let text = response.text().await.map_err(|error| {
            ServerError::Internal(format!("OpenRouter key disable response failed: {error}"))
        })?;
        if !status.is_success() {
            return Err(ServerError::Internal(format!(
                "OpenRouter key disable returned {status}: {}",
                truncate(&text, 200)
            )));
        }
        let envelope: GetKeyEnvelope = serde_json::from_str(&text).map_err(|error| {
            ServerError::Internal(format!("invalid OpenRouter key disable response: {error}"))
        })?;
        if !envelope.data.disabled {
            return Err(ServerError::Internal(
                "OpenRouter did not disable the key".to_string(),
            ));
        }
        Ok(())
    }

    pub async fn delete_key(&self, hash: &str) -> Result<(), ServerError> {
        let response = self
            .http
            .delete(self.key_url(hash))
            .bearer_auth(&self.management_key)
            .send()
            .await
            .map_err(|error| {
                ServerError::Internal(format!("OpenRouter key deletion failed: {error}"))
            })?;
        // Deletion is idempotent: a lost success response must be recoverable.
        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ServerError::Internal(format!(
                "OpenRouter key deletion returned {status}: {}",
                truncate(&text, 200)
            )));
        }
        if response.status().is_success() && response.status() != reqwest::StatusCode::NO_CONTENT {
            let body: serde_json::Value = response.json().await.map_err(|error| {
                ServerError::Internal(format!("invalid OpenRouter key deletion response: {error}"))
            })?;
            if body["deleted"] != true {
                return Err(ServerError::Internal(
                    "OpenRouter did not confirm key deletion".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Remove keys with a request-unique name before retrying a provisioning
    /// record left incomplete by a process crash. A plaintext runtime key can
    /// never be recovered from the Management API, so revocation is the only
    /// safe reconciliation.
    pub async fn delete_keys_named(&self, name: &str) -> Result<(), ServerError> {
        for hash in self.key_hashes_named(name).await? {
            self.delete_key(&hash).await?;
        }
        Ok(())
    }

    /// Background cleanup of a terminal lease's key: disable it, then delete
    /// it. A key that no longer exists (404) is already cleaned up.
    pub async fn retire_key(&self, hash: &str) -> Result<(), ServerError> {
        let response = self
            .http
            .patch(self.key_url(hash))
            .bearer_auth(&self.management_key)
            .json(&json!({ "disabled": true }))
            .send()
            .await
            .map_err(|error| {
                ServerError::Internal(format!("OpenRouter key disable failed: {error}"))
            })?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ServerError::Internal(format!(
                "OpenRouter key disable returned {status}: {}",
                truncate(&text, 200)
            )));
        }
        self.delete_key(hash).await
    }

    /// Clean up any key a failed or abandoned issuance may have created
    /// under the lease's request-unique name.
    pub async fn retire_keys_named(&self, name: &str) -> Result<(), ServerError> {
        for hash in self.key_hashes_named(name).await? {
            self.retire_key(&hash).await?;
        }
        Ok(())
    }

    async fn key_hashes_named(&self, name: &str) -> Result<Vec<String>, ServerError> {
        let mut offset = 0usize;
        let mut matching_hashes = Vec::new();
        loop {
            let response = self
                .http
                .get(self.keys_url())
                .bearer_auth(&self.management_key)
                .query(&[("offset", offset)])
                .send()
                .await
                .map_err(|error| {
                    ServerError::Internal(format!("OpenRouter key listing failed: {error}"))
                })?;
            let status = response.status();
            let text = response.text().await.map_err(|error| {
                ServerError::Internal(format!("OpenRouter key-list response failed: {error}"))
            })?;
            if !status.is_success() {
                return Err(ServerError::Internal(format!(
                    "OpenRouter key listing returned {status}: {}",
                    truncate(&text, 300)
                )));
            }
            let envelope: ListKeysEnvelope = serde_json::from_str(&text).map_err(|error| {
                ServerError::Internal(format!("invalid OpenRouter key-list response: {error}"))
            })?;
            if envelope.data.is_empty() {
                break;
            }
            offset = offset.saturating_add(envelope.data.len());
            matching_hashes.extend(
                envelope
                    .data
                    .into_iter()
                    .filter(|key| key.name == name && !key.hash.is_empty())
                    .map(|key| key.hash),
            );
            if offset > 10_000 {
                return Err(ServerError::Internal(
                    "OpenRouter key reconciliation exceeded 10,000 keys".to_string(),
                ));
            }
        }
        Ok(matching_hashes)
    }
}

/// Format a UNIX timestamp as the UTC ISO-8601 representation accepted by
/// OpenRouter's `expires_at` field.
pub fn unix_to_iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// OpenRouter canonicalizes whole-second RFC 3339 timestamps with a `.000Z`
/// suffix even when the create request used `Z`. Accept only those two
/// equivalent representations so the provider cannot silently move expiry.
fn openrouter_expiry_matches(actual: &str, expected: &str) -> bool {
    if actual == expected {
        return true;
    }
    expected
        .strip_suffix('Z')
        .is_some_and(|prefix| actual == format!("{prefix}.000Z"))
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let end = value
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= max)
        .last()
        .unwrap_or(0);
    format!("{}…", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_openrouter_expiry_as_utc() {
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(unix_to_iso8601(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn accepts_openrouter_zero_millisecond_expiry_without_accepting_a_time_change() {
        let expected = "2026-08-12T20:23:54Z";
        assert!(openrouter_expiry_matches(expected, expected));
        assert!(openrouter_expiry_matches(
            "2026-08-12T20:23:54.000Z",
            expected
        ));
        assert!(!openrouter_expiry_matches(
            "2026-08-12T20:23:55.000Z",
            expected
        ));
        assert!(!openrouter_expiry_matches(
            "2026-08-12T20:23:54.001Z",
            expected
        ));
    }

    #[test]
    fn truncate_is_unicode_safe() {
        assert_eq!(truncate("abc", 3), "abc");
        assert!(truncate("ab🙂cd", 3).starts_with("ab"));
    }
}

//! Password transport for the explicitly selected Sepolia protocol server.
//! Never use this transport for an indexer, Ethereum RPC, verifier or provider.
use crate::error::ClientError;

const HEADER: &str = "X-ZKAPI-Testnet-Password";

pub fn request(
    chain_id: u64,
    server: &str,
    method: reqwest::Method,
    target: String,
) -> Result<reqwest::RequestBuilder, ClientError> {
    let password = if chain_id == 11155111 {
        std::env::var("OA_ZKAPI_TESTNET_PASSWORD").ok()
    } else {
        None
    };
    build_request(chain_id, server, method, target, password.as_deref())
}

fn build_request(
    chain_id: u64,
    server: &str,
    method: reqwest::Method,
    target: String,
    password: Option<&str>,
) -> Result<reqwest::RequestBuilder, ClientError> {
    let invalid = || ClientError::ServerError("invalid testnet authentication transport".into());
    let base = reqwest::Url::parse(server).map_err(|_| invalid())?;
    let url = reqwest::Url::parse(&target).map_err(|_| invalid())?;
    let prefix = format!("{}/", base.path().trim_end_matches('/'));
    if base.origin() != url.origin()
        || !url.path().starts_with(&prefix)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid());
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| invalid())?;
    let mut request = http.request(method, url.clone());
    if chain_id == 11155111 {
        if let Some(password) = password.filter(|value| !value.is_empty()) {
            if url.scheme() != "https"
                || password.len() > 1024
                || password.trim() != password
                || !password.bytes().all(|c| (0x20..=0x7e).contains(&c))
            {
                return Err(invalid());
            }
            let mut value =
                reqwest::header::HeaderValue::from_str(password).map_err(|_| invalid())?;
            value.set_sensitive(true);
            request = request.header(HEADER, value);
        }
    }
    Ok(request)
}

pub fn check_response(response: reqwest::Response) -> Result<reqwest::Response, ClientError> {
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ClientError::TestnetPasswordRequired);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn password_is_sepolia_only_and_sensitive() {
        for chain in [1, 11155111] {
            let request = build_request(
                chain,
                "https://server.example/protocol",
                reqwest::Method::GET,
                "https://server.example/protocol/v2/auth".into(),
                Some("shared secret"),
            )
            .unwrap()
            .build()
            .unwrap();
            let header = request.headers().get(HEADER);
            assert_eq!(header.is_some(), chain == 11155111);
            if let Some(header) = header {
                assert!(header.is_sensitive());
                assert_eq!(header, "shared secret");
            }
            assert!(!format!("{request:?}").contains("shared secret"));
        }
    }
    #[test]
    fn refuses_plaintext_and_other_destinations() {
        for target in [
            "https://rpc.example/protocol/v2/auth",
            "https://server.example/elsewhere",
            "https://server.example/protocol-other/v2/auth",
            "https://user@server.example/protocol/v2/auth",
        ] {
            assert!(build_request(
                11155111,
                "https://server.example/protocol",
                reqwest::Method::GET,
                target.into(),
                Some("secret")
            )
            .is_err());
        }
        assert!(build_request(
            11155111,
            "http://server.example",
            reqwest::Method::GET,
            "http://server.example/v2/auth".into(),
            Some("secret")
        )
        .is_err());
        for password in ["secret\r\ninjected", " leading", "trailing "] {
            assert!(build_request(
                11155111,
                "https://server.example",
                reqwest::Method::GET,
                "https://server.example/v2/auth".into(),
                Some(password)
            )
            .is_err());
        }
    }
}

//! Operator-pinned exception for using an explicitly unverified provider key.
//! Registry flags and names alone never authenticate a station-issued key.

#[derive(Clone, Copy)]
pub(crate) struct StationTrust<'a> {
    pub station_id: &'a str,
    pub public_key_hex: &'a str,
    pub verifier_url: &'a str,
}

pub(crate) const TRUSTED_STATION: StationTrust<'static> = StationTrust {
    station_id: "oa-station",
    public_key_hex: "20019ebb3cfa61a34ac75879bca8ccf9168ce435c6007d5279b84ebeb83fd097",
    verifier_url: "https://verifier2.openanonymity.ai",
};

fn hex_bytes(text: &str, size: usize) -> Option<Vec<u8>> {
    if text.len() != size * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

impl StationTrust<'_> {
    pub fn authenticates(
        &self,
        configured_verifier: &str,
        evidence_verifier: &str,
        station_id: &str,
        api_key: &str,
        key_valid_till: u64,
        station_signature: &str,
    ) -> bool {
        if configured_verifier.trim_end_matches('/') != self.verifier_url
            || evidence_verifier.trim_end_matches('/') != self.verifier_url
            || station_id != self.station_id
            || api_key.is_empty()
            || key_valid_till == 0
        {
            return false;
        }
        let (Some(public_key), Some(signature)) = (
            hex_bytes(self.public_key_hex, 32),
            hex_bytes(station_signature, 64),
        ) else {
            return false;
        };
        let message = format!("{station_id}|{api_key}|{key_valid_till}");
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
            .verify(message.as_bytes(), &signature)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    #[test]
    fn signature_authenticates_only_pinned_station_key_expiry_and_origin() {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let public = pair
            .public_key()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let signature = pair
            .sign(b"oa-station|test-child-key|2000000000")
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let trust = StationTrust {
            public_key_hex: &public,
            ..TRUSTED_STATION
        };
        let url = TRUSTED_STATION.verifier_url;
        assert!(trust.authenticates(
            url,
            url,
            "oa-station",
            "test-child-key",
            2_000_000_000,
            &signature
        ));
        for (configured, evidence, station, key, expiry, sig) in [
            (
                url,
                url,
                "unknown",
                "test-child-key",
                2_000_000_000,
                signature.as_str(),
            ),
            (
                url,
                url,
                "oa-station",
                "swapped-key",
                2_000_000_000,
                signature.as_str(),
            ),
            (
                url,
                url,
                "oa-station",
                "test-child-key",
                2_000_000_001,
                signature.as_str(),
            ),
            (
                "https://other.example",
                url,
                "oa-station",
                "test-child-key",
                2_000_000_000,
                signature.as_str(),
            ),
            (
                url,
                "https://other.example",
                "oa-station",
                "test-child-key",
                2_000_000_000,
                signature.as_str(),
            ),
            (
                url,
                url,
                "oa-station",
                "test-child-key",
                2_000_000_000,
                "not-hex",
            ),
        ] {
            assert!(!trust.authenticates(configured, evidence, station, key, expiry, sig));
        }
        assert!(!TRUSTED_STATION.authenticates(
            url,
            url,
            "oa-station",
            "test-child-key",
            2_000_000_000,
            &signature
        ));
    }
}

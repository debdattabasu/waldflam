//! Emulator-mode authorization, matching the official emulator's semantics:
//!
//! - no `authorization` header → unauthenticated (`request.auth == null`)
//! - `Bearer owner` (case-insensitive) → admin, bypasses security rules
//! - any other bearer token → an *unsigned* JWT (`alg: "none"`, empty
//!   signature); claims are decoded but never verified. `request.auth.uid`
//!   is the `sub` claim, `request.auth.token` the whole payload.
//! - anything malformed → INVALID_ARGUMENT
//!
//! Production-mode signature verification layers on later without changing
//! this interface.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tonic::Status;

#[derive(Debug, Clone, PartialEq)]
pub enum Authorization {
    /// No credentials: rules see `request.auth == null`.
    Unauthenticated,
    /// `Bearer owner`: full bypass, like a server/Admin SDK.
    Admin,
    /// Decoded (unverified) JWT claims payload.
    User(JwtClaims),
}

#[derive(Debug, Clone, PartialEq)]
pub struct JwtClaims {
    /// The `sub` claim — becomes `request.auth.uid`.
    pub uid: Option<String>,
    /// The entire decoded payload — becomes `request.auth.token`.
    pub payload: serde_json::Map<String, serde_json::Value>,
}

impl Authorization {
    /// Parses an `authorization` header value (or its absence).
    pub fn from_header(header: Option<&str>) -> Result<Self, Status> {
        let Some(header) = header else {
            return Ok(Self::Unauthenticated);
        };
        let token = header
            .get(..7)
            .filter(|p| p.eq_ignore_ascii_case("bearer "))
            .map(|_| &header[7..])
            .ok_or_else(|| Status::invalid_argument("expected Bearer authorization"))?;
        if token.eq_ignore_ascii_case("owner") {
            return Ok(Self::Admin);
        }
        parse_unsigned_jwt(token)
            .map(Self::User)
            .map_err(|reason| Status::invalid_argument(format!("invalid jwt: {reason}")))
    }
}

fn parse_unsigned_jwt(token: &str) -> Result<JwtClaims, &'static str> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("expected three dot-separated segments");
    };
    if !signature.is_empty() {
        return Err("expected empty signature");
    }

    let header: serde_json::Map<String, serde_json::Value> = decode_json_segment(header)?;
    match header.get("alg").and_then(|v| v.as_str()) {
        Some("none") => {}
        _ => return Err("expected alg 'none'"),
    }

    let payload: serde_json::Map<String, serde_json::Value> = decode_json_segment(payload)?;
    let uid = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    Ok(JwtClaims { uid, payload })
}

fn decode_json_segment(
    segment: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, &'static str> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment.trim_end_matches('='))
        .map_err(|_| "invalid base64url")?;
    match serde_json::from_slice(&bytes) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        _ => Err("segment is not a JSON object"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsigned_jwt(payload: serde_json::Value) -> String {
        let enc = |v: &serde_json::Value| URL_SAFE_NO_PAD.encode(v.to_string());
        format!(
            "{}.{}.",
            enc(&serde_json::json!({"alg": "none", "typ": "JWT"})),
            enc(&payload)
        )
    }

    #[test]
    fn absent_header_is_unauthenticated() {
        assert_eq!(
            Authorization::from_header(None).unwrap(),
            Authorization::Unauthenticated
        );
    }

    #[test]
    fn owner_is_admin_case_insensitively() {
        for h in ["Bearer owner", "bearer owner", "Bearer OWNER", "BEARER Owner"] {
            assert_eq!(
                Authorization::from_header(Some(h)).unwrap(),
                Authorization::Admin,
                "{h}"
            );
        }
    }

    #[test]
    fn unsigned_jwt_claims_are_decoded_not_verified() {
        let jwt = unsigned_jwt(serde_json::json!({
            "sub": "alice",
            "email": "alice@example.com",
            "firebase": {"sign_in_provider": "password"},
        }));
        let auth = Authorization::from_header(Some(&format!("Bearer {jwt}"))).unwrap();
        let Authorization::User(claims) = auth else {
            panic!("expected user auth");
        };
        assert_eq!(claims.uid.as_deref(), Some("alice"));
        assert_eq!(
            claims.payload["email"],
            serde_json::json!("alice@example.com")
        );
    }

    #[test]
    fn missing_sub_is_allowed() {
        let jwt = unsigned_jwt(serde_json::json!({"custom": true}));
        let Authorization::User(claims) =
            Authorization::from_header(Some(&format!("Bearer {jwt}"))).unwrap()
        else {
            panic!("expected user auth");
        };
        assert_eq!(claims.uid, None);
    }

    #[test]
    fn rejects_malformed_tokens() {
        for h in [
            "Basic abc",                        // wrong scheme
            "Bearer not.a",                     // two segments
            "Bearer a.b.c.d",                   // four segments
            "Bearer !!.!!.",                    // bad base64
        ] {
            assert!(Authorization::from_header(Some(h)).is_err(), "{h}");
        }
        // signed JWT (non-empty signature) must be rejected in this mode
        let signed = format!("{}sig", unsigned_jwt(serde_json::json!({"sub": "x"})));
        assert!(Authorization::from_header(Some(&format!("Bearer {signed}"))).is_err());
        // alg RS256 must be rejected
        let enc = |v: serde_json::Value| URL_SAFE_NO_PAD.encode(v.to_string());
        let rs256 = format!(
            "{}.{}.",
            enc(serde_json::json!({"alg": "RS256"})),
            enc(serde_json::json!({"sub": "x"}))
        );
        assert!(Authorization::from_header(Some(&format!("Bearer {rs256}"))).is_err());
    }
}

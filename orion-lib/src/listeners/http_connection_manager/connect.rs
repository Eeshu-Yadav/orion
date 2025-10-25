// Copyright 2025 The kmesh Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! HTTP CONNECT method implementation for tunneling TCP through HTTP

use http::{Request, Response, StatusCode};
use http_body_util::Full;
use bytes::Bytes;
use std::fmt;
use std::io;
use tracing::debug;

/// Errors that can occur during CONNECT handling
#[derive(Debug)]
pub enum ConnectError {
    /// The authority form URI is invalid or missing
    InvalidAuthority(String),
    /// CONNECT request contains a body (not allowed)
    BodyNotAllowed,
    /// Failed to connect to upstream
    UpstreamConnectionFailed(io::Error),
    /// Upstream connection timed out
    UpstreamTimeout,
    /// Error during tunnel operation
    TunnelError(io::Error),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAuthority(msg) => write!(f, "Invalid authority: {}", msg),
            Self::BodyNotAllowed => write!(f, "CONNECT request must not have a body"),
            Self::UpstreamConnectionFailed(e) => write!(f, "Failed to connect to upstream: {}", e),
            Self::UpstreamTimeout => write!(f, "Upstream connection timed out"),
            Self::TunnelError(e) => write!(f, "Tunnel error: {}", e),
        }
    }
}

impl std::error::Error for ConnectError {}

impl ConnectError {
    /// Convert error to HTTP status code
    pub fn to_status_code(&self) -> StatusCode {
        match self {
            Self::InvalidAuthority(_) | Self::BodyNotAllowed => StatusCode::BAD_REQUEST,
            Self::UpstreamConnectionFailed(_) => StatusCode::BAD_GATEWAY,
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::TunnelError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Convert error to HTTP response
    pub fn to_response(&self) -> Response<Full<Bytes>> {
        let status = self.to_status_code();
        let body = format!("{}: {}\r\n", status.canonical_reason().unwrap_or("Error"), self);
        
        Response::builder()
            .status(status)
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }
}

/// Validate a CONNECT request
///
/// RFC 9110 Section 9.3.6:
/// - The request-target is in authority-form (host:port)
/// - There must be no request body
pub fn validate_connect_request<B>(req: &Request<B>) -> Result<String, ConnectError> {
    // 1. Verify method is CONNECT (caller should have already checked this)
    debug_assert_eq!(req.method(), http::Method::CONNECT);

    // 2. Extract authority from URI
    // For CONNECT, the URI should be in authority-form: "host:port"
    let authority = req
        .uri()
        .authority()
        .ok_or_else(|| {
            ConnectError::InvalidAuthority("Missing authority in CONNECT request".to_string())
        })?
        .as_str()
        .to_string();

    // 3. Validate authority format (should be host:port)
    if authority.is_empty() {
        return Err(ConnectError::InvalidAuthority("Empty authority".to_string()));
    }

    // Check that it has a port (should contain ':')
    if !authority.contains(':') {
        return Err(ConnectError::InvalidAuthority(
            format!("Authority must include port: {}", authority)
        ));
    }

    debug!("Validated CONNECT request for authority: {}", authority);
    Ok(authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    #[test]
    fn test_validate_connect_request_valid() {
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri("example.com:443")
            .body(())
            .unwrap();

        let result = validate_connect_request(&req);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com:443");
    }

    #[test]
    fn test_validate_connect_request_missing_authority() {
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri("/")  // Invalid for CONNECT
            .body(())
            .unwrap();

        let result = validate_connect_request(&req);
        assert!(result.is_err());
        matches!(result.unwrap_err(), ConnectError::InvalidAuthority(_));
    }

    #[test]
    fn test_validate_connect_request_missing_port() {
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri("example.com")  // Missing port
            .body(())
            .unwrap();

        let result = validate_connect_request(&req);
        assert!(result.is_err());
        matches!(result.unwrap_err(), ConnectError::InvalidAuthority(_));
    }

    #[test]
    fn test_error_to_status_code() {
        assert_eq!(
            ConnectError::InvalidAuthority("test".to_string()).to_status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ConnectError::UpstreamConnectionFailed(io::Error::new(io::ErrorKind::Other, "test")).to_status_code(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            ConnectError::UpstreamTimeout.to_status_code(),
            StatusCode::GATEWAY_TIMEOUT
        );
    }
}

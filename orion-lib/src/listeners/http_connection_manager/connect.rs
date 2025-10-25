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

use http::{Request, Response, StatusCode, Version};
use http_body_util::{Empty, Full};
use bytes::Bytes;
use hyper_util::rt::TokioIo;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::body::body_with_metrics::BodyWithMetrics;
use crate::PolyBody;

/// Errors that can occur during CONNECT handling
#[derive(Debug)]
pub enum ConnectError {
    /// The authority form URI is invalid or missing
    InvalidAuthority(String),
    /// CONNECT request contains a body (not allowed per RFC 9110)
    /// Currently unused but reserved for future validation
    #[allow(dead_code)]
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
    /// Currently unused - errors are handled in route.rs using to_status_code()
    #[allow(dead_code)]
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

/// Establish TCP connection to upstream target
///
/// Parses the authority string (host:port), resolves it, and establishes
/// a TCP connection with timeout and proper socket options.
pub async fn establish_upstream_connection(authority: &str) -> Result<TcpStream, ConnectError> {
    debug!("Establishing upstream connection to: {}", authority);

    // Parse authority into SocketAddr
    // Note: This does DNS resolution if needed
    let addr: SocketAddr = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::lookup_host(authority)
    )
    .await
    .map_err(|_| ConnectError::UpstreamTimeout)?
    .map_err(|e| ConnectError::UpstreamConnectionFailed(e))?
    .next()
    .ok_or_else(|| {
        ConnectError::UpstreamConnectionFailed(
            io::Error::new(io::ErrorKind::NotFound, "No addresses found for host")
        )
    })?;

    // Establish TCP connection with timeout
    let stream = timeout(
        Duration::from_secs(30),
        TcpStream::connect(addr)
    )
    .await
    .map_err(|_| ConnectError::UpstreamTimeout)?
    .map_err(ConnectError::UpstreamConnectionFailed)?;

    // Set TCP_NODELAY for low latency
    if let Err(e) = stream.set_nodelay(true) {
        warn!("Failed to set TCP_NODELAY on upstream connection: {}", e);
    }

    info!("Successfully connected to upstream: {} ({})", authority, addr);
    Ok(stream)
}

/// Run bidirectional tunnel between client and upstream
///
/// Copies data in both directions until either side closes the connection.
/// Handles graceful shutdown and error conditions.
pub async fn run_tunnel<C, U>(
    client: &mut C,
    upstream: &mut U,
) -> Result<(u64, u64), ConnectError>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    debug!("Starting bidirectional tunnel");

    // Copy data in both directions concurrently
    let result = copy_bidirectional(client, upstream)
        .await
        .map_err(ConnectError::TunnelError)?;

    let (bytes_client_to_upstream, bytes_upstream_to_client) = result;
    
    info!(
        "Tunnel closed: {} bytes sent to upstream, {} bytes received from upstream",
        bytes_client_to_upstream, bytes_upstream_to_client
    );

    Ok((bytes_client_to_upstream, bytes_upstream_to_client))
}

/// Handle a complete CONNECT tunnel request
///
/// This is the main entry point for CONNECT handling:
/// 1. Validate the request
/// 2. Establish upstream connection
/// 3. Send 200 Connection Established
/// 4. Run bidirectional tunnel
pub async fn handle_connect_tunnel(
    mut request: Request<BodyWithMetrics<PolyBody>>,
) -> Result<Response<PolyBody>, ConnectError> {
    let version = request.version();
    
    // Only HTTP/1.1 supports traditional CONNECT
    if version != Version::HTTP_11 {
        warn!("CONNECT method only supported for HTTP/1.1, got {:?}", version);
        return Err(ConnectError::InvalidAuthority(
            "CONNECT only supported for HTTP/1.1".to_string()
        ));
    }

    // Validate and extract authority
    let authority = validate_connect_request(&request)?;
    
    // Get the upgrade future before consuming the request
    let upgrade_future = hyper::upgrade::on(&mut request);
    
    // Establish upstream connection
    let upstream = establish_upstream_connection(&authority).await?;
    
    // Create 200 Connection Established response
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(PolyBody::Empty(Empty::new()))
        .unwrap();
    
    // Spawn task to handle tunnel after response is sent
    tokio::spawn(async move {
        match upgrade_future.await {
            Ok(upgraded) => {
                let mut client = TokioIo::new(upgraded);
                let mut upstream = upstream;
                
                match run_tunnel(&mut client, &mut upstream).await {
                    Ok((sent, received)) => {
                        debug!("CONNECT tunnel completed: {} sent, {} received", sent, received);
                    }
                    Err(e) => {
                        error!("CONNECT tunnel error: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("Failed to upgrade connection for CONNECT: {}", e);
            }
        }
    });
    
    Ok(response)
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

    #[tokio::test]
    async fn test_establish_upstream_connection_success() {
        // Start a test TCP server
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // Spawn server task
        tokio::spawn(async move {
            let (_socket, _addr) = listener.accept().await.unwrap();
            // Just accept and hold the connection
        });

        // Test connecting to it
        let result = establish_upstream_connection(&addr.to_string()).await;
        assert!(result.is_ok(), "Should successfully connect to localhost");
        
        let stream = result.unwrap();
        assert!(stream.peer_addr().is_ok(), "Should have valid peer address");
    }

    #[tokio::test]
    async fn test_establish_upstream_connection_timeout() {
        // Use a non-routable IP to trigger timeout
        let result = establish_upstream_connection("192.0.2.1:80").await;
        assert!(result.is_err(), "Should timeout connecting to non-routable IP");
        
        match result.unwrap_err() {
            ConnectError::UpstreamTimeout | ConnectError::UpstreamConnectionFailed(_) => {},
            other => panic!("Expected timeout or connection failed, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_establish_upstream_connection_invalid_host() {
        let result = establish_upstream_connection("invalid-host-that-does-not-exist.local:80").await;
        assert!(result.is_err(), "Should fail with invalid hostname");
        
        match result.unwrap_err() {
            ConnectError::UpstreamConnectionFailed(_) => {},
            other => panic!("Expected connection failed, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_run_tunnel_bidirectional() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Create two pairs of connected streams
        let (mut client_local, client_remote) = tokio::io::duplex(1024);
        let (mut upstream_local, upstream_remote) = tokio::io::duplex(1024);

        // Don't wrap in TokioIo for tests - DuplexStream already implements AsyncRead/AsyncWrite
        let mut client = client_remote;
        let mut upstream = upstream_remote;

        // Spawn tunnel task
        let tunnel_handle = tokio::spawn(async move {
            run_tunnel(&mut client, &mut upstream).await
        });

        // Test client -> upstream
        let test_data = b"Hello from client";
        client_local.write_all(test_data).await.unwrap();
        
        let mut buf = vec![0u8; test_data.len()];
        upstream_local.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, test_data, "Data should flow from client to upstream");

        // Test upstream -> client
        let response_data = b"Hello from upstream";
        upstream_local.write_all(response_data).await.unwrap();
        
        let mut buf = vec![0u8; response_data.len()];
        client_local.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, response_data, "Data should flow from upstream to client");

        // Close connections to end tunnel
        drop(client_local);
        drop(upstream_local);

        // Wait for tunnel to complete
        let result = tunnel_handle.await.unwrap();
        assert!(result.is_ok(), "Tunnel should complete successfully");
        
        let (client_to_upstream, upstream_to_client) = result.unwrap();
        assert_eq!(client_to_upstream, test_data.len() as u64);
        assert_eq!(upstream_to_client, response_data.len() as u64);
    }

    #[tokio::test]
    async fn test_run_tunnel_large_data() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client_local, client_remote) = tokio::io::duplex(64 * 1024);
        let (mut upstream_local, upstream_remote) = tokio::io::duplex(64 * 1024);

        let mut client = client_remote;
        let mut upstream = upstream_remote;

        let tunnel_handle = tokio::spawn(async move {
            run_tunnel(&mut client, &mut upstream).await
        });

        // Send 1MB of data
        let test_data = vec![0xAB; 1024 * 1024];
        let data_len = test_data.len();
        
        tokio::spawn(async move {
            client_local.write_all(&test_data).await.unwrap();
            client_local.shutdown().await.unwrap();
        });

        let mut received = Vec::new();
        upstream_local.read_to_end(&mut received).await.unwrap();
        
        assert_eq!(received.len(), data_len, "Should receive all data");
        assert_eq!(received[0], 0xAB, "Data should be correct");
        
        drop(upstream_local);
        
        let result = tunnel_handle.await.unwrap();
        assert!(result.is_ok(), "Large data transfer should succeed");
    }
}


# CLAUDE.md - Zenwave HTTP Client Framework

## Project Overview

**Zenwave** is an ergonomic HTTP client framework written in Rust that provides a powerful middleware-based architecture for HTTP requests. It supports multiple backends, authentication methods, cookie management, and request/response processing.

## Architecture

### Core Components

1. **Client Trait** (`src/client.rs`): The main interface for making HTTP requests
2. **Backend System** (`src/backend/`): Pluggable HTTP backends for different environments
3. **Middleware System**: Composable request/response processing pipeline
4. **Authentication** (`src/auth.rs`): Bearer and Basic authentication middleware

### Key Design Patterns

- **Trait-based Architecture**: Core functionality exposed through the `Client` trait
- **Middleware Pipeline**: Request processing through composable middleware layers
- **Backend Abstraction**: Support for different HTTP implementations (Hyper, Web)
- **Builder Pattern**: Fluent API for request construction via `RequestBuilder`
- **Type Safety**: Heavy use of Rust's type system for compile-time guarantees

## Project Structure

```
src/
├── lib.rs              # Main library entry point, convenience functions
├── client.rs           # Core Client trait and RequestBuilder
├── auth.rs            # Bearer and Basic authentication middleware
├── cookie_store.rs    # Cookie persistence middleware
├── redirect.rs        # HTTP redirect following middleware
├── backend/
│   ├── mod.rs         # Backend trait definitions
│   ├── hyper.rs       # Hyper-based backend for native Rust
│   └── web.rs         # Web API backend for WASM
└── tests/             # Comprehensive unit test suite
    ├── auth_tests.rs
    ├── backend_tests.rs
    ├── client_tests.rs
    ├── convenience_tests.rs
    ├── error_tests.rs
    ├── integration_tests.rs
    └── middleware_tests.rs
```

## Key Dependencies

- **http-kit 0.2.0**: Core HTTP abstractions and middleware system
- **hyper + hyper-tls**: HTTP client implementation for native targets
- **web-sys**: WebAPI bindings for WASM targets
- **serde + serde_json**: Serialization for JSON request/response bodies
- **base64**: Basic authentication encoding
- **tokio**: Async runtime for tests

## Development Commands

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test module
cargo test auth_tests
cargo test integration_tests

# Run with output
cargo test -- --nocapture

# Run backend-specific tests
cargo test backend_tests
```

### Linting and Formatting

```bash
# Check code formatting
cargo fmt --check

# Format code
cargo fmt

# Run clippy lints
cargo clippy
```

### Building

```bash
# Build for native
cargo build

# Build for WASM
cargo build --target wasm32-unknown-unknown
```

## Common Usage Patterns

### Basic HTTP Requests

```rust
use zenwave::get;

// Simple GET request
let response = get("https://api.example.com/data").await?;
let json: Value = response.into_body().into_json().await?;
```

### Client with Middleware

```rust
use zenwave::client;

let mut client = client()
    .follow_redirect()
    .enable_cookie()
    .bearer_auth("your-token-here");

let response = client.get("https://api.example.com/protected").await?;
```

### Request Building

```rust
let response = client
    .post("https://api.example.com/data")
    .json_body(&request_data)?
    .header("X-Custom", "value")
    .await?;
```

### Authentication

```rust
// Per-request authentication
let response = client
    .get("https://api.example.com/data")
    .bearer_auth("token")
    .await?;

// Client-level authentication
let mut client = client().basic_auth("username", Some("password"));
```

## Important Implementation Details

### Response Body Processing

With http-kit 0.2.0, body methods moved from `Response` to `Body`:

```rust
// Correct pattern
let response = client.get(url).await?;
let body = response.into_body();
let json = body.into_json().await?;

// NOT: response.into_json().await (old API)
```

### Header Manipulation

Headers are accessed through the standard `http` crate methods:

```rust
// Reading headers
if request.headers().contains_key(header::AUTHORIZATION) { ... }

// Setting headers
request.headers_mut().insert(header::CONTENT_TYPE, "application/json".parse()?);
```

### Middleware Implementation

Custom middleware implements the `Middleware` trait:

```rust
impl Middleware for CustomMiddleware {
    async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
        // Pre-processing
        modify_request(request);

        // Call next middleware/backend
        let response = next.respond(request).await?;

        // Post-processing
        Ok(process_response(response))
    }
}
```

### Backend Implementation

Custom backends implement both `Endpoint` and `ClientBackend`:

```rust
impl Endpoint for CustomBackend {
    async fn respond(&mut self, request: &mut Request) -> Result<Response> {
        // HTTP implementation
    }
}

impl ClientBackend for CustomBackend {}
```

## Testing Patterns

### Unit Tests

- **Client Tests**: Verify Client trait functionality
- **Backend Tests**: Test HTTP backend implementations
- **Middleware Tests**: Validate middleware behavior
- **Auth Tests**: Authentication middleware verification

### Integration Tests

- **Real HTTP Requests**: Tests against httpbin.org for real-world scenarios
- **Error Handling**: Network errors, invalid URLs, parsing failures
- **Response Processing**: JSON, text, binary data handling

### Test Utilities

Tests use helper functions for common patterns:

```rust
// Creating test clients
let mut client = client();
let mut auth_client = client().bearer_auth("test-token");

// Response verification
assert!(response.status().is_success());
assert_eq!(response.status().as_u16(), 200);
```

## Common Gotchas

1. **Body Consumption**: Response bodies can only be consumed once
2. **Mutable Client References**: Client methods require `&mut self`
3. **Header Parsing**: Header values must be valid HTTP header strings
4. **WASM Limitations**: Some features unavailable in browser environments
5. **Async Context**: All network operations are async and require proper await handling

## Future Development Areas

- **Request/Response Interceptors**: More granular request modification
- **Connection Pooling**: Better connection management for high-throughput scenarios
- **Retry Mechanisms**: Built-in retry logic for transient failures
- **Metrics Collection**: Request/response timing and statistics
- **Custom Serialization**: Beyond JSON for request/response bodies

## Debugging Tips

1. **Enable Debug Logging**: Use `RUST_LOG=debug` for detailed HTTP logs
2. **Inspect Headers**: Use `dbg!(request.headers())` to examine request headers
3. **Network Issues**: Test with curl/httpie to isolate client vs server issues
4. **WASM Debugging**: Use browser developer tools for web target debugging
5. **Test Isolation**: Run tests with `cargo test -- --test-threads=1` for debugging race conditions

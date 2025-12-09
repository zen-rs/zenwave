# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/zen-rs/zenwave/releases/tag/v0.1.0) - 2025-12-09

### Added

- Add websocket support and update tests to use local httpbin server
- Add retry middleware for automatic request retries on failure
- Introduce WebSocket split functionality for concurrent sending and receiving
- Implement fragmented binary message handling in WebSocket tests
- Enhance WebSocketConfig with frame size option and default values
- Add binary roundtrip and server ping handling tests for WebSocket
- Add public echo service tests and utility function for WebSocket echo URLs
- Introduce WebSocket configuration options and enhance backend selection logic
- Enhance backend selection documentation and default configurations in README and source files
- Refactor WebSocket and timeout middleware for improved error handling and compatibility
- Refactor TLS handling and improve WebSocket error management
- Add Remote error variant to error enums for Apple, Curl, and Web backends
- Enhance CI workflow and add native and apple backend test scripts
- Add timeout middleware for request duration enforcement and enhance client functionality
- Update proxy feature naming and enhance documentation for backend support
- Add error handling improvements and introduce custom error types
- Implement proxy support for HTTP clients and update documentation
- Add ResultExt for enhanced error handling and update response status handling
- Enhance Apple backend with URLSession delegate for redirect handling and update documentation
- Add support for streaming uploads and persistent cookie storage
- Add HTTP caching middleware to honor Cache-Control and validator headers
- Add download_to_path functionality with resume support for large files
- Enhance Apple backend with ephemeral URLSession and improve session management
- Add experimental apple-backend feature for URLSession support on Apple platforms
- Implement Apple backend using NSURLSession
- update tokio dependencies for multi-threaded runtime support; add example files for basic GET request, custom client, and WebSocket echo
- add websocket support with client implementation and echo test
- add multipart/form-data utilities and enhance request handling
- Enhance Zenwave HTTP client framework

### Fixed

- Restore Endpoint import in backend_tests
- Fix test warnings for apple-backend feature
- Handle httpbingo.org array format in WASM test
- Use httpbingo.org for WASM tests (supports CORS)
- Update feature-checks to avoid mutually exclusive TLS features
- Fix CI feature checks and flaky websocket test
- Cover lints for all code
- Remove lint and clippy job in test ci
- Fix CI
- Update http-kit dependency to use version instead of git reference
- Restore previously removed WebSocket echo service URL in public echo server list
- Update tokio-rustls dependency to include default features and specify feature flags
- Update dependencies for async-tungstenite and async-fs, and adjust WebSocketMessage types
- Update test URLs from httpbin.org to httpbingo.org and improve error handling assertions
- Enhance HyperError handling to include status and body in remote errors
- Implement status method for ClientError to return status from Remote errors
- Update header method to use TryInto for header name and value conversion
- Update download logic to use existing file length for resumable downloads

### Other

- Mark Safari wasm-pack as continue-on-error due to safaridriver issues
- Mark flaky wasm-pack browser tests as continue-on-error
- Update CI configuration and dependencies
- Update CI configuration for Clippy and enhance WebSocket error handling
- Update dependencies and improve error handling in WebBackend
- Simplify client request syntax in tests by removing unnecessary line breaks
- Update HttpError implementations to return StatusCode directly and simplify error handling
- Enhance WebSocketMessage handling to include Ping, Pong, and Close variants
- Remove WebSocketMessage enum and related implementations
- Update HttpError implementations to return StatusCode directly
- Simplify error handling for InvalidUri in WebSocketError conversion
- Simplify error conversion implementations across multiple modules
- Introduce unified error handling across zenwave
- Update WebSocketConfig documentation for message and frame size options
- Update dependencies in Cargo.toml and modify CI configuration
- Remove "wss://echo.websocket.events" from the public echo server list in `public_echo_servers` function to streamline the available WebSocket echo services for testing.
- Replace ClientBackend trait with Client trait across backend implementations
- Update Cargo.toml lints and refactor client and backend code for improved clarity and performance
- Refactor WebSocket connection handling and update tests to use async-std
- Refactor error handling and improve code clarity across multiple modules
- Remove network access requirement from tests to enable local execution
- Refactor OAuth2 middleware and error handling
- Add OAuth2 client credentials middleware
- Add ResponseExt trait for enhanced response handling; implement JSON, SSE, string, and byte conversions
- Refactor authentication middleware and tests for improved readability; reorganize test module imports
- Enhance RequestBuilder with SSE support and improve JSON and form handling; refactor code for better readability
- Refactor HTTP client tests and middleware to improve readability and consistency; remove unnecessary mutable bindings
- Add comprehensive documentation for Zenwave HTTP client framework, update dependencies, and enhance middleware and request handling
- Add CI and release workflows, implement authentication middleware, and enhance tests
- Add hyper-tls dependency and update HyperBackend to use HttpsConnector; add basic HTTP and HTTPS tests
- Add LICENSE and README files; enhance client API with RequestBuilder for better request handling
- Refactor dependencies and implement WebBackend and CookieStore for enhanced HTTP client functionality
- update http-kit
- update http-kit
- adapt to new `http-kit` api
- update `http-kit`
- Add `method` method for Client
- Provide some convenient method for receiving body
- some fixes
- Initial implement

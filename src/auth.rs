use http_kit::{Endpoint, Middleware, Request, Response, Result, header};

#[derive(Debug, Clone)]
pub struct BearerAuth {
    token: String,
}

impl BearerAuth {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

impl Middleware for BearerAuth {
    async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
        // Only add auth header if one isn't already present
        if !request.headers().contains_key(header::AUTHORIZATION) {
            let auth_value = format!("Bearer {}", self.token);
            request.headers_mut().insert(
                header::AUTHORIZATION,
                auth_value.parse().unwrap(),
            );
        }
        
        next.respond(request).await
    }
}

#[derive(Debug, Clone)]
pub struct BasicAuth {
    username: String,
    password: Option<String>,
}

impl BasicAuth {
    pub fn new(username: impl Into<String>, password: Option<impl Into<String>>) -> Self {
        Self {
            username: username.into(),
            password: password.map(|p| p.into()),
        }
    }
}

impl Middleware for BasicAuth {
    async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
        // Only add auth header if one isn't already present
        if !request.headers().contains_key(header::AUTHORIZATION) {
            use base64::Engine;
            
            let credentials = match &self.password {
                Some(password) => format!("{}:{}", self.username, password),
                None => format!("{}:", self.username),
            };
            
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
            let auth_value = format!("Basic {}", encoded);
            
            request.headers_mut().insert(
                header::AUTHORIZATION,
                auth_value.parse().unwrap(),
            );
        }
        
        next.respond(request).await
    }
}
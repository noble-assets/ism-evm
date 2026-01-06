use tonic::{Request, Status, service::Interceptor};

#[derive(Clone)]
pub struct AuthInterceptor {
    api_key: String,
}

impl AuthInterceptor {
    pub fn new(api_key: String) -> Self {
        Self { api_key }
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        match request.metadata().get("x-api-key") {
            Some(key) if key == self.api_key.as_str() => Ok(request),
            Some(_) => Err(Status::unauthenticated("Invalid API key")),
            None => Err(Status::unauthenticated("Missing API key")),
        }
    }
}

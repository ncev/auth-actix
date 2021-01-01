use std::fmt::{Display, Formatter};
use std::fmt;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use actix_web::{Error, ResponseError};
use actix_web::http::StatusCode;


/// AuthResult => type alias
pub type AuthResult<T> = Result<Auth<T>, Error>;






/// Configuration, token information
/// inject it throught app_data (checkout the example)
#[derive(Deserialize)]
pub struct AuthConfiguration {
    pub secret: &'static [u8]
}





/// idiom type to wrap the type identification
pub struct Auth<T: DeserializeOwned + Display> {
    pub(crate) wrapped: T
}


/// unwrap the Auth value
#[inline]
pub fn run_auth<T>(auth: Auth<T>) -> T
    where T: DeserializeOwned + Display
    { auth.wrapped }


/// Display implementation, needed by FromRequest
impl<T: DeserializeOwned + Display> Display for Auth<T> {
    fn fmt(&self, f: &mut Formatter<'_>)
        -> fmt::Result { write!(f, "authentication") }
}





/// Authentication failed representation
#[derive(Debug)]
pub enum AuthenticationError {
    Failed,
    MissingConfiguration
}

/// display implementation, needed for FromRequest trait
impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut Formatter<'_>)
           -> fmt::Result {
        match self {
            AuthenticationError::Failed =>
                write!(f, "Missing configuration, inject it through app_data"),
            AuthenticationError::MissingConfiguration =>
                write!(f, "Authentication failed")
        }
    }
}


/// ResponseError implementation, UNAUTHORIZED being 401
impl ResponseError for AuthenticationError {
    fn status_code(&self)
                   -> StatusCode { StatusCode::UNAUTHORIZED }
}

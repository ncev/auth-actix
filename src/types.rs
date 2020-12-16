use std::fmt::{Display, Formatter};
use std::fmt;
use serde::de::DeserializeOwned;
use serde::Deserialize;



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
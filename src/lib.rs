pub mod types;

use actix_web::{Error, ResponseError, HttpRequest, FromRequest};
use futures::future::{ok, Ready, err};
use actix_web::http::{StatusCode, HeaderValue};
use core::fmt;
use serde::export::Formatter;
use serde::Serialize;
use serde::export::fmt::Display;
use jsonwebtoken::{decode, DecodingKey, Validation, Header, encode, EncodingKey};
use serde::de::DeserializeOwned;
use std::borrow::Borrow;
use actix_web::dev::{Payload, PayloadStream};
use actix_web::web::Data;
use crate::types::{Auth, AuthenticationError, AuthConfiguration};


/// FromRequest
///
/// allow to get it throught our endpoint function arguments
impl<T: DeserializeOwned + Display> FromRequest for Auth<T> {
    type Error = Error;
    type Future = Ready<Result<Auth<T>, Error>>;
    type Config = ();

    fn from_request(
        req: &HttpRequest,
        _payload: &mut Payload<PayloadStream>
    ) -> Self::Future {


        // get the auth configuration
        // (ex: secret)
        let conf: Option<&Data<AuthConfiguration>> =
            req.app_data::<Data<AuthConfiguration>>();



        match conf {
            // if None => Configuration is missing
            None =>
                err(Error::from(AuthenticationError::MissingConfiguration)),


            Some(conf) => {

                let validation = Validation {
                    validate_exp: false,
                    ..Validation::default()
                };

                // log the user
                authenticate_from_request(req, &validation, conf.secret)
            }
        }
    }
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








/// Read from a token
fn read_token<T>(
    token: &HeaderValue,
    validation: &Validation,
    secret: &[u8]
) -> Option<T>
    where T: DeserializeOwned + Display
{

    // we convert the HeaderValue to str
    token.to_str().ok()


        // we remove the 'Bearer ' prefix
        .and_then(
            |header_value| header_value.split("Bearer ").last())


        // we read the str to A
        .and_then(
            |header_value| decode(header_value, DecodingKey::from_secret(secret).borrow(), validation).ok())


        // we keep the claim
        .map(
            |token_data| token_data.claims)
}


/// authenticate user throught token
pub fn authenticate_from_request<T>(
    req: &HttpRequest,
    validation: &Validation,
    secret: &[u8]
) -> Ready<Result<Auth<T>, Error>>
    where T: DeserializeOwned + Display
{


    // we get the header which hold the token
    let header_token =
        req.headers().get("Authorization");



    // then we parse it to an A
    let auth = header_token
        .and_then(
        |header_token|
            read_token(
                header_token,
                validation,
                secret)
    );




    // in the end we wrap it in an ok
    // if Nothing, then we wrap an AuthenticationError in err
    match auth {
        Some(x) =>
            ok(Auth { wrapped: x }),
        None =>
            err(Error::from(AuthenticationError::Failed))
    }
}



/// User information => token JWT
pub fn write_token<A>(
    header: &Header,
    claims: &A,
    secret: &[u8]
) -> Option<String>
    where A: Serialize
{
    encode(header, claims, EncodingKey::from_secret(secret).borrow()).ok()
}









#[cfg(test)]
mod tests {
    use actix_web::http::HeaderValue;
    use jsonwebtoken::Validation;
    use std::fmt::{Display, Formatter};
    use serde::{Serialize, Deserialize};
    use std::fmt;
    use crate::read_token;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct ClaimUser {
        name: String,
        age: i32
    }

    impl Display for ClaimUser {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.name)
        }
    }


    #[test]
    fn read_token_test() {

        // token mock
        let token =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9\
            .eyJuYW1lIjoiSm9obiIsImFnZSI6MzB9\
            .MVBuir8NRKn_eGJJHM1bj-bAN1ynJP_7o3g5nbaYNLE";



        let header =
            HeaderValue::from_static(token);

        let secret =
            b"secret";

        let validation =
            Validation { validate_exp: false, ..Validation::default() };



        assert_eq!(
            Some(ClaimUser {
                name: "John".to_string(),
                age: 30
            }),
            read_token(&header, &validation, secret)
        )
    }
}
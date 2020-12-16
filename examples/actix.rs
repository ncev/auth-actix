use actix_web::{Error, HttpServer, web, App, HttpRequest, FromRequest, HttpResponse};
use futures::future::{Ready};
use actix_web::dev::{PayloadStream, Payload};
use serde::{Serialize, Deserialize};
use serde::export::fmt::Display;
use serde::export::Formatter;
use core::fmt;
use jsonwebtoken::{Validation, Header};
use std::borrow::Borrow;
use actix_web::web::Data;
use auth_actix::{authenticate_from_request, write_token};

extern crate auth_actix;

/// Define User struct (used for our token)
#[derive(Serialize, Deserialize)]
struct User {
    name: String,
    age: i32
}

/// Display implementation, needed by FromRequest
impl Display for User {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}






/// FromRequest
///
/// allow to get it throught our endpoint function arguments
impl FromRequest for User {
    type Error = Error;
    type Future = Ready<Result<User, Error>>;
    type Config = ();

    fn from_request(
        req: &HttpRequest,
        _payload: &mut Payload<PayloadStream>
    ) -> Self::Future {





        let validation = Validation {
            validate_exp: false,
            ..Validation::default()
        };



        authenticate_from_request(req, &validation, b"secret")


    }
}





/// check token is valid
///
/// user is None => token invalid
async fn check_token(_req: HttpRequest, user: Option<User>) -> HttpResponse {



    let is_valid = match user {
        Some(user) =>
            format!("you are {}", user.name),
        None =>
            "token invalid".into()
    };



    HttpResponse::Ok()
        .body(is_valid)
}



/// host, get user token
async fn host(
    _req: HttpRequest,
    configuration: Data<Config>, // configuration for the token
    user: String // user information (body)
) -> HttpResponse {


    // we get user informations throught the body
    let user: Option<User> = serde_json::from_str(user.as_str()).ok();


    // then we get a token
    let token =
        user.and_then(
            |user|
                write_token(Header::default().borrow(), &user, configuration.secret)
    );



    // and return the token
    match token {
        Some(token) =>
            HttpResponse::Ok().json(token),
        None =>
            HttpResponse::Forbidden().body("Invalid credentials")
    }
}






/// Configuration, token information
struct Config {
    secret: &'static [u8]
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {


    let configuration = Data::new(
            Config { secret: b"secret" }
        );



    HttpServer::new(move ||
        App::new()

            // inject the configuration
            .app_data(configuration.clone())


            // endpoints
            .route("/check", web::get().to(check_token))
            .route("/host", web::post().to(host))
    )
        .bind("127.0.0.1:8080")?
        .run()
        .await
}

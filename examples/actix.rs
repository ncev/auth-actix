use actix_web::{HttpServer, web, App, HttpRequest, HttpResponse};
use serde::{Serialize, Deserialize};
use serde::export::fmt::Display;
use serde::export::Formatter;
use core::fmt;
use jsonwebtoken::Header;
use std::borrow::Borrow;
use actix_web::web::Data;
use auth_actix::write_token;
use auth_actix::types::{AuthConfiguration, Auth, run_auth};

extern crate auth_actix;

/// Define User struct (used for our token)
#[derive(Serialize, Deserialize)]
struct User {
    name: String,
    age: i32
}

/// Display implementation, needed by FromRequest
impl Display for User {
    fn fmt(&self, f: &mut Formatter<'_>)
        -> fmt::Result { write!(f, "{}", self.name) }
}


/// check token is valid
///
/// user is None => token invalid
///
/// note, user is wrapped in an Auth, meaning check it will check the token by itself
///
/// but, feel free to implement the 'FromRequest' by yourself for your own type
/// https://docs.rs/actix-web/3.3.2/actix_web/trait.FromRequest.html
///
async fn check_token(_req: HttpRequest, user: Option<Auth<User>>) -> HttpResponse {

    let is_valid = match user {
        Some(user) =>
            // run_auth simply unwrap the owned value
            format!("you are {}", run_auth(user).name),
        None =>
            "token invalid".into()
    };

    HttpResponse::Ok().body(is_valid)
}



/// host, get user token
async fn host(
    _req: HttpRequest,
    configuration: Data<AuthConfiguration>, // configuration for the token
    user: String // user information (body)
) -> HttpResponse {


    // we get user informations throught the body
    let user: Option<User> =
        serde_json::from_str(user.as_str()).ok();


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





#[actix_web::main]
async fn main() -> std::io::Result<()> {


    // initialise the configuration
    let configuration =
        Data::new(AuthConfiguration { secret: b"secret" });



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

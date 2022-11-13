#[macro_use]
extern crate rocket;

use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use jwt::VerifyWithKey;
use rocket::fairing::AdHoc;
use rocket::form::Form;
use rocket::outcome::Outcome;
use rocket::request::FromRequest;
use rocket::response::stream::{Event, EventStream};
use rocket::serde::json::serde_json;
use rocket::Config;
use rocket::State;
use rocket::{
    serde::{Deserialize, Serialize},
    tokio::sync::broadcast::{channel, Sender},
};
use rocket::{Data, Request, Response};
use sha2::Sha256;
use std::collections::BTreeMap;

#[derive(Clone, Debug, FromForm, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct Message {
    #[field(validate = len(..=30))]
    room: String,
    message: String,
    uid: String,
    timestamp: u32,
}

#[get("/test")]
fn test() -> &'static str {
    "Hello, world!"
}

#[derive(Clone, Debug, FromForm, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]

struct User {
    uid: String,
    name: String,
    token: String,
}

#[derive(Clone, Debug, FromForm, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct UserWoToken {
    uid: String,
    name: String,
    password: String,
}

const SECRET: &[u8] = b"secret";

async fn validate_user<'a>(uid: &'a str, password: &'a str) -> Option<UserWoToken> {
    let users: Vec<UserWoToken> = vec![
        UserWoToken {
            uid: "1".to_string(),
            name: "user1".to_string(),
            password: "password1".to_string(),
        },
        UserWoToken {
            uid: "2".to_string(),
            name: "user2".to_string(),
            password: "password2".to_string(),
        },
        UserWoToken {
            uid: "3".to_string(),
            name: "user3".to_string(),
            password: "password3".to_string(),
        },
    ];
    rocket::tokio::time::sleep(rocket::tokio::time::Duration::from_millis(100)).await;
    let user = users
        .into_iter()
        .find(|user| &user.uid == uid && user.password == password);
    match user {
        Some(_) => user,
        None => None,
    }
}

impl User {
    async fn new(user: &UserWoToken) -> Result<Self, String> {
        let UserWoToken { uid, password, .. } = user;
        if let Some(user) = validate_user(uid, password).await {
            //return found user with token
            let key: Hmac<Sha256> = Hmac::new_from_slice(SECRET).unwrap();
            let mut claims = BTreeMap::new();
            claims.insert("sub", uid);
            let token_str = claims.sign_with_key(&key).unwrap();
            Ok(User {
                uid: user.uid.clone(),
                name: user.name,
                token: token_str,
            })
        } else {
            Err("User not found".to_string())
        }
    }
}

//login route to get a token
#[post("/login", data = "<user>")]
async fn login(user: Form<UserWoToken>) -> String {
    match User::new(&user).await {
        Ok(user) => serde_json::to_string(&user).unwrap(),
        Err(e) => serde_json::to_string(&e).unwrap(),
    }
}

#[post("/message", data = "<form>")]
fn post(
    form: Form<Message>,
    sender: &State<Sender<Message>>,
    _uid: JWT,
) -> rocket::serde::json::Value {
    let form = form.into_inner();
    //may fail if no one is listening
    let res = sender.send(form.clone());
    if res.is_err() {
        println!("No one is listening");
    }
    serde_json::json!({
        "status": "ok",
        "message": &form
    })
}

#[get("/stream")]
async fn stream(sender: &State<Sender<Message>>, _uid: JWT) -> EventStream![] {
    let mut rx = sender.subscribe();
    EventStream! {
        loop {
            match rx.recv().await {
                Ok(message) => yield Event::json(&message),
                Err(_) => break,
            }
        }
    }
}
struct JWT(String);
#[rocket::async_trait]
impl<'r> FromRequest<'r> for JWT {
    type Error = String;
    async fn from_request(req: &'r Request<'_>) -> rocket::request::Outcome<Self, Self::Error> {
        let token = req.headers().get_one("Authorization");
        //strip the bearer part
        let token_str = match token {
            Some(token) => token[7..].to_string(),
            None => {
                return Outcome::Failure((
                    rocket::http::Status::Unauthorized,
                    "No token".to_string(),
                ))
            }
        };
        if token_str.is_empty() {
            return Outcome::Failure((rocket::http::Status::Unauthorized, "No token".to_string()));
        }
        let key: Hmac<Sha256> = Hmac::new_from_slice(SECRET).unwrap();
        let claims: BTreeMap<String, String> = token_str.verify_with_key(&key).unwrap();
        let uid = claims.get("sub").unwrap().to_owned();
        Outcome::Success(JWT(uid))
    }
}

fn rocket() -> rocket::Rocket<rocket::Build> {
    let rocket = rocket::build();
    let figment = rocket.figment();

    let _config: Config = figment.extract().expect("config");

    // Store the typed config in managed state
    rocket
        .mount("/", routes![test, login, post, stream])
        .manage(channel::<Message>(1024).0)
        .attach(AdHoc::config::<Config>())
}

#[rocket::main]
async fn main() {
    rocket().launch().await.unwrap();
}

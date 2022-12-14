#[macro_use]
extern crate rocket;

use chrono::Utc;
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use jwt::VerifyWithKey;
use rocket::fairing::AdHoc;
use rocket::form::Form;
use rocket::outcome::Outcome;
use rocket::request::FromRequest;
use rocket::response::stream::{Event, EventStream};
use rocket::serde::json::json;
use rocket::serde::json::serde_json;
use rocket::Config;
use rocket::Request;
use rocket::State;
use rocket::{
    serde::{Deserialize, Serialize},
    tokio::sync::broadcast::{channel, Sender},
};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

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
    refresh_token: String,
}

#[derive(Clone, Debug, FromForm, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct UserWoToken {
    #[field(validate = len(1..).or_else(msg!("uid is required")))]
    uid: String,
    #[field(validate = len(1..))]
    name: String,
    #[field(validate = len(1..))]
    password: String,
}

#[derive(Clone, Debug, FromForm, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct RefreshTokenPayload {
    refresh_token: String,
}

const SECRET: &[u8] = b"secret";
const REFRESH_TOKEN_SECRET: &[u8] = b"refresh_token_secret";

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

fn create_jwt_token(uid: &str, secret: &[u8]) -> String {
    let key = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    let mut claims = BTreeMap::new();
    claims.insert("sub", uid);
    let exp = (Utc::now().timestamp() + 43200).to_string();
    claims.insert("iat", &exp);
    claims.sign_with_key(&key).unwrap()
}

impl User {
    async fn new(user: &UserWoToken, token_map: &State<RefreshTokens>) -> Result<Self, String> {
        let UserWoToken { uid, password, .. } = user;
        if let Some(user) = validate_user(uid, password).await {
            //return found user with token
            let token = create_jwt_token(&user.uid, SECRET);
            let refresh_token = create_jwt_token(&user.uid, REFRESH_TOKEN_SECRET);
            //write token to map
            token_map.insert(refresh_token.clone(), token.clone());
            Ok(User {
                uid: user.uid.clone(),
                name: user.name,
                token,
                refresh_token,
            })
        } else {
            Err("User not found".to_string())
        }
    }
}

//login route to get a token
#[post("/login", data = "<user>")]
async fn login(user: Form<UserWoToken>, token_map: &State<RefreshTokens>) -> String {
    match User::new(&user, token_map).await {
        Ok(user) => serde_json::to_string(&user).unwrap(),
        Err(e) => e,
    }
}

//refresh token route
#[post("/refresh", data = "<refresh_token>")]
fn refresh(
    refresh_token: Form<RefreshTokenPayload>,
    token_map: &State<RefreshTokens>,
    token_from_header: JWT,
) -> serde_json::Value {
    let old_refresh_token = refresh_token.into_inner().refresh_token;
    let token_from_header = token_from_header.0;
    let uid = match get_fields_from_token(&token_from_header) {
        Some((uid, _)) => uid,
        None => "".to_string(),
    };
    match token_map.read(old_refresh_token.as_str()) {
        Some(token) if token_from_header == token && !uid.is_empty() => {
            //we can only refresh the token if the token from the header is the same as the token in the map
            let new_token = create_jwt_token(&uid, SECRET);
            let new_refresh_token = create_jwt_token(&uid, REFRESH_TOKEN_SECRET);
            //update token in map
            token_map.insert(new_refresh_token.clone(), new_token.clone());
            token_map.delete(old_refresh_token.as_str());
            json!({ "token": new_token , "refresh_token": new_refresh_token })
        }
        Some(_) => json!({ "error": "invalid token was provided" }),
        None => json!({ "error": "refresh token not found", "uid": uid }),
    }
}

#[post("/message", data = "<form>")]
fn post(form: Form<Message>, sender: &State<Sender<Message>>, _token: JWT) -> serde_json::Value {
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
async fn stream(sender: &State<Sender<Message>>, _token: JWT) -> EventStream![] {
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
        if let Some((_, exp)) = get_fields_from_token(&token_str) {
            let exp = exp.parse::<i64>().unwrap();
            let now = Utc::now().timestamp();
            if exp < now {
                return Outcome::Failure((
                    rocket::http::Status::Unauthorized,
                    "Token expired".to_string(),
                ));
            }
            Outcome::Success(JWT(token_str))
        } else {
            Outcome::Failure((
                rocket::http::Status::Unauthorized,
                "Invalid token".to_string(),
            ))
        }
    }
}
fn get_fields_from_token(token: &str) -> Option<(String, String)> {
    if token.is_empty() {
        None
    } else {
        let key: Hmac<Sha256> = Hmac::new_from_slice(SECRET).unwrap();
        let claims: BTreeMap<String, String> = token.verify_with_key(&key).unwrap();
        let uid = claims.get("sub").unwrap().to_owned();
        let exp = claims.get("iat").unwrap().to_owned();
        Some((uid, exp))
    }
}

//state to hold the list of refresh tokens
//ideally this should be a database
type TokenMap = Mutex<HashMap<String, String>>;

struct RefreshTokens(TokenMap);

impl RefreshTokens {
    fn new() -> Self {
        RefreshTokens(Mutex::new(HashMap::new()))
    }
    fn insert(&self, refresh_token: String, token: String) {
        let mut map = self.0.lock().unwrap();
        map.insert(refresh_token, token);
    }
    fn read(&self, refresh_token: &str) -> Option<String> {
        let map = self.0.lock().unwrap();
        map.get(refresh_token).map(|s| s.to_string())
    }

    fn read_all(&self) -> Vec<(String, String)> {
        let map = self.0.lock().unwrap();
        map.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    fn delete(&self, refresh_token: &str) {
        let mut map = self.0.lock().unwrap();
        map.remove(refresh_token);
    }
}

fn rocket() -> rocket::Rocket<rocket::Build> {
    let rocket = rocket::build();

    rocket
        .mount("/", routes![test, login, post, stream, refresh])
        .manage(channel::<Message>(1024).0)
        .manage(RefreshTokens::new())
}

#[rocket::main]
async fn main() {
    rocket().launch().await.unwrap();
}

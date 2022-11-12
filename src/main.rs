#[macro_use]
extern crate rocket;

use rocket::form::Form;
use rocket::response::stream::{Event, EventStream};
use rocket::serde::json::serde_json;
use rocket::State;
use rocket::{
    serde::{Deserialize, Serialize},
    tokio::sync::broadcast::{channel, Sender},
};

#[derive(Clone, Debug, FromForm, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct Message {
    #[field(validate = len(..=30))]
    room: String,
    message: String,
    uid: u32,
    timestamp: u32,
}

#[get("/test")]
fn test() -> &'static str {
    "Hello, world!"
}

#[post("/message", data = "<form>")]
fn post(form: Form<Message>, sender: &State<Sender<Message>>) -> rocket::serde::json::Value {
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
async fn stream(sender: &State<Sender<Message>>) -> EventStream![] {
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

#[launch]
fn rocket() -> _ {
    rocket::build()
        .manage(channel::<Message>(1014).0)
        .mount("/", routes![test, post, stream])
}

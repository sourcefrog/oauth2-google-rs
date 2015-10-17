use std::io::prelude::*;
use std::io;
use std::process;

extern crate oauth2;

// TODO: Move to client_secrets.json.
static CLIENT_ID: &'static str = "723533174019-rc74ecb4n6fl0papdl6qj89rsd286j0i.apps.googleusercontent.com";
static AUTH_URI: &'static str = "https://accounts.google.com/o/oauth2/auth";
static TOKEN_URI: &'static str = "https://accounts.google.com/o/oauth2/token";
// static "auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs";
static CLIENT_SECRET: &'static str = "zBZtr2fEz5yoFGWux4wK2vbj";
static REDIRECT_URI: &'static str = "urn:ietf:wg:oauth:2.0:oob";

fn main() {
    let scopes: Vec<String> = vec!["https://www.googleapis.com/auth/drive.readonly".to_string()];
    let oauth2_config = oauth2::Flow::new(
        CLIENT_ID, CLIENT_SECRET, AUTH_URI, TOKEN_URI,
        REDIRECT_URI, scopes);

    let auth_url_str = oauth2_config.get_authorize_uri(
        "Authorize oauth2-google example application?".to_string()).serialize();
    println!("{}", auth_url_str);

    process::Command::new("open").arg(auth_url_str).spawn().unwrap();

    println!("Please enter the OAuth2 code, then press enter.");
    let mut code = String::new();

    io::stdin().read_line(&mut code)
        .ok().expect("Failed to read line");

    println!("{:?}", oauth2_config.exchange(code));

}

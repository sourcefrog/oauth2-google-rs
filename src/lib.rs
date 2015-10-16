#![cfg_attr(test, deny(warnings))]

extern crate url;
extern crate curl;
#[macro_use] extern crate log;
extern crate rustc_serialize;

// TODO: Maybe serde not rustc_serialize?
use rustc_serialize::json;

use url::Url;
use std::collections::HashMap;

/// TODO: Is Hyper better than Curl for Rust?
use curl::http;

/// A flow by which an OAuth2 application can aquire credentials.
pub struct Flow {
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub auth_url: Url,
    pub token_url: Url,
    pub redirect_url: String,
    pub response_type: String,
}

/// Credentials that can be used to make general API calls.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, RustcDecodable, RustcEncodable)]
pub struct Credentials {
    pub access_token: String,
    // pub scopes: Vec<String>,
    pub token_type: String,
    pub expires_in: u32,
    pub refresh_token: String,
}

/// Helper trait for extending the builder-style pattern of curl::Request.
///
/// This trait allows chaining the correct authorization headers onto a curl
/// request via the builder style.
pub trait Authorization {
    fn auth_with(self, token: &Credentials) -> Self;
}

impl Flow {
    /// TODO: Option to load from client_secrets.json as recommended by
    /// Google.
    pub fn new(id: &str, secret: &str, auth_url: &str,
               token_url: &str, redirect_url: &str,
               scopes: Vec<String>) -> Flow {
        Flow {
            client_id: id.to_string(),
            client_secret: secret.to_string(),
            auth_url: Url::parse(auth_url).unwrap(),
            token_url: Url::parse(token_url).unwrap(),
            redirect_url: redirect_url.to_string(),
            response_type: "code".to_string(),
            scopes: scopes.clone(),
        }
    }

    #[allow(deprecated)] // connect => join in 1.3
    /// Make a URL at which the user can authorize the application.
    ///
    /// `state` is a string to be shown to the user in the authorization flow.
    ///
    /// TODO: Maybe take a list of scopes here rather than in the config.
    pub fn get_authorize_uri(&self, state: String) -> Url {
        let scopes = self.scopes.connect(",");
        let mut pairs = vec![
            ("client_id", &self.client_id),
            ("state", &state),
            ("scope", &scopes),
            ("response_type", &self.response_type),
        ];
        if self.redirect_url.len() > 0 {
            pairs.push(("redirect_uri", &self.redirect_url));
        }
        let mut url = self.auth_url.clone();
        url.set_query_from_pairs(pairs.iter().map(|&(k, v)| {
            (k, &v[..])
        }));
        return url;
    }

    /// Exchange an authorization code for credentials.
    ///
    /// `code` is obtained after the user authorizes the application at
    /// `get_authorize_uri`, and then typically pastes the code back to this
    /// application.
    pub fn exchange(&self, code: String) -> Result<Credentials, String> {
        let mut form = HashMap::new();
        form.insert("client_id", self.client_id.clone());
        form.insert("client_secret", self.client_secret.clone());
        form.insert("code", code);
        if self.redirect_url.len() > 0 {
            form.insert("redirect_uri", self.redirect_url.clone());
        }
        form.insert("grant_type", "authorization_code".to_string());

        let form = url::form_urlencoded::serialize(form.iter().map(|(k, v)| {
            (&k[..], &v[..])
        }));
        let form = form.into_bytes();
        let mut form = &form[..];

        let result = try!(http::handle()
                               .post(&self.token_url.to_string()[..], &mut form)
                               .header("Content-Type",
                                       "application/x-www-form-urlencoded")
                               .exec()
                               .map_err(|s| s.to_string()));

        if result.get_code() != 200 {
            return Err(format!("expected `200`, found `{}`: {}",
                               result.get_code(),
                               String::from_utf8_lossy(result.get_body())))
        }

        println!("response headers: {:?}", result.get_headers());
        
        // TODO: If response isn't 200, return some appropriate error,
        // including the body.

        let body_string = std::str::from_utf8(result.get_body()).unwrap();
        println!("{}", body_string);
        let token: Credentials = json::decode(body_string).unwrap();
        
        // TODO: Check whether the response is json or urlencoded, and decode
        // appropriately.
        Ok(token)
    }
}

// TODO: Perhaps this wants 'bearer' not 'token' for Google?
impl<'a, 'b> Authorization for http::Request<'a, 'b> {
    fn auth_with(self, token: &Credentials) -> http::Request<'a, 'b> {
        self.header("Authorization",
                    &format!("token {}", token.access_token))
    }
}

//! Library for Zaim API

use crate::oauth1a::OAuth1;

use std::collections::HashMap;
use std::io::stdin;
use std::error::Error;

use anyhow::Result;
use reqwest::{header, Request, RequestBuilder, Client, Method, Url};
use serde;
use serde_json;

pub const REQUEST_TOKEN_URL: &str = "https://api.zaim.net/v2/auth/request";
pub const AUTH_URL: &str = "https://auth.zaim.net/users/auth";
pub const ACCESS_TOKEN_URL: &str = "https://api.zaim.net/v2/auth/access";

#[derive(serde::Deserialize, Debug)]
pub struct ConsumerInfo {
    pub consumer_key: String,
    pub consumer_secret: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct AccessTokens {
    pub access_token: String,
    pub access_token_secret: String,
}

impl AccessTokens {
    fn new_uninit() -> Self {
        Self {
            access_token: String::new(),
            access_token_secret: String::new(),
        }
    }
}

pub struct ZaimApi {
    pub oauth1: OAuth1,
    pub consumer_info: ConsumerInfo,
    pub access_tokens: Option<AccessTokens>,
}

impl ZaimApi {
    pub fn new(
        oauth1: OAuth1,
        consumer_info: ConsumerInfo,
        access_tokens: Option<AccessTokens>
    ) -> Self {

        Self { oauth1, consumer_info, access_tokens }
    }

    pub fn authenticate(&mut self) -> Result<(), ZaimApiError> {
        if self.access_tokens.is_some() {
            return Ok(());
        }

        match authenticate(&self.oauth1) {
            Ok(tokens) => self.access_tokens = Some(tokens),
            Err(e) => return Err(e)
        }

        Ok(())
    }

    pub fn is_authenticated(&self) -> bool {
        self.access_tokens.is_some()
    }

    fn request_rest_api(
        &self,
        url: &str,
        protocol: &str,
        queries: Option<&HashMap<String, String>>
    ) -> Result<String, ZaimApiError> {
        let _access_tokens = self.access_tokens.as_ref().unwrap();
        request_rest_api(
            &self.oauth1,
            url,
            protocol,
            &_access_tokens.access_token,
            &_access_tokens.access_token_secret,
            queries
        )
    }

    pub fn rest_api_verify_user(&self) -> Result<(), ZaimApiError> {
        if self.access_tokens.is_some() {
            let _access_tokens = &self.access_tokens.as_ref().unwrap();
            return rest_api_verify_user(
                &self.oauth1,
                &_access_tokens.access_token,
                &_access_tokens.access_token_secret,
            )
        } else {
            return Err(ZaimApiError::new(
                String::from("User authentication not done")
            ));
        }
    }
}

#[derive(Debug)]
pub struct ZaimApiError {
    description: String,
}

impl ZaimApiError {
    fn new(description: String) -> Self {
        Self { description }
    }
}

impl Error for ZaimApiError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl std::fmt::Display for ZaimApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description)
    }
}

#[derive(Debug)]
pub struct UnauthorizedRequestToken {
    pub request_token: String,
    pub request_token_secret: String,
    pub callback_confirmed: bool,
}

impl UnauthorizedRequestToken {
    fn new_uninit() -> Self {
        Self {
            request_token: String::new(),
            request_token_secret: String::new(),
            callback_confirmed: false,
        }
    }
}

fn _gen_request_for_get(
    url: &str,
    headers: header::HeaderMap,
    queries: Option<&HashMap<String, String>>
) -> Result<RequestBuilder> {
    let mut request_builder = RequestBuilder::from_parts(
        Client::new(), Request::new(Method::GET, Url::parse(url)?)
    );
    request_builder = request_builder.headers(headers);

    if queries.is_some() {
        request_builder = request_builder.query(queries.unwrap());
    }

    Ok(request_builder)
}

fn _gen_request_for_post(
    url: &str,
    headers: header::HeaderMap,
    queries: Option<&HashMap<String, String>>
) -> Result<RequestBuilder> {
    let mut request_builder = RequestBuilder::from_parts(
        Client::new(), Request::new(Method::POST, Url::parse(url)?)
    );
    request_builder = request_builder.headers(headers);

    if queries.is_some() {
        // NOTE: unwrap is safety?
        request_builder = request_builder.body(
            serde_json::to_string(queries.unwrap()).unwrap()
        );
    }

    Ok(request_builder)
}

#[tokio::main]
async fn request(
    url: &str,
    protocol: &str,
    auth: &str,
    queries: Option<&HashMap<String, String>>
) -> Result<String, ZaimApiError> {
    let mut headers = header::HeaderMap::new();
    let auth_header_value;
    match header::HeaderValue::from_str(auth) {
        Ok(v) => auth_header_value = v,
        Err(e) => return Err(ZaimApiError::new(format!("reqwest Error: {}", e))),
    }
    headers.insert(header::AUTHORIZATION, auth_header_value);

    let request_builder;
    if protocol == "GET" {
        request_builder = match _gen_request_for_get(url, headers, queries){
            Ok(r) => r,
            Err(e) => return Err(ZaimApiError::new(format!("reqwest Error: {}", e))),
        }
    } else if protocol == "POST" {
        request_builder = match _gen_request_for_post(url, headers, queries){
            Ok(r) => r,
            Err(e) => return Err(ZaimApiError::new(format!("reqwest Error: {}", e))),
        }
    } else {
        return Err(ZaimApiError::new(format!("Unexpected protocol: {}", protocol)));
    }

    let ret = request_builder.send().await;
    
    let http_res;
    match ret {
        Ok(r) => http_res = r,
        Err(e) => return Err(ZaimApiError::new(format!("reqwest Error: {}", e))),
    }
    let status = http_res.status();
    if status == reqwest::StatusCode::OK {
        match http_res.text().await {
            Ok(data) => return Ok(data),
            Err(e) => return Err(ZaimApiError::new(format!("reqwest Error: {}", e))),
        }
    } else {
        return Err(ZaimApiError::new(format!("reqwest Error: {}", status)));
    }
}

pub fn request_request_token(
    url: &str,
    auth: &str
) -> Result<UnauthorizedRequestToken, ZaimApiError> {
    let mut response = UnauthorizedRequestToken::new_uninit();
    let mut flags: u32 = 0;
    let http_res = request(url, "POST", auth, None);

    if let Err(e) = http_res {
        return Err(ZaimApiError::new(format!("Failed http request: {}", e)));
    }
    let http_res = http_res.unwrap();

    let tokens = http_res.split('&');
    for token in tokens {
        let mut key_value: Vec<String> = token.split("=").map(String::from).collect();
        if key_value.len() != 2 {
            return Err(ZaimApiError::new(format!("Unexpected response format")));
        }

        let v = key_value.pop().unwrap();
        let k = key_value.pop().unwrap();

        if k.as_str() == "oauth_token" {
            response.request_token = v;
            flags |= 1;
        } else if k.as_str() == "oauth_token_secret" {
            response.request_token_secret = v;
            flags |= 2;
        } else if k.as_str() == "oauth_callback_confirmed" {
            if v == "true" {
                response.callback_confirmed = true;
            } else if v == "false" {
                response.callback_confirmed = false;
            } else {
                return Err(ZaimApiError::new(String::from("Error: Unexpected value of 'oauth_callback_confirmed' key")));
            }
            flags |= 4;
        } else {
            eprintln!("Warn: Unknown key: {}", k);
        }
    }       

    if flags != 0b111u32 {
        return Err(ZaimApiError::new(String::from("response is not completed")));
    }

    Ok(response)
}

pub fn request_access_token(
    url: &str,
    auth: &str
) -> Result<AccessTokens, ZaimApiError> {
    let mut response = AccessTokens::new_uninit();
    let mut flags: u32 = 0;
    let http_res = request(url, "POST", auth, None);

    if let Err(e) = http_res {
        return Err(ZaimApiError::new(format!("Failed http request: {}", e)));
    }
    let http_res = http_res.unwrap();

    let tokens = http_res.split('&');
    for token in tokens {
        let mut key_value: Vec<String> = token.split("=").map(String::from).collect();
        if key_value.len() != 2 {
            return Err(ZaimApiError::new(format!("Error: Unexpected response format")));
        }

        let v = key_value.pop().unwrap();
        let k = key_value.pop().unwrap();

        if k.as_str() == "oauth_token" {
            response.access_token = v;
            flags |= 1;
        } else if k.as_str() == "oauth_token_secret" {
            response.access_token_secret = v;
            flags |= 2;
        } else {
            eprintln!("Warn: Unknown key: {}", k);
        }
    }

    if flags != 0b11u32 {
        return Err(ZaimApiError::new(String::from("response is not completed")));
    }

    Ok(response)
}

pub fn authenticate(oauth1: &OAuth1) -> Result<AccessTokens, ZaimApiError> {
    let auth_for_request_token = oauth1.gen_auth_for_request_token();
    if let Err(e) = auth_for_request_token {
        return Err(ZaimApiError::new(
            format!("Failed to gen auth for request token: {}", e)
        ));
    }
    let auth_for_request_token = auth_for_request_token.unwrap();

    let request_tokens = request_request_token(
        REQUEST_TOKEN_URL,
        auth_for_request_token.as_str()
    );

    if let Err(e) = request_tokens {
        return Err(ZaimApiError::new(
            format!("Failed to get request tokens: {}", e)
        ));
    }
    let request_tokens = request_tokens.unwrap();

    println!("Please access following url by your web browser.\n  {}",
            oauth1.gen_user_auth_link(request_tokens.request_token.as_str()));
    println!("When you can get verifier code, input it.");

    let mut user_input = String::new();
    if let Err(e) = stdin().read_line(&mut user_input) {
        return Err(ZaimApiError::new(
            format!("Failed to read user input\n{}", e)
        ));
    }
    let verifier_code = user_input.trim().to_string();

    let auth_for_access_token = oauth1.gen_auth_for_access_token(
        &request_tokens.request_token,
        &request_tokens.request_token_secret,
        &verifier_code
    );
    if let Err(e) = auth_for_access_token {
       return Err(ZaimApiError::new(
            format!("Failed to gen auth for access token: {}", e)
        ));
    }
    let auth_for_access_token = auth_for_access_token.unwrap();

    let access_tokens = request_access_token(
        ACCESS_TOKEN_URL,
        auth_for_access_token.as_str()
    );

    if let Err(e) = access_tokens {
        return Err(ZaimApiError::new(
            format!("Failed to get access tokens: {}", e)
        ));
    }
    let access_tokens = access_tokens.unwrap();

    Ok(access_tokens)
}

pub fn request_rest_api(
    oauth1: &OAuth1,
    url: &str,
    protocol: &str,
    access_token: &str,
    access_token_secret: &str,
    queries: Option<&HashMap<String, String>>
) -> Result<String, ZaimApiError> {
    let auth = oauth1.gen_auth_for_rest_api(
        url,
        protocol,
        access_token,
        access_token_secret,
        queries
    );

    if let Err(e) = auth {
        return Err(ZaimApiError::new(format!("Failed to generate auth: {}", e)));
    }
    let auth = auth.unwrap();

    request(url, protocol, &auth, queries)
}

// NOTE: This is debug code
pub fn rest_api_verify_user(
    oauth1: &OAuth1,
    access_token: &str,
    access_token_secret: &str
) -> Result<(), ZaimApiError> {
    let url = "https://api.zaim.net/v2/home/user/verify";
    let protocol = "GET";

    let http_res = request_rest_api(
        oauth1,
        url,
        protocol,
        access_token,
        access_token_secret,
        None
    );
    if let Err(e) = http_res {
        return Err(ZaimApiError::new(format!("Failed http request: {}", e)));
    }
    let http_res = http_res.unwrap();
    println!("Response:\n{}", http_res);

    Ok(())
}

// NOTE: This is debug code
pub fn rest_api_fetch_transactions(
    oauth1: &OAuth1,
    access_token: &str,
    access_token_secret: &str
) -> Result<(), ZaimApiError> {
    let url = "https://api.zaim.net/v2/home/money";
    let protocol = "GET";
    let mut queries: HashMap<String, String> = HashMap::new();

    queries.insert(
        String::from("mapping"),
        String::from("1"),
    );
    queries.insert(
        String::from("page"),
        String::from("1"),
    );
    queries.insert(
        String::from("mode"),
        String::from("payment"),
    );
    queries.insert(
        String::from("group_by"),
        String::from("receipt_id"),
    );
    // queries.insert(
    //     String::from("start_date"),
    //     String::from("2024-06-17"),
    // );
    // queries.insert(
    //     String::from("end_date"),
    //     String::from("2024-06-23"),
    // );


    let http_res = request_rest_api(
        oauth1,
        url,
        protocol,
        access_token,
        access_token_secret,
        Some(&queries)
    );
    if let Err(e) = http_res {
        return Err(ZaimApiError::new(format!("Failed http request: {}", e)));
    }
    let http_res = http_res.unwrap();
    println!("Response:\n{}", http_res);

    Ok(())

}

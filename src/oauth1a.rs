//! Implementation of OAuth1a

use crate::helper;

use std::collections::HashMap;

use anyhow::Result;
use base64::prelude::*;
use hmac::{Hmac, Mac};
use sha1::Sha1;
type HmacSha1 = Hmac<Sha1>;

pub struct OAuth1 {
    pub consumer_key: String,
    pub consumer_secret: String,
    pub request_token_url: String,
    pub auth_url: String,
    pub access_token_url: String,

    pub signature_method: String,
    pub version: String,
    pub callback: String,
}

impl OAuth1 {
    pub fn new(
        consumer_key: String,
        consumer_secret: String,
        callback: String,
        request_token_url: String,
        auth_url: String,
        access_token_url: String,
    ) -> Self {
        Self {
            consumer_key: consumer_key,
            consumer_secret: consumer_secret,
            request_token_url: request_token_url,
            auth_url: auth_url,
            access_token_url: access_token_url,
            signature_method: String::from("HMAC-SHA1"),
            version: String::from("1.0"),
            callback: callback,
        }
    }
    
    fn _into_oauth_base_params(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();

        params.insert(
            String::from("oauth_consumer_key"),
            String::from(&self.consumer_key)
        );
        params.insert(
            String::from("oauth_signature_method"),
            String::from(&self.signature_method)
        );
        params.insert(
            String::from("oauth_version"),
            String::from(&self.version)
        );

        params
    }

    /// Generate signing key
    /// If access_token is not None, return "<token>&<token_secret>"
    /// If access_token is None, return "<token>&".
    pub fn gen_signing_key(token: &str, token_secret: Option<&str>) -> String {
        let mut key = String::from(token);
        key.push('&');
        if let Some(ts) = token_secret {
            key.push_str(ts);
        }

        key
    }

    pub fn gen_signature_base_string(
        auth_params: &HashMap<String, String>,
        protocol: &str,
        url: &str,
        queries: Option<&HashMap<String, String>>
    ) -> String {
        let mut request_params: HashMap<String, String> = HashMap::new();
        request_params.extend(auth_params.clone());
        if queries.is_some() {
            request_params.extend(queries.unwrap().clone());
        }

        let mut base_str = String::from(protocol);
        base_str.push('&');

        let url_encoded = helper::percent_encode(url);
        base_str.push_str(url_encoded.as_str());
        base_str.push('&');

        let mut keys: Vec<&String> = request_params.keys().collect();
        keys.sort();
        let mut params_str = String::new();
        for k in keys {
            params_str.push_str(k.as_str());
            params_str.push('=');
            params_str.push_str(request_params.get(k).unwrap());
            params_str.push('&');
        }
        if ! params_str.is_empty() {
            params_str.pop();
        }

        let params_str = helper::percent_encode(params_str.as_str());

        base_str.push_str(params_str.as_str());

        base_str
    }

    pub fn gen_signature(
        signature_base_string: String,
        signing_key: String
    ) -> anyhow::Result<String> {
        let mut mac = HmacSha1::new_from_slice(signing_key.into_bytes().as_slice())?;
        mac.update(signature_base_string.into_bytes().as_slice());

        let result = mac.finalize();
        let s_hmac = result.into_bytes();
        let s_hmac_base64: String = BASE64_STANDARD.encode(s_hmac.as_slice());
        Ok(helper::percent_encode(s_hmac_base64.as_str()))
    }

    /// Generate user authentication url.
    pub fn gen_user_auth_link(&self, request_token: &str) -> String {
        format!("{}?oauth_token={}", self.auth_url, request_token)
    }

    fn _gen_auth_common(
        &self,
        url: &str,
        protocol: &str,
        mut params: HashMap<String, String>,
        token_secret: Option<&str>,
        queries: Option<&HashMap<String, String>>
    ) -> Result<String> {
        let signing_key = OAuth1::gen_signing_key(self.consumer_secret.as_str(), token_secret);
        let signature_base_string = OAuth1::gen_signature_base_string(
            &params, protocol, url, queries
        );
        let signature = OAuth1::gen_signature(
            signature_base_string, signing_key
        )?;
        params.insert(
            String::from("oauth_signature"),
            signature
        );

        let mut keys_sorted: Vec<&String> = params.keys().collect();
        keys_sorted.sort();
        let mut auth = String::from("OAuth ");
        for key in keys_sorted {
            auth.push_str(format!(
                "{}=\"{}\", ", key, params.get(key).unwrap()
            ).as_str());
        }
        // remove ", "
        let _ = auth.pop();
        let _ = auth.pop();
        
        Ok(auth)
    }

    pub fn gen_auth_for_request_token(&self) -> Result<String> {
        let mut params = self._into_oauth_base_params();
        params.insert(
            String::from("oauth_nonce"),
            String::from(helper::get_random_string(32)),
        );
        params.insert(
            String::from("oauth_timestamp"),
            String::from(helper::get_unix_timestamp()?.to_string()),
        );
        params.insert(
            String::from("oauth_callback"),
            helper::percent_encode(self.callback.as_str()),
        );

        self._gen_auth_common(
            self.request_token_url.as_str(),
            "POST",
            params,
            None,
            None
        )
    }

    pub fn gen_auth_for_access_token(
        &self,
        request_token: &str,
        request_token_secret: &str,
        verifier_code: &str
    ) -> Result<String> {
        let mut params = self._into_oauth_base_params();

        params.insert(
            String::from("oauth_token"),
            String::from(request_token),
        );
        params.insert(
            String::from("oauth_nonce"),
            String::from(helper::get_random_string(32)),
        );
        params.insert(
            String::from("oauth_timestamp"),
            String::from(helper::get_unix_timestamp()?.to_string()),
        );
        params.insert(
            String::from("oauth_verifier"),
            String::from(verifier_code),
        );

        self._gen_auth_common(
            self.access_token_url.as_str(),
            "POST",
            params,
            Some(request_token_secret),
            None
        )
    }

    pub fn gen_auth_for_rest_api(
        &self,
        url: &str,
        protocol: &str,
        access_token: &str,
        access_token_secret: &str,
        queries: Option<&HashMap<String, String>>
    ) -> Result<String> {
        let mut params = self._into_oauth_base_params();

        params.insert(
            String::from("oauth_token"),
            String::from(access_token),
        );
        params.insert(
            String::from("oauth_nonce"),
            String::from(helper::get_random_string(32)),
        );
        params.insert(
            String::from("oauth_timestamp"),
            String::from(helper::get_unix_timestamp()?.to_string()),
        );

        self._gen_auth_common(
            url,
            protocol,
            params,
            Some(access_token_secret),
            queries
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::helper;
    use super::OAuth1;
    use std::collections::HashMap;

    // Dummy data
    const PROTOCOL: &str = "POST";
    const CONSUMER_KEY: &str = "qazjrpypgj2dmk85rt2wdfgwidots6phmd8bn6qt";
    const CONSUMER_SECRET: &str = "0pgz53iyp7cajbaqtyhnjj3cbqivog5iil7wybvh";
    const CALLBACK: &str = "https://zaim.net/";
    const REQUEST_TOKEN_URL: &str = "https://api.zaim.net/v2/auth/request";
    const AUTH_URL: &str = "https://auth.zaim.net/users/auth";
    const ACCESS_TOKEN_URL: &str = "https://api.zaim.net/v2/auth/access";

    const TIMESTAMP: &str = "1718193989";
    const NONCE: &str = "85877103587931253546137854859006";

    // Answer
    const ANS_SIGNING_KEY: &str = "0pgz53iyp7cajbaqtyhnjj3cbqivog5iil7wybvh&";
    const ANS_SIGNATURE_BASE_STRING: &str = "POST&https%3A%2F%2Fapi.zaim.net%2Fv2%2Fauth%2Frequest&oauth_callback%3Dhttps%253A%252F%252Fzaim.net%252F%26oauth_consumer_key%3Dqazjrpypgj2dmk85rt2wdfgwidots6phmd8bn6qt%26oauth_nonce%3D85877103587931253546137854859006%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1718193989%26oauth_version%3D1.0";
    const ANS_SIGNATURE: &str = "RK8sOwCsye4tH0fTWiTCrPH8dJA%3D";

    fn prepare_oauth1() -> OAuth1 {
        OAuth1::new(
            CONSUMER_KEY.to_string(),
            CONSUMER_SECRET.to_string(),
            CALLBACK.to_string(),
            REQUEST_TOKEN_URL.to_string(),
            AUTH_URL.to_string(),
            ACCESS_TOKEN_URL.to_string()
        )
    }

    fn prepare_params(oauth1: &OAuth1) -> HashMap<String, String> {
        let mut params = oauth1._into_oauth_base_params();
        params.insert(
            String::from("oauth_nonce"),
            String::from(NONCE),
        );
        params.insert(
            String::from("oauth_timestamp"),
            String::from(TIMESTAMP),
        );
        params.insert(
            String::from("oauth_callback"),
            helper::percent_encode(CALLBACK),
        );

        params
    }

    #[test]
    fn test_oauth1_gen_signing_key() {
        let oauth1 = prepare_oauth1();
        let signing_key = OAuth1::gen_signing_key(oauth1.consumer_secret.as_str(), None);

        assert_eq!(signing_key, String::from(ANS_SIGNING_KEY));
    }

    #[test]
    fn test_oauth1_gen_signature_base_string() {
        let oauth1 = prepare_oauth1();
        let params = prepare_params(&oauth1);
        let signature_base_string = OAuth1::gen_signature_base_string(
            &params, PROTOCOL, REQUEST_TOKEN_URL, None
        );

        assert_eq!(signature_base_string, String::from(ANS_SIGNATURE_BASE_STRING));
    }

    #[test]
    fn test_oauth1_gen_signature() {
        let oauth1 = prepare_oauth1();
        let params = prepare_params(&oauth1);
        let signing_key = OAuth1::gen_signing_key(oauth1.consumer_secret.as_str(), None);
        let signature_base_string = OAuth1::gen_signature_base_string(
            &params, PROTOCOL, REQUEST_TOKEN_URL, None
        );
        let signature = OAuth1::gen_signature(
            signature_base_string, signing_key
        ).unwrap();

        assert_eq!(signature, String::from(ANS_SIGNATURE));
    }
}

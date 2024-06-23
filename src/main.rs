//! zaim-cli

mod helper;
mod oauth1a;
mod zaim_api;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{Read, Write};
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use serde_json;


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli{
    /// File path of consumer (client) information, which presented by json
    #[arg(long, value_name = "FILE")]
    consumer_info: PathBuf,

    /// File path of access tokens, which presented by json
    #[arg(long, value_name = "FILE")]
    access_token: Option<PathBuf>,

    /// Zaim Rest API URI
    #[arg(long, value_name = "URI")]
    uri: String,

    /// HTTP Method: GET, POST
    /// Please a http method for the specified rest api
    #[arg(long, value_name = "METHOD")]
    method: String,

    /// (Optional) Query parameters for the rest api
    #[arg(long, value_name = "JSON STR")]
    query: Option<String>,

    /// File to save response
    #[arg(long, value_name = "FILE")]
    save: PathBuf,
}

fn open_and_read_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut data = String::new();
    let _ = file.read_to_string(&mut data)?;

    Ok(data)
}

fn save_access_tokens(access_tokens: &zaim_api::AccessTokens) -> Result<()> {
    let mut file = File::create("access_tokens.json")?;
    let data = serde_json::to_string(access_tokens)?;
    file.write_all(data.as_bytes())?;

    Ok(())
}

fn save_api_response(save_file: &Path, response: &str) -> Result<()> {
    let mut file = File::create(save_file)?;
    file.write_all(response.as_bytes())?;

    Ok(())
}

fn main() -> ExitCode {
    let mut skip_user_confirm = false;
    let access_tokens: zaim_api::AccessTokens;
    let mut api_query_params: Option<HashMap<String, String>> = None;

    let cli = Cli::parse();

    let path_consumer_info = &cli.consumer_info;
    let path_access_token = cli.access_token.as_deref();

    if ! path_consumer_info.exists() {
        eprintln!("Error: {} not found", path_consumer_info.display());
        return ExitCode::FAILURE;
    }

    let consumer_data = match open_and_read_file(&path_consumer_info) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: failed to open and read {}\n{}", path_consumer_info.display(), e);
            return ExitCode::FAILURE;
        }
    };
    let consumer_info: zaim_api::ConsumerInfo = match serde_json::from_str(&consumer_data) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Error: failed to parse consumer_info into json\n{}", e);
            return ExitCode::FAILURE;
        }
    };

    if cli.query.is_some() {
        let ret = serde_json::from_str::<HashMap<String, String>>(cli.query.as_ref().unwrap());
        api_query_params = match ret {
            Ok(ret) => Some(ret),
            Err(e) => {
                eprintln!("Error: failed to parse query for rest api as json: {}", e);
                return ExitCode::FAILURE;
            }
        };
    }

    if let Some(p) = path_access_token {
        if p.exists() {
            // println!("Debug: Provided access token");
            skip_user_confirm = true;
        } else {
            eprintln!("Error: {} not found", p.display());
            return ExitCode::FAILURE;
        }
    }

    let oauth1 = oauth1a::OAuth1::new(
        consumer_info.consumer_key.clone(),
        consumer_info.consumer_secret.clone(),
        String::from("oob"),
        zaim_api::REQUEST_TOKEN_URL.to_string(),
        zaim_api::AUTH_URL.to_string(),
        zaim_api::ACCESS_TOKEN_URL.to_string()
    );

    if ! skip_user_confirm {
        access_tokens = match zaim_api::authenticate(&oauth1) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Error: {}", e);
                return ExitCode::FAILURE;
            }
        };

        if let Err(e) = save_access_tokens(&access_tokens) {
            eprintln!("Failed to save access tokens: {}", e);
            eprintln!("access_tokens:\n{:?}", access_tokens);
            return ExitCode::FAILURE;
        }
    } else {
        let p = path_access_token.unwrap();

        let data = open_and_read_file(&p);
        match data {
            Ok(d) => {
                access_tokens = match serde_json::from_str(&d) {
                    Ok(j) => j,
                    Err(e) => {
                        eprintln!("Error: failed to parse access_token into json\n{}", e);
                        return ExitCode::FAILURE;
                    }
                };
            },
            Err(e) => {
                eprintln!("Error: failed to open and read {}\n{}", p.display(), e);
                return ExitCode::FAILURE;
            }
        }

        // println!("Debug: access_tokens: {:?}", access_tokens);
    }

    let fetched_data = zaim_api::request_rest_api(
        &oauth1,
        &cli.uri,
        &cli.method,
        &access_tokens.access_token,
        &access_tokens.access_token_secret,
        api_query_params.as_ref(),
    );

    match fetched_data {
        Ok(data) => {
            if let Err(e) = save_api_response(&cli.save, &data) {
                eprintln!("Error: failed to save api response: {}", e);
                return ExitCode::FAILURE;
            }
        },
        Err(e) => {
            eprintln!("Error: failed to request to rest api: {}", e);
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}


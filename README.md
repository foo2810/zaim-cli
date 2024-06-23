# zaim-cli

zaim-cli is a cli tool to kick Zaim rest api.

This tool is written by Rust.


## Simple Example

Following example is to kick `https://api.zaim.net/v2/genre` (GET method).
Response is saved into "response.json".
```
$ cargo run -- --consumer-info consumer_info.json --access-token access_tokens.json --uri https://api.zaim.net/v2/genre --method GET --save response.json

$ jq < response.json
{
  "genres": [
    {
      "id": 10101,
      "name": "Groceries",
      "category_id": 101
    },
    {
      "id": 10102,
      "name": "Cafe",
      "category_id": 101
    },

    ...
```


## Necessary Information

You must prepare following information in advance.
- Consumer ID
- Consumer Secret 

You can get this information by signing in to "https://dev.zaim.net/users/login" and adding your application.


## Build

To build this tool, `cargo` is necessary.

Example:
```
$ cargo build --release
...

$ ls target/release/zaim-cli
target/release/zaim-cli

$ target/release/zaim-cli
error: the following required arguments were not provided:
  --consumer-info <FILE>
  --uri <URI>
  --method <METHOD>
  --save <FILE>

Usage: zaim-cli --consumer-info <FILE> --uri <URI> --method <METHOD> --save <FILE>

For more information, try '--help'.
```


## How to use

### Basic usage 

First, prepare json file that represents consumer infomation, and execute cli as following.
```
$ cat consumer_info.json 
{
    "consumer_key": "<your consumer id>",
    "consumer_secret": "<your consumer secret>"
}


$ cargo run -- --consumer-info consumer_info.json --uri https://api.zaim.net/v2/genre --method GET --save response.json
Please access following url by your web browser.
  https://auth.zaim.net/users/auth?oauth_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
When you can get verifier code, input it.
```

Copy displayed link (e.g. `https://auth.zaim.net/users/auth?oauth_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`) 
and access to this link by your browser.

Signing the site, a code is displayed.
So, copy the code and input into executing cli.

After that the cli kicks the specified api and save "response.json".
Also, access token and access token secret are saved into "access_tokens.json".
In next executing, use these tokens.

Next execution example:
```
$ cat access_tokens.json
{"access_token":"<your access token>","access_token_secret":"<your access token secret>"}

$ cargo run -- --consumer-info consumer_info.json --access-token access_tokens.json --uri https://api.zaim.net/v2/genre --method GET --save response.json
```

### Example using query parameters

Kick `https://api.zaim.net/v2/home/money` with query parameters.
```
$ cargo run -- --consumer-info consumer_info.json --access-token access_tokens.json --uri https://api.zaim.net/v2/home/money --method GET --query '{"mapping": "1", "mode": "payment", "group_by": "receipt_id"}' --save response.json
```


## License

These software may be freely used under the MIT License.
See the [LICENSE](LICENSE) file for copyright information and license notice.

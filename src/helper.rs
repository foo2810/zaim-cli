use anyhow::Result;
use rand::distributions::Distribution;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

#[allow(dead_code)]
pub fn type_of<T>(_: &T) -> &'static str {
    std::any::type_name::<T>()
}

pub fn get_random_string(sz: usize) -> String {
    rand::distributions::Alphanumeric
        .sample_iter(&mut rand::thread_rng())
        .filter(|x| *x >= 48 && *x <= 57)
        .take(sz)
        .map(char::from)
        .collect::<String>()
}

pub fn get_unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d: Duration| -> u64 {d.as_secs()})?)
}

const FRAGMENT: &AsciiSet = &CONTROLS
    .add(b':').add(b'/').add(b'?').add(b'#').add(b'[')
    .add(b']').add(b'@').add(b'!').add(b'$').add(b'&')
    .add(b'\'').add(b'(').add(b')').add(b'*').add(b'+')
    .add(b',').add(b';').add(b'=').add(b'%');

/// c.f. https://developer.mozilla.org/ja/docs/Glossary/Percent-encoding
pub fn percent_encode(string: &str) -> String {
    // utf8_percent_encode(string, NON_ALPHANUMERIC).to_string()
    utf8_percent_encode(string, FRAGMENT).to_string()
}

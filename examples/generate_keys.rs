use anyhow::Result;
use openssl::rsa::Rsa;
use std::{fs, path::Path};

const CONSUMER_RSA_PEM_FILEPATH: &str = "tests/consumer_rsa.pem";

fn main() -> Result<()> {
    fs::create_dir_all("tests")?;
    if !Path::new(CONSUMER_RSA_PEM_FILEPATH).exists() {
        let private_key = Rsa::generate(2048)?;
        let pem = private_key.private_key_to_pem()?;
        fs::write(CONSUMER_RSA_PEM_FILEPATH, pem)?;
    } else {
        println!("File already exists");
    }
    Ok(())
}

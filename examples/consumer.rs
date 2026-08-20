use anyhow::{Context, Error, Result};
use openssl::rsa::Rsa;
use std::fs;
use std::sync::Arc;
use tracing::info;

use z_abe::consumer::*;

const CONSUMER_RSA_PEM_FILEPATH: &str = "tests/consumer_rsa.pem";
const CONTENT_TOPIC: &str = "tenantA/example/test";

#[tokio::main]
async fn main() -> Result<()> {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(non_blocking)
        .init();

    // Configure log-tracing bridge
    tracing_log::LogTracer::init().ok();

    info!("Opening session...");
    let config = zenoh::Config::default();
    let session = zenoh::open(config).await.map_err(Error::from_boxed)?;

    // Set up the consumer
    let private_key_pem = fs::read_to_string(CONSUMER_RSA_PEM_FILEPATH)?;
    let private_key = Rsa::private_key_from_pem(private_key_pem.as_bytes())?;
    let content_key_store = InMemoryContentKeyStore::new();
    let consumer = Consumer::new(session.clone(), Arc::new(content_key_store), private_key);
    let mut cached_secret_key = consumer.get_secret_key().await?;

    // Declare zenoh subscriber
    let subscriber = session
        .declare_subscriber(CONTENT_TOPIC)
        .await
        .map_err(Error::from_boxed)?;

    while let Ok(sample) = subscriber.recv_async().await {
        // Encrypted content received from the producer
        let encrypted_content = sample.payload();

        // Get the secret key and cache it for future use
        if cached_secret_key.is_none() {
            cached_secret_key = consumer.get_secret_key().await?;
        }
        let secret_key = cached_secret_key.as_ref().context("No secret key")?;

        // Decrypt the content using the secret key
        let decrypted_content = consumer.decrypt(encrypted_content, secret_key).await?;
        let decrypted_content = decrypted_content.try_to_string().unwrap();

        info!(
            ">> [Subscriber] Received {} ('{}': '{}')",
            sample.kind(),
            sample.key_expr().as_str(),
            decrypted_content
        );
    }

    Ok(())
}

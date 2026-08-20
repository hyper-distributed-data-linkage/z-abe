use anyhow::{Error, Result};
use rabe::schemes::ac17::setup;
use tracing::info;
use z_abe::attribute_authority::*;

const CONSUMER_RSA_PUBLIC_KEY: &str = "MIIBCgKCAQEAwfw/Kz7GDTZ3oCoR1TgUVhz8zYLCtM1whzB47JGPYTOiftxexYlzPmOK5/M012GtNgm717Wn5Hn9NYK7WBhLOnOlW8on/oyuAvAwu90LnIZvlzl9PIG1TYqsTYhvlSVhTYUSSCzdwDPmdfD8UlhyK64aK8jZTSbE2dlsliRfozP9DeoHrELdRg42WofQRkivFB4EjlMFoGfsyqWYSDUTiCbo4JJipkmsYHNJ1UAS3XilK16hOyJdQOJYKbTYp9aGJUM8hWU8srGmEB8CZ8x86SBFgbrq9EjdzDheKfUPAmyK+2bxdGdGbFLo3Bb9YN5fdBCIVfi1+KoRbQgouwtH8wIDAQAB";
const CONSUMER_ATTRIBUTES: &[&str] = &["A", "B", "C"];

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

    // Set up the attribute authority
    let (pk, msk) = setup();
    let attribute_store = InMemoryAttributeStore::new();
    let attribute_authority = AttributeAuthority::new(session, attribute_store.clone(), pk, msk);

    // Spawn tasks to handle public key and secret key queries
    let attribute_authority_clone = attribute_authority.clone();
    let handle_pk_query = tokio::spawn(async move {
        attribute_authority_clone
            .handle_public_key_query()
            .await
            .unwrap()
    });

    let attribute_authority_clone = attribute_authority.clone();
    let handle_sk_query = tokio::spawn(async move {
        attribute_authority_clone
            .handle_secret_key_query()
            .await
            .unwrap()
    });

    // Update the attribute store with the consumer's public key and attributes
    attribute_store
        .set_attributes(CONSUMER_RSA_PUBLIC_KEY, CONSUMER_ATTRIBUTES)
        .await?;

    // Update the ABE keys in the attribute authority is possible (consumer whould have to get the new secret key)
    // let (new_pk, new_msk) = setup();
    // attribute_authority.update_abe_keys(new_pk, new_msk).await;

    tokio::try_join!(handle_pk_query, handle_sk_query)?;
    Ok(())
}

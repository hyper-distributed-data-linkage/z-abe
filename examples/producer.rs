use std::time::Duration;

use anyhow::Error;
use anyhow::Result;
use std::sync::Arc;
use tokio::time::sleep;
use tracing::info;

use z_abe::producer::*;

const PRODUCER_PREFIX: &str = "tenantA";
const CONTENT_TOPIC: &str = "tenantA/example/test";
const ROTATION_INTERVAL: u64 = 10;

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
    let session = zenoh::open(config).await.unwrap();

    // Set up the producer
    let content_key_store = Arc::new(InMemoryContentKeyStore::new());
    let producer = Producer::new(session.clone(), content_key_store, PRODUCER_PREFIX);

    // Declare zenoh publisher
    let publisher = session
        .declare_publisher(CONTENT_TOPIC)
        .await
        .map_err(Error::from_boxed)?;

    // Spawn a task to handle content key queries
    let producer_clone = producer.clone();
    tokio::spawn(async move { producer_clone.handle_content_key_query().await.unwrap() });

    // Initialize current CK and prepare next CK from the start
    producer
        .initialize_content_key(CONTENT_TOPIC)
        .await
        .unwrap();
    let (_next_ck_id, _next_ck) = producer
        .prepare_next_content_key(CONTENT_TOPIC)
        .await
        .unwrap();
    info!(">> [Publisher] Initial current CK and next CK prepared");

    let mut message_count: u64 = 0;

    loop {
        let content = "Hello, world!";

        // Get current content key
        let content_key = producer
            .get_current_content_key(CONTENT_TOPIC)
            .await
            .unwrap();

        // Get the next CK ID if available
        let next_ck_id = producer
            .get_next_content_key(CONTENT_TOPIC)
            .await
            .unwrap()
            .map(|(id, _)| id);

        message_count += 1;

        // Encrypt with current CK, including next_ck_id in the header if available
        let encrypted_content = producer
            .encrypt(content, &content_key, next_ck_id.clone())
            .unwrap();

        publisher
            .put(encrypted_content)
            .await
            .map_err(Error::from_boxed)?;

        info!(
            ">> [Publisher] Published ('{}': '{}') [message #{}, next_ck_id={:?}]",
            CONTENT_TOPIC, content, message_count, next_ck_id,
        );

        if message_count.is_multiple_of(ROTATION_INTERVAL) {
            // Rotate: set next CK as current CK
            producer.rotate_content_key(CONTENT_TOPIC).await.unwrap();
            info!(">> [Publisher] Content key rotated");

            // Prepare a new next CK (next_ck_id will change)
            let (new_next_ck_id, _new_next_ck) = producer
                .prepare_next_content_key(CONTENT_TOPIC)
                .await
                .unwrap();
            info!(
                ">> [Publisher] New next CK prepared, new next_ck_id={}",
                new_next_ck_id
            );
        }

        sleep(Duration::from_secs(1)).await;
    }
}

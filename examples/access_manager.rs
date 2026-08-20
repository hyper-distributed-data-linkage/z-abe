use anyhow::{Error, Result};
use tracing::info;
use z_abe::access_manager::*;

const CONTENT_TOPIC: &str = "tenantA/example/test";
const CONTENT_POLICY: &str = r#""A" or "B""#;

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

    // Set up the access manager
    let policy_store = InMemoryPolicyStore::new();
    let access_manager = AccessManager::new(session, policy_store.clone());

    // Spawn a task to handle policy queries
    let handle_policy_query =
        tokio::spawn(async move { access_manager.handle_policy_query().await.unwrap() });

    // Update the policy store with the content topic and policy
    policy_store
        .set_policy(CONTENT_TOPIC, CONTENT_POLICY)
        .await?;

    // It's compatible with both log and tracing.
    log::debug!("policy_store : {:?}", &policy_store);

    tokio::try_join!(handle_policy_query)?;
    Ok(())
}

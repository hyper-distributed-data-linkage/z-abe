use serial_test::serial;
use std::future::Future;
use test_log::test;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

/// Tests are serialized and all spawned tasks are aborted during teardown, so
/// they can safely reuse one set of ports.
mod net {
    fn build(listen: &[String], connect: &[String]) -> zenoh::Config {
        let to_json = |eps: &[String]| {
            format!(
                "[{}]",
                eps.iter()
                    .map(|e| format!("\"{e}\""))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let mut config = zenoh::Config::default();
        config
            .insert_json5("scouting/multicast/enabled", "false")
            .unwrap();
        config
            .insert_json5("listen/endpoints", &to_json(listen))
            .unwrap();
        config
            .insert_json5("connect/endpoints", &to_json(connect))
            .unwrap();
        config
    }

    fn attribute_authority_endpoint(port: u16) -> String {
        format!("tcp/127.0.0.1:{port}")
    }

    pub fn attribute_authority(port: u16) -> zenoh::Config {
        build(&[attribute_authority_endpoint(port)], &[])
    }

    pub fn peer(authority_port: u16) -> zenoh::Config {
        build(
            &["tcp/127.0.0.1:0".to_string()],
            &[attribute_authority_endpoint(authority_port)],
        )
    }
}

const PORT_BASE: u16 = 17440;

#[derive(Default)]
struct TestTasks(Vec<JoinHandle<()>>);

impl TestTasks {
    fn spawn<F>(&mut self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.0.push(tokio::spawn(future));
    }
}

impl Drop for TestTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

mod attribute_authority {
    use anyhow::Error;
    use rabe::schemes::ac17::setup;
    use z_abe::attribute_authority::*;

    pub async fn test_attribute_authority(
        consumer_rsa_public_key: &str,
        consumer_attributes: &[&str],
        port_base: u16,
    ) {
        log::info!("Opening session...");
        let config = crate::net::attribute_authority(port_base);
        let session = zenoh::open(config)
            .await
            .map_err(Error::from_boxed)
            .unwrap();

        // Set up the attribute authority
        let (pk, msk) = setup();
        let attribute_store = InMemoryAttributeStore::new();
        attribute_store
            .set_attributes(consumer_rsa_public_key, consumer_attributes)
            .await
            .unwrap();
        let attribute_authority =
            AttributeAuthority::new(session, attribute_store.clone(), pk, msk);

        // Run both query handlers in this task so cancelling it also cancels them.
        tokio::try_join!(
            attribute_authority.handle_public_key_query(),
            attribute_authority.handle_secret_key_query(),
        )
        .unwrap();
    }
}

mod access_manager {
    use anyhow::Error;
    use z_abe::access_manager::*;

    pub async fn test_access_manager(content_topic: &str, content_policy: &str, port_base: u16) {
        log::info!("Opening session...");
        let config = crate::net::peer(port_base);
        let session = zenoh::open(config)
            .await
            .map_err(Error::from_boxed)
            .unwrap();

        // Set up the access manager
        let policy_store = InMemoryPolicyStore::new();
        policy_store
            .set_policy(content_topic, content_policy)
            .await
            .unwrap();
        let access_manager = AccessManager::new(session, policy_store.clone());

        access_manager.handle_policy_query().await.unwrap();
    }
}

mod producer {
    use std::time::Duration;

    use anyhow::Error;
    use std::sync::Arc;
    use tokio::time::sleep;
    use z_abe::producer::*;

    pub async fn test_producer(
        producer_prefix: &str,
        content_topic: &str,
        content: &str,
        sleep_duration: Duration,
        port_base: u16,
    ) {
        log::info!("Opening session...");
        let config = crate::net::peer(port_base);
        let session = zenoh::open(config).await.unwrap();

        // Set up the producer
        let content_key_store = InMemoryContentKeyStore::new();
        let producer = Producer::new(
            session.clone(),
            Arc::new(content_key_store),
            producer_prefix,
        );

        // Declare zenoh publisher
        let publisher = session
            .declare_publisher(content_topic)
            .await
            .map_err(Error::from_boxed)
            .unwrap();

        // Keep the query task tied to this producer's lifetime.
        let producer_clone = producer.clone();
        let mut query_tasks = crate::TestTasks::default();
        query_tasks.spawn(async move {
            producer_clone.handle_content_key_query().await.unwrap();
        });

        // Initialize the content key before entering the loop
        producer
            .initialize_content_key(content_topic)
            .await
            .unwrap();

        loop {
            // Get current content key for the topic
            let content_key = producer
                .get_current_content_key(content_topic)
                .await
                .unwrap();

            // Encrypt the content using the content key
            let encrypted_content = producer.encrypt(content, &content_key, None).unwrap();

            // Publish the encrypted content
            publisher
                .put(encrypted_content)
                .await
                .map_err(Error::from_boxed)
                .unwrap();

            log::info!(
                ">> [Publisher] Published ('{}': '{}')",
                content_topic,
                content,
            );

            sleep(sleep_duration).await;
        }
    }

    /// Producer that performs CK rotation after `rotation_interval` messages,
    /// following the same pattern as examples/producer.rs.
    pub async fn test_producer_with_rotation(
        producer_prefix: &str,
        content_topic: &str,
        content: &str,
        sleep_duration: Duration,
        rotation_interval: u64,
        port_base: u16,
    ) {
        log::info!("Opening session...");
        let config = crate::net::peer(port_base);
        let session = zenoh::open(config).await.unwrap();

        let content_key_store = InMemoryContentKeyStore::new();
        let producer = Producer::new(
            session.clone(),
            Arc::new(content_key_store),
            producer_prefix,
        );

        let publisher = session
            .declare_publisher(content_topic)
            .await
            .map_err(Error::from_boxed)
            .unwrap();

        // Keep the query task tied to this producer's lifetime.
        let producer_clone = producer.clone();
        let mut query_tasks = crate::TestTasks::default();
        query_tasks.spawn(async move {
            producer_clone.handle_content_key_query().await.unwrap();
        });

        // Initialize current CK and prepare next CK
        producer
            .initialize_content_key(content_topic)
            .await
            .unwrap();
        let (_next_ck_id, _next_ck) = producer
            .prepare_next_content_key(content_topic)
            .await
            .unwrap();
        log::info!(">> [Publisher] Initial current CK and next CK prepared");

        let mut message_count: u64 = 0;

        loop {
            let content_key = producer
                .get_current_content_key(content_topic)
                .await
                .unwrap();

            let next_ck_id = producer
                .get_next_content_key(content_topic)
                .await
                .unwrap()
                .map(|(id, _)| id);

            message_count += 1;

            let encrypted_content = producer
                .encrypt(content, &content_key, next_ck_id.clone())
                .unwrap();

            publisher
                .put(encrypted_content)
                .await
                .map_err(Error::from_boxed)
                .unwrap();

            log::info!(
                ">> [Publisher] Published ('{}': '{}') [message #{}, next_ck_id={:?}]",
                content_topic,
                content,
                message_count,
                next_ck_id,
            );

            if message_count.is_multiple_of(rotation_interval) {
                producer.rotate_content_key(content_topic).await.unwrap();
                log::info!(
                    ">> [Publisher] Content key rotated at message #{}",
                    message_count
                );

                let (new_next_ck_id, _) = producer
                    .prepare_next_content_key(content_topic)
                    .await
                    .unwrap();
                log::info!(
                    ">> [Publisher] New next CK prepared, new next_ck_id={}",
                    new_next_ck_id
                );
            }

            sleep(sleep_duration).await;
        }
    }
}

mod consumer {
    use anyhow::{Context, Error};
    use openssl::rsa::Rsa;
    use std::fs;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;
    use z_abe::consumer::*;

    pub async fn test_consumer_single_shot(
        consumer_rsa_pem_filepath: &str,
        content_topic: &str,
        recv_timeout: Duration,
        port_base: u16,
    ) -> String {
        log::info!("Opening session...");
        let config = crate::net::peer(port_base);
        let session = zenoh::open(config)
            .await
            .map_err(Error::from_boxed)
            .unwrap();

        // Set up the consumer
        let private_key_pem = fs::read_to_string(consumer_rsa_pem_filepath).unwrap();
        let private_key = Rsa::private_key_from_pem(private_key_pem.as_bytes()).unwrap();
        let content_key_store = InMemoryContentKeyStore::new();
        let consumer = Consumer::new(session.clone(), Arc::new(content_key_store), private_key);

        // Declare zenoh subscriber
        let subscriber = session
            .declare_subscriber(content_topic)
            .await
            .map_err(Error::from_boxed)
            .unwrap();

        // Try to receive the encrypted content from the producer within a timeout
        let sample = timeout(recv_timeout, subscriber.recv_async())
            .await
            .context("No content received")
            .unwrap()
            .unwrap();

        // Encrypted content received from the producer
        let encrypted_content = sample.payload();

        let secret_key = consumer
            .get_secret_key()
            .await
            .unwrap()
            .context("No secret key")
            .unwrap();

        // Decrypt the content using the secret key
        let decrypted_content = consumer
            .decrypt(encrypted_content, &secret_key)
            .await
            .unwrap();

        let decrypted_content = decrypted_content.try_to_string().unwrap();

        log::info!(
            ">> [Subscriber] Received {} ('{}': '{}')",
            sample.kind(),
            sample.key_expr().as_str(),
            decrypted_content
        );

        decrypted_content.to_string()
    }

    /// Consumer that receives `count` messages and returns all decrypted contents.
    pub async fn test_consumer_multi_shot(
        consumer_rsa_pem_filepath: &str,
        content_topic: &str,
        count: usize,
        recv_timeout: Duration,
        port_base: u16,
    ) -> Vec<String> {
        log::info!("Opening session...");
        let config = crate::net::peer(port_base);
        let session = zenoh::open(config)
            .await
            .map_err(Error::from_boxed)
            .unwrap();

        let private_key_pem = fs::read_to_string(consumer_rsa_pem_filepath).unwrap();
        let private_key = Rsa::private_key_from_pem(private_key_pem.as_bytes()).unwrap();
        let content_key_store = InMemoryContentKeyStore::new();
        let consumer = Consumer::new(session.clone(), Arc::new(content_key_store), private_key);

        let subscriber = session
            .declare_subscriber(content_topic)
            .await
            .map_err(Error::from_boxed)
            .unwrap();

        // Fetch the secret key lazily and (re)fetch it once a sample has been
        // received if it was not available yet, mirroring examples/consumer.rs.
        let mut cached_secret_key = consumer.get_secret_key().await.unwrap();

        let mut results = Vec::with_capacity(count);

        for i in 0..count {
            let sample = timeout(recv_timeout, subscriber.recv_async())
                .await
                .context(format!("No content received for message #{}", i + 1))
                .unwrap()
                .unwrap();

            let encrypted_content = sample.payload();

            if cached_secret_key.is_none() {
                cached_secret_key = consumer.get_secret_key().await.unwrap();
            }
            let secret_key = cached_secret_key.as_ref().context("No secret key").unwrap();

            let decrypted_content = consumer
                .decrypt(encrypted_content, secret_key)
                .await
                .unwrap();

            let decrypted_str = decrypted_content.try_to_string().unwrap().to_string();

            log::info!(
                ">> [Subscriber] Received message #{} {} ('{}': '{}')",
                i + 1,
                sample.kind(),
                sample.key_expr().as_str(),
                decrypted_str,
            );

            results.push(decrypted_str);
        }

        results
    }
}

// Test scenario
const CONSUMER_RSA_PEM_FILEPATH: &str = "tests/consumer_rsa.pem";
const CONSUMER_RSA_PUBLIC_KEY: &str = "MIIBCgKCAQEAwfw/Kz7GDTZ3oCoR1TgUVhz8zYLCtM1whzB47JGPYTOiftxexYlzPmOK5/M012GtNgm717Wn5Hn9NYK7WBhLOnOlW8on/oyuAvAwu90LnIZvlzl9PIG1TYqsTYhvlSVhTYUSSCzdwDPmdfD8UlhyK64aK8jZTSbE2dlsliRfozP9DeoHrELdRg42WofQRkivFB4EjlMFoGfsyqWYSDUTiCbo4JJipkmsYHNJ1UAS3XilK16hOyJdQOJYKbTYp9aGJUM8hWU8srGmEB8CZ8x86SBFgbrq9EjdzDheKfUPAmyK+2bxdGdGbFLo3Bb9YN5fdBCIVfi1+KoRbQgouwtH8wIDAQAB";
const CONSUMER_ATTRIBUTES_1: &[&str] = &["A", "B", "C"];
const CONSUMER_ATTRIBUTES_2: &[&str] = &["D", "E", "F"];

const PRODUCER_PREFIX: &str = "tenantA";

const CONTENT_TOPIC: &str = "tenantA/example/test";
const CONTENT_POLICY: &str = r#""A" or "B""#;
const CONTENT: &str = "Hello, world!";

async fn start_services(consumer_attributes: &'static [&'static str]) -> TestTasks {
    let mut tasks = TestTasks::default();

    tasks.spawn(attribute_authority::test_attribute_authority(
        CONSUMER_RSA_PUBLIC_KEY,
        consumer_attributes,
        PORT_BASE,
    ));
    tasks.spawn(access_manager::test_access_manager(
        CONTENT_TOPIC,
        CONTENT_POLICY,
        PORT_BASE,
    ));

    sleep(Duration::from_secs(3)).await;
    tasks
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_integration() {
    let mut tasks = start_services(CONSUMER_ATTRIBUTES_1).await;

    tasks.spawn(producer::test_producer(
        PRODUCER_PREFIX,
        CONTENT_TOPIC,
        CONTENT,
        Duration::from_secs(1),
        PORT_BASE,
    ));

    let decrypted_content = consumer::test_consumer_single_shot(
        CONSUMER_RSA_PEM_FILEPATH,
        CONTENT_TOPIC,
        Duration::from_secs(3),
        PORT_BASE,
    )
    .await;

    assert_eq!(decrypted_content, CONTENT);
}

#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_integration_ck_rotation() {
    let mut tasks = start_services(CONSUMER_ATTRIBUTES_1).await;

    tasks.spawn(producer::test_producer_with_rotation(
        PRODUCER_PREFIX,
        CONTENT_TOPIC,
        CONTENT,
        Duration::from_millis(300),
        3, // rotate after 3 messages
        PORT_BASE,
    ));

    // Consumer receives messages across the CK rotation boundary
    let decrypted_contents = consumer::test_consumer_multi_shot(
        CONSUMER_RSA_PEM_FILEPATH,
        CONTENT_TOPIC,
        5, // receive 5 messages total (3 before rotation + 2 after)
        Duration::from_secs(10),
        PORT_BASE,
    )
    .await;

    // All messages should be correctly decrypted regardless of CK rotation
    assert_eq!(decrypted_contents.len(), 5);
    for content in &decrypted_contents {
        assert_eq!(content, CONTENT);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic = "FailedToDecryptContentKey"]
#[serial]
async fn test_integration_should_panic() {
    let mut tasks = start_services(CONSUMER_ATTRIBUTES_2).await;

    tasks.spawn(producer::test_producer(
        PRODUCER_PREFIX,
        CONTENT_TOPIC,
        CONTENT,
        Duration::from_secs(1),
        PORT_BASE,
    ));

    consumer::test_consumer_single_shot(
        CONSUMER_RSA_PEM_FILEPATH,
        CONTENT_TOPIC,
        Duration::from_secs(3),
        PORT_BASE,
    )
    .await;
}

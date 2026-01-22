mod kafka;

use common::{database::get_db_connection, models::UsageEvent};
use std::{env, time::Duration};

use dotenvy::dotenv;
use rdkafka::{Message, consumer::{CommitMode, Consumer}};
use tokio::time::interval;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{batcher::Batcher, kafka::create_consumer};

mod batcher;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    tracing_subscriber::registry().with(tracing_subscriber::fmt::layer()).with(EnvFilter::from_default_env()).init();

    let database_url = env::var("database_url").expect("Could not find Database URL in the enviroment files...");
    let kafka_url = env::var("KAFKA_URL").unwrap_or("localhost:9092".to_string());
    let topic = "usage-logs";
    let group_id = "worker-group";


    let db_pool = get_db_connection(&database_url).await?;
    let consumer = create_consumer(&kafka_url, group_id);

    consumer.subscribe(&[topic])?;

    tracing::debug!("Listening to topic: {}", topic);

    let mut batcher = Batcher::new(db_pool, 1000);
    let mut flush_timer = interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            rec = consumer.recv() => {
                match rec {
                    Ok(msg) => {
                        if let Some(payload) = msg.payload() {
                            if let Ok(event) = serde_json::from_slice::<UsageEvent>(payload){
                                batcher.add(event);
                            }

                            if batcher.should_flush() {
                                if let Err(error) = batcher.flush().await {
                                    tracing::error!("Error while flushing into DB: {}", error)
                                    // TODO: Implement retries in order to prevent data loss
                                } else {
                                    if let Err(error) = consumer.commit_consumer_state(CommitMode::Async) {
                                        tracing::error!("Error commiting offset: {}", error);
                                    }
                                }
                            }
                        };
                    }, Err(error)=> {
                        tracing::error!("Kafka Error: {}", error);
                    }
                }
            }
            _ = flush_timer.tick() => {
                tracing::debug!("5 seconds...");
                tracing::debug!("{:?}", batcher.buffer);
                if let Err(error) = batcher.flush().await {
                    tracing::error!("Error while flushing into DB: {}", error)
                    // TODO: Implement retries in order to prevent data loss
                } else {
                    if let Err(error) = consumer.commit_consumer_state(CommitMode::Async) {
                        tracing::error!("Error commiting offset: {}", error);
                    }
                };
            }
        }
    }
}

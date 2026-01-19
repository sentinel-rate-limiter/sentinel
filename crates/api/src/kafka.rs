use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer,FutureRecord};
use std::time::Duration;

pub type KafkaProducer = FutureProducer;

pub fn create_producer(broker_url: &str) -> KafkaProducer {
  ClientConfig::new()
    .set("bootstrap.servers", broker_url)
    .set("message.timeout.ms", "5000")
    .create().expect("Error while creating kafka producer")
}

pub async fn send_event(producer: &KafkaProducer, topic: &str, key: String, payload: String){
  let record = FutureRecord::to(topic).payload(&payload).key(&key);

  match producer.send(record,   Duration::from_secs(0)).await {
    Ok(_) => tracing::debug!("Event sent to kafka: {}", key),
    Err((error,_)) => tracing::debug!("Failed to send event to kafka: {}", error)
  };
}
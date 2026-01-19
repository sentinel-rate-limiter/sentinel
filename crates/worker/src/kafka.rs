use rdkafka::{ClientConfig, consumer::StreamConsumer};


pub type KafkaConsumer = StreamConsumer;

pub fn create_consumer(broker_url: &str, group_id: &str) -> KafkaConsumer {
  ClientConfig::new().set("bootstrap.servers", broker_url)
    .set("group.id", group_id)
    .set("enable.auto.commit", "false")
    .set("auto.offset.reset", "earliest")
    .create().expect("Error while creatng kafka consumer")
}
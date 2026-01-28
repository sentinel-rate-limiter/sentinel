use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};


pub fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sentinel=debug,tower_http=debug,sqlx=warn"));
    let format_layer = tracing_subscriber::fmt::layer();
    let is_prod = std::env::var("APP_ENV").unwrap_or_default() == "production";

    if is_prod {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(format_layer.json()) // <--- JSON para AWS CloudWatch
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(format_layer.pretty()) // <--- Colores y formato humano para tu terminal
            .init();
    }
}
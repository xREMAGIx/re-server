use anyhow::Context;
use clap::Parser;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use re_server::config::Config;
use re_server::api;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    env_logger::init();

    let config = Config::parse();

    tracing_subscriber::registry()
    .with(tracing_subscriber::EnvFilter::new(
        std::env::var("tower_http=trace")
            .unwrap_or_else(|_| "re_server_tracing=debug,tower_http=debug".into()),
    ))
    .with(tracing_subscriber::fmt::layer())
    .init();

    let db = PgPoolOptions::new()
        .max_connections(50)
        .connect(&config.database_url)
        .await
        .context("could not connect to database_url")?;

    sqlx::migrate!().run(&db).await?;

    api::serve(config, db).await?;

    Ok(())
}

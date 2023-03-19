#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use axum::extract::Path;

use axum::Server;
use axum_server::tls_rustls::RustlsConfig;
use database::Postgres;
use eyre::{Context, Error, Report, Result};

use crate::settings::Settings;

pub mod auth;
pub mod calendar;
pub mod database;
pub mod handlers;
pub mod models;
pub mod router;
pub mod settings;

pub async fn launch(settings: Settings, host: String, port: u16) -> Result<()> {
    let host = host.parse::<IpAddr>()?;

    let postgres = Postgres::new(settings.clone())
        .await
        .wrap_err_with(|| format!("failed to connect to db: {}", settings.db_uri))?;

    let r = router::router(postgres, settings);

    let addr = SocketAddr::new(host, port);
    if settings.use_tls {
        let cert = PathBuf::from(settings.cert.as_str());
        let private_key = PathBuf::from(settings.priv_key.as_str());
        if !cert.exists() {
            return Err(Report::msg(
                format!("certificate {} not exist", settings.cert.as_str())));
        }

        if !private_key.exists() {
            return Err(Report::msg(
                format!("private key {} not exist", settings.priv_key.as_str())));
        }

        let config = RustlsConfig::from_pem_file(cert, private_key)
            .await
            .unwrap();

        axum_server::bind_rustls(addr, config)
            .serve(r.into_make_service())
            .await?;
    } else {
        Server::bind(&addr)
            .serve(r.into_make_service())
            .await?;
    }

    Ok(())
}

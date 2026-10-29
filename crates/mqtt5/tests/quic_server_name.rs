//! A quics:// connection checks the server's certificate for the host it
//! connects to, an IP address included, as mqtts:// does.
#![cfg(all(feature = "broker", feature = "transport-quic"))]

mod common;

use mqtt5::broker::config::{
    BrokerConfig, QuicConfig as BrokerQuicConfig, StorageBackend, StorageConfig,
};
use mqtt5::broker::MqttBroker;
use mqtt5::MqttClient;
use std::net::SocketAddr;
use std::path::Path;

/// A CA in PEM, and a QUIC broker with a certificate it signs for
/// `localhost` alone, with its files in `dir`
async fn broker_for_localhost_alone(
    dir: &Path,
) -> (Vec<u8>, SocketAddr, tokio::task::JoinHandle<()>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = common::certificate_for(dir, &["localhost"]);
    let config = BrokerConfig::default()
        .with_storage(StorageConfig::default().with_backend(StorageBackend::Memory))
        .with_bind_address(([127, 0, 0, 1], 0))
        .with_quic(
            BrokerQuicConfig::new(dir.join("server.pem"), dir.join("server.key"))
                .with_bind_address("127.0.0.1:0".parse::<SocketAddr>().unwrap()),
        );
    let mut broker = MqttBroker::with_config(config).await.unwrap();
    let addr = broker
        .quic_local_addr()
        .expect("QUIC endpoint must be bound");
    let handle = tokio::spawn(async move {
        let _ = broker.run().await;
    });
    (ca, addr, handle)
}

#[tokio::test]
async fn quics_to_an_ip_address_is_checked_for_that_address() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, addr, broker) = broker_for_localhost_alone(dir.path()).await;
    let client = MqttClient::new("quics-ip-address");
    client.set_tls_config(None, None, Some(ca)).await;
    client
        .connect(&format!("quics://localhost:{}", addr.port()))
        .await
        .expect("the certificate names localhost");
    client.disconnect().await.unwrap();
    client
        .connect(&format!("quics://{addr}"))
        .await
        .expect_err("the certificate does not name 127.0.0.1");
    broker.abort();
}

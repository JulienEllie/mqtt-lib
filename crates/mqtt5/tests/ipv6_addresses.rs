//! Connections to an IPv6 address, `[::1]`, over mqtts:// and quics://: the
//! server's certificate is checked for `::1`. Skipped where `::1` can't be
//! bound.
#![cfg(feature = "broker")]

mod common;

use mqtt5::broker::config::{
    BrokerConfig, StorageBackend, StorageConfig, TlsConfig as BrokerTlsConfig,
};
use mqtt5::broker::MqttBroker;
use mqtt5::MqttClient;
use std::net::SocketAddr;

fn ipv6_available() -> bool {
    std::net::TcpListener::bind("[::1]:0").is_ok()
}

fn broker_config() -> BrokerConfig {
    BrokerConfig::default()
        .with_storage(StorageConfig::default().with_backend(StorageBackend::Memory))
        .with_bind_address(([127, 0, 0, 1], 0))
}

#[tokio::test]
async fn mqtts_to_an_ipv6_address() {
    if !ipv6_available() {
        eprintln!("skipped: ::1 can't be bound");
        return;
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let ca = common::certificate_for(dir.path(), &["::1"]);
    let config = broker_config().with_tls(
        BrokerTlsConfig::new(dir.path().join("server.pem"), dir.path().join("server.key"))
            .with_require_client_cert(false)
            .with_bind_address("[::1]:0".parse::<SocketAddr>().unwrap()),
    );
    let mut broker = MqttBroker::with_config(config).await.unwrap();
    let port = broker.tls_local_addr().expect("TLS listener bound").port();
    let handle = tokio::spawn(async move {
        let _ = broker.run().await;
    });
    let client = MqttClient::new("mqtts-ipv6");
    client.set_tls_config(None, None, Some(ca)).await;
    client
        .connect(&format!("mqtts://[::1]:{port}"))
        .await
        .expect("the certificate names ::1");
    client.disconnect().await.unwrap();
    handle.abort();
}

#[cfg(feature = "transport-quic")]
#[tokio::test]
async fn quics_to_an_ipv6_address() {
    use mqtt5::broker::config::QuicConfig as BrokerQuicConfig;
    if !ipv6_available() {
        eprintln!("skipped: ::1 can't be bound");
        return;
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let ca = common::certificate_for(dir.path(), &["::1"]);
    let config = broker_config().with_quic(
        BrokerQuicConfig::new(dir.path().join("server.pem"), dir.path().join("server.key"))
            .with_bind_address("[::1]:0".parse::<SocketAddr>().unwrap()),
    );
    let mut broker = MqttBroker::with_config(config).await.unwrap();
    let port = broker
        .quic_local_addr()
        .expect("QUIC endpoint bound")
        .port();
    let handle = tokio::spawn(async move {
        let _ = broker.run().await;
    });
    let client = MqttClient::new("quics-ipv6");
    client.set_tls_config(None, None, Some(ca)).await;
    client
        .connect(&format!("quics://[::1]:{port}"))
        .await
        .expect("the certificate names ::1");
    client.disconnect().await.unwrap();
    handle.abort();
}

/// A QUIC server gives no answer on an address it does not listen on, so a
/// name with an IPv6 and an IPv4 address reaches a server listening on IPv4
/// alone without waiting for the connect timeout on IPv6
#[cfg(feature = "transport-quic")]
#[tokio::test]
async fn quics_to_a_name_reaches_a_server_on_ipv4_alone_at_once() {
    use mqtt5::broker::config::QuicConfig as BrokerQuicConfig;
    if !ipv6_available() {
        eprintln!("skipped: ::1 can't be bound");
        return;
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let ca = common::certificate_for(dir.path(), &["localhost"]);
    let config = broker_config().with_quic(
        BrokerQuicConfig::new(dir.path().join("server.pem"), dir.path().join("server.key"))
            .with_bind_address("127.0.0.1:0".parse::<SocketAddr>().unwrap()),
    );
    let mut broker = MqttBroker::with_config(config).await.unwrap();
    let port = broker
        .quic_local_addr()
        .expect("QUIC endpoint bound")
        .port();
    let handle = tokio::spawn(async move {
        let _ = broker.run().await;
    });
    let client = MqttClient::new("quics-name-ipv4");
    client.set_tls_config(None, None, Some(ca)).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.connect(&format!("quics://localhost:{port}")),
    )
    .await
    .expect("connected without waiting on ::1")
    .expect("the certificate names localhost");
    client.disconnect().await.unwrap();
    handle.abort();
}

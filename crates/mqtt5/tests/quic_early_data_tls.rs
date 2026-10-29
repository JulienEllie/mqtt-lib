//! With early data on, a client keeps the QUIC configuration of its last
//! connection to use again: it is used only with the TLS settings it was
//! built with, so a quics:// connection is verified as those settings say.
#![cfg(all(feature = "broker", feature = "transport-quic"))]

mod common;

use common::find_workspace_root;
use mqtt5::broker::config::{
    BrokerConfig, QuicConfig as BrokerQuicConfig, StorageBackend, StorageConfig,
};
use mqtt5::broker::MqttBroker;
use mqtt5::MqttClient;
use std::net::SocketAddr;

/// A QUIC broker with early data on, whose certificate is signed by the
/// test CA: trusted by no system roots
async fn start_quic_broker() -> (tokio::task::JoinHandle<()>, SocketAddr) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = find_workspace_root().join("test_certs");
    let config = BrokerConfig::default()
        .with_storage(StorageConfig::default().with_backend(StorageBackend::Memory))
        .with_bind_address(([127, 0, 0, 1], 0))
        .with_quic(
            BrokerQuicConfig::new(certs.join("server.pem"), certs.join("server.key"))
                .with_bind_address("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .with_early_data(true),
        );
    let mut broker = MqttBroker::with_config(config).await.unwrap();
    let addr = broker
        .quic_local_addr()
        .expect("QUIC endpoint must be bound");
    let handle = tokio::spawn(async move {
        let _ = broker.run().await;
    });
    (handle, addr)
}

fn test_ca() -> Vec<u8> {
    std::fs::read(find_workspace_root().join("test_certs/ca.pem")).unwrap()
}

#[tokio::test]
async fn quics_after_quic_is_verified() {
    let (broker, addr) = start_quic_broker().await;
    let client = MqttClient::new("early-data-after-quic");
    client.set_quic_early_data(true).await;
    client
        .connect(&format!("quic://{addr}"))
        .await
        .expect("quic:// verifies nothing");
    client.disconnect().await.unwrap();
    client
        .connect(&format!("quics://{addr}"))
        .await
        .expect_err("the test CA is not among the system roots");
    broker.abort();
}

#[tokio::test]
async fn quics_after_insecure_tls_is_verified() {
    let (broker, addr) = start_quic_broker().await;
    let client = MqttClient::new("early-data-after-insecure");
    client.set_quic_early_data(true).await;
    client.set_insecure_tls(true).await;
    client
        .connect(&format!("quics://{addr}"))
        .await
        .expect("no verification asked");
    client.disconnect().await.unwrap();
    client.set_insecure_tls(false).await;
    client
        .connect(&format!("quics://{addr}"))
        .await
        .expect_err("the test CA is not among the system roots");
    broker.abort();
}

#[tokio::test]
async fn quics_takes_a_new_stored_tls_config() {
    let (broker, addr) = start_quic_broker().await;
    let client = MqttClient::new("early-data-new-stored");
    client.set_quic_early_data(true).await;
    client.set_tls_config(None, None, Some(test_ca())).await;
    client
        .connect(&format!("quics://{addr}"))
        .await
        .expect("trusted by the stored configuration's CA");
    client.disconnect().await.unwrap();
    let other_ca = rcgen::generate_simple_self_signed(vec!["other-ca".to_string()])
        .unwrap()
        .cert
        .pem();
    client
        .set_tls_config(None, None, Some(other_ca.into_bytes()))
        .await;
    client
        .connect(&format!("quics://{addr}"))
        .await
        .expect_err("not trusted by the CA stored since");
    broker.abort();
}

#[tokio::test]
async fn early_data_is_used_again_with_the_same_settings() {
    let (broker, addr) = start_quic_broker().await;
    let client = MqttClient::new("early-data-kept");
    client.set_quic_early_data(true).await;
    client.set_tls_config(None, None, Some(test_ca())).await;
    client
        .connect(&format!("quics://{addr}"))
        .await
        .expect("trusted by the stored configuration's CA");
    client.disconnect().await.unwrap();
    // The server sends its session ticket after the handshake: the second
    // connection uses 0-RTT once it has arrived.
    let mut zero_rtt = false;
    for _ in 0..20 {
        client
            .connect(&format!("quics://{addr}"))
            .await
            .expect("trusted again");
        zero_rtt = client.was_zero_rtt().await;
        client.disconnect().await.unwrap();
        if zero_rtt {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(zero_rtt, "a later connection uses 0-RTT");
    broker.abort();
}

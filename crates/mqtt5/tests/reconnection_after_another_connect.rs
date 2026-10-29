//! A reconnection left running from an earlier connection stops once the
//! client is connected again some other way: it never connects to its old
//! address with the options given since, credentials included.
#![cfg(feature = "broker")]

use mqtt5::time::Duration;
use mqtt5::transport::tls::TlsConfig;
use mqtt5::{ConnectOptions, MqttClient};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

const PASSWORD: &[u8] = b"given-to-connect-with-tls";

/// An address nothing listens on, for now
async fn unused_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Listens on `addr` and keeps all it is sent
async fn record(addr: SocketAddr) -> Arc<Mutex<Vec<u8>>> {
    let listener = TcpListener::bind(addr).await.unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let kept = received.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let kept = kept.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 {
                        break;
                    }
                    kept.lock().unwrap().extend_from_slice(&buffer[..n]);
                }
            });
        }
    });
    received
}

fn options() -> ConnectOptions {
    ConnectOptions::new("reconnection-after-another-connect")
        .with_reconnect_delay(Duration::from_millis(300), Duration::from_millis(300))
}

/// Connects to `plain` in the clear, which fails and leaves a reconnection
/// trying it again, then with TLS to an address that refuses, with a password;
/// `plain` then listens
async fn plain_then_tls(disconnect_between: bool) -> Arc<Mutex<Vec<u8>>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let plain = unused_address().await;
    let client = MqttClient::with_options(options());
    client
        .connect(&format!("mqtt://{plain}"))
        .await
        .expect_err("nothing listens there yet");
    // The reconnection takes the address once it has seen the connection
    // down, which it checks for every second, and then tries it again and
    // again.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    if disconnect_between {
        let _ = client.disconnect().await;
    }
    client
        .connect_with_tls_and_options(
            TlsConfig::new(unused_address().await, "localhost"),
            options().with_credentials("user", PASSWORD),
        )
        .await
        .expect_err("nothing listens there");
    let received = record(plain).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    // Not disconnected: had the client sent a CONNECT to `plain`, which never
    // answers, it would wait for the CONNACK first.
    received
}

fn contains_password(received: &[u8]) -> bool {
    received
        .windows(PASSWORD.len())
        .any(|window| window == PASSWORD)
}

#[tokio::test]
async fn an_earlier_reconnection_does_not_send_later_credentials() {
    let received = plain_then_tls(false).await;
    assert!(
        !contains_password(&received.lock().unwrap()),
        "the password went to the earlier address in the clear"
    );
}

#[tokio::test]
async fn an_earlier_reconnection_does_not_send_later_credentials_after_disconnect() {
    let received = plain_then_tls(true).await;
    assert!(
        !contains_password(&received.lock().unwrap()),
        "the password went to the earlier address in the clear"
    );
}

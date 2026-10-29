#![cfg(feature = "broker")]
//! A server certificate verifier given by the caller, in place of the root
//! certificates: on `TlsConfig` (mqtts://), on the client (any URL, quics://
//! included, and reconnections), and on `QuicConfig` (`QuicTransport`).

mod common;
#[cfg(feature = "transport-websocket")]
mod wss_test_server;
use common::{find_workspace_root, TestBroker};
use mqtt5::transport::tls::TlsConfig;
use mqtt5::{ConnectOptions, MqttClient};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Checks the server's certificate against the test CA, counting its calls,
/// or refuses every certificate.
#[derive(Debug)]
struct Counting {
    checks: Arc<WebPkiServerVerifier>,
    refuses: bool,
    calls: AtomicUsize,
}

impl Counting {
    fn new(refuses: bool) -> Arc<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = RootCertStore::empty();
        let ca = CertificateDer::from_pem_file(find_workspace_root().join("test_certs/ca.pem"))
            .expect("the test CA");
        roots.add(ca).unwrap();
        let checks = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        Arc::new(Self {
            checks,
            refuses,
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ServerCertVerifier for Counting {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.refuses {
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        self.checks
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.checks.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.checks.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.checks.supported_verify_schemes()
    }
}

fn tls_address(broker: &TestBroker) -> SocketAddr {
    broker
        .address()
        .strip_prefix("mqtts://")
        .unwrap()
        .parse()
        .unwrap()
}

/// A TLS configuration with no root certificates at all, so that only the
/// verifier can accept the server.
fn without_roots(addr: SocketAddr) -> TlsConfig {
    TlsConfig::new(addr, "localhost").with_system_roots(false)
}

#[tokio::test]
async fn tls_config_verifier_replaces_the_root_certificates() {
    let broker = TestBroker::start_with_tls().await;
    let verifier = Counting::new(false);
    let client = MqttClient::new("verifier-tls-accepts");
    client
        .connect_with_tls(
            without_roots(tls_address(&broker)).with_server_cert_verifier(verifier.clone()),
        )
        .await
        .expect("the verifier accepts the server");
    assert!(verifier.calls() > 0);
    client.disconnect().await.unwrap();
}

#[tokio::test]
async fn tls_config_verifier_refusing_fails_the_connection() {
    let broker = TestBroker::start_with_tls().await;
    let verifier = Counting::new(true);
    let mut config = without_roots(tls_address(&broker));
    config
        .load_ca_cert_pem(
            find_workspace_root()
                .join("test_certs/ca.pem")
                .to_str()
                .unwrap(),
        )
        .unwrap();
    let client = MqttClient::new("verifier-tls-refuses");
    let refused = client
        .connect_with_tls(config.with_server_cert_verifier(verifier.clone()))
        .await
        .expect_err("refused by the verifier, whatever the root certificates");
    assert!(
        refused.to_string().contains("invalid peer certificate"),
        "{refused}"
    );
    assert!(verifier.calls() > 0);
}

#[tokio::test]
async fn tls_config_without_verification_does_not_call_the_verifier() {
    let broker = TestBroker::start_with_tls().await;
    let verifier = Counting::new(true);
    let client = MqttClient::new("verifier-tls-unverified");
    client
        .connect_with_tls(
            without_roots(tls_address(&broker))
                .with_server_cert_verifier(verifier.clone())
                .with_verify_server_cert(false),
        )
        .await
        .expect("no verification asked");
    assert_eq!(verifier.calls(), 0);
    client.disconnect().await.unwrap();
}

#[tokio::test]
async fn client_verifier_checks_an_mqtts_url() {
    let broker = TestBroker::start_with_tls().await;
    let refusing = Counting::new(true);
    let client = MqttClient::new("verifier-client-mqtts");
    client
        .set_server_cert_verifier(Some(refusing.clone()))
        .await;
    client
        .connect(broker.address())
        .await
        .expect_err("refused by the client's verifier");
    assert!(refusing.calls() > 0);
    let accepting = Counting::new(false);
    client
        .set_server_cert_verifier(Some(accepting.clone()))
        .await;
    client.connect(broker.address()).await.expect("accepted");
    assert!(accepting.calls() > 0);
    client.disconnect().await.unwrap();
}

#[tokio::test]
async fn insecure_tls_does_not_call_the_client_verifier() {
    let broker = TestBroker::start_with_tls().await;
    let refusing = Counting::new(true);
    let client = MqttClient::new("verifier-client-insecure");
    client
        .set_server_cert_verifier(Some(refusing.clone()))
        .await;
    client.set_insecure_tls(true).await;
    client
        .connect(broker.address())
        .await
        .expect("no verification asked");
    assert_eq!(refusing.calls(), 0);
    client.disconnect().await.unwrap();
}

#[tokio::test]
async fn client_verifier_checks_automatic_reconnections() {
    let broker = TestBroker::start_with_tls().await;
    let (proxy, cut) = common::cutting_proxy(tls_address(&broker)).await;
    let client = MqttClient::with_options(
        ConnectOptions::new("verifier-client-reconnect")
            .with_reconnect_delay(Duration::from_millis(100), Duration::from_millis(200)),
    );
    let verifier = Counting::new(false);
    client
        .set_server_cert_verifier(Some(verifier.clone()))
        .await;
    client
        .connect(&format!("mqtts://{proxy}"))
        .await
        .expect("accepted");
    let at_first = verifier.calls();
    cut.notify_waiters();
    tokio::time::timeout(Duration::from_secs(10), async {
        while verifier.calls() <= at_first || !client.is_connected().await {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("reconnected by itself, checked by the client's verifier");
    client.disconnect().await.unwrap();
}

#[tokio::test]
async fn connect_with_tls_reconnects_with_its_own_configuration() {
    let broker = TestBroker::start_with_tls().await;
    let (proxy, cut) = common::cutting_proxy(tls_address(&broker)).await;
    let client = MqttClient::with_options(
        ConnectOptions::new("verifier-connect-with-tls-reconnect")
            .with_reconnect_delay(Duration::from_millis(100), Duration::from_millis(200)),
    );
    // The client's verifier is for connections made from a URL: one made
    // with connect_with_tls, its reconnections included, uses the
    // configuration it was given.
    let refusing = Counting::new(true);
    client
        .set_server_cert_verifier(Some(refusing.clone()))
        .await;
    let accepting = Counting::new(false);
    client
        .connect_with_tls(without_roots(proxy).with_server_cert_verifier(accepting.clone()))
        .await
        .expect("accepted");
    let at_first = accepting.calls();
    cut.notify_waiters();
    tokio::time::timeout(Duration::from_secs(10), async {
        while accepting.calls() <= at_first || !client.is_connected().await {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("reconnected by itself with the configuration's verifier");
    assert_eq!(refusing.calls(), 0);
    client.disconnect().await.unwrap();
}

#[cfg(feature = "transport-websocket")]
#[tokio::test]
async fn client_verifier_checks_a_wss_url() {
    let (addr, _server) = one_wss_connection().await;
    let refusing = Counting::new(true);
    let client = MqttClient::new("verifier-client-wss");
    client
        .set_server_cert_verifier(Some(refusing.clone()))
        .await;
    let refused = client
        .connect(&format!("wss://localhost:{}/mqtt", addr.port()))
        .await
        .expect_err("refused by the client's verifier");
    assert!(refusing.calls() > 0, "{refused}");
    // The test server takes one connection: another for the accepting
    // verifier, which shows it accepted when the WebSocket handshake is done.
    let (addr, handshake) = one_wss_connection().await;
    let accepting = Counting::new(false);
    client
        .set_server_cert_verifier(Some(accepting.clone()))
        .await;
    let connecting = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .connect(&format!("wss://localhost:{}/mqtt", addr.port()))
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(10), handshake)
        .await
        .expect("accepted, the test CA being in no root certificates")
        .expect("the handshake");
    assert!(accepting.calls() > 0);
    connecting.abort();
}

#[tokio::test]
async fn client_verifier_replaces_a_stored_verifier_over_mqtts() {
    let broker = TestBroker::start_with_tls().await;
    let stored = Counting::new(false);
    let client = MqttClient::new("verifier-client-over-stored");
    client
        .connect_with_tls(
            without_roots(tls_address(&broker)).with_server_cert_verifier(stored.clone()),
        )
        .await
        .expect("accepted by the stored verifier");
    client.disconnect().await.unwrap();
    let by_stored = stored.calls();
    let refusing = Counting::new(true);
    client
        .set_server_cert_verifier(Some(refusing.clone()))
        .await;
    client
        .connect(broker.address())
        .await
        .expect_err("refused by the client's verifier");
    assert!(refusing.calls() > 0);
    assert_eq!(stored.calls(), by_stored);
}

#[tokio::test]
async fn client_verifier_checks_a_redirect() {
    use mqtt5::broker::config::{
        BrokerConfig, LoadBalancerConfig, StorageBackend, StorageConfig,
        TlsConfig as BrokerTlsConfig,
    };
    use mqtt5::broker::MqttBroker;
    let backend = TestBroker::start_with_tls().await;
    let certs = find_workspace_root().join("test_certs");
    let config = BrokerConfig::default()
        .with_bind_address("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .with_storage(StorageConfig::default().with_backend(StorageBackend::Memory))
        .with_tls(
            BrokerTlsConfig::new(certs.join("server.pem"), certs.join("server.key"))
                .with_require_client_cert(false)
                .with_bind_address("127.0.0.1:0".parse::<SocketAddr>().unwrap()),
        )
        .with_load_balancer(LoadBalancerConfig::new(vec![backend.address().to_string()]));
    let mut balancer = MqttBroker::with_config(config).await.unwrap();
    let address = balancer.tls_local_addr().expect("TLS listener bound");
    let balancer = tokio::spawn(async move {
        let _ = balancer.run().await;
    });
    let verifier = Counting::new(false);
    let client = MqttClient::new("verifier-client-redirect");
    client
        .set_server_cert_verifier(Some(verifier.clone()))
        .await;
    client
        .connect(&format!("mqtts://{address}"))
        .await
        .expect("redirected and accepted");
    // Once for the server that redirects, once for the one it redirects to.
    assert!(verifier.calls() >= 2, "{} calls", verifier.calls());
    client.disconnect().await.unwrap();
    balancer.abort();
}

/// A WebSocket server over TLS for one connection, which says when the
/// WebSocket handshake is done (it speaks no MQTT).
#[cfg(feature = "transport-websocket")]
async fn one_wss_connection() -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<wss_test_server::Handshake>,
) {
    use wss_test_server::{certs, key, server_config, wss_server, SERVER_CERT, SERVER_KEY};
    wss_server(server_config(
        certs(SERVER_CERT),
        key(SERVER_KEY),
        false,
        &[],
    ))
    .await
}

#[cfg(feature = "transport-websocket")]
#[tokio::test]
async fn client_verifier_replaces_a_websocket_configs_own() {
    use mqtt5::transport::websocket::WebSocketConfig;
    let (addr, _server) = one_wss_connection().await;
    let url = format!("wss://localhost:{}/mqtt", addr.port());
    let mut accepting_by_roots = TlsConfig::new(addr, "localhost").with_system_roots(false);
    accepting_by_roots
        .load_ca_cert_pem(
            find_workspace_root()
                .join("test_certs/ca.pem")
                .to_str()
                .unwrap(),
        )
        .unwrap();
    let websocket = WebSocketConfig::new(&url)
        .unwrap()
        .with_tls_config(accepting_by_roots);
    let client = MqttClient::with_options(
        ConnectOptions::new("verifier-client-websocket-config").with_websocket_config(websocket),
    );
    let refusing = Counting::new(true);
    client
        .set_server_cert_verifier(Some(refusing.clone()))
        .await;
    client.connect(&url).await.expect_err(
        "refused by the client's verifier, whatever the WebSocket configuration's roots",
    );
    assert!(refusing.calls() > 0);
}

#[cfg(feature = "transport-websocket")]
#[tokio::test]
async fn stored_tls_config_verifier_checks_a_wss_url() {
    let broker = TestBroker::start_with_tls().await;
    let refusing = Counting::new(true);
    let client = MqttClient::new("verifier-stored-wss");
    client
        .connect_with_tls(
            without_roots(tls_address(&broker)).with_server_cert_verifier(refusing.clone()),
        )
        .await
        .expect_err("refused, and the configuration kept");
    let over_tls = refusing.calls();
    let (addr, _server) = one_wss_connection().await;
    client
        .connect(&format!("wss://localhost:{}/mqtt", addr.port()))
        .await
        .expect_err("refused by the stored configuration's verifier");
    assert!(refusing.calls() > over_tls);
}

#[cfg(feature = "transport-websocket")]
#[tokio::test]
async fn insecure_wss_does_not_call_the_client_verifier() {
    let (addr, handshake) = one_wss_connection().await;
    let refusing = Counting::new(true);
    let client = MqttClient::new("verifier-client-insecure-wss");
    client
        .set_server_cert_verifier(Some(refusing.clone()))
        .await;
    client.set_insecure_tls(true).await;
    let connecting = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .connect(&format!("wss://localhost:{}/mqtt", addr.port()))
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(10), handshake)
        .await
        .expect("no verification asked")
        .expect("the handshake");
    assert_eq!(refusing.calls(), 0);
    connecting.abort();
}

#[cfg(feature = "transport-quic")]
mod quic {
    use super::*;
    use mqtt5::broker::config::{
        BrokerConfig, QuicConfig as BrokerQuicConfig, StorageBackend, StorageConfig,
    };
    use mqtt5::broker::MqttBroker;
    use mqtt5::transport::quic::{QuicConfig, QuicTransport};
    use mqtt5::Transport;

    async fn start_quic_broker(early_data: bool) -> (tokio::task::JoinHandle<()>, SocketAddr) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certs = find_workspace_root().join("test_certs");
        let config = BrokerConfig::default()
            .with_storage(StorageConfig::default().with_backend(StorageBackend::Memory))
            .with_bind_address(([127, 0, 0, 1], 0))
            .with_quic(
                BrokerQuicConfig::new(certs.join("server.pem"), certs.join("server.key"))
                    .with_bind_address("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                    .with_early_data(early_data),
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

    #[tokio::test]
    async fn client_verifier_checks_a_quics_url() {
        let (broker, addr) = start_quic_broker(false).await;
        let refusing = Counting::new(true);
        let client = MqttClient::new("verifier-client-quics");
        client
            .set_server_cert_verifier(Some(refusing.clone()))
            .await;
        client
            .connect(&format!("quics://{addr}"))
            .await
            .expect_err("refused by the client's verifier");
        assert!(refusing.calls() > 0);
        let accepting = Counting::new(false);
        client
            .set_server_cert_verifier(Some(accepting.clone()))
            .await;
        client
            .connect(&format!("quics://{addr}"))
            .await
            .expect("accepted");
        assert!(accepting.calls() > 0);
        client.disconnect().await.unwrap();
        broker.abort();
    }

    #[tokio::test]
    async fn stored_tls_config_verifier_checks_a_quics_url() {
        let (tls_broker, (quic_broker, quic_addr)) = (
            TestBroker::start_with_tls().await,
            start_quic_broker(false).await,
        );
        let verifier = Counting::new(false);
        let client = MqttClient::new("verifier-stored-quics");
        // As the root certificates and the client certificate of a stored TLS
        // configuration are, its verifier is taken by a later quics:// connection.
        client
            .connect_with_tls(
                without_roots(tls_address(&tls_broker)).with_server_cert_verifier(verifier.clone()),
            )
            .await
            .expect("accepted over TLS");
        client.disconnect().await.unwrap();
        let over_tls = verifier.calls();
        client
            .connect(&format!("quics://{quic_addr}"))
            .await
            .expect("accepted over QUIC");
        assert!(verifier.calls() > over_tls);
        client.disconnect().await.unwrap();
        quic_broker.abort();
    }

    #[tokio::test]
    async fn quic_config_verifier_replaces_the_root_certificates() {
        let (broker, addr) = start_quic_broker(false).await;
        let refusing = Counting::new(true);
        let mut transport = QuicTransport::new(
            QuicConfig::new(addr, "localhost")
                .with_root_certs(vec![CertificateDer::from_pem_file(
                    find_workspace_root().join("test_certs/ca.pem"),
                )
                .unwrap()])
                .with_server_cert_verifier(refusing.clone()),
        );
        transport
            .connect()
            .await
            .expect_err("refused by the verifier");
        assert!(refusing.calls() > 0);
        let accepting = Counting::new(false);
        let mut transport = QuicTransport::new(
            QuicConfig::new(addr, "localhost").with_server_cert_verifier(accepting.clone()),
        );
        transport
            .connect()
            .await
            .expect("accepted with no root certificates");
        assert!(accepting.calls() > 0);
        broker.abort();
    }

    #[tokio::test]
    async fn client_verifier_set_again_is_used_with_early_data() {
        let (broker, addr) = start_quic_broker(true).await;
        let client = MqttClient::new("verifier-client-early-data");
        client.set_quic_early_data(true).await;
        let accepting = Counting::new(false);
        client
            .set_server_cert_verifier(Some(accepting.clone()))
            .await;
        client
            .connect(&format!("quics://{addr}"))
            .await
            .expect("accepted");
        client.disconnect().await.unwrap();
        // The configuration kept for early data was built with the first
        // verifier, so it can't be used with another.
        let refusing = Counting::new(true);
        client
            .set_server_cert_verifier(Some(refusing.clone()))
            .await;
        client
            .connect(&format!("quics://{addr}"))
            .await
            .expect_err("refused by the verifier set since");
        assert!(refusing.calls() > 0);
        broker.abort();
    }

    #[tokio::test]
    async fn quic_config_without_verification_does_not_call_the_verifier() {
        let (broker, addr) = start_quic_broker(false).await;
        let refusing = Counting::new(true);
        let mut transport = QuicTransport::new(
            QuicConfig::new(addr, "localhost")
                .with_server_cert_verifier(refusing.clone())
                .with_verify_server_cert(false),
        );
        transport.connect().await.expect("no verification asked");
        assert_eq!(refusing.calls(), 0);
        broker.abort();
    }

    #[tokio::test]
    async fn insecure_tls_does_not_call_the_client_verifier_over_quics() {
        let (broker, addr) = start_quic_broker(false).await;
        let refusing = Counting::new(true);
        let client = MqttClient::new("verifier-client-insecure-quics");
        client
            .set_server_cert_verifier(Some(refusing.clone()))
            .await;
        client.set_insecure_tls(true).await;
        client
            .connect(&format!("quics://{addr}"))
            .await
            .expect("no verification asked");
        assert_eq!(refusing.calls(), 0);
        client.disconnect().await.unwrap();
        broker.abort();
    }

    #[tokio::test]
    async fn early_data_is_used_again_with_the_same_verifier() {
        let (broker, addr) = start_quic_broker(true).await;
        let client = MqttClient::new("verifier-early-data-kept");
        client.set_quic_early_data(true).await;
        client
            .set_server_cert_verifier(Some(Counting::new(false)))
            .await;
        client
            .connect(&format!("quics://{addr}"))
            .await
            .expect("accepted");
        client.disconnect().await.unwrap();
        // The server sends its session ticket after the handshake: a later
        // connection uses 0-RTT once it has arrived.
        let mut zero_rtt = false;
        for _ in 0..20 {
            client
                .connect(&format!("quics://{addr}"))
                .await
                .expect("accepted again");
            zero_rtt = client.was_zero_rtt().await;
            client.disconnect().await.unwrap();
            if zero_rtt {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(zero_rtt, "a later connection uses 0-RTT");
        broker.abort();
    }
}

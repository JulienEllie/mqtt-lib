//! Builder patterns and factory methods for MQTT client

use crate::types::ConnectOptions;
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(not(target_arch = "wasm32"))]
use crate::transport::tls::TlsConfig;

use super::connection::ConnectionEvent;
use super::direct::DirectClientInner;
use super::error_recovery::ErrorRecoveryConfig;

pub type ConnectionEventCallback = Arc<dyn Fn(ConnectionEvent) + Send + Sync>;

use super::MqttClient;

impl MqttClient {
    /// Creates a new MQTT client with default options
    ///
    /// # Examples
    ///
    /// ```
    /// use mqtt5::MqttClient;
    ///
    /// let client = MqttClient::new("my-device-001");
    /// ```
    pub fn new(client_id: impl Into<String>) -> Self {
        let client_id_str = client_id.into();
        tracing::trace!(client_id = %client_id_str, "MQTT CLIENT - new() method called");
        let options = ConnectOptions::new(client_id_str);
        Self::with_options(options)
    }

    /// Creates a new MQTT client with custom options
    ///
    /// # Examples
    ///
    /// ```
    /// use mqtt5::{MqttClient, ConnectOptions};
    /// use std::time::Duration;
    ///
    /// let options = ConnectOptions::new("client-001")
    ///     .with_clean_start(true)
    ///     .with_keep_alive(Duration::from_secs(60))
    ///     .with_credentials("mqtt_user", b"secret");
    ///
    /// let client = MqttClient::with_options(options);
    /// ```
    #[must_use]
    pub fn with_options(options: ConnectOptions) -> Self {
        tracing::trace!(client_id = %options.client_id, "MQTT CLIENT - with_options() method called");
        let inner = DirectClientInner::new(options);
        let connection_event_callbacks = Arc::clone(&inner.connection_event_callbacks);

        Self {
            inner: Arc::new(RwLock::new(inner)),
            connection_event_callbacks,
            error_recovery_config: Arc::new(RwLock::new(ErrorRecoveryConfig::default())),
            connection_mutex: Arc::new(tokio::sync::Mutex::new(())),
            monitor_wakeup: Arc::new(tokio::sync::Notify::new()),
            tls_config: Arc::new(RwLock::new(super::StoredTlsConfig::default())),
            server_cert_verifier: Arc::new(RwLock::new(None)),
            transport_config: Arc::new(RwLock::new(
                crate::transport::ClientTransportConfig::default(),
            )),
            #[cfg(feature = "transport-quic")]
            quic_client_config: Arc::new(RwLock::new(None)),
        }
    }

    /// Set whether to skip TLS certificate verification
    ///
    /// # Safety
    ///
    /// This disables certificate verification and should only be used for testing
    /// with self-signed certificates. Never use in production.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use mqtt5::MqttClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = MqttClient::new("my-client");
    ///
    /// // Enable insecure mode for testing
    /// client.set_insecure_tls(true).await;
    ///
    /// // Connect will now skip certificate verification
    /// client.connect("mqtts://test-broker:8883").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_insecure_tls(&self, insecure: bool) {
        self.transport_config.write().await.insecure_tls = insecure;
    }

    /// Sets the verifier of the server certificate for connections made from
    /// a URL (mqtts://, wss:// and quics://), reconnections and redirects
    /// included, or `None` to go back to a stored TLS configuration's
    /// verifier or root certificates, and with none stored, to the default
    /// root certificates (the bundled ones for mqtts:// and quics://, the
    /// system's for wss://)
    ///
    /// It replaces the root certificates, the verifier of a stored TLS
    /// configuration, and that of the TLS configuration of
    /// [`ConnectOptions::with_websocket_config`](crate::ConnectOptions::with_websocket_config):
    /// see [`TlsConfig::with_server_cert_verifier`]. It is a rustls 0.23
    /// `ServerCertVerifier`. A connection made with
    /// [`connect_with_tls`](Self::connect_with_tls) does not use it: it uses
    /// the configuration it is given, and so do its reconnections and the
    /// redirects it follows.
    ///
    /// Insecure TLS ([`set_insecure_tls`](Self::set_insecure_tls)) still
    /// disables verification, the verifier included, and so does a WebSocket
    /// configuration's TLS configuration that has verification disabled. A
    /// stored TLS configuration's own `with_verify_server_cert(false)` does
    /// not: for connections made from a URL, insecure TLS alone decides.
    ///
    /// With early data ([`set_quic_early_data`](Self::set_quic_early_data)),
    /// the QUIC configuration kept is used again only with the verifier it
    /// was built with, and a quics:// connection that resumes a TLS session
    /// made with it does not call the verifier again: rustls verified the
    /// server's certificate when the session was made. A verifier that
    /// should check every connection again is set again (a new `Arc`), or
    /// early data left off.
    pub async fn set_server_cert_verifier(
        &self,
        verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
    ) {
        *self.server_cert_verifier.write().await = verifier;
    }

    pub async fn set_quic_stream_strategy(&self, strategy: crate::transport::StreamStrategy) {
        self.transport_config.write().await.stream_strategy = strategy;
    }

    pub async fn set_quic_flow_headers(&self, enable: bool) {
        self.transport_config.write().await.flow_headers = enable;
    }

    pub async fn set_quic_flow_expire(&self, duration: crate::time::Duration) {
        self.transport_config.write().await.flow_expire = duration;
    }

    pub async fn set_quic_max_streams(&self, max: Option<usize>) {
        self.transport_config.write().await.max_streams = max;
    }

    pub async fn set_quic_datagrams(&self, enable: bool) {
        self.transport_config.write().await.datagrams = enable;
    }

    pub async fn set_quic_connect_timeout(&self, timeout: crate::time::Duration) {
        self.transport_config.write().await.connect_timeout = timeout;
    }

    /// Sets whether quics:// and quic:// connections use 0-RTT early data
    ///
    /// The QUIC configuration of a connection is then kept and used again,
    /// with the TLS sessions it resumes, while the TLS settings it was built
    /// from stay the same: quics:// or quic://, insecure TLS, the stored TLS
    /// configuration and the client's verifier. The QUIC settings it was
    /// built with (flow headers, the stream limit, datagrams) stay with it
    /// until one of those changes.
    pub async fn set_quic_early_data(&self, enable: bool) {
        self.transport_config.write().await.enable_early_data = enable;
    }

    pub async fn set_tls_config(
        &self,
        cert_pem: Option<Vec<u8>>,
        key_pem: Option<Vec<u8>>,
        ca_cert_pem: Option<Vec<u8>>,
    ) {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        tracing::debug!(
            "set_tls_config called - cert: {}, key: {}, ca: {}",
            cert_pem.is_some(),
            key_pem.is_some(),
            ca_cert_pem.is_some()
        );

        let mut config_lock = self.tls_config.write().await;
        let placeholder_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

        if cert_pem.is_some() || key_pem.is_some() || ca_cert_pem.is_some() {
            let mut config = TlsConfig::new(placeholder_addr, "placeholder");

            if let (Some(cert), Some(key)) = (cert_pem, key_pem) {
                if let Err(e) = config.load_client_cert_pem_bytes(&cert) {
                    tracing::error!("Failed to load client certificate: {e}");
                    return;
                }
                if let Err(e) = config.load_client_key_pem_bytes(&key) {
                    tracing::error!("Failed to load client key: {e}");
                    return;
                }
                tracing::debug!("Loaded client cert and key");
            }

            if let Some(ca_cert) = ca_cert_pem {
                if let Err(e) = config.load_ca_cert_pem_bytes(&ca_cert) {
                    tracing::error!("Failed to load CA certificate: {e}");
                    return;
                }
                config.use_system_roots = false;
                tracing::debug!(
                    "Loaded CA cert, use_system_roots=false, has {} certs",
                    config.root_certs.as_ref().map_or(0, Vec::len)
                );
            }

            config_lock.store(config);
            tracing::debug!("TLS config stored");
        }
    }
}

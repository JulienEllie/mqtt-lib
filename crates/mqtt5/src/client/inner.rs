use crate::error::{MqttError, Result};
use crate::protocol::v5::reason_codes::ReasonCode;
use crate::types::{ConnectOptions, ConnectResult};
use crate::Transport;
use tracing::instrument;

#[cfg(all(not(target_arch = "wasm32"), feature = "transport-quic"))]
use crate::transport::quic::QuicConfig;
#[cfg(not(target_arch = "wasm32"))]
use crate::transport::tcp::TcpConfig;
#[cfg(not(target_arch = "wasm32"))]
use crate::transport::tls::TlsConfig;
#[cfg(all(not(target_arch = "wasm32"), feature = "transport-websocket"))]
use crate::transport::websocket::{WebSocketConfig, WebSocketTransport};
#[cfg(all(not(target_arch = "wasm32"), feature = "transport-quic"))]
use crate::transport::QuicTransport;
#[cfg(not(target_arch = "wasm32"))]
use crate::transport::{TcpTransport, TlsTransport, TransportType};

use super::connection::ConnectionEvent;
use super::direct::{AutomaticReconnectLifecycle, StoredSubscription};
use super::state::ClientTransportType;
#[cfg(feature = "transport-websocket")]
use super::state::WebSocketSettings;
use super::MqttClient;

/// The TLS settings a QUIC connection's configuration was built from: the
/// configuration kept for early data is used again only with the same ones,
/// so that a quics:// connection is never made with one built for quic://,
/// for insecure TLS or for another stored TLS configuration
#[cfg(feature = "transport-quic")]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct QuicBuiltFor {
    secure: bool,
    insecure_tls: bool,
    tls_config_times_stored: u64,
}

/// A connected transport, with what its configuration was built from if it is
/// QUIC's
struct Connected {
    transport: TransportType,
    #[cfg(feature = "transport-quic")]
    quic_built_for: Option<QuicBuiltFor>,
}

impl From<TransportType> for Connected {
    fn from(transport: TransportType) -> Self {
        Self {
            transport,
            #[cfg(feature = "transport-quic")]
            quic_built_for: None,
        }
    }
}

impl MqttClient {
    /// The configuration kept for early data, if it was built for `built_for`
    #[cfg(feature = "transport-quic")]
    async fn kept_quic_client_config(
        &self,
        built_for: &QuicBuiltFor,
    ) -> Option<quinn::ClientConfig> {
        let (kept_for, config) = self.quic_client_config.read().await.clone()?;
        (kept_for == *built_for).then_some(config)
    }

    async fn on_successful_connect(
        &self,
        stored_subs: Vec<StoredSubscription>,
        session_present: bool,
        keep_alive: std::time::Duration,
    ) {
        self.trigger_connection_event(ConnectionEvent::Connected {
            session_present,
            keep_alive,
        })
        .await;
        #[cfg(feature = "transport-quic")]
        self.recover_quic_flows().await;
        self.restore_subscriptions_after_connect(stored_subs, session_present)
            .await;
        if !session_present {
            self.restore_ack_subscriptions_after_lost_session().await;
        }
    }

    #[cfg(any(not(feature = "transport-websocket"), not(feature = "transport-quic")))]
    fn unsupported_transport_feature(transport: &str, feature: &str) -> MqttError {
        MqttError::Configuration(format!(
            "{transport} transport is disabled at compile time; enable the `{feature}` feature"
        ))
    }

    pub(crate) fn is_aws_iot_endpoint(hostname: &str) -> bool {
        hostname.contains(".iot.") && hostname.ends_with(".amazonaws.com")
    }

    /// Parses an address string to determine transport type and components
    ///
    /// # Errors
    ///
    /// Returns an error if the address format is invalid
    pub(crate) fn parse_address(address: &str) -> Result<(ClientTransportType, &str, u16)> {
        if let Some(rest) = address.strip_prefix("mqtt://") {
            let (host, port) = Self::split_host_port(rest, 1883)?;
            Ok((ClientTransportType::Tcp, host, port))
        } else if let Some(rest) = address.strip_prefix("mqtts://") {
            let (host, port) = Self::split_host_port(rest, 8883)?;
            Ok((ClientTransportType::Tls, host, port))
        } else if let Some(rest) = address.strip_prefix("ws://") {
            #[cfg(feature = "transport-websocket")]
            {
                let (host, port) = Self::split_host_port(rest, 80)?;
                Ok((
                    ClientTransportType::WebSocket(
                        address.to_string(),
                        WebSocketSettings::Configured,
                    ),
                    host,
                    port,
                ))
            }
            #[cfg(not(feature = "transport-websocket"))]
            {
                Self::split_host_port(rest, 80).and(Err(Self::unsupported_transport_feature(
                    "WebSocket",
                    "transport-websocket",
                )))
            }
        } else if let Some(rest) = address.strip_prefix("wss://") {
            #[cfg(feature = "transport-websocket")]
            {
                let (host, port) = Self::split_host_port(rest, 443)?;
                Ok((
                    ClientTransportType::WebSocketSecure(
                        address.to_string(),
                        WebSocketSettings::Configured,
                    ),
                    host,
                    port,
                ))
            }
            #[cfg(not(feature = "transport-websocket"))]
            {
                Self::split_host_port(rest, 443).and(Err(Self::unsupported_transport_feature(
                    "WebSocket",
                    "transport-websocket",
                )))
            }
        } else if let Some(rest) = address.strip_prefix("tcp://") {
            let (host, port) = Self::split_host_port(rest, 1883)?;
            Ok((ClientTransportType::Tcp, host, port))
        } else if let Some(rest) = address.strip_prefix("ssl://") {
            let (host, port) = Self::split_host_port(rest, 8883)?;
            Ok((ClientTransportType::Tls, host, port))
        } else if let Some(rest) = address.strip_prefix("quic://") {
            #[cfg(feature = "transport-quic")]
            {
                let (host, port) = Self::split_host_port(rest, 14567)?;
                Ok((ClientTransportType::Quic, host, port))
            }
            #[cfg(not(feature = "transport-quic"))]
            {
                Self::split_host_port(rest, 14567).and(Err(Self::unsupported_transport_feature(
                    "QUIC",
                    "transport-quic",
                )))
            }
        } else if let Some(rest) = address.strip_prefix("quics://") {
            #[cfg(feature = "transport-quic")]
            {
                let (host, port) = Self::split_host_port(rest, 14567)?;
                Ok((ClientTransportType::QuicSecure, host, port))
            }
            #[cfg(not(feature = "transport-quic"))]
            {
                Self::split_host_port(rest, 14567).and(Err(Self::unsupported_transport_feature(
                    "QUIC",
                    "transport-quic",
                )))
            }
        } else {
            let (host, port) = Self::split_host_port(address, 1883)?;
            Ok((ClientTransportType::Tcp, host, port))
        }
    }

    /// The address a server's redirect (`UseAnotherServer`, `ServerMoved`)
    /// sends a connection to `from` to. A reference with no scheme, as
    /// `host:port` usually is, means TCP, made TLS (mqtts://) when `from` is
    /// over TLS (mqtts://, wss://, quics://); and a connection over TLS is
    /// not redirected to one without.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is not an address, or would take a
    /// connection over TLS to one without
    pub(crate) fn redirect_address(from: &str, to: &str) -> Result<String> {
        let (from_transport, _, _) = Self::parse_address(from)?;
        if !to.contains("://") {
            return Ok(if from_transport.is_secure() {
                format!("mqtts://{to}")
            } else {
                to.to_string()
            });
        }
        let (to_transport, _, _) = Self::parse_address(to)?;
        if from_transport.is_secure() && !to_transport.is_secure() {
            return Err(MqttError::ConnectionError(format!(
                "Server redirect to {to} refused: it is not over TLS, as the connection redirected was"
            )));
        }
        Ok(to.to_string())
    }

    /// Splits a host:port string
    ///
    /// # Errors
    ///
    /// Returns an error if the port is invalid
    pub(crate) fn split_host_port(address: &str, default_port: u16) -> Result<(&str, u16)> {
        let address_without_path = address.split('/').next().unwrap_or(address);

        if let Some(colon_pos) = address_without_path.rfind(':') {
            let host = &address_without_path[..colon_pos];
            let port_str = &address_without_path[colon_pos + 1..];
            let port = port_str
                .parse::<u16>()
                .map_err(|_| MqttError::ConnectionError(format!("Invalid port: {port_str}")))?;
            Ok((host, port))
        } else {
            Ok((address_without_path, default_port))
        }
    }

    pub(crate) async fn resolve_addresses(
        host: &str,
        port: u16,
    ) -> Result<Vec<std::net::SocketAddr>> {
        let addr_str = format!("{host}:{port}");
        tracing::debug!(addr_str = %addr_str, "🌐 DNS RESOLUTION - Starting address resolution");

        let addrs: Vec<_> = tokio::net::lookup_host(addr_str.as_str())
            .await
            .map_err(|e| {
                tracing::error!(addr_str = %addr_str, error = %e, "🌐 DNS RESOLUTION - Failed to resolve address");
                MqttError::ConnectionError(format!("Failed to resolve address: {e}"))
            })?
            .collect();

        tracing::debug!(addr_str = %addr_str, resolved_count = addrs.len(), "🌐 DNS RESOLUTION - Address resolved successfully");

        if addrs.is_empty() {
            return Err(MqttError::ConnectionError(
                "No valid address found".to_string(),
            ));
        }

        Ok(addrs)
    }

    pub(crate) fn select_addresses_for_connection<'a>(
        addrs: &'a [std::net::SocketAddr],
        host: &str,
    ) -> &'a [std::net::SocketAddr] {
        if Self::is_aws_iot_endpoint(host) {
            tracing::debug!("AWS IoT endpoint detected, limiting to first resolved address");
            &addrs[0..1]
        } else {
            addrs
        }
    }

    async fn try_connect_address(
        &self,
        addr: std::net::SocketAddr,
        client_transport_type: ClientTransportType,
        host: &str,
    ) -> Result<Connected> {
        match client_transport_type {
            ClientTransportType::Tcp => Self::connect_tcp(addr).await.map(Connected::from),
            ClientTransportType::Tls => self.connect_tls(addr, host).await.map(Connected::from),
            #[cfg(feature = "transport-websocket")]
            ClientTransportType::WebSocket(url, settings) => self
                .connect_websocket(&url, settings)
                .await
                .map(Connected::from),
            #[cfg(feature = "transport-websocket")]
            ClientTransportType::WebSocketSecure(url, settings) => self
                .connect_websocket_secure(addr, host, &url, settings)
                .await
                .map(Connected::from),
            #[cfg(feature = "transport-quic")]
            ClientTransportType::Quic => self.connect_quic(addr, host).await,
            #[cfg(feature = "transport-quic")]
            ClientTransportType::QuicSecure => self.connect_quic_secure(addr, host).await,
        }
    }

    async fn connect_tcp(addr: std::net::SocketAddr) -> Result<TransportType> {
        let config = TcpConfig::new(addr);
        let mut tcp_transport = TcpTransport::new(config);
        tcp_transport
            .connect()
            .await
            .map_err(|e| MqttError::ConnectionError(format!("TCP connect failed: {e}")))?;
        Ok(TransportType::Tcp(tcp_transport))
    }

    async fn connect_tls(&self, addr: std::net::SocketAddr, host: &str) -> Result<TransportType> {
        let insecure = self.transport_config.read().await.insecure_tls;
        let tls_config_lock = self.tls_config.read().await;
        let config = if let Some(existing_config) = &tls_config_lock.config {
            tracing::debug!(
                "Using stored TLS config - use_system_roots: {}, has_ca: {}, has_cert: {}",
                existing_config.use_system_roots,
                existing_config.root_certs.is_some(),
                existing_config.client_cert.is_some()
            );
            let mut cfg = existing_config.clone();
            cfg.addr = addr;
            cfg.hostname = host.to_string();
            cfg.verify_server_cert = !insecure;
            cfg
        } else {
            tracing::debug!("No stored TLS config, using default");
            TlsConfig::new(addr, host).with_verify_server_cert(!insecure)
        };
        drop(tls_config_lock);

        let mut tls_transport = TlsTransport::new(config);
        tls_transport
            .connect()
            .await
            .map_err(|e| MqttError::ConnectionError(format!("TLS connect failed: {e}")))?;
        Ok(TransportType::Tls(Box::new(tls_transport)))
    }

    /// The WebSocket configuration for a connection to `url`: the one set with
    /// `ConnectOptions::with_websocket_config`, read on every attempt so
    /// reconnects use it too, or a default one, which a server redirect
    /// always gets.
    #[cfg(feature = "transport-websocket")]
    async fn websocket_config_for(
        &self,
        url: &str,
        settings: WebSocketSettings,
    ) -> Result<WebSocketConfig> {
        let configured = match settings {
            WebSocketSettings::Configured => {
                self.inner.read().await.options.websocket_config.clone()
            }
            WebSocketSettings::Default => None,
        };
        match configured {
            Some(config) => WebSocketConfig::clone(&config).with_url(url),
            None => WebSocketConfig::new(url),
        }
        .map_err(|e| MqttError::ConnectionError(format!("Invalid WebSocket URL: {e}")))
    }

    #[cfg(feature = "transport-websocket")]
    async fn connect_websocket(
        &self,
        url: &str,
        settings: WebSocketSettings,
    ) -> Result<TransportType> {
        let config = self.websocket_config_for(url, settings).await?;
        Self::open_websocket(config).await
    }

    #[cfg(feature = "transport-websocket")]
    async fn connect_websocket_secure(
        &self,
        addr: std::net::SocketAddr,
        host: &str,
        url: &str,
        settings: WebSocketSettings,
    ) -> Result<TransportType> {
        let insecure = self.transport_config.read().await.insecure_tls;
        let mut config = self.websocket_config_for(url, settings).await?;

        if let Some(tls_config) = config.tls_config.as_mut() {
            if insecure {
                tls_config.verify_server_cert = false;
            }
            return Self::open_websocket(config).await;
        }

        // As in connect_tls: a stored TLS config applies to wss:// too. With
        // none, an insecure connection still needs one to disable
        // verification; a secure one keeps the WebSocket transport's default.
        // The stored ALPN protocols are left out: they name the protocol for
        // MQTT directly over TLS (mqtts://, e.g. AWS IoT's x-amzn-mqtt-ca),
        // while a WebSocket server negotiates HTTP.
        let stored = self.tls_config.read().await.config.clone();
        let tls_config = match stored {
            Some(mut cfg) => {
                cfg.addr = addr;
                cfg.hostname = host.to_string();
                cfg.verify_server_cert = !insecure;
                cfg.alpn_protocols = None;
                Some(cfg)
            }
            None if insecure => Some(TlsConfig::new(addr, host).with_verify_server_cert(false)),
            None => None,
        };
        if let Some(tls_config) = tls_config {
            config = config.with_tls_config(tls_config);
        }

        Self::open_websocket(config).await
    }

    #[cfg(feature = "transport-websocket")]
    async fn open_websocket(config: WebSocketConfig) -> Result<TransportType> {
        let mut ws_transport = WebSocketTransport::new(config);
        ws_transport.connect().await?;
        Ok(TransportType::WebSocket(Box::new(ws_transport)))
    }

    #[cfg(feature = "transport-quic")]
    async fn connect_quic(&self, addr: std::net::SocketAddr, host: &str) -> Result<Connected> {
        let (config, built_for) = self.quic_config(addr, host).await;
        Self::open_quic(config, built_for).await
    }

    /// The configuration of a quic:// connection to `addr`, which verifies
    /// nothing, so is built from none of the TLS settings
    #[cfg(feature = "transport-quic")]
    async fn quic_config(
        &self,
        addr: std::net::SocketAddr,
        host: &str,
    ) -> (QuicConfig, QuicBuiltFor) {
        let built_for = QuicBuiltFor {
            secure: false,
            insecure_tls: true,
            tls_config_times_stored: 0,
        };
        let qc = self.transport_config.read().await;
        let server_name = if host.parse::<std::net::IpAddr>().is_ok() {
            "localhost"
        } else {
            host
        };
        let mut config = QuicConfig::new(addr, server_name)
            .with_verify_server_cert(false)
            .with_stream_strategy(qc.stream_strategy)
            .with_flow_headers(qc.flow_headers)
            .with_flow_expire_interval(qc.flow_expire.as_secs())
            .with_datagrams(qc.datagrams)
            .with_connect_timeout(qc.connect_timeout)
            .with_early_data(qc.enable_early_data);
        if let Some(max) = qc.max_streams {
            config = config.with_max_concurrent_streams(max);
        }
        let enable_early_data = qc.enable_early_data;
        drop(qc);
        if enable_early_data {
            if let Some(cached) = self.kept_quic_client_config(&built_for).await {
                config = config.with_cached_client_config(cached);
            }
        }
        (config, built_for)
    }

    #[cfg(feature = "transport-quic")]
    async fn open_quic(config: QuicConfig, built_for: QuicBuiltFor) -> Result<Connected> {
        let mut quic_transport = QuicTransport::new(config);
        quic_transport
            .connect()
            .await
            .map_err(|e| MqttError::ConnectionError(format!("QUIC connect failed: {e}")))?;
        Ok(Connected {
            transport: TransportType::Quic(Box::new(quic_transport)),
            quic_built_for: Some(built_for),
        })
    }

    #[cfg(feature = "transport-quic")]
    async fn connect_quic_secure(
        &self,
        addr: std::net::SocketAddr,
        host: &str,
    ) -> Result<Connected> {
        let (config, built_for) = self.quic_secure_config(addr, host).await;
        Self::open_quic(config, built_for).await
    }

    /// The configuration of a quics:// connection to `addr`, and what it was
    /// built from: the client's transport settings and a stored TLS
    /// configuration's certificates, each read once
    #[cfg(feature = "transport-quic")]
    async fn quic_secure_config(
        &self,
        addr: std::net::SocketAddr,
        host: &str,
    ) -> (QuicConfig, QuicBuiltFor) {
        let qc: crate::transport::ClientTransportConfig =
            (*self.transport_config.read().await).clone();
        let tls_config_lock = self.tls_config.read().await;
        let server_name = if host.parse::<std::net::IpAddr>().is_ok() {
            "localhost"
        } else {
            host
        };
        let mut config = QuicConfig::new(addr, server_name)
            .with_verify_server_cert(!qc.insecure_tls)
            .with_stream_strategy(qc.stream_strategy)
            .with_flow_headers(qc.flow_headers)
            .with_flow_expire_interval(qc.flow_expire.as_secs())
            .with_datagrams(qc.datagrams)
            .with_connect_timeout(qc.connect_timeout)
            .with_early_data(qc.enable_early_data);

        if let Some(max) = qc.max_streams {
            config = config.with_max_concurrent_streams(max);
        }

        if let Some(existing_config) = &tls_config_lock.config {
            tracing::debug!(
                "Using stored TLS config for QUIC - use_system_roots: {}, has_ca: {}, has_cert: {}",
                existing_config.use_system_roots,
                existing_config.root_certs.is_some(),
                existing_config.client_cert.is_some()
            );

            if let (Some(ref cert_chain), Some(ref key)) =
                (&existing_config.client_cert, &existing_config.client_key)
            {
                config = config.with_client_cert(cert_chain.clone(), key.clone_key());
            }

            if let Some(ref certs) = existing_config.root_certs {
                config = config.with_root_certs(certs.clone());
            }
        } else {
            tracing::debug!("No stored TLS config for QUIC, using default");
        }
        let built_for = QuicBuiltFor {
            secure: true,
            insecure_tls: qc.insecure_tls,
            tls_config_times_stored: tls_config_lock.times_stored,
        };
        drop(tls_config_lock);

        if qc.enable_early_data {
            if let Some(cached) = self.kept_quic_client_config(&built_for).await {
                config = config.with_cached_client_config(cached);
            }
        }
        (config, built_for)
    }

    pub(crate) async fn try_connect_to_addresses(
        &self,
        addresses: &[std::net::SocketAddr],
        transport_type: ClientTransportType,
        host: &str,
    ) -> Result<ConnectResult> {
        let mut last_error = None;

        for addr in addresses {
            tracing::debug!("Trying to connect to address: {}", addr);

            let connected = match self
                .try_connect_address(*addr, transport_type.clone(), host)
                .await
            {
                Ok(connected) => connected,
                Err(e) => {
                    tracing::debug!("Failed to connect to {}: {}", addr, e);
                    last_error = Some(e);
                    continue;
                }
            };

            self.reset_reconnect_counter().await;

            let mut inner = self.inner.write().await;
            match inner.connect(connected.transport).await {
                Ok(result) => {
                    #[cfg(feature = "transport-quic")]
                    if let (Some(cached), Some(built_for)) = (
                        inner.cached_quic_client_config.take(),
                        connected.quic_built_for,
                    ) {
                        *self.quic_client_config.write().await = Some((built_for, cached));
                    }
                    let stored_subs = inner.stored_subscriptions.lock().clone();
                    let session_present = result.session_present;
                    let keep_alive = inner.negotiated_keep_alive();
                    drop(inner);

                    self.on_successful_connect(stored_subs, session_present, keep_alive)
                        .await;

                    return Ok(result);
                }
                Err(
                    e @ MqttError::ConnectionRefused(
                        ReasonCode::UseAnotherServer | ReasonCode::ServerMoved,
                    ),
                ) => {
                    drop(inner);
                    return Err(e);
                }
                Err(e) => {
                    drop(inner);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            MqttError::ConnectionError("Failed to connect to any address".to_string())
        }))
    }

    pub(crate) async fn connect_internal(&self, address: &str) -> Result<ConnectResult> {
        Box::pin(self.connect_following_redirects(address, 0)).await
    }

    async fn connect_following_redirects(
        &self,
        address: &str,
        redirects_followed: u8,
    ) -> Result<ConnectResult> {
        const MAX_REDIRECTS: u8 = 3;
        self.inner.read().await.options.validate_deferred_ack()?;
        let mut current_address = address.to_string();
        let mut redirect_count = redirects_followed;

        loop {
            let client_id = self.inner.read().await.options.client_id.clone();
            tracing::debug!(
                address = %current_address,
                client_id = %client_id,
                redirect_count,
                "Connection attempt"
            );

            let (requested_transport_type, host, port) = Self::parse_address(&current_address)?;
            let client_transport_type = if redirect_count == 0 {
                requested_transport_type
            } else {
                requested_transport_type.redirected()
            };
            let addrs = if client_transport_type.dials_by_url() {
                vec![std::net::SocketAddr::new(
                    std::net::Ipv4Addr::UNSPECIFIED.into(),
                    port,
                )]
            } else {
                Self::resolve_addresses(host, port).await?
            };
            let addresses_to_try = Self::select_addresses_for_connection(&addrs, host);

            match self
                .try_connect_to_addresses(addresses_to_try, client_transport_type, host)
                .await
            {
                Ok(result) => return Ok(result),
                Err(MqttError::ConnectionRefused(
                    reason @ (ReasonCode::UseAnotherServer | ReasonCode::ServerMoved),
                )) => {
                    let redirect_url = self.inner.write().await.server_redirect.take();
                    if let Some(url) = redirect_url {
                        if redirect_count < MAX_REDIRECTS {
                            tracing::info!(
                                from = %current_address,
                                to = %url,
                                reason = ?reason,
                                "Following server redirect"
                            );
                            redirect_count += 1;
                            current_address = Self::redirect_address(&current_address, &url)?;
                            continue;
                        }
                    }
                    return Err(MqttError::ConnectionError(
                        "Server redirect failed: too many redirects or missing server reference"
                            .to_string(),
                    ));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Internal connection method using custom TLS configuration
    ///
    /// # Errors
    ///
    /// Returns an error if TLS connection fails
    pub(crate) async fn connect_internal_with_tls(
        &self,
        tls_config: crate::transport::tls::TlsConfig,
    ) -> Result<ConnectResult> {
        self.tls_config.write().await.store(tls_config.clone());

        let mut tls_transport = crate::transport::tls::TlsTransport::new(tls_config);
        tls_transport
            .connect()
            .await
            .map_err(|e| MqttError::ConnectionError(format!("TLS connect failed: {e}")))?;

        let transport = TransportType::Tls(Box::new(tls_transport));

        {
            let mut inner = self.inner.write().await;
            inner.reconnect_attempt = 0;
        }

        let mut inner = self.inner.write().await;
        match inner.connect(transport).await {
            Ok(result) => {
                let stored_subs = inner.stored_subscriptions.lock().clone();
                let session_present = result.session_present;
                let keep_alive = inner.negotiated_keep_alive();
                drop(inner);

                self.on_successful_connect(stored_subs, session_present, keep_alive)
                    .await;

                Ok(result)
            }
            Err(MqttError::ConnectionRefused(
                reason @ (ReasonCode::UseAnotherServer | ReasonCode::ServerMoved),
            )) => {
                let redirect_url = inner.server_redirect.take();
                drop(inner);
                if let Some(url) = redirect_url {
                    tracing::info!(
                        to = %url,
                        reason = ?reason,
                        "Following server redirect from TLS connection"
                    );
                    let url = Self::redirect_address("mqtts://", &url)?;
                    return Box::pin(self.connect_following_redirects(&url, 1)).await;
                }
                Err(MqttError::ConnectionError(
                    "Server redirect missing server reference".to_string(),
                ))
            }
            Err(e) => {
                drop(inner);
                Err(e)
            }
        }
    }

    #[instrument(skip(self, options), fields(client_id = %options.client_id, clean_start = %options.clean_start), level = "debug")]
    pub(crate) async fn connect_with_options_internal(
        &self,
        address: &str,
        options: ConnectOptions,
    ) -> Result<ConnectResult> {
        if self.is_connected().await {
            return Err(MqttError::AlreadyConnected);
        }

        {
            let mut inner = self.inner.write().await;
            inner
                .auth_method
                .clone_from(&options.properties.authentication_method);
            inner.options = options.clone();
            inner.last_address = Some(address.to_string());
            inner.automatic_reconnect_lifecycle = AutomaticReconnectLifecycle::Armed;
        }

        self.trigger_connection_event(ConnectionEvent::Connecting)
            .await;
        let result = self.connect_internal(address).await;

        if let Err(ref error) = result {
            let error_recovery_config =
                crate::client::error_recovery::ErrorRecoveryConfig::default();
            if crate::client::error_recovery::is_recoverable(error, &error_recovery_config)
                .is_some()
            {
                if options.reconnect_config.enabled {
                    tracing::debug!(
                        error = %error,
                        "Initial connection failed with recoverable error, starting background reconnection"
                    );
                    let client = self.clone();
                    tokio::spawn(async move {
                        client.monitor_connection().await;
                    });
                } else {
                    tracing::debug!(error = %error, "Initial connection failed with recoverable error, but automatic reconnection is disabled");
                }
            } else {
                tracing::debug!(error = %error, "Initial connection failed with non-recoverable error, not starting background reconnection");
            }
        } else if result.is_ok() && options.reconnect_config.enabled {
            tracing::debug!(
                "Successful connection, starting monitor task for future disconnections"
            );
            let client = self.clone();
            tokio::spawn(async move {
                client.monitor_connection().await;
            });
        }

        result
    }

    /// Internal TLS connection method (no mutex guard)
    ///
    /// # Errors
    ///
    /// Returns an error if connection fails or configuration is invalid
    pub(crate) async fn connect_with_tls_and_options_internal(
        &self,
        tls_config: crate::transport::tls::TlsConfig,
        options: ConnectOptions,
    ) -> Result<ConnectResult> {
        if self.is_connected().await {
            return Err(MqttError::AlreadyConnected);
        }

        {
            let mut inner = self.inner.write().await;
            inner.options = options.clone();
            inner.last_address = Some(format!(
                "{}:{}",
                tls_config.hostname,
                tls_config.addr.port()
            ));
            inner.automatic_reconnect_lifecycle = AutomaticReconnectLifecycle::Armed;
        }

        self.trigger_connection_event(ConnectionEvent::Connecting)
            .await;
        let result = self.connect_internal_with_tls(tls_config).await;

        if result.is_err() && options.reconnect_config.enabled {
            tracing::warn!("Automatic reconnection with custom TLS config is not yet supported");
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::MqttClient;
    use std::future::Future;
    use std::task::{Context, Waker};

    #[tokio::test(flavor = "current_thread")]
    async fn hostname_resolution_yields_to_the_runtime() {
        let mut resolution = Box::pin(MqttClient::resolve_addresses("localhost", 1883));
        let first_poll = resolution
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        assert!(
            first_poll.is_pending(),
            "resolving a hostname must not block the runtime thread"
        );

        let addrs = resolution.await.unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|addr| addr.port() == 1883));
        assert!(addrs.iter().all(|addr| addr.ip().is_loopback()));
    }

    #[test]
    fn a_redirect_without_a_scheme_is_tcp_made_tls_from_a_secure_connection() {
        assert_eq!(
            MqttClient::redirect_address("mqtt://lb:1883", "backend:1883").unwrap(),
            "backend:1883"
        );
        assert_eq!(
            MqttClient::redirect_address("mqtts://lb:8883", "backend:8883").unwrap(),
            "mqtts://backend:8883"
        );
        #[cfg(feature = "transport-websocket")]
        {
            assert_eq!(
                MqttClient::redirect_address("ws://lb/mqtt", "backend:1883").unwrap(),
                "backend:1883"
            );
            assert_eq!(
                MqttClient::redirect_address("wss://lb/mqtt", "backend:8883").unwrap(),
                "mqtts://backend:8883"
            );
        }
        #[cfg(feature = "transport-quic")]
        {
            assert_eq!(
                MqttClient::redirect_address("quic://lb:14567", "backend:1883").unwrap(),
                "backend:1883"
            );
            assert_eq!(
                MqttClient::redirect_address("quics://lb:14567", "backend:8883").unwrap(),
                "mqtts://backend:8883"
            );
        }
    }

    #[test]
    fn a_redirect_from_a_secure_connection_to_a_plain_one_is_refused() {
        for plain in ["mqtt://backend", "tcp://backend"] {
            assert!(MqttClient::redirect_address("mqtts://lb", plain).is_err());
        }
        #[cfg(feature = "transport-websocket")]
        {
            assert!(MqttClient::redirect_address("wss://lb/mqtt", "ws://backend/mqtt").is_err());
            assert!(MqttClient::redirect_address("mqtts://lb", "ws://backend/mqtt").is_err());
        }
        #[cfg(feature = "transport-quic")]
        assert!(MqttClient::redirect_address("quics://lb", "quic://backend").is_err());
        assert_eq!(
            MqttClient::redirect_address("mqtt://lb", "mqtts://backend").unwrap(),
            "mqtts://backend"
        );
    }
}

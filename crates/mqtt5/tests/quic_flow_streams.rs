#![cfg(feature = "broker")]
#![cfg(feature = "transport-quic")]

use bytes::BytesMut;
use mqtt5::broker::config::{
    BrokerConfig, QuicConfig as BrokerQuicConfig, StorageBackend, StorageConfig,
};
use mqtt5::broker::{BrokerShutdownHandle, MqttBroker};
use mqtt5::error::Result;
use mqtt5::transport::flow::{ControlFlowHeader, DataFlowHeader, FlowFlags, FlowId};
use mqtt5::transport::{QuicConfig, QuicSplitResult, QuicTransport};
use mqtt5::Transport;
use mqtt5_protocol::QuicStreamCode;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Once;
use std::time::Duration;
use tokio::task::JoinHandle;

const CERT: &str = "../../test_certs/server.pem";
const KEY: &str = "../../test_certs/server.key";
const PINGREQ: [u8; 2] = [0xC0, 0x00];
const USER_DEFINED_FLOWS: [&[u8]; 2] = [&[0x14, 0x02, b'h', b'i'], &[0x14, 0x61, 0x70, 0x70]];

#[derive(Debug, PartialEq)]
struct Outcome {
    session_alive: bool,
    close_code: Option<u64>,
}

const STILL_SERVED: Outcome = Outcome {
    session_alive: true,
    close_code: None,
};

static CRYPTO_PROVIDER: Once = Once::new();

struct Broker {
    shutdown: BrokerShutdownHandle,
    run: JoinHandle<Result<()>>,
}

impl Broker {
    async fn start() -> (Self, SocketAddr) {
        CRYPTO_PROVIDER.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("install crypto provider");
        });
        let config = BrokerConfig::default()
            .with_storage(StorageConfig::default().with_backend(StorageBackend::Memory))
            .with_bind_address(([127, 0, 0, 1], 0))
            .with_quic(
                BrokerQuicConfig::new(PathBuf::from(CERT), PathBuf::from(KEY))
                    .with_bind_address("127.0.0.1:0".parse::<SocketAddr>().expect("bind address")),
            );
        let mut broker = MqttBroker::with_config(config)
            .await
            .expect("broker starts");
        let addr = broker.quic_local_addr().expect("QUIC endpoint bound");
        let shutdown = broker.shutdown_handle();
        let run = tokio::spawn(async move { broker.run().await });
        (Self { shutdown, run }, addr)
    }

    async fn stop(self) {
        self.shutdown.shutdown();
        tokio::time::timeout(Duration::from_secs(5), self.run)
            .await
            .expect("broker stops")
            .expect("broker task joins")
            .expect("broker run succeeds");
    }
}

fn connect_frame(client_id: &str) -> Vec<u8> {
    let mut body = vec![
        0x00, 0x04, b'M', b'Q', b'T', b'T', 0x05, 0x02, 0x00, 0x3C, 0x00,
    ];
    body.extend_from_slice(
        &u16::try_from(client_id.len())
            .expect("client id fits u16")
            .to_be_bytes(),
    );
    body.extend_from_slice(client_id.as_bytes());
    let mut frame = vec![0x10, u8::try_from(body.len()).expect("short CONNECT")];
    frame.extend_from_slice(&body);
    frame
}

async fn connected_session(client_id: &str) -> (Broker, QuicSplitResult) {
    let (broker, addr) = Broker::start().await;
    let mut transport =
        QuicTransport::new(QuicConfig::new(addr, "localhost").with_verify_server_cert(false));
    transport.connect().await.expect("QUIC handshake");
    let mut split = transport.into_split().expect("split transport");
    split
        .send
        .write_all(&connect_frame(client_id))
        .await
        .expect("send CONNECT");
    let mut header = [0u8; 2];
    split
        .recv
        .read_exact(&mut header)
        .await
        .expect("read CONNACK header");
    assert_eq!(header[0], 0x20);
    let mut body = vec![0u8; usize::from(header[1])];
    split
        .recv
        .read_exact(&mut body)
        .await
        .expect("read CONNACK body");
    (broker, split)
}

async fn outcome(split: &mut QuicSplitResult) -> Outcome {
    let mut response = [0u8; 2];
    let session_alive = split.send.write_all(&PINGREQ).await.is_ok()
        && matches!(
            tokio::time::timeout(Duration::from_secs(2), split.recv.read_exact(&mut response))
                .await,
            Ok(Ok(()))
        )
        && response == [0xD0, 0x00];
    let close_code = tokio::time::timeout(Duration::from_secs(3), split.connection.closed())
        .await
        .ok()
        .and_then(|error| match error {
            quinn::ConnectionError::ApplicationClosed(close) => Some(close.error_code.into_inner()),
            _ => None,
        });
    Outcome {
        session_alive,
        close_code,
    }
}

#[derive(Debug, PartialEq)]
enum StreamEnd {
    Stopped(u64),
    Refused(u64),
    Finished,
    Open,
}

fn code(code: QuicStreamCode) -> u64 {
    u64::from(code.code())
}

fn data_flow(sequence: u64, expire: u64, flags: FlowFlags) -> Vec<u8> {
    let mut buf = BytesMut::new();
    DataFlowHeader::client(FlowId::client(sequence), expire, flags).encode(&mut buf);
    buf.to_vec()
}

fn with_pingreq(mut header: Vec<u8>) -> Vec<u8> {
    header.extend_from_slice(&PINGREQ);
    header
}

fn server_flow() -> Vec<u8> {
    let mut buf = BytesMut::new();
    DataFlowHeader::server(FlowId::server(1), 0, FlowFlags::default()).encode(&mut buf);
    with_pingreq(buf.to_vec())
}

fn client_flow_with_server_id() -> Vec<u8> {
    let mut buf = BytesMut::new();
    DataFlowHeader::client(FlowId::server(1), 0, FlowFlags::default()).encode(&mut buf);
    with_pingreq(buf.to_vec())
}

fn second_control_flow() -> Vec<u8> {
    let mut buf = BytesMut::new();
    ControlFlowHeader::new(FlowFlags::default()).encode(&mut buf);
    with_pingreq(buf.to_vec())
}

async fn on_uni(bytes: &[u8]) -> (StreamEnd, Outcome) {
    let (broker, mut split) = connected_session("uni-flow").await;
    let mut stream = split.connection.open_uni().await.expect("open uni");
    stream.write_all(bytes).await.expect("write uni");
    let end = match tokio::time::timeout(Duration::from_secs(1), stream.stopped()).await {
        Ok(Ok(Some(code))) => StreamEnd::Stopped(code.into_inner()),
        Ok(_) => StreamEnd::Finished,
        Err(_) => StreamEnd::Open,
    };
    let result = outcome(&mut split).await;
    broker.stop().await;
    (end, result)
}

async fn on_bidi(bytes: &[u8], finish: bool) -> (StreamEnd, Outcome) {
    let (broker, mut split) = connected_session("bidi-flow").await;
    let (mut send, mut recv) = split.connection.open_bi().await.expect("open bidi");
    send.write_all(bytes).await.expect("write bidi");
    if finish {
        send.finish().expect("finish bidi");
    }
    let end = match tokio::time::timeout(Duration::from_secs(1), recv.read_to_end(64)).await {
        Ok(Ok(data)) if data.is_empty() => StreamEnd::Finished,
        Ok(Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)))) => {
            let stopped = tokio::time::timeout(Duration::from_secs(1), send.stopped()).await;
            assert!(
                matches!(stopped, Ok(Ok(Some(stop))) if stop == code),
                "send side was not stopped with the reset code: {stopped:?}"
            );
            StreamEnd::Refused(code.into_inner())
        }
        Ok(other) => panic!("unexpected bidi stream end: {other:?}"),
        Err(_) => StreamEnd::Open,
    };
    let result = outcome(&mut split).await;
    broker.stop().await;
    (end, result)
}

#[tokio::test]
async fn user_defined_flows_are_refused_without_closing_the_connection() {
    for flow in USER_DEFINED_FLOWS {
        assert_eq!(
            on_uni(flow).await,
            (
                StreamEnd::Stopped(code(QuicStreamCode::FlowRefused)),
                STILL_SERVED
            )
        );
        assert_eq!(
            on_bidi(flow, false).await,
            (
                StreamEnd::Refused(code(QuicStreamCode::FlowRefused)),
                STILL_SERVED
            )
        );
    }
}

#[tokio::test]
async fn flows_only_the_server_may_open_are_refused_as_a_bad_flow_id() {
    for flow in [server_flow(), client_flow_with_server_id()] {
        assert_eq!(
            on_uni(&flow).await,
            (
                StreamEnd::Stopped(code(QuicStreamCode::BadFlowId)),
                STILL_SERVED
            )
        );
        assert_eq!(
            on_bidi(&flow, false).await,
            (
                StreamEnd::Refused(code(QuicStreamCode::BadFlowId)),
                STILL_SERVED
            )
        );
    }
}

#[tokio::test]
async fn a_second_control_flow_is_refused_as_a_stream_type_error() {
    let flow = second_control_flow();
    assert_eq!(
        on_uni(&flow).await,
        (
            StreamEnd::Stopped(code(QuicStreamCode::StreamType)),
            STILL_SERVED
        )
    );
    assert_eq!(
        on_bidi(&flow, false).await,
        (
            StreamEnd::Refused(code(QuicStreamCode::StreamType)),
            STILL_SERVED
        )
    );
}

#[tokio::test]
async fn a_bidirectional_stream_without_a_flow_header_is_refused() {
    assert_eq!(
        on_bidi(&PINGREQ, false).await,
        (
            StreamEnd::Refused(code(QuicStreamCode::StreamType)),
            STILL_SERVED
        )
    );
}

#[tokio::test]
async fn a_unidirectional_client_data_flow_is_served() {
    assert_eq!(
        on_uni(&with_pingreq(data_flow(1, 0, FlowFlags::default()))).await,
        (StreamEnd::Open, STILL_SERVED)
    );
    assert_eq!(on_uni(&PINGREQ).await, (StreamEnd::Open, STILL_SERVED));
}

#[tokio::test]
async fn a_discard_header_ended_by_fin_is_answered_with_fin() {
    assert_eq!(
        on_bidi(&data_flow(1, 0, FlowFlags::discard()), true).await,
        (StreamEnd::Finished, STILL_SERVED)
    );
}

#[tokio::test]
async fn a_unidirectional_flow_ending_inside_a_packet_keeps_the_session() {
    let mut flow = data_flow(1, 0, FlowFlags::default());
    flow.extend_from_slice(&PINGREQ[..1]);
    let (broker, mut split) = connected_session("incomplete-flow").await;
    let mut stream = split.connection.open_uni().await.expect("open uni");
    stream.write_all(&flow).await.expect("write uni");
    stream.finish().expect("finish uni");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(outcome(&mut split).await, STILL_SERVED);
    broker.stop().await;
}

fn subscribe_frame(topic: &str) -> Vec<u8> {
    let mut body = vec![0x00, 0x01, 0x00];
    body.extend_from_slice(
        &u16::try_from(topic.len())
            .expect("short topic")
            .to_be_bytes(),
    );
    body.extend_from_slice(topic.as_bytes());
    body.push(0x00);
    let mut frame = vec![0x82, u8::try_from(body.len()).expect("short SUBSCRIBE")];
    frame.extend_from_slice(&body);
    frame
}

fn publish_frame(topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        &u16::try_from(topic.len())
            .expect("short topic")
            .to_be_bytes(),
    );
    body.extend_from_slice(topic.as_bytes());
    body.push(0x00);
    body.extend_from_slice(payload);
    let mut frame = vec![0x30, u8::try_from(body.len()).expect("short PUBLISH")];
    frame.extend_from_slice(&body);
    frame
}

async fn delivered_to_aborted_flow(discard: bool) -> bool {
    let (broker, mut split) = connected_session("discard-subscriptions").await;
    let preserved = FlowFlags {
        err_tolerance: 2,
        persistent_subscriptions: 1,
        ..FlowFlags::default()
    };
    let mut flow = split.connection.open_uni().await.expect("open flow");
    let mut bytes = data_flow(5, 300, preserved);
    bytes.extend_from_slice(&subscribe_frame("flows/discard"));
    flow.write_all(&bytes).await.expect("subscribe on flow");
    let mut suback = [0u8; 5];
    split
        .recv
        .read_exact(&mut suback)
        .await
        .expect("read SUBACK");
    assert_eq!(suback, [0x90, 0x04, 0x00, 0x01, 0x00]);
    flow.reset(quinn::VarInt::from_u32(
        QuicStreamCode::FlowCancelled.code(),
    ))
    .expect("abort flow");
    tokio::time::sleep(Duration::from_millis(200)).await;

    if discard {
        let (mut send, mut recv) = split.connection.open_bi().await.expect("open discard");
        send.write_all(&data_flow(5, 0, FlowFlags::discard()))
            .await
            .expect("send discard");
        send.finish().expect("finish discard");
        let response = tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(16))
            .await
            .expect("discard answered")
            .expect("discard ends with FIN");
        assert!(response.is_empty());
    }

    split
        .send
        .write_all(&publish_frame("flows/discard", b"after"))
        .await
        .expect("publish");
    let delivered = tokio::time::timeout(Duration::from_secs(2), split.connection.accept_bi())
        .await
        .is_ok();
    broker.stop().await;
    delivered
}

#[tokio::test]
async fn discarding_a_flow_removes_its_subscriptions() {
    assert!(delivered_to_aborted_flow(false).await);
    assert!(!delivered_to_aborted_flow(true).await);
}

const PINGRESP: [u8; 2] = [0xD0, 0x00];

async fn read_frame(recv: &mut quinn::RecvStream) -> Option<Vec<u8>> {
    let mut frame = vec![0u8; 2];
    tokio::time::timeout(Duration::from_secs(2), recv.read_exact(&mut frame))
        .await
        .ok()?
        .ok()?;
    let mut body = vec![0u8; usize::from(frame[1])];
    recv.read_exact(&mut body).await.ok()?;
    frame.extend_from_slice(&body);
    Some(frame)
}

async fn reset_code(recv: &mut quinn::RecvStream) -> Option<u64> {
    match tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(1024)).await {
        Ok(Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)))) => {
            Some(code.into_inner())
        }
        _ => None,
    }
}

fn qos1_subscribe_frame(topic: &str) -> Vec<u8> {
    let mut frame = subscribe_frame(topic);
    let last = frame.len() - 1;
    frame[last] = 0x01;
    frame
}

fn qos1_publish_frame(topic: &str, packet_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        &u16::try_from(topic.len())
            .expect("short topic")
            .to_be_bytes(),
    );
    body.extend_from_slice(topic.as_bytes());
    body.extend_from_slice(&packet_id.to_be_bytes());
    body.push(0x00);
    body.extend_from_slice(payload);
    let mut frame = vec![0x32, u8::try_from(body.len()).expect("short PUBLISH")];
    frame.extend_from_slice(&body);
    frame
}

fn payload_of(frame: &[u8]) -> &[u8] {
    let topic_len = usize::from(u16::from_be_bytes([frame[2], frame[3]]));
    let packet_id_len = if frame[0] & 0x06 == 0 { 0 } else { 2 };
    let properties_at = 4 + topic_len + packet_id_len;
    &frame[properties_at + 1 + usize::from(frame[properties_at])..]
}

async fn open_flow(
    split: &QuicSplitResult,
    sequence: u64,
    first: &[u8],
) -> (quinn::SendStream, quinn::RecvStream) {
    let (mut send, recv) = split.connection.open_bi().await.expect("open bidi flow");
    let mut bytes = data_flow(sequence, 300, FlowFlags::default());
    bytes.extend_from_slice(first);
    send.write_all(&bytes).await.expect("write flow");
    (send, recv)
}

async fn publish_from_control(
    split: &mut QuicSplitResult,
    topic: &str,
    packet_id: u16,
    payload: &[u8],
) {
    split
        .send
        .write_all(&qos1_publish_frame(topic, packet_id, payload))
        .await
        .expect("publish on control");
    let puback = read_frame(&mut split.recv)
        .await
        .expect("PUBACK on control");
    assert_eq!(puback[0], 0x40);
}

async fn nothing_off_the_flow(split: &mut QuicSplitResult) -> bool {
    let server_stream =
        tokio::time::timeout(Duration::from_millis(500), split.connection.accept_bi())
            .await
            .is_err();
    server_stream && outcome(split).await == STILL_SERVED
}

#[tokio::test]
async fn a_bidirectional_client_data_flow_is_answered_on_its_own_stream() {
    for flags in [FlowFlags::default(), FlowFlags::discard()] {
        let (broker, mut split) = connected_session("bidi-served").await;
        let (mut send, mut recv) = split.connection.open_bi().await.expect("open bidi");
        send.write_all(&with_pingreq(data_flow(1, 0, flags)))
            .await
            .expect("write flow");
        assert_eq!(read_frame(&mut recv).await, Some(PINGRESP.to_vec()));
        assert_eq!(outcome(&mut split).await, STILL_SERVED);
        broker.stop().await;
    }
}

#[tokio::test]
async fn subscriptions_on_a_bidirectional_flow_are_delivered_on_it() {
    let (broker, mut split) = connected_session("bidi-subscribe").await;
    let (_send, mut recv) = open_flow(&split, 1, &qos1_subscribe_frame("bidi/a")).await;
    assert_eq!(
        read_frame(&mut recv).await,
        Some(vec![0x90, 0x04, 0x00, 0x01, 0x00, 0x01])
    );
    publish_from_control(&mut split, "bidi/a", 7, b"one").await;
    let delivered = read_frame(&mut recv).await.expect("PUBLISH on the flow");
    assert_eq!(delivered[0] & 0xF0, 0x30);
    assert_eq!(payload_of(&delivered), b"one");
    assert!(nothing_off_the_flow(&mut split).await);
    broker.stop().await;
}

#[tokio::test]
async fn a_newer_stream_takes_the_flow_over() {
    let (broker, mut split) = connected_session("bidi-takeover").await;
    let (_old_send, mut old_recv) = open_flow(&split, 1, &qos1_subscribe_frame("bidi/t")).await;
    assert!(read_frame(&mut old_recv).await.is_some());
    let (_new_send, mut new_recv) = open_flow(&split, 1, &PINGREQ).await;
    assert_eq!(read_frame(&mut new_recv).await, Some(PINGRESP.to_vec()));
    assert_eq!(
        reset_code(&mut old_recv).await,
        Some(code(QuicStreamCode::NoError))
    );
    publish_from_control(&mut split, "bidi/t", 8, b"after").await;
    let delivered = read_frame(&mut new_recv)
        .await
        .expect("PUBLISH on the new stream");
    assert_eq!(payload_of(&delivered), b"after");
    assert!(nothing_off_the_flow(&mut split).await);
    broker.stop().await;
}

async fn late_older_stream_is_refused(newer_aborted: bool) {
    let (broker, mut split) = connected_session("bidi-late").await;
    let (mut older_send, mut older_recv) = split.connection.open_bi().await.expect("open older");
    let (mut newer_send, mut newer_recv) =
        open_flow(&split, 1, &qos1_subscribe_frame("bidi/l")).await;
    assert!(read_frame(&mut newer_recv).await.is_some());
    if newer_aborted {
        newer_send
            .reset(quinn::VarInt::from_u32(
                QuicStreamCode::FlowCancelled.code(),
            ))
            .expect("abort the newer stream");
        assert_eq!(
            reset_code(&mut newer_recv).await,
            Some(code(QuicStreamCode::NoError))
        );
    }
    older_send
        .write_all(&with_pingreq(data_flow(1, 300, FlowFlags::default())))
        .await
        .expect("write older");
    assert_eq!(
        reset_code(&mut older_recv).await,
        Some(code(QuicStreamCode::NoError))
    );
    if !newer_aborted {
        publish_from_control(&mut split, "bidi/l", 9, b"newer").await;
        let delivered = read_frame(&mut newer_recv)
            .await
            .expect("PUBLISH on the newer stream");
        assert_eq!(payload_of(&delivered), b"newer");
    }
    assert!(nothing_off_the_flow(&mut split).await);
    broker.stop().await;
}

#[tokio::test]
async fn an_older_stream_arriving_late_does_not_take_the_flow_back() {
    late_older_stream_is_refused(false).await;
    late_older_stream_is_refused(true).await;
}

#[tokio::test]
async fn messages_wait_for_a_flow_that_lost_its_stream() {
    let (broker, mut split) = connected_session("bidi-detached").await;
    let (mut first_send, mut first_recv) =
        open_flow(&split, 1, &qos1_subscribe_frame("bidi/d")).await;
    assert!(read_frame(&mut first_recv).await.is_some());
    first_send
        .reset(quinn::VarInt::from_u32(
            QuicStreamCode::FlowCancelled.code(),
        ))
        .expect("abort the flow's stream");
    assert_eq!(
        reset_code(&mut first_recv).await,
        Some(code(QuicStreamCode::NoError))
    );
    split
        .send
        .write_all(&publish_frame("bidi/d", b"qos0"))
        .await
        .expect("QoS 0 publish");
    publish_from_control(&mut split, "bidi/d", 10, b"waited").await;
    assert!(nothing_off_the_flow(&mut split).await);
    let (mut second_send, mut second_recv) = open_flow(&split, 1, &[]).await;
    let delivered = read_frame(&mut second_recv).await.expect("waiting PUBLISH");
    assert_eq!(delivered[0] & 0x06, 0x02);
    assert_eq!(payload_of(&delivered), b"waited");
    let packet_id = [delivered[10], delivered[11]];
    second_send
        .write_all(&[0x40, 0x02, packet_id[0], packet_id[1], 0xC0, 0x00])
        .await
        .expect("PUBACK and PINGREQ on the flow");
    assert_eq!(read_frame(&mut second_recv).await, Some(PINGRESP.to_vec()));
    broker.stop().await;
}

#[tokio::test]
async fn finishing_a_bidirectional_flow_ends_it() {
    let (broker, mut split) = connected_session("bidi-finish").await;
    let (mut send, mut recv) = open_flow(&split, 1, &subscribe_frame("bidi/f")).await;
    assert!(read_frame(&mut recv).await.is_some());
    send.finish().expect("finish the flow");
    let rest = tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(64))
        .await
        .expect("flow finished by the broker")
        .expect("flow ends with FIN");
    assert!(rest.is_empty());
    split
        .send
        .write_all(&publish_frame("bidi/f", b"gone"))
        .await
        .expect("publish");
    assert!(nothing_off_the_flow(&mut split).await);
    broker.stop().await;
}

#[tokio::test]
async fn a_bidirectional_flow_ending_inside_a_packet_is_reset() {
    let (broker, mut split) = connected_session("bidi-incomplete").await;
    let (mut send, mut recv) = open_flow(&split, 1, &PINGREQ[..1]).await;
    send.finish().expect("finish inside a packet");
    assert_eq!(
        reset_code(&mut recv).await,
        Some(code(QuicStreamCode::IncompletePacket))
    );
    assert_eq!(outcome(&mut split).await, STILL_SERVED);
    broker.stop().await;
}

#[tokio::test]
async fn retained_messages_for_a_bidirectional_flow_arrive_on_it() {
    let (broker, mut split) = connected_session("bidi-retained").await;
    let mut retained = publish_frame("bidi/r", b"kept");
    retained[0] = 0x31;
    split
        .send
        .write_all(&retained)
        .await
        .expect("retained publish");
    assert!(outcome(&mut split).await.session_alive);
    let (_send, mut recv) = open_flow(&split, 1, &qos1_subscribe_frame("bidi/r")).await;
    assert_eq!(
        read_frame(&mut recv).await,
        Some(vec![0x90, 0x04, 0x00, 0x01, 0x00, 0x01])
    );
    let delivered = read_frame(&mut recv)
        .await
        .expect("retained PUBLISH on the flow");
    assert_eq!(delivered[0] & 0x01, 0x01);
    assert_eq!(payload_of(&delivered), b"kept");
    assert!(nothing_off_the_flow(&mut split).await);
    broker.stop().await;
}

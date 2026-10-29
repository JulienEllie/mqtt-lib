use bytes::BytesMut;
use mqtt5::packet::connack::ConnAckPacket;
use mqtt5::packet::connect::ConnectPacket;
use mqtt5::packet::publish::PublishPacket;
use mqtt5::packet::{FixedHeader, MqttPacket, Packet, PacketType};
use mqtt5::protocol::v5::reason_codes::ReasonCode;
use mqtt5::session::TopicAliasManager;
use mqtt5::{
    AckToken, ConnectOptions, Message, MqttClient, MqttError, ProtocolVersion, PublishOptions,
    PublishProperties, QoS, SubscribeOptions,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const CONNECT: u8 = 1;
const PUBLISH: u8 = 3;
const SUBSCRIBE: u8 = 8;
const PINGREQ: u8 = 12;
const DISCONNECT: u8 = 14;

const SHORT: Duration = Duration::from_millis(600);
const MEDIUM: Duration = Duration::from_secs(3);

struct Frame {
    first: u8,
    body: Vec<u8>,
}

impl Frame {
    fn kind(&self) -> u8 {
        self.first >> 4
    }

    fn packet_id(&self) -> u16 {
        if self.kind() == PUBLISH {
            return self
                .publish()
                .packet_id
                .expect("QoS > 0 PUBLISH carries a packet id");
        }
        u16::from_be_bytes([self.body[0], self.body[1]])
    }

    fn reason_code(&self) -> u8 {
        match self.kind() {
            DISCONNECT => self.body.first().copied().unwrap_or(0),
            _ => self.body.get(2).copied().unwrap_or(0),
        }
    }

    fn packet(&self) -> Packet {
        let packet_type = PacketType::from_u8(self.kind()).expect("known packet type");
        let header = FixedHeader::new(
            packet_type,
            self.first & 0x0F,
            u32::try_from(self.body.len()).expect("body fits u32"),
        );
        let mut buf = BytesMut::from(&self.body[..]);
        Packet::decode_from_body_with_version(packet_type, &header, &mut buf, 5)
            .expect("client sent a decodable packet")
    }

    fn publish(&self) -> PublishPacket {
        match self.packet() {
            Packet::Publish(publish) => publish,
            other => panic!("expected PUBLISH, got {}", other.packet_type_name()),
        }
    }
}

enum Next {
    Frame(Frame),
    Closed,
    Timeout,
}

async fn read_frame(stream: &mut TcpStream) -> Option<Frame> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await.ok()?;
    let mut multiplier = 1usize;
    let mut remaining = 0usize;
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.ok()?;
        remaining += usize::from(byte[0] & 0x7F) * multiplier;
        if byte[0] & 0x80 == 0 {
            break;
        }
        multiplier *= 128;
    }
    let mut body = vec![0u8; remaining];
    stream.read_exact(&mut body).await.ok()?;
    Some(Frame {
        first: first[0],
        body,
    })
}

async fn next_frame(stream: &mut TcpStream, wait: Duration) -> Next {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline, read_frame(stream)).await {
            Err(_) => return Next::Timeout,
            Ok(None) => return Next::Closed,
            Ok(Some(frame)) if frame.kind() == PINGREQ => {
                let _ = stream.write_all(&[0xD0, 0x00]).await;
            }
            Ok(Some(frame)) => return Next::Frame(frame),
        }
    }
}

async fn expect_kind(stream: &mut TcpStream, kind: u8, wait: Duration) -> Frame {
    match next_frame(stream, wait).await {
        Next::Frame(frame) if frame.kind() == kind => frame,
        Next::Frame(frame) => panic!("expected packet type {kind}, got {}", frame.kind()),
        Next::Closed => panic!("connection closed while waiting for packet type {kind}"),
        Next::Timeout => panic!("timed out waiting for packet type {kind}"),
    }
}

async fn collect_frames(stream: &mut TcpStream, wait: Duration) -> (Vec<Frame>, bool) {
    let deadline = tokio::time::Instant::now() + wait;
    let mut frames = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match next_frame(stream, left).await {
            Next::Frame(frame) => frames.push(frame),
            Next::Closed => return (frames, true),
            Next::Timeout => return (frames, false),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Termination {
    Disconnect(u8),
    Closed,
    StillOpen,
}

async fn termination(stream: &mut TcpStream, wait: Duration) -> Termination {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match next_frame(stream, left).await {
            Next::Frame(frame) if frame.kind() == DISCONNECT => {
                return Termination::Disconnect(frame.reason_code())
            }
            Next::Frame(_) => {}
            Next::Closed => return Termination::Closed,
            Next::Timeout => return Termination::StillOpen,
        }
    }
}

fn encode_varint(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = u8::try_from(value % 128).expect("remainder fits u8");
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn frame_bytes(first: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![first];
    encode_varint(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

fn raw_publish(
    qos: u8,
    dup: bool,
    topic: &str,
    packet_id: Option<u16>,
    props: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        &u16::try_from(topic.len())
            .expect("topic fits u16")
            .to_be_bytes(),
    );
    body.extend_from_slice(topic.as_bytes());
    if let Some(id) = packet_id {
        body.extend_from_slice(&id.to_be_bytes());
    }
    encode_varint(props.len(), &mut body);
    body.extend_from_slice(props);
    body.extend_from_slice(payload);
    frame_bytes(0x30 | (u8::from(dup) << 3) | (qos << 1), &body)
}

fn subscription_id_prop(id: usize) -> Vec<u8> {
    let mut out = vec![0x0B];
    encode_varint(id, &mut out);
    out
}

fn suback_bytes(packet_id: u16, code: u8) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    body.push(0);
    body.push(code);
    frame_bytes(0x90, &body)
}

fn connack(session_present: bool, configure: impl FnOnce(&mut ConnAckPacket)) -> Vec<u8> {
    let mut packet = ConnAckPacket::new(session_present, ReasonCode::Success);
    configure(&mut packet);
    let mut encoded = Vec::new();
    packet.encode(&mut encoded).expect("CONNACK encodes");
    encoded
}

fn plain_connack() -> Vec<u8> {
    connack(false, |_| {})
}

async fn bind() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("mqtt://{}", listener.local_addr().expect("local addr"));
    (listener, url)
}

async fn accept_session(
    listener: &TcpListener,
    connack_bytes: &[u8],
) -> (TcpStream, ConnectPacket) {
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client connected within 10s")
        .expect("accept");
    let frame = expect_kind(&mut stream, CONNECT, MEDIUM).await;
    let connect = match frame.packet() {
        Packet::Connect(connect) => *connect,
        other => panic!("expected CONNECT, got {}", other.packet_type_name()),
    };
    stream
        .write_all(connack_bytes)
        .await
        .expect("write CONNACK");
    (stream, connect)
}

fn base_options(client_id: &str) -> ConnectOptions {
    ConnectOptions::new(client_id).with_automatic_reconnect(false)
}

async fn connect_client(
    options: ConnectOptions,
    connack_bytes: &[u8],
) -> (MqttClient, TcpStream, TcpListener) {
    let (listener, url) = bind().await;
    let client = MqttClient::with_options(options);
    let connecting = client.clone();
    let task = tokio::spawn(async move { connecting.connect(&url).await });
    let (stream, _) = accept_session(&listener, connack_bytes).await;
    task.await
        .expect("connect task")
        .expect("client connects to fake broker");
    (client, stream, listener)
}

async fn subscribe(
    client: &MqttClient,
    stream: &mut TcpStream,
    filter: &str,
    options: SubscribeOptions,
) -> mpsc::UnboundedReceiver<Message> {
    let (tx, rx) = mpsc::unbounded_channel();
    let subscriber = client.clone();
    let filter = filter.to_string();
    let granted = options.qos as u8;
    let task = tokio::spawn(async move {
        subscriber
            .subscribe_with_options(filter, options, move |message| {
                let _ = tx.send(message);
            })
            .await
    });
    let frame = expect_kind(stream, SUBSCRIBE, MEDIUM).await;
    stream
        .write_all(&suback_bytes(frame.packet_id(), granted))
        .await
        .expect("write SUBACK");
    task.await.expect("subscribe task").expect("subscribe");
    rx
}

fn qos_options(qos: QoS) -> SubscribeOptions {
    SubscribeOptions {
        qos,
        ..Default::default()
    }
}

async fn drain(rx: &mut mpsc::UnboundedReceiver<Message>, wait: Duration) -> Vec<Message> {
    let mut messages = Vec::new();
    while let Ok(Some(message)) = tokio::time::timeout(wait, rx.recv()).await {
        messages.push(message);
    }
    messages
}

async fn wait_until_disconnected(client: &MqttClient) {
    for _ in 0..100 {
        if !client.is_connected().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("client did not observe the dropped connection");
}

async fn published_frame_for(
    options: PublishOptions,
    topic: &str,
) -> (std::result::Result<(), MqttError>, Option<Frame>) {
    published_frame_with_connack(options, topic, &plain_connack()).await
}

async fn published_frame_with_connack(
    options: PublishOptions,
    topic: &str,
    connack_bytes: &[u8],
) -> (std::result::Result<(), MqttError>, Option<Frame>) {
    let (client, mut stream, _listener) =
        connect_client(base_options("conf-b-pub"), connack_bytes).await;
    let result = client
        .publish_with_options(topic.to_string(), b"x".to_vec(), options)
        .await
        .map(|_| ());
    let frame = match next_frame(&mut stream, SHORT).await {
        Next::Frame(frame) if frame.kind() == PUBLISH => Some(frame),
        _ => None,
    };
    (result, frame)
}

fn qos0_with(properties: PublishProperties) -> PublishOptions {
    PublishOptions {
        qos: QoS::AtMostOnce,
        properties,
        ..Default::default()
    }
}

#[tokio::test]
async fn zero_length_topic_requires_topic_alias() {
    let (result, frame) = published_frame_for(qos0_with(PublishProperties::default()), "").await;
    if let Some(frame) = frame {
        let publish = frame.publish();
        assert!(
            publish.topic_alias().is_some(),
            "§3.3.2.3.4: client sent PUBLISH with zero-length Topic Name and no Topic Alias (publish returned {result:?})"
        );
    }
}

#[tokio::test]
async fn subscribe_subscription_identifier_zero_not_sent() {
    let (client, mut stream, _listener) =
        connect_client(base_options("conf-b-subid0"), &plain_connack()).await;
    let subscriber = client.clone();
    let task = tokio::spawn(async move {
        subscriber
            .subscribe_with_options(
                "t/x",
                SubscribeOptions {
                    subscription_identifier: Some(0),
                    ..Default::default()
                },
                |_| {},
            )
            .await
    });
    let sent = match next_frame(&mut stream, SHORT).await {
        Next::Frame(frame) if frame.kind() == SUBSCRIBE => match frame.packet() {
            Packet::Subscribe(sub) => sub.properties.get_subscription_identifier(),
            _ => None,
        },
        _ => None,
    };
    task.abort();
    assert_ne!(
        sent,
        Some(0),
        "[§3.8.2.1.2] client sent SUBSCRIBE with Subscription Identifier 0 (Protocol Error)"
    );
}

#[tokio::test]
async fn inbound_subscription_identifier_zero_is_protocol_error() {
    let (client, mut stream, _listener) =
        connect_client(base_options("conf-b-inbound-subid0"), &plain_connack()).await;
    let mut rx = subscribe(&client, &mut stream, "t/sid", qos_options(QoS::AtMostOnce)).await;
    stream
        .write_all(&raw_publish(
            0,
            false,
            "t/sid",
            None,
            &subscription_id_prop(0),
            b"x",
        ))
        .await
        .unwrap();
    let delivered = drain(&mut rx, SHORT).await.len();
    let end = termination(&mut stream, MEDIUM).await;
    assert!(
        delivered == 0 && matches!(end, Termination::Closed | Termination::Disconnect(0x80..)),
        "[§3.3.2.3.8] inbound PUBLISH with Subscription Identifier 0 must be a Protocol Error; delivered={delivered} termination={end:?}"
    );
}

fn deferred_options(client_id: &str, receive_maximum: u16) -> ConnectOptions {
    ConnectOptions::new(client_id)
        .with_clean_start(false)
        .with_session_expiry_interval(300)
        .with_receive_maximum(receive_maximum)
        .with_deferred_ack(true)
        .with_automatic_reconnect(false)
}

#[tokio::test]
async fn deferred_ack_redelivery_at_receive_maximum_after_resume() {
    let (listener, url) = bind().await;
    let mut options = deferred_options("conf-b-deferred-resume", 1);
    options.reconnect_config.enabled = true;
    options.reconnect_config.initial_delay = Duration::from_millis(100);
    options.reconnect_config.max_delay = Duration::from_millis(200);
    let client = MqttClient::with_options(options);
    let connecting = client.clone();
    let connect_task = tokio::spawn(async move { connecting.connect(&url).await });
    let (mut first, _) = accept_session(&listener, &plain_connack()).await;
    connect_task.await.unwrap().expect("connect");

    let held: Arc<Mutex<Vec<AckToken>>> = Arc::new(Mutex::new(Vec::new()));
    let deliveries = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let subscriber = client.clone();
    let (held_cb, deliveries_cb) = (Arc::clone(&held), Arc::clone(&deliveries));
    let sub_task = tokio::spawn(async move {
        subscriber
            .subscribe_with_ack(
                "t/deferred",
                qos_options(QoS::AtLeastOnce),
                move |publish, token| {
                    deliveries_cb.lock().unwrap().push(publish.payload.to_vec());
                    held_cb.lock().unwrap().push(token);
                },
            )
            .await
    });
    let sub = expect_kind(&mut first, SUBSCRIBE, MEDIUM).await;
    first
        .write_all(&suback_bytes(sub.packet_id(), 1))
        .await
        .unwrap();
    sub_task.await.unwrap().expect("subscribe_with_ack");

    first
        .write_all(&raw_publish(1, false, "t/deferred", Some(1), &[], b"held"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        held.lock().unwrap().len(),
        1,
        "first delivery holds its token"
    );
    drop(first);
    wait_until_disconnected(&client).await;

    let (mut second, _) = accept_session(&listener, &connack(true, |_| {})).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    second
        .write_all(&raw_publish(1, true, "t/deferred", Some(1), &[], b"held"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let tokens: Vec<AckToken> = held.lock().unwrap().drain(..).collect();
    for token in tokens {
        token.ack();
    }
    let _ = collect_frames(&mut second, Duration::from_millis(300)).await;

    second
        .write_all(&raw_publish(1, false, "t/deferred", Some(2), &[], b"next"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let got_next = deliveries
        .lock()
        .unwrap()
        .iter()
        .any(|payload| payload == b"next");
    assert!(
        got_next,
        "a resumed-session DUP redelivery of a still-held message at client Receive Maximum 1 broke the connection: later PUBLISH id 2 was never delivered"
    );
}

#[tokio::test]
async fn topic_alias_boundary_no_panic_via_public_api() {
    let outcome = tokio::spawn(async move {
        let mut inbound = TopicAliasManager::new(u16::MAX);
        inbound
            .register_alias(u16::MAX, "t/max")
            .expect("alias == maximum is valid");
        let mut outbound = TopicAliasManager::new(u16::MAX);
        let mut last = None;
        for i in 0..u32::from(u16::MAX) {
            last = outbound.get_or_create_alias(&format!("t/{i}"));
        }
        last
    })
    .await;
    match outcome {
        Ok(last) => assert_eq!(last, Some(u16::MAX)),
        Err(e) => panic!(
            "mqtt5::session::TopicAliasManager panicked assigning outbound Topic Alias == Topic Alias Maximum (65535): {e}"
        ),
    }

    let (client, mut stream, _listener) = connect_client(
        base_options("conf-b-alias-boundary-wire"),
        &connack(false, |c| c.properties.set_topic_alias_maximum(u16::MAX)),
    )
    .await;
    let properties = PublishProperties {
        topic_alias: Some(u16::MAX),
        ..Default::default()
    };
    client
        .publish_with_options("t/max", b"x".to_vec(), qos0_with(properties))
        .await
        .expect("publish with alias == server maximum");
    let frame = expect_kind(&mut stream, PUBLISH, MEDIUM).await;
    assert_eq!(frame.publish().topic_alias(), Some(u16::MAX));
}

#[tokio::test]
async fn v311_publish_ignores_v5_only_properties_and_sends_none() {
    let (listener, url) = bind().await;
    let client = MqttClient::with_options(
        base_options("conf-b-v311-props").with_protocol_version(ProtocolVersion::V311),
    );
    let connecting = client.clone();
    let task = tokio::spawn(async move { connecting.connect(&url).await });
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("client connected within 10s")
        .expect("accept");
    let connect = expect_kind(&mut stream, CONNECT, MEDIUM).await;
    assert_eq!(
        connect.body[6], 4,
        "CONNECT protocol level must be 4 (3.1.1)"
    );
    stream
        .write_all(&[0x20, 0x02, 0x00, 0x00])
        .await
        .expect("write CONNACK");
    task.await.unwrap().expect("3.1.1 connect");

    let properties = PublishProperties {
        topic_alias: Some(1),
        response_topic: Some("r/#".to_string()),
        subscription_identifiers: vec![1],
        ..Default::default()
    };
    client
        .publish_with_options("a/b", b"x".to_vec(), qos0_with(properties))
        .await
        .expect("3.1.1 publish must not be failed by v5-only property checks");
    let frame = expect_kind(&mut stream, PUBLISH, MEDIUM).await;
    assert_eq!(
        frame.body,
        vec![0x00, 0x03, b'a', b'/', b'b', b'x'],
        "3.1.1 PUBLISH must carry only Topic Name and payload, no v5 properties"
    );
}

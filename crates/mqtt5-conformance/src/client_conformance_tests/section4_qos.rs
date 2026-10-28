use super::common::{
    parse_publish, queued_flush, received_after, start, subscribe_and_ack, SHORT, TIMEOUT,
};
use crate::client_conformance_test;
use crate::client_sut::{ClientSutHandle, ConnectSpec};
use crate::scripted_broker::{ack, publish, publish_first_byte, PUBACK, PUBCOMP, PUBREC};

/// [MQTT-4.3.3-10] [MQTT-4.3.3-12] A duplicate `QoS` 2 PUBLISH that arrives
/// before PUBREL is acknowledged again with PUBREC and not delivered twice;
/// after PUBCOMP the same Packet Identifier starts a new Application
/// Message.
#[client_conformance_test(ids = ["MQTT-4.3.3-10", "MQTT-4.3.3-12"])]
async fn duplicate_qos2_before_pubrel_delivered_once_then_id_reusable(sut: ClientSutHandle) {
    let mut s = start(&sut, ConnectSpec::new("qos-dup2"), false, &[]).await;
    s.result.as_ref().unwrap();
    subscribe_and_ack(&mut s, "t/q2", 2).await;

    s.conn
        .send(&publish(
            publish_first_byte(2, false),
            b"t/q2",
            Some(5),
            &[],
            b"first",
        ))
        .await
        .unwrap();
    assert_eq!(
        s.conn
            .next_of_type(PUBREC, TIMEOUT)
            .await
            .and_then(|p| p.leading_packet_id()),
        Some(5)
    );
    s.conn
        .send(&publish(
            publish_first_byte(2, true),
            b"t/q2",
            Some(5),
            &[],
            b"first",
        ))
        .await
        .unwrap();
    assert_eq!(
        s.conn
            .next_of_type(PUBREC, TIMEOUT)
            .await
            .and_then(|p| p.leading_packet_id()),
        Some(5),
        "[MQTT-4.3.3-10] duplicate before PUBREL must be re-acknowledged with PUBREC"
    );
    assert_eq!(
        received_after(&s.client, SHORT).await.len(),
        1,
        "[MQTT-4.3.3-10] duplicate QoS2 PUBLISH before PUBREL delivered more than once"
    );

    s.conn.send(&ack(0x62, 5)).await.unwrap();
    assert_eq!(
        s.conn
            .next_of_type(PUBCOMP, TIMEOUT)
            .await
            .and_then(|p| p.leading_packet_id()),
        Some(5)
    );

    s.conn
        .send(&publish(
            publish_first_byte(2, false),
            b"t/q2",
            Some(5),
            &[],
            b"second",
        ))
        .await
        .unwrap();
    assert_eq!(
        s.conn
            .next_of_type(PUBREC, TIMEOUT)
            .await
            .and_then(|p| p.leading_packet_id()),
        Some(5)
    );
    let received = received_after(&s.client, SHORT).await;
    assert_eq!(
        received.len(),
        2,
        "[MQTT-4.3.3-12] PUBLISH reusing a completed QoS2 id must be a new message"
    );
    assert_eq!(received[1].payload, b"second");
}

/// [MQTT-4.3.2-5] After PUBACK, a `QoS` 1 PUBLISH with the same Packet
/// Identifier is a new Application Message, whatever its DUP flag.
#[client_conformance_test(ids = ["MQTT-4.3.2-5"])]
async fn qos1_id_reuse_after_puback_is_new_message(sut: ClientSutHandle) {
    let mut s = start(&sut, ConnectSpec::new("qos-reuse1"), false, &[]).await;
    s.result.as_ref().unwrap();
    subscribe_and_ack(&mut s, "t/q1", 1).await;
    for (dup, payload) in [(false, &b"a"[..]), (true, &b"b"[..])] {
        s.conn
            .send(&publish(
                publish_first_byte(1, dup),
                b"t/q1",
                Some(9),
                &[],
                payload,
            ))
            .await
            .unwrap();
        assert_eq!(
            s.conn
                .next_of_type(PUBACK, TIMEOUT)
                .await
                .and_then(|p| p.leading_packet_id()),
            Some(9)
        );
    }
    assert_eq!(
        received_after(&s.client, SHORT).await.len(),
        2,
        "[MQTT-4.3.2-5] QoS1 PUBLISH reusing an acknowledged id must be treated as new"
    );
}

/// [MQTT-4.3.2-2] A `QoS` 1 message queued while offline is sent for the first
/// time with DUP 0.
#[client_conformance_test(
    ids = ["MQTT-4.3.2-2"],
    requires = ["client.automatic_reconnect", "client.offline_queue"],
)]
async fn queued_message_first_transmission_has_dup_zero(sut: ClientSutHandle) {
    let publishes = queued_flush(&sut, "qos-queued-dup").await;
    let first = parse_publish(
        publishes
            .first()
            .expect("queued messages were never sent after reconnect"),
    );
    assert!(
        !first.dup,
        "[MQTT-4.3.2-2] queued QoS1 message sent for the first time with DUP=1 (packet id {:?})",
        first.packet_id
    );
}

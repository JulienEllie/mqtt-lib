#[cfg(all(not(target_arch = "wasm32"), feature = "transport-quic"))]
pub(crate) use quic::{BidiFlow, BidiFlowEvent, OpenedStream, StreamEnding};

#[cfg(any(target_arch = "wasm32", not(feature = "transport-quic")))]
pub(crate) enum BidiFlowEvent {}

#[cfg(all(not(target_arch = "wasm32"), feature = "transport-quic"))]
mod quic {
    use super::super::subscribe::FlowActivity;
    use super::super::ClientHandler;
    use crate::broker::router::RoutableMessage;
    use crate::broker::storage::QueuedMessage;
    use crate::error::Result;
    use crate::packet::Packet;
    use crate::session::quic_flow::FlowState;
    use crate::QoS;
    use mqtt5_protocol::QuicStreamCode;
    use quinn::{SendStream, VarInt};
    use std::collections::VecDeque;
    use tokio::sync::oneshot;
    use tracing::{debug, warn};

    const MAX_BIDI_FLOWS: usize = 256;

    pub(crate) enum StreamEnding {
        Finished,
        Incomplete,
        Aborted,
    }

    pub(crate) struct OpenedStream {
        pub(crate) flow: FlowState,
        pub(crate) stream_id: u64,
        pub(crate) send: SendStream,
        pub(crate) abort: oneshot::Sender<QuicStreamCode>,
    }

    pub(crate) enum BidiFlowEvent {
        Opened(Box<OpenedStream>),
        Packet {
            flow_id: u64,
            stream_id: u64,
            packet: Packet,
        },
        Closed {
            flow_id: u64,
            stream_id: u64,
            ending: StreamEnding,
        },
    }

    struct FlowStream {
        id: u64,
        send: SendStream,
        abort: oneshot::Sender<QuicStreamCode>,
    }

    impl FlowStream {
        fn close(mut self, code: QuicStreamCode) {
            if let Err(e) = self.send.reset(VarInt::from_u32(code.code())) {
                debug!(
                    stream_id = self.id,
                    "flow stream already closed before reset: {e}"
                );
            }
            if self.abort.send(code).is_err() {
                debug!(stream_id = self.id, "flow stream reader already ended");
            }
        }

        fn finish(mut self) {
            if let Err(e) = self.send.finish() {
                debug!(
                    stream_id = self.id,
                    "flow stream already closed before finish: {e}"
                );
            }
        }
    }

    pub(crate) struct LiveFlow {
        current: Option<FlowStream>,
        highest: u64,
        detached: VecDeque<RoutableMessage>,
    }

    pub(crate) enum BidiFlow {
        Live(LiveFlow),
        Ended { highest: u64 },
    }

    impl BidiFlow {
        fn highest(&self) -> u64 {
            match self {
                Self::Live(live) => live.highest,
                Self::Ended { highest } => *highest,
            }
        }
    }

    impl ClientHandler {
        pub(in super::super) async fn handle_bidi_event(
            &mut self,
            event: BidiFlowEvent,
        ) -> Result<FlowActivity> {
            match event {
                BidiFlowEvent::Opened(opened) => {
                    self.open_bidi_stream(opened).await;
                    Ok(FlowActivity::Lifecycle)
                }
                BidiFlowEvent::Packet {
                    flow_id,
                    stream_id,
                    packet,
                } => {
                    self.handle_bidi_packet(flow_id, stream_id, packet).await?;
                    Ok(FlowActivity::Packet)
                }
                BidiFlowEvent::Closed {
                    flow_id,
                    stream_id,
                    ending,
                } => {
                    self.close_bidi_stream(flow_id, stream_id, ending).await;
                    Ok(FlowActivity::Lifecycle)
                }
            }
        }

        async fn open_bidi_stream(&mut self, opened: Box<OpenedStream>) {
            let OpenedStream {
                flow,
                stream_id,
                send,
                abort,
            } = *opened;
            let flow_id = flow.id.raw();
            let stream = FlowStream {
                id: stream_id,
                send,
                abort,
            };
            if self
                .bidi_flows
                .get(&flow_id)
                .is_some_and(|known| stream_id <= known.highest())
            {
                debug!(
                    flow_id,
                    stream_id, "aborting a stream older than the flow's newest"
                );
                stream.close(QuicStreamCode::NoError);
                return;
            }
            if let Some(BidiFlow::Live(live)) = self.bidi_flows.get_mut(&flow_id) {
                if let Some(previous) = live.current.replace(stream) {
                    debug!(
                        flow_id,
                        stream_id,
                        previous = previous.id,
                        "flow taken over"
                    );
                    previous.close(QuicStreamCode::NoError);
                }
                live.highest = stream_id;
                let waiting = std::mem::take(&mut live.detached);
                self.touch_flow(flow.id).await;
                self.requeue_for_flow(flow_id, waiting);
                return;
            }
            if !self.admit_bidi_flow(flow_id) || !self.register_flow(flow).await {
                warn!(flow_id, "refusing bidirectional flow: flow limit reached");
                stream.close(QuicStreamCode::FlowRefused);
                return;
            }
            debug!(flow_id, stream_id, "bidirectional client data flow opened");
            self.bidi_flows.insert(
                flow_id,
                BidiFlow::Live(LiveFlow {
                    current: Some(stream),
                    highest: stream_id,
                    detached: VecDeque::new(),
                }),
            );
        }

        fn admit_bidi_flow(&mut self, flow_id: u64) -> bool {
            if self.bidi_flows.contains_key(&flow_id) || self.bidi_flows.len() < MAX_BIDI_FLOWS {
                return true;
            }
            let ended = self
                .bidi_flows
                .iter()
                .find_map(|(id, flow)| matches!(flow, BidiFlow::Ended { .. }).then_some(*id));
            ended.is_some_and(|id| self.bidi_flows.remove(&id).is_some())
        }

        async fn register_flow(&self, flow: FlowState) -> bool {
            let Some(registry) = self.flow_registry.as_ref() else {
                return true;
            };
            let mut registry = registry.lock().await;
            if registry.contains(flow.id) {
                registry.touch(flow.id);
                return true;
            }
            registry.register_flow(flow)
        }

        async fn touch_flow(&self, flow_id: crate::transport::flow::FlowId) {
            if let Some(registry) = self.flow_registry.as_ref() {
                registry.lock().await.touch(flow_id);
            }
        }

        fn requeue_for_flow(&self, flow_id: u64, waiting: VecDeque<RoutableMessage>) {
            if waiting.is_empty() {
                return;
            }
            let (Some(queue), Some(client_id)) = (self.queue.as_ref(), self.client_id.as_ref())
            else {
                warn!(
                    flow_id,
                    count = waiting.len(),
                    "no session queue for the flow's waiting messages"
                );
                return;
            };
            debug!(
                flow_id,
                count = waiting.len(),
                "delivering messages that waited for the flow"
            );
            let messages = waiting
                .into_iter()
                .map(|routable| {
                    let qos = routable.publish.qos;
                    QueuedMessage::new(routable.publish, client_id.clone(), qos, None)
                        .with_target_flow(Some(flow_id))
                })
                .collect();
            queue.requeue_front_in_epoch(messages, self.queue_epoch);
            queue.notify();
        }

        async fn handle_bidi_packet(
            &mut self,
            flow_id: u64,
            stream_id: u64,
            packet: Packet,
        ) -> Result<()> {
            if !self.is_current_stream(flow_id, stream_id) {
                debug!(
                    flow_id,
                    stream_id, "dropping packet from a stream that is not the flow's current one"
                );
                return Ok(());
            }
            self.pending_external_flow_id = Some(flow_id);
            self.reply_flow = Some(flow_id);
            let result = self.handle_packet(packet).await;
            self.reply_flow = None;
            self.pending_external_flow_id = None;
            result
        }

        fn is_current_stream(&self, flow_id: u64, stream_id: u64) -> bool {
            matches!(
                self.bidi_flows.get(&flow_id),
                Some(BidiFlow::Live(LiveFlow { current: Some(stream), .. })) if stream.id == stream_id
            )
        }

        async fn close_bidi_stream(&mut self, flow_id: u64, stream_id: u64, ending: StreamEnding) {
            if !self.is_current_stream(flow_id, stream_id) {
                return;
            }
            let Some(stream) = self.detach_stream(flow_id) else {
                return;
            };
            match ending {
                StreamEnding::Finished => {
                    debug!(flow_id, stream_id, "flow finished by the client");
                    stream.finish();
                    self.end_bidi_flow(flow_id).await;
                }
                StreamEnding::Incomplete => {
                    warn!(flow_id, stream_id, "flow ended inside a packet");
                    stream.close(QuicStreamCode::IncompletePacket);
                }
                StreamEnding::Aborted => {
                    debug!(flow_id, stream_id, "flow aborted by the client");
                    stream.close(QuicStreamCode::NoError);
                }
            }
        }

        fn detach_stream(&mut self, flow_id: u64) -> Option<FlowStream> {
            match self.bidi_flows.get_mut(&flow_id) {
                Some(BidiFlow::Live(live)) => live.current.take(),
                _ => None,
            }
        }

        async fn end_bidi_flow(&mut self, flow_id: u64) {
            let Some(flow) = self.bidi_flows.get_mut(&flow_id) else {
                return;
            };
            let highest = flow.highest();
            if let BidiFlow::Live(live) = std::mem::replace(flow, BidiFlow::Ended { highest }) {
                if let Some(stream) = live.current {
                    stream.close(QuicStreamCode::NoError);
                }
            }
            if let Some(registry) = self.flow_registry.as_ref() {
                registry
                    .lock()
                    .await
                    .remove(crate::transport::flow::FlowId::from(flow_id));
            }
            self.handle_flow_closed(flow_id).await;
        }

        pub(in super::super) fn discard_bidi_flow(&mut self, flow_id: u64) {
            let Some(flow) = self.bidi_flows.get_mut(&flow_id) else {
                return;
            };
            let highest = flow.highest();
            if let BidiFlow::Live(live) = std::mem::replace(flow, BidiFlow::Ended { highest }) {
                if let Some(stream) = live.current {
                    stream.close(QuicStreamCode::DiscardState);
                }
            }
        }

        pub(in super::super) async fn hold_for_flow(
            &mut self,
            routable: RoutableMessage,
        ) -> Option<RoutableMessage> {
            let Some(flow_id) = routable.target_flow else {
                return Some(routable);
            };
            let capacity = usize::from(self.client_receive_maximum);
            match self.bidi_flows.get_mut(&flow_id) {
                None => Some(routable),
                Some(BidiFlow::Ended { .. }) => {
                    debug!(flow_id, "dropping a message for a flow that has ended");
                    None
                }
                Some(BidiFlow::Live(live)) => {
                    if live.current.is_some() {
                        return Some(routable);
                    }
                    if routable.publish.qos == QoS::AtMostOnce {
                        debug!(
                            flow_id,
                            "dropping a QoS 0 message while the flow has no stream"
                        );
                        return None;
                    }
                    if live.detached.len() < capacity {
                        live.detached.push_back(routable);
                        return None;
                    }
                    warn!(
                        flow_id,
                        capacity, "flow has no stream and its waiting messages are at the limit; discarding the flow"
                    );
                    self.end_bidi_flow(flow_id).await;
                    None
                }
            }
        }

        pub(in super::super) fn is_bidi_flow(&self, flow_id: u64) -> bool {
            self.bidi_flows.contains_key(&flow_id)
        }

        pub(in super::super) async fn write_buffer_to_flow(&mut self, flow_id: u64) -> Result<()> {
            let Some(BidiFlow::Live(LiveFlow {
                current: Some(stream),
                ..
            })) = self.bidi_flows.get_mut(&flow_id)
            else {
                debug!(flow_id, "dropping a write for a flow without a stream");
                return Ok(());
            };
            if let Err(e) = stream.send.write_all(&self.write_buffer).await {
                debug!(flow_id, "flow stream write failed, detaching the flow: {e}");
                if let Some(stream) = self.detach_stream(flow_id) {
                    stream.close(QuicStreamCode::NoError);
                }
            }
            Ok(())
        }

        pub(in super::super) fn take_detached_messages(
            &mut self,
            client_id: &str,
        ) -> Vec<QueuedMessage> {
            self.bidi_flows
                .iter_mut()
                .filter_map(|(flow_id, flow)| match flow {
                    BidiFlow::Live(live) => Some((*flow_id, std::mem::take(&mut live.detached))),
                    BidiFlow::Ended { .. } => None,
                })
                .flat_map(|(flow_id, waiting)| {
                    waiting.into_iter().map(move |routable| {
                        let qos = routable.publish.qos;
                        QueuedMessage::new(routable.publish, client_id.to_string(), qos, None)
                            .with_target_flow(Some(flow_id))
                    })
                })
                .collect()
        }
    }
}

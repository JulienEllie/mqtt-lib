# Client data flows on bidirectional QUIC streams

Model for #207: how the broker serves a client data flow (0x12) that the client opens on a
bidirectional stream. MQoQ §9.1.2 requires the broker to answer on the same flow: PUBACK,
PUBREC, PUBREL and PUBCOMP "must be exchanged in the same data flow", PINGRESP goes "through
the same data flow where it received the PINGREQ", and "the subscriber must expect messages for
subscriptions from the same flow it subscribed to". §9.14 lets the client take a flow over with
a newer stream, and "greater QUIC Stream ID of the same QUIC stream type always takes
precedence".

## What is modelled

One client data flow with a subscription, up to `MaxStreams` bidirectional streams for it
(numbered in the order the client opens them), `MaxReq` requests and `MaxMsg` published
messages.

- The client opens streams in order, sends requests on an open stream, aborts streams, and
  discards the flow once none of its streams is open.
- Each stream has its own broker reader. A reader announces the stream, forwards each request,
  and announces the end. All readers feed one channel to the client handler, so events from
  different streams interleave in any order while each stream's own events stay in order.
- The client handler keeps the flow's current stream (`cur`), answers requests, and delivers the
  subscription's messages. A discard arrives on its own path, as it does in the broker.
- Writes are recorded per stream in `out`; `out[0]` stands for any stream that is not one of the
  flow's own, such as the control stream or a broker-opened server stream.

## Design rules and their alternatives

| Constant | Proposed | Alternatives |
|---|---|---|
| `TAKEOVER` | `highest`: a stream becomes current only if its ID is above every stream the flow has had | `current`: above the current stream; `latest`: the last one announced wins |
| `ROUTE` | `stream`: answer on the stream the request came from, only while it is current, else drop | `current`: answer on whatever stream is current; `control`: answer on the control stream |
| `CLOSE` | `check`: a stream's end clears `cur` only if it is the current stream | `blind`: any stream's end clears `cur` |
| `DETACHED` | `queue`: while the flow has no current stream, its messages wait | `serverstream`: send them on a stream the broker opens; `drop`: drop them |

## Properties

- `ReplyOnOwnStream`: every reply on a stream answers a request read from that stream.
- `NothingOffFlow`: nothing for the flow is written outside its own streams.
- `CurrentIsNewest`: the current stream is the highest stream the handler has seen.
- `NewestLiveIsCurrentWhenQuiet`: once the broker has nothing left to do, the client's newest
  open stream that the broker has not aborted is the current one.
- `AnsweredWhenQuiet`: once the broker is quiet, every request read from that stream is answered.
- `DeliveredWhenQuiet`: once the broker is quiet and the flow has a live stream, no message is
  left waiting.
- `NoSilentDrop`: no message is dropped.

`NEG_TakeoverDelivers` and `NEG_RecoveryDelivers` are reachability controls and must be
violated: a message delivered on a stream that took over from an older one, and a message
published while the flow had lost its stream that is delivered once a new stream recovers it.

## Results

All runs use `MaxStreams = 3`, `MaxReq = 2`, `MaxMsg = 2`, checked with tla-mcp to completion or
to the first violation.

| Config | Result |
|---|---|
| `BidiClientFlow.cfg` (proposed) | all invariants hold, 3,478,866 states, depth 31, state space exhausted |
| `BidiClientFlow_V_takeover_current.cfg` | `CurrentIsNewest` violated at depth 10 |
| `BidiClientFlow_V_takeover_latest.cfg` | `CurrentIsNewest` violated at depth 7 |
| `BidiClientFlow_V_route_current.cfg` | `ReplyOnOwnStream` violated at depth 10 |
| `BidiClientFlow_V_route_control.cfg` | `NothingOffFlow` violated at depth 7 |
| `BidiClientFlow_V_close_blind.cfg` | `NewestLiveIsCurrentWhenQuiet` violated at depth 9 |
| `BidiClientFlow_V_detached_serverstream.cfg` | `NothingOffFlow` violated at depth 3 |
| `BidiClientFlow_V_detached_drop.cfg` | `NoSilentDrop` violated at depth 3 |
| `BidiClientFlow_NEG_takeover.cfg` | violated at depth 9, as required |
| `BidiClientFlow_NEG_recovery.cfg` | violated at depth 12, as required |

The `current` takeover rule was the first proposal. Its counterexample: the client opens streams
1 and 2, stream 2 is announced and becomes current, stream 2 ends so `cur` is cleared, and then
stream 1's late announcement makes the older stream current. Comparing against the highest
stream the flow has ever had, rather than the current one, closes it.

The recovery control's trace: stream 1 is current, the client aborts it and the broker clears
`cur`, a message is published and waits, the client opens stream 2, and the waiting message is
delivered on stream 2.

## Implementation

The broker follows the proposed configuration.

- Readers: `serve_bidi_flow` in `crates/mqtt5/src/broker/quic_acceptor.rs`, one per stream, sends `Opened`, `Packet` and `Closed` events on one channel to the client handler (`chan`). A reader the handler aborts stops without a `Closed` event.
- Handler: `crates/mqtt5/src/broker/client_handler/bidi_flow.rs` keeps each flow's current stream and the highest stream ID it has had (`cur`, `Highest(handled)`).
  - `TAKEOVER = highest` is `open_bidi_stream`.
  - `ROUTE = stream` is `handle_bidi_packet`, which also drops a packet from a stream that is not current instead of only its reply.
  - `CLOSE = check` is `close_bidi_stream`.
  - `DETACHED = queue` is `hold_for_flow`, with the waiting messages requeued at the front of the session queue when a new stream takes the flow over.
- Beyond the model: QoS 0 messages are dropped while the flow has no stream, as §9.21.2 allows, and the waiting QoS 1/2 messages are capped at the client's Receive Maximum. A FIN from the client ends the flow and removes its subscriptions (§9.13).

`crates/mqtt5/tests/quic_flow_streams.rs` exercises the rules against a running broker. Against main, all eight bidirectional flow tests fail and the eight others pass. Each rule was also broken in the implementation, one at a time, to check that a test catches it:

| Mutation | Failing test |
|---|---|
| takeover compared against the current stream | `an_older_stream_arriving_late_does_not_take_the_flow_back` |
| messages dropped while the flow has no stream | `messages_wait_for_a_flow_that_lost_its_stream` |
| answers written to the control stream | six tests, including `a_bidirectional_client_data_flow_is_answered_on_its_own_stream` |
| retained messages not bound to the flow | `retained_messages_for_a_bidirectional_flow_arrive_on_it` |

`CLOSE = check` has no test that fails without it. The handler aborts a superseded stream's reader, which then stops without sending `Closed`. A stale `Closed` therefore needs the client's own reset to reach the reader before the handler's abort does, and no test can force that ordering.

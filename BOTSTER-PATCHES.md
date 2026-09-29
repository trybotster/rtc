# Botster repairs on rtc 0.21.0-rc.1

This fork (`trybotster/rtc`) is upstream `webrtc-rs/rtc` at `51558ffb` (0.21.0-rc.1) plus the repairs
below, one commit each. The Hub takes the whole crate family from this fork with a single
`[patch.crates-io] rtc = { git = ..., rev = ... }` entry. Nothing here is submitted upstream.

Repairs 1 to 3 change the `rtc` crate (`src/`, `tests/`). Repair 4 changes `rtc-sctp`
(`rtc-sctp/src/association/`). Run the tests from this workspace: `cargo test -p rtc`, and
`cargo test -p rtc-sctp --lib`. The interop tests (`test_ice_restart_interop`, the two mDNS tests)
depend on the host network and fail on the published crate as well.

## Repair 1: ordered data channel close (send side)

The published implementation can process a close marker before an accepted application payload.
Application payload enters the endpoint queue. The published close method writes directly to the lower channel queue.

The repair queues the existing internal close event through the endpoint queue.
The channel handler applies close after earlier payload from that queue.
The public close method marks the channel `Closing` immediately and rejects new sends.
Repeated close remains idempotent. Internal abort paths still close directly.
The repair uses the channel handler's logical time. It adds no sleep or Hub delivery wait.

This repair was first written against `rtc 0.21.0-beta.2`. Upstream `rc.1` does not contain it.

Changed upstream files:

- `src/data_channel/mod.rs`: queue close and reject sends after close starts.
- `src/peer_connection/handler/datachannel.rs`: apply queued close and expose logical time within the crate.
- `src/peer_connection/handler/mod.rs`: test both queue schedules, repeated close, rejected late sends, and public close before open with a late ACK.
- `tests/data_channel_backpressure_rtc2rtc.rs`: test final payload delivery before remote close over a real peer connection, and accepted payload under the Hub high-water pressure signal before remote close.

## Repair 2: terminal stream results inside the SCTP drain (receive side)

`rtc-sctp 0.21.0-rc.1` defers a peer's outgoing stream reset while the stream still holds a complete unread message.
It performs the deferred reset inside the `read_sctp()` call that drains the last message.
That read unregisters the stream. The next `read_sctp()` in the same drain loop reports `ErrStreamClosed`.

`SctpHandler::drain_stream` in the published crate propagates that error with `?`.
The error leaves `handle_read` or `resume_pending_reads` before either moves its collected batch into `read_outs`.
The accepted payload is lost. On the parked path the entry also stays parked, and every later `poll_read` retries and fails again.

The repair treats two results as normal terminal states of one stream:

- `Association::stream()` reports `ErrStreamNotExisted`: the parked entry names a stream the association no longer has. The drain forgets the entry and reads nothing.
- `read_sctp()` reports `ErrStreamClosed` after an earlier read in the same loop: the drain forgets the entry and returns the messages it already collected.

Every other error is returned unchanged.

The reset performed inside the drain queues `AssociationLost` on the association. `handle_read` polls that queue after its own drain, so on the immediate path `SCTPStreamClosed` enters `event_outs` in the same `handle_read`.
The published `resume_pending_reads` never polled that queue, so a close produced by a resumed drain waited for the next inbound datagram, which a peer that has already sent its reset need not send.
The repair moves the event translation of `handle_read` into one shared function, `forward_association_event`, and calls it from `resume_pending_reads` after each drain. The resumed drain therefore places `SCTPStreamClosed` into `event_outs` inside the same `poll_read`.

An event placed into `event_outs` during `poll_read` is consumed by the peer connection's next `poll_event`. The `webrtc` driver runs writes, then events, then reads in each pass, so no stage of the pass that produced the event consumes it. The next pass follows the driver's next wake. The peer does not guarantee that wake: it has sent its reset, and `rtc-sctp` stops its reconfig timer when the in-progress reply arrives, without reading the reply's result.

The repair therefore adds one local readiness wake. `SctpHandler::poll_timeout` reports the last observed logical instant while `event_outs` is not empty, in addition to the association deadlines it already reports. A caller reads that instant as zero delay and runs another pass. That pass's `poll_event` empties the queue, which clears the wake. The drain also marks the transport for flush, so the reset reply and the raised window leave in that pass's `poll_write`.
The wake is set by queued events only. Parked unread data never sets it, which the published test `poll_timeout_reports_nothing_for_a_parked_stream` continues to check. Events produced by `handle_read` are consumed by the pass that follows the read, before `poll_timeout` runs, so the wake does not fire for them.

The repair changes no signature and no queue.

Changed upstream files:

- `src/peer_connection/handler/sctp.rs`: `forward_association_event` shared by `handle_read` and `resume_pending_reads`; the two terminal arms in `drain_stream`; the event forward after a resumed drain; the readiness wake in `poll_timeout`; and tests for the immediate drain with a reset that overtook its data, the parked drain with a reset deferred against parked data (payload sequence, cleared entry, the close forwarded without another datagram, the wake while that close waits, and the wake cleared once it is consumed), a stale parked entry for a missing stream, and an unrelated `ErrShortBuffer` that must still fail the read. The two drain tests run with a read budget above one.
- Repair 4 (`rtc-sctp`) keeps a remotely reset stream registered until the peer answers our answering reset. The two drain tests therefore assert that the stream is still registered and that no close is reported after the drain, then deliver the peer's answer (`deliver_reset_answer`: the client flushes its reset, the server answers, the client reads the answer) and assert that the stream is gone and that the close is reported once. The wake assertions in the parked test are unchanged and still pass.
- The immediate-path test asserts a data count and a close count on two separate queues. It does not prove public data-before-close ordering; that proof belongs to the peer-connection boundary and the real-peer tests.

## Repair 3: receive-side close barrier at the public queue boundary

`RTCPeerConnection::handle_read` drains every handler's `poll_read` into the public `data_read_outs` queue in one pass.
The datachannel handler's `OnClose` for that channel waits in its own event queue at the same time.
The `webrtc` driver polls events before reads on every pass.
When the final payload and the close marker are processed in one intake, the driver sees `OnClose` while the accepted payload still waits in `data_read_outs`.
A consumer that stops at `OnClose` never reads that payload.

The barrier holds a channel's `OnClose` at the public queue boundary until that channel's accepted data has been read.
Both barrier maps are keyed by the public channel handle (`RTCDataChannelId`), which the rc.1 registry allocates monotonically and never reuses.
A successor channel on the same SCTP stream id therefore has its own count and its own held close. No stream-id parking or generation tracking exists.

- `PipelineContext` keeps a per-handle pending count. The single enqueue site into `data_read_outs`, `route_read_out`, increments it. Both public dequeue paths, `poll_data_read` and the data branches of `poll_read`, go through `pop_data_read_out`, which decrements it and removes the entry at zero.
- The public `poll_event` holds `OnDataChannel(OnClose(handle))` while that handle has a pending count. Every other event, including a close for a drained channel, passes unchanged. One channel's backlog never blocks another channel's close.
- The read that brings a handle's count to zero moves that handle's held close into the ordinary `event_outs` queue, behind whatever is already queued there. Held closes therefore surface in read order, one per `poll_event`.
- A held close exists only while its handle has a pending count, at most one per handle, so the number of held closes never exceeds the number of unread data-channel messages. A second `OnClose` for a handle that already holds one is dropped; the datachannel handler emits `OnClose` at most once per channel.
- `poll_timeout` keeps every handler deadline. While `event_outs` is not empty it also reports the datachannel handler's last observed logical instant, so the driver runs another pass now; that pass's `poll_event` empties the queue, which clears the wake. `event_outs` is otherwise empty when `poll_timeout` runs, because the driver drains events before reads. A held close whose data stays undrained schedules nothing.
- Whole-connection `close()` is a separate teardown case. Queued events and accepted data stay pollable after `close()`, as before. `close()` moves every held close into the event queue in held order, ahead of the `Closed` state event, and clears the counts. Retained data stays readable through both read APIs. A close that reaches the public queue after teardown is never held again. Explicit teardown can therefore expose closure before retained data. That is teardown behavior, not proof of graceful delivery.
- Local close semantics are unchanged. `OnClosing` has no producer in this crate and is not held.

Changed upstream files for this repair:

- `src/peer_connection/handler/mod.rs`: pending counts, held closes, `route_read_out`, `pop_data_read_out`, `hold_close_behind_pending_data`, the `poll_timeout` wake, the `close()` flush, and unit tests through the public API with events polled first: one channel, a reused stream id with distinct handles, a back-pressured sibling, both `poll_read` data branches, no added deadline while data stays undrained, two released closes in read order, duplicate close, and whole-connection teardown.
- `src/peer_connection/internal.rs`: initialize the barrier state.
- `tests/data_channel_backpressure_rtc2rtc.rs`: real-peer case in which the receiver polls events before reads and drains every datagram already at its socket in one intake.

## Repair 4: a stream id is reusable only after both directions of its reset complete (`rtc-sctp`)

RFC 8831 section 6.7: a peer that sees an incoming stream reset resets its own outgoing stream, and
streams are available for reuse after a reset has been performed. RFC 6525 section 5.2.7 stops
processing on an unsuccessful result and restarts the timer on "In progress".

- An incoming reset resets our outgoing direction only if it is not yet requested, so an answering reset
  is not echoed. This protects the peer that reuses the id.
- A stream is unregistered, which frees its id, only when its incoming reset was performed and our
  outgoing reset was answered with a success (performed, or nothing to do). Any other final result ends
  the request and leaves the stream registered, its id unused. "In progress" keeps the request.
- New data on a stream whose incoming direction was reset opens a new stream on the same id, and the old
  stream's pending reset request is retired with it, so a delayed answer cannot touch the replacement.
- An answering reset request has its retransmission timer armed in the transmit pass.

Four existing `rtc-sctp` endpoint tests (`kps_816_write_then_reset_delivered_in_order_survives`,
`kps_repro_816_bundled_data_and_reset_must_not_lose_data`,
`kps_repro_816_reordered_reset_before_data_must_not_lose_data`,
`kps_816_deferred_reset_completes_when_the_application_drains`) assert that the receiver no longer
has the stream right after applying the peer's reset. That is now true only after the peer answers our
answering reset, so they run one round of that handshake (`complete_reset_handshake`) first. Their
data-delivery assertions are unchanged. On the pristine upstream commit all 133 `rtc-sctp` lib tests
pass; with Repair 4 all 139 pass (the six new ones cover the reset-state rules).

Known gap: RFC 6525 section 5.2.1 duplicate-request handling (answer a retransmitted request without
performing it again). Files: `rtc-sctp/src/association/mod.rs`, `stream.rs`, and unit tests in
`association_test.rs`. The `rtc` regression test is `tests/data_channel_stream_id_reuse_rtc2rtc.rs`.

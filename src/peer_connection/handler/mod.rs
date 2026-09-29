pub(crate) mod datachannel;
pub(crate) mod demuxer;
pub(crate) mod dtls;
pub(crate) mod endpoint;
pub(crate) mod ice;
pub(crate) mod interceptor;
pub(crate) mod sctp;
pub(crate) mod srtp;

use crate::data_channel::RTCDataChannelId;
use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEvent};
use crate::peer_connection::handler::datachannel::{DataChannelHandler, DataChannelHandlerContext};
use crate::peer_connection::handler::demuxer::{DemuxerHandler, DemuxerHandlerContext};
use crate::peer_connection::handler::dtls::{DtlsHandler, DtlsHandlerContext};
use crate::peer_connection::handler::endpoint::{EndpointHandler, EndpointHandlerContext};
use crate::peer_connection::handler::ice::{IceHandler, IceHandlerContext};
use crate::peer_connection::handler::interceptor::{InterceptorHandler, InterceptorHandlerContext};
use crate::peer_connection::handler::sctp::{SctpHandler, SctpHandlerContext};
use crate::peer_connection::handler::srtp::{SrtpHandler, SrtpHandlerContext};
use crate::peer_connection::message::{
    RTCMessage, TaggedRTCMessage,
    internal::{
        ApplicationMessage, DTLSMessage, DataChannelEvent, RTCMessageInternal, RTPMessage,
        TaggedRTCMessageInternal,
    },
};
use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use crate::peer_connection::state::signaling_state::RTCSignalingState;
use crate::statistics::accumulator::RTCStatsAccumulator;
use ::interceptor::Packet;
use log::warn;
use shared::TaggedBytesMut;
use shared::error::{Error, flatten_errs};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Forward handler list - invokes callback with handler list
macro_rules! forward_handlers {
    ($callback:ident!($($args:tt)*)) => {
        $callback!(
            $($args)*,
            [
                get_demuxer_handler,
                get_ice_handler,
                get_dtls_handler,
                get_sctp_handler,
                get_datachannel_handler,
                get_srtp_handler,
                get_interceptor_handler,
                get_endpoint_handler
            ]
        )
    };
}

/// Reverse handler list - invokes callback with handler list
macro_rules! reverse_handlers {
    ($callback:ident!($($args:tt)*)) => {
        $callback!(
            $($args)*,
            [
                get_endpoint_handler,
                get_interceptor_handler,
                get_srtp_handler,
                get_datachannel_handler,
                get_sctp_handler,
                get_dtls_handler,
                get_ice_handler,
                get_demuxer_handler
            ]
        )
    };
}

/// Helper macro that processes a list of handlers with code blocks
macro_rules! process_handler_list {
    (call_macro: process_handler!($self:expr, $handler:ident, $code:block), [$($getter:ident),+]) => {{
        $(
            {
                let mut $handler = $self.$getter();
                $code
            }
        )+
    }};
}

/// Unified macro to iterate over handlers with code blocks
macro_rules! for_each_handler {
    // Forward order: execute code block for each handler
    (forward: $macro:ident!($($args:tt)*)) => {
        forward_handlers!(process_handler_list!(call_macro: $macro!($($args)*)))
    };

    // Reverse order: execute code block for each handler
    (reverse: $macro:ident!($($args:tt)*)) => {
        reverse_handlers!(process_handler_list!(call_macro: $macro!($($args)*)))
    };
}

pub(crate) struct PipelineContext {
    // Handler contexts
    pub(crate) demuxer_handler_context: DemuxerHandlerContext,
    pub(crate) ice_handler_context: IceHandlerContext,
    pub(crate) dtls_handler_context: DtlsHandlerContext,
    pub(crate) sctp_handler_context: SctpHandlerContext,
    pub(crate) datachannel_handler_context: DataChannelHandlerContext,
    pub(crate) srtp_handler_context: SrtpHandlerContext,
    pub(crate) interceptor_handler_context: InterceptorHandlerContext,
    pub(crate) endpoint_handler_context: EndpointHandlerContext,

    // Pipeline
    /// Media (RTP/RTCP) ready for the application.
    ///
    /// Split from data-channel output deliberately. Back-pressure is applied by *not draining
    /// a queue* — that is what grows [`Self::data_read_outs`], bounds the SCTP drain,
    /// lowers `a_rwnd` and throttles the peer. While both kinds shared one queue, a caller
    /// applying that back-pressure necessarily stopped draining media too, so a slow
    /// data-channel consumer froze video on the same connection for as long as it stalled —
    /// video that arrives over SRTP and is subject to none of SCTP's flow control.
    pub(crate) media_read_outs: VecDeque<TaggedRTCMessage>,
    /// Data-channel messages ready for the application.
    ///
    /// Its length *is* the back-pressure signal the SCTP handler bounds against, so a caller
    /// that declines to drain it throttles the peer — and nothing else. No counter to keep in
    /// step with it: the queue is the count.
    pub(crate) data_read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedBytesMut>,
    pub(crate) event_outs: VecDeque<RTCPeerConnectionEvent>,

    // Receive-side close barrier (Botster patch).
    //
    // `handle_read` drains every handler's `poll_read` into `data_read_outs` in one pass,
    // while the datachannel handler's `OnClose` waits in its event queue. A driver that
    // polls events before reads then sees the close while the channel's final accepted
    // payload still sits in `data_read_outs`, and a consumer that stops at `OnClose` never
    // reads it. The barrier holds that channel's `OnClose` until the channel's accepted data
    // has been read through either public read API. Both maps are keyed by the public
    // channel handle, which the registry never reuses, so a successor channel on the same
    // SCTP stream id has its own entries.
    /// Accepted data-channel messages still queued in `data_read_outs`, per channel handle.
    /// An entry exists only while its count is non-zero.
    pub(crate) pending_data_by_channel: HashMap<RTCDataChannelId, usize>,
    /// `OnClose` events held behind their channel's pending data, in arrival order. At most
    /// one per handle, and only while that handle has a pending count, so the number of held
    /// closes never exceeds the number of unread data-channel messages. The read that empties
    /// a channel moves its held close into `event_outs`.
    pub(crate) held_data_channel_closes: VecDeque<(RTCDataChannelId, RTCPeerConnectionEvent)>,

    // Statistics accumulator
    pub(crate) stats: RTCStatsAccumulator,
}

impl RTCPeerConnection {
    /// Route one message that left the handler chain into the public read queues.
    ///
    /// The single enqueue site for `data_read_outs`, so the per-channel pending count is kept
    /// in step here and nowhere else.
    pub(crate) fn route_read_out(&mut self, msg: TaggedRTCMessageInternal) {
        let rtc_message = match msg.message {
            RTCMessageInternal::Dtls(DTLSMessage::DataChannel(application_message)) => {
                if let DataChannelEvent::Message(data_channel_message) =
                    application_message.data_channel_event
                {
                    Some(RTCMessage::DataChannelMessage(
                        application_message.data_channel_id,
                        data_channel_message,
                    ))
                } else {
                    None
                }
            }
            RTCMessageInternal::Rtp(RTPMessage::TrackPacket(track_packet)) => {
                match track_packet.packet {
                    Packet::Rtp(packet) => {
                        Some(RTCMessage::RtpPacket(track_packet.track_id, packet))
                    }
                    Packet::Rtcp(packet) => {
                        Some(RTCMessage::RtcpPacket(track_packet.track_id, packet))
                    }
                    _ => None,
                }
            }
            _ => None,
        };

        if let Some(rtc_message) = rtc_message {
            // The instant travels with the message: the application learns when the packet
            // was observed at the socket, not when it happened to drain it.
            let tagged = TaggedRTCMessage {
                now: msg.now,
                message: rtc_message,
            };
            // Routed by kind, so a caller can decline data-channel output — the only way
            // to apply SCTP back-pressure — without also declining media.
            match &tagged.message {
                RTCMessage::DataChannelMessage(id, _) => {
                    *self
                        .pipeline_context
                        .pending_data_by_channel
                        .entry(*id)
                        .or_insert(0) += 1;
                    self.pipeline_context.data_read_outs.push_back(tagged)
                }
                _ => self.pipeline_context.media_read_outs.push_back(tagged),
            }
        }
    }

    /// Pop the next data-channel message and keep the pending count in step.
    ///
    /// The pop that empties a channel releases that channel's held `OnClose`, if any, into
    /// `event_outs` behind whatever is already queued there. Only this channel's entries
    /// change: an unrelated channel's count is untouched, and a successor channel on the same
    /// stream id has its own handle and its own count. Cost: the count update is a map lookup;
    /// the zero-count path scans and removes from `held_data_channel_closes`, which is linear
    /// in the number of held closes, as is the duplicate check in
    /// `hold_close_behind_pending_data`. That number never exceeds the unread data-channel
    /// messages, so the scan is bounded by the back-pressure the caller is already applying.
    fn pop_data_read_out(&mut self) -> Option<TaggedRTCMessage> {
        let tagged = self.pipeline_context.data_read_outs.pop_front()?;
        if let RTCMessage::DataChannelMessage(id, _) = &tagged.message {
            let ctx = &mut self.pipeline_context;
            let drained = match ctx.pending_data_by_channel.get_mut(id) {
                Some(count) => {
                    *count = count.saturating_sub(1);
                    *count == 0
                }
                None => true,
            };
            if drained {
                ctx.pending_data_by_channel.remove(id);
                if let Some(index) = ctx
                    .held_data_channel_closes
                    .iter()
                    .position(|(held_id, _)| held_id == id)
                    && let Some((_, event)) = ctx.held_data_channel_closes.remove(index)
                {
                    ctx.event_outs.push_back(event);
                }
            }
        }
        Some(tagged)
    }

    /// Hold `event` when it is an `OnClose` for a channel with pending accepted data.
    ///
    /// Returns the event back when it must pass through unchanged. A second close for a
    /// channel that already holds one is a duplicate and is dropped: the datachannel handler
    /// emits `OnClose` at most once per channel, so the held entry is the one that counts.
    /// After whole-connection teardown nothing is held: `close()` flushed every held close,
    /// and a later one passes through.
    fn hold_close_behind_pending_data(
        &mut self,
        event: RTCPeerConnectionEvent,
    ) -> Option<RTCPeerConnectionEvent> {
        let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(id)) = &event else {
            return Some(event);
        };
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Some(event);
        }
        let ctx = &mut self.pipeline_context;
        if !ctx.pending_data_by_channel.contains_key(id) {
            return Some(event);
        }
        let already_held = ctx
            .held_data_channel_closes
            .iter()
            .any(|(held_id, _)| held_id == id);
        if !already_held {
            ctx.held_data_channel_closes.push_back((*id, event));
        }
        None
    }

    /*
     Pipeline Flow (Read Path):
     Raw Bytes -> Demuxer -> ICE -> DTLS -> SCTP -> DataChannel -> SRTP -> Interceptor -> Endpoint -> Application

     Pipeline Flow (Write Path):
     Application -> Endpoint -> Interceptor -> SRTP -> DataChannel -> SCTP -> DTLS -> ICE -> Demuxer -> Raw Bytes
    */

    pub(crate) fn get_demuxer_handler(&mut self) -> DemuxerHandler<'_> {
        DemuxerHandler::new(
            &mut self.pipeline_context.demuxer_handler_context,
            &mut self.pipeline_context.stats,
        )
    }

    pub(crate) fn get_ice_handler(&mut self) -> IceHandler<'_> {
        IceHandler::new(
            &mut self.pipeline_context.ice_handler_context,
            &mut self.pipeline_context.stats,
        )
    }

    pub(crate) fn get_dtls_handler(&mut self) -> DtlsHandler<'_> {
        DtlsHandler::new(
            &mut self.pipeline_context.dtls_handler_context,
            &mut self.pipeline_context.stats,
        )
    }

    /// Next media (RTP/RTCP) message for the application, if any.
    ///
    /// Never affected by data-channel back-pressure. Media arrives over SRTP and is subject to
    /// none of SCTP's flow control, so a caller throttling a slow data-channel consumer must
    /// still be able to deliver video — draining this is how.
    #[doc(hidden)]
    pub fn poll_media_read(&mut self) -> Option<TaggedRTCMessage> {
        self.pipeline_context.media_read_outs.pop_front()
    }

    /// Next data-channel message for the application, if any.
    ///
    /// **Declining to call this is how back-pressure is applied.** Undrained messages leave
    /// bytes in SCTP's reassembly queue, which lowers the receiver-window credit advertised in
    /// every SACK, which tells the peer to slow down. Stop calling it while the application is
    /// behind, resume when it catches up.
    #[doc(hidden)]
    pub fn poll_data_read(&mut self) -> Option<TaggedRTCMessage> {
        self.pop_data_read_out()
    }

    pub(crate) fn get_sctp_handler(&mut self) -> SctpHandler<'_> {
        // The SCTP handler bounds how much it pulls out of the reassembly queues against what
        // the application has not yet consumed. That backlog lives here, not in the handler's
        // own `read_outs` — the pipeline empties that within a single `handle_read` — and it
        // is data-channel output only, so unrelated media cannot throttle SCTP.
        let downstream_backlog = self.pipeline_context.data_read_outs.len();
        SctpHandler::new(
            &mut self.pipeline_context.sctp_handler_context,
            downstream_backlog,
        )
    }

    pub(crate) fn get_datachannel_handler(&mut self) -> DataChannelHandler<'_> {
        // Read the Copy values before `&mut self.data_channels` borrows self mutably. The
        // handler needs the DTLS role to give stream ids the parity RFC 8832 §6 requires, and
        // the negotiated stream count to bound them.
        let dtls_role = self.dtls_transport().role();
        let max_channels = self.sctp_transport().max_channels();
        DataChannelHandler::new(
            &mut self.pipeline_context.datachannel_handler_context,
            &mut self.data_channels,
            &mut self.pipeline_context.stats,
            self.setting_engine.data_channel.dcep_handshake_timeout,
            dtls_role,
            max_channels,
        )
    }

    pub(crate) fn get_srtp_handler(&mut self) -> SrtpHandler<'_> {
        SrtpHandler::new(&mut self.pipeline_context.srtp_handler_context)
    }

    pub(crate) fn get_interceptor_handler(&mut self) -> InterceptorHandler<'_> {
        InterceptorHandler::new(
            &mut self.pipeline_context.interceptor_handler_context,
            &mut self.rtp_transceivers,
            &self.media_engine,
            &mut self.interceptor,
            &mut self.pipeline_context.stats,
        )
    }

    pub(crate) fn get_endpoint_handler(&mut self) -> EndpointHandler<'_> {
        EndpointHandler::new(
            &mut self.pipeline_context.endpoint_handler_context,
            &mut self.rtp_transceivers,
            &mut self.pipeline_context.stats,
        )
    }
}

impl sansio::Protocol<TaggedBytesMut, TaggedRTCMessage, TaggedRTCEvent> for RTCPeerConnection {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedBytesMut;
    type Eout = RTCPeerConnectionEvent;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<(), Self::Error> {
        let mut intermediate_routs = VecDeque::new();
        intermediate_routs.push_back(TaggedRTCMessageInternal {
            now: msg.now,
            transport: msg.transport,
            message: RTCMessageInternal::Raw(msg.message),
        });

        for_each_handler!(forward: process_handler!(self, handler, {
            while let Some(msg) = intermediate_routs.pop_front() {
                if let Err(err) = handler.handle_read(msg) {
                    warn!("{}.handle_read got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_read() {
                intermediate_routs.push_back(msg);
            }
        }));

        // Finally, put intermediate_routs into RTCPeerConnection's routs
        while let Some(msg) = intermediate_routs.pop_front() {
            self.route_read_out(msg);
        }

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        if let (Some(data), Some(media)) = (
            self.pipeline_context.data_read_outs.front(),
            self.pipeline_context.media_read_outs.front(),
        ) {
            if data.now <= media.now {
                self.pop_data_read_out()
            } else {
                self.pipeline_context.media_read_outs.pop_front()
            }
        } else if self.pipeline_context.data_read_outs.front().is_some() {
            self.pop_data_read_out()
        } else {
            self.pipeline_context.media_read_outs.pop_front()
        }
    }

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<(), Self::Error> {
        let now = msg.now;
        let rtc_message_internal = match msg.message {
            RTCMessage::DataChannelMessage(data_channel_id, data_channel_message) => {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                    data_channel_id,
                    data_channel_event: DataChannelEvent::Message(data_channel_message),
                }))
            }
            RTCMessage::RtpPacket(_track_id, rtp_packet) => {
                RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(rtp_packet)))
            }
            RTCMessage::RtcpPacket(_track_id, rtcp_packet) => {
                RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(rtcp_packet)))
            }
        };

        // Only endpoint can handle user write message
        let mut endpoint_handler = self.get_endpoint_handler();
        endpoint_handler.handle_write(TaggedRTCMessageInternal {
            now,
            transport: Default::default(),
            message: rtc_message_internal,
        })
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        let mut intermediate_wouts = VecDeque::new();

        for_each_handler!(reverse: process_handler!(self, handler, {
            while let Some(msg) = intermediate_wouts.pop_front() {
                if let Err(err) = handler.handle_write(msg) {
                    warn!("{}.handle_write got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_write() {
                intermediate_wouts.push_back(msg);
            }
        }));

        // Final poll write out to pipeline's write out
        while let Some(msg) = intermediate_wouts.pop_front() {
            if let RTCMessageInternal::Raw(message) = msg.message {
                self.pipeline_context.write_outs.push_back(TaggedBytesMut {
                    now: msg.now,
                    transport: msg.transport,
                    message,
                });
            }
        }

        self.pipeline_context.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEvent) -> Result<(), Self::Error> {
        // `RTCEvent` is `pub enum RTCEvent {}` — uninhabited, reserved for future use — so no
        // caller can construct one and this arm is unreachable. Diverging on the empty match
        // keeps that fact in the type system, and avoids inventing an instant to wrap the
        // event with when there is none to be had. C3-03 replaces this with `evt.now` once
        // the public channel carries a timestamp.
        match evt.event {}
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        let mut intermediate_eouts = VecDeque::new();

        for_each_handler!(forward: process_handler!(self, handler, {
            while let Some(evt) = intermediate_eouts.pop_front() {
                if let Err(err) = handler.handle_event(evt) {
                    warn!("{}.handle_event got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_event() {
                intermediate_eouts.push_back(msg);
            }
        }));

        // Finally, put intermediate_eouts into RTCPeerConnection's eouts
        while let Some(evt_internal) = intermediate_eouts.pop_front() {
            match &evt_internal.event {
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(_),
                )
                | RTCEventInternal::DTLSHandshakeComplete(_, _) => {
                    self.update_connection_state(false);
                }
                _ => {}
            };

            if let RTCEventInternal::RTCPeerConnectionEvent(evt) = evt_internal.event
                && let Some(evt) = self.hold_close_behind_pending_data(evt)
            {
                self.pipeline_context.event_outs.push_back(evt);
            }
        }

        self.pipeline_context.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        for_each_handler!(forward: process_handler!(self, handler, {
            handler.handle_timeout(now)?;
        }));
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        let mut eto: Option<Instant> = None;
        for_each_handler!(forward: process_handler!(self, handler, {
            if let Some(next) = handler.poll_timeout() {
                eto = Some(eto.map_or(next, |curr| std::cmp::min(curr, next)));
            }
        }));
        // A released close waits in `event_outs` only when a read moved it there after this
        // pass's event stage, so it is due now, at the last observed logical instant. The
        // next `poll_event` empties the queue, which clears this. A held close whose data
        // stays undrained schedules nothing.
        if !self.pipeline_context.event_outs.is_empty() {
            let now = self.pipeline_context.datachannel_handler_context.now;
            eto = Some(eto.map_or(now, |curr| std::cmp::min(curr, now)));
        }
        eto
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #1)
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Ok(());
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #3)
        self.signaling_state = RTCSignalingState::Closed;

        // Try closing everything and collect the errors
        // Shutdown strategy:
        // 1. All Conn close by closing their underlying Conn.
        // 2. A Mux stops this chain. It won't close the underlying
        //    Conn if one of the endpoints is closed down. To
        //    continue the chain the Mux has to be closed.
        for_each_handler!(forward: process_handler!(self, handler, {
            handler.close()?;
        }));

        // Teardown ends the barrier. Queued events and accepted data stay pollable after
        // `close()`, so every held close returns to the event queue in held order, ahead of
        // the `Closed` state event, and no held state outlives the connection.
        {
            let ctx = &mut self.pipeline_context;
            for (_, event) in ctx.held_data_channel_closes.drain(..) {
                ctx.event_outs.push_back(event);
            }
            ctx.pending_data_by_channel.clear();
        }

        let close_errs: Vec<Error> = vec![];

        /* TODO:
        if let Err(err) = self.interceptor.close().await {
            close_errs.push(Error::new(format!("interceptor: {err}")));
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #4)
        {
            let mut rtp_transceivers = self.internal.rtp_transceivers.lock().await;
            for t in &*rtp_transceivers {
                if let Err(err) = t.stop().await {
                    close_errs.push(Error::new(format!("rtp_transceivers: {err}")));
                }
            }
            rtp_transceivers.clear();
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #5)
        {
            let mut data_channels = self.internal.sctp_transport.data_channels.lock().await;
            for d in &*data_channels {
                if let Err(err) = d.close().await {
                    close_errs.push(Error::new(format!("data_channels: {err}")));
                }
            }
            data_channels.clear();
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #6)
        if let Err(err) = self.internal.sctp_transport.stop().await {
            close_errs.push(Error::new(format!("sctp_transport: {err}")));
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #7)
        if let Err(err) = self.internal.dtls_transport.stop().await {
            close_errs.push(Error::new(format!("dtls_transport: {err}")));
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #8, #9, #10)
        if let Err(err) = self.internal.ice_transport.stop().await {
            close_errs.push(Error::new(format!("ice_transport: {err}")));
        }
         */

        self.update_connection_state(true);

        flatten_errs(close_errs)
    }
}

#[cfg(test)]
mod handler_test {
    use super::*;
    use crate::data_channel::message::RTCDataChannelMessage;
    use crate::peer_connection::RTCPeerConnectionBuilder;
    use bytes::BytesMut;
    use sansio::Protocol;
    use std::time::Duration;

    /// Media must be drainable while data-channel output is held back.
    ///
    /// That is the whole point of the split: back-pressure is applied by declining to drain
    /// the data-channel queue, and while both kinds shared one queue that also stopped media.
    /// A slow signalling channel froze video on the same connection for as long as it stalled.
    #[test]
    fn media_drains_while_data_channel_output_is_held_back() {
        let base = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(base)
            .expect("build peer connection");

        // Media outnumbering data, the shape of a real SFU connection.
        for i in 0..10 {
            let message = if i % 5 == 0 {
                RTCMessage::DataChannelMessage(0, RTCDataChannelMessage::default())
            } else {
                RTCMessage::RtpPacket(Default::default(), ::rtp::packet::Packet::default())
            };
            let tagged = TaggedRTCMessage { now: base, message };
            match tagged.message {
                RTCMessage::DataChannelMessage(..) => {
                    pc.pipeline_context.data_read_outs.push_back(tagged)
                }
                _ => pc.pipeline_context.media_read_outs.push_back(tagged),
            }
        }

        // Drain media only — as a caller applying data-channel back-pressure would.
        let mut media = 0;
        while let Some(msg) = pc.poll_media_read() {
            assert!(
                !matches!(msg.message, RTCMessage::DataChannelMessage(..)),
                "poll_media_read must never yield data-channel output"
            );
            media += 1;
        }

        assert_eq!(
            media, 8,
            "all media must be deliverable while data is held back"
        );
        assert_eq!(
            pc.pipeline_context.data_read_outs.len(),
            2,
            "held-back data-channel output must stay queued — its length is the signal the \
             SCTP drain is bounded against, so losing it would drop the back-pressure"
        );

        // And releasing it hands over exactly what was held.
        let mut data = 0;
        while let Some(msg) = pc.poll_data_read() {
            assert!(matches!(msg.message, RTCMessage::DataChannelMessage(..)));
            data += 1;
        }
        assert_eq!(data, 2);
    }

    /// `poll_read` still yields both kinds, so the callers that predate the split — 58 files
    /// across tests and examples — behave exactly as before.
    #[test]
    fn poll_read_still_yields_both_kinds() {
        let base = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(base)
            .expect("build peer connection");

        pc.pipeline_context
            .data_read_outs
            .push_back(TaggedRTCMessage {
                now: base,
                message: RTCMessage::DataChannelMessage(0, RTCDataChannelMessage::default()),
            });
        pc.pipeline_context
            .media_read_outs
            .push_back(TaggedRTCMessage {
                now: base,
                message: RTCMessage::RtpPacket(
                    Default::default(),
                    ::rtp::packet::Packet::default(),
                ),
            });

        let mut kinds = vec![];
        while let Some(msg) = pc.poll_read() {
            kinds.push(matches!(msg.message, RTCMessage::DataChannelMessage(..)));
        }
        assert_eq!(kinds.len(), 2, "poll_read must still drain everything");
        assert!(kinds.contains(&true) && kinds.contains(&false));
    }

    /// The instant the application supplies on `handle_write` is the one the core stamps the
    /// resulting internal message with — not a reading the core took for itself. Before C3-03
    /// the public `Win` was a bare `RTCMessage`, so this entry point had no time source and
    /// stamped `Instant::now()`.
    #[test]
    fn handle_write_stamps_from_the_caller_not_the_clock() {
        let base = Instant::now();
        let t = |secs| base + Duration::from_secs(secs);

        let mut pc = RTCPeerConnectionBuilder::new()
            .build(t(0))
            .expect("a default peer connection builds");

        pc.handle_write(TaggedRTCMessage {
            now: t(5),
            message: RTCMessage::DataChannelMessage(
                1,
                RTCDataChannelMessage {
                    is_string: true,
                    data: BytesMut::from(&b"hello"[..]),
                },
            ),
        })
        .expect("handle_write queues the message");

        let queued = pc
            .pipeline_context
            .endpoint_handler_context
            .write_outs
            .front()
            .expect("the message reaches the endpoint handler");

        assert_eq!(
            queued.now,
            t(5),
            "the internal message carries the caller's instant, not an ambient reading"
        );
        assert_ne!(queued.now, t(0), "and not the construction instant either");
    }
}

#[cfg(test)]
mod botster_enqueue_close_probe {
    use super::*;
    use crate::data_channel::internal::RTCDataChannelInternal;
    use crate::data_channel::parameters::DataChannelParameters;
    use crate::peer_connection::RTCPeerConnectionBuilder;
    use crate::peer_connection::configuration::RTCConfigurationBuilder;
    use ::datachannel::message::Message;
    use ::sctp::PayloadProtocolIdentifier;
    use sansio::Protocol;
    use shared::marshal::Unmarshal;
    use std::time::Instant;

    fn order(advance_before_close: bool) -> Vec<&'static str> {
        let now = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .build(now)
            .unwrap();
        // Out-of-band: `negotiated` fixes stream id 1, so the channel can dial at once. The
        // registry assigns the public handle on insert; every later call uses that handle.
        let mut dc = RTCDataChannelInternal::new(DataChannelParameters {
            label: "enqueue-close-probe".to_owned(),
            protocol: String::new(),
            ordered: true,
            max_packet_life_time: None,
            max_retransmits: None,
            negotiated: Some(1),
        });
        // This check establishes only the local queue path. It creates no peer.
        dc.dial(0).unwrap();
        let id = pc.data_channels.insert(dc);
        while pc.get_datachannel_handler().poll_write().is_some() {}
        pc.data_channel(id)
            .unwrap()
            .send_text(now, "exit-probe")
            .unwrap();
        if advance_before_close {
            let queued = pc.get_endpoint_handler().poll_write().unwrap();
            pc.get_datachannel_handler().handle_write(queued).unwrap();
        }
        pc.data_channel(id).unwrap().close().unwrap();
        pc.data_channel(id).unwrap().close().unwrap();
        assert!(matches!(
            pc.data_channel(id).unwrap().send_text(now, "late"),
            Err(shared::error::Error::ErrDataChannelClosed)
        ));
        while let Some(queued) = pc.get_endpoint_handler().poll_write() {
            pc.get_datachannel_handler().handle_write(queued).unwrap();
        }
        let mut order = Vec::new();
        while let Some(message) = pc.get_datachannel_handler().poll_write() {
            if let RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)) = message.message {
                if message.ppi == PayloadProtocolIdentifier::Dcep {
                    let mut payload = &message.payload[..];
                    if matches!(
                        Message::unmarshal(&mut payload).unwrap(),
                        Message::DataChannelClose(_)
                    ) {
                        order.push("close");
                    }
                } else {
                    assert_eq!(&message.payload[..], b"exit-probe");
                    order.push("payload");
                }
            }
            assert!(order.len() <= 2);
        }
        order
    }

    /// Public close while the in-band channel is still `Connecting`: the DCEP OPEN is
    /// still queued, a late ACK arrives while the close is queued behind it, and the
    /// channel must end Closed with exactly one close marker after the open marker.
    #[test]
    fn public_close_before_open_ignores_late_ack_and_orders_close_after_open() {
        use crate::data_channel::state::RTCDataChannelState;
        use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
        use crate::peer_connection::message::internal::{
            DTLSMessage, RTCMessageInternal, TaggedRTCMessageInternal,
        };
        use ::datachannel::data_channel::DataChannelMessage;
        use ::datachannel::message::message_channel_ack::DataChannelAck;
        use ::datachannel::message::message_channel_threshold::DataChannelThreshold;
        use bytes::BytesMut;
        use shared::TransportContext;
        use shared::marshal::Marshal;

        let now = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .build(now)
            .unwrap();
        // In-band: the stream id waits for the DTLS role in production. This check has no
        // association, so it binds stream id 1 the way the connected procedure would, then
        // dials. The public handle comes from the registry on insert.
        let dc = RTCDataChannelInternal::new(DataChannelParameters {
            label: "close-before-open".to_owned(),
            protocol: String::new(),
            ordered: true,
            max_packet_life_time: None,
            max_retransmits: None,
            negotiated: None,
        });
        let id = pc.data_channels.insert(dc);
        pc.data_channels.assign_stream_id(id, 1);
        pc.data_channels.get_mut(&id).unwrap().dial(0).unwrap();
        // Nothing is drained: the DCEP OPEN stays queued when the public close runs.
        pc.data_channel(id).unwrap().close().unwrap();
        pc.data_channel(id).unwrap().close().unwrap();
        assert!(matches!(
            pc.data_channel(id).unwrap().send_text(now, "late"),
            Err(shared::error::Error::ErrDataChannelClosed)
        ));
        // A late ACK reaches the handler while the queued close is still pending.
        let ack = Message::DataChannelAck(DataChannelAck {})
            .marshal()
            .unwrap();
        pc.get_datachannel_handler()
            .handle_read(TaggedRTCMessageInternal {
                now,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage {
                    association_handle: 0,
                    stream_id: 1,
                    ppi: PayloadProtocolIdentifier::Dcep,
                    payload: BytesMut::from(&ack[..]),
                    negotiated: false,
                })),
            })
            .unwrap();
        while let Some(queued) = pc.get_endpoint_handler().poll_write() {
            pc.get_datachannel_handler().handle_write(queued).unwrap();
        }
        assert_eq!(
            pc.data_channels.get(&id).unwrap().ready_state,
            RTCDataChannelState::Closed
        );
        let mut opens = 0;
        while let Some(event) = pc.get_datachannel_handler().poll_event() {
            if matches!(
                event.event,
                RTCEventInternal::RTCPeerConnectionEvent(RTCPeerConnectionEvent::OnDataChannel(
                    RTCDataChannelEvent::OnOpen(_)
                ))
            ) {
                opens += 1;
            }
        }
        assert_eq!(opens, 0, "a late ACK must not open a closing channel");
        // `RTCDataChannelInternal::dial` queues the DCEP OPEN and then the low and
        // high threshold controls (`write_data_channel_low_threshold`,
        // `write_data_channel_high_threshold` in rtc-datachannel). The queued close
        // must follow all three; any other marker is a defect.
        let mut order = Vec::new();
        while let Some(message) = pc.get_datachannel_handler().poll_write() {
            if let RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)) = message.message {
                assert_eq!(message.ppi, PayloadProtocolIdentifier::Dcep);
                let mut payload = &message.payload[..];
                order.push(match Message::unmarshal(&mut payload).unwrap() {
                    Message::DataChannelOpen(_) => "open",
                    Message::DataChannelThreshold(DataChannelThreshold::Low(_)) => "threshold-low",
                    Message::DataChannelThreshold(DataChannelThreshold::High(_)) => {
                        "threshold-high"
                    }
                    Message::DataChannelClose(_) => "close",
                    other => panic!("unexpected DCEP marker before close: {other:?}"),
                });
            }
        }
        assert_eq!(
            order,
            ["open", "threshold-low", "threshold-high", "close"],
            "one close marker after the open marker and the dial threshold controls"
        );
    }

    #[test]
    fn enqueue_then_close_preserves_payload_order() {
        let advanced = order(true);
        let queued = order(false);
        eprintln!("advanced_before_close={advanced:?}; queued_before_close={queued:?}");
        assert_eq!(advanced, ["payload", "close"], "control path");
        assert_eq!(
            queued,
            ["payload", "close"],
            "accepted payload must precede close"
        );
    }
}

/// Receive-side close barrier at the public queue boundary (Botster patch).
///
/// Every case injects through the datachannel handler (payload via `handle_read`, remote
/// close via `SCTPStreamClosed`), routes the handler output into the public data queue
/// exactly as `handle_read` does, and then observes only through the public
/// `RTCPeerConnection` API with events polled before reads, as the webrtc driver does.
/// Channels are addressed by the public handle the registry assigns; the SCTP stream id is
/// only how the injected wire messages name them.
#[cfg(test)]
mod botster_receive_close_barrier {
    use super::*;
    use crate::data_channel::internal::RTCDataChannelInternal;
    use crate::data_channel::parameters::DataChannelParameters;
    use crate::data_channel::state::RTCDataChannelState;
    use crate::peer_connection::RTCPeerConnectionBuilder;
    use crate::peer_connection::configuration::RTCConfigurationBuilder;
    use crate::peer_connection::event::TaggedRTCEventInternal;
    use crate::peer_connection::message::internal::TrackPacket;
    use ::datachannel::data_channel::DataChannelMessage;
    // `::sctp` is the crate; a bare `sctp` here would be the handler submodule of that name.
    use ::sctp::{PayloadProtocolIdentifier, StreamId};
    use bytes::BytesMut;
    use sansio::Protocol;
    use shared::TransportContext;
    use std::time::Duration;

    fn peer(now: Instant) -> RTCPeerConnection {
        RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .build(now)
            .unwrap()
    }

    /// A negotiated channel on `stream_id` dials straight to `Open`, so accepted payload is
    /// delivered without a DCEP handshake. Returns the public handle. This creates no peer.
    fn open_channel(pc: &mut RTCPeerConnection, stream_id: StreamId) -> RTCDataChannelId {
        let mut dc = RTCDataChannelInternal::new(DataChannelParameters {
            label: "receive-barrier".to_owned(),
            protocol: String::new(),
            ordered: true,
            max_packet_life_time: None,
            max_retransmits: None,
            negotiated: Some(stream_id),
        });
        dc.dial(0).unwrap();
        assert_eq!(dc.ready_state, RTCDataChannelState::Open);
        let id = pc.data_channels.insert(dc);
        while pc.get_datachannel_handler().poll_write().is_some() {}
        id
    }

    /// An in-band channel still in its DCEP handshake carries a real handler deadline, so
    /// the barrier's wake can be checked against a deadline that must survive unchanged.
    fn connecting_channel_with_deadline(
        pc: &mut RTCPeerConnection,
        stream_id: StreamId,
        deadline: Instant,
    ) -> RTCDataChannelId {
        let dc = RTCDataChannelInternal::new(DataChannelParameters {
            label: "handshake-deadline".to_owned(),
            protocol: String::new(),
            ordered: true,
            max_packet_life_time: None,
            max_retransmits: None,
            negotiated: None,
        });
        let id = pc.data_channels.insert(dc);
        pc.data_channels.assign_stream_id(id, stream_id);
        let dc = pc.data_channels.get_mut(&id).unwrap();
        dc.dial(0).unwrap();
        assert_eq!(dc.ready_state, RTCDataChannelState::Connecting);
        dc.handshake_deadline = Some(deadline);
        while pc.get_datachannel_handler().poll_write().is_some() {}
        id
    }

    /// Accept one payload on `stream_id` and route it to the public data queue.
    fn deliver(pc: &mut RTCPeerConnection, stream_id: StreamId, now: Instant, data: &str) {
        pc.get_datachannel_handler()
            .handle_read(TaggedRTCMessageInternal {
                now,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage {
                    association_handle: 0,
                    stream_id,
                    ppi: PayloadProtocolIdentifier::String,
                    payload: BytesMut::from(data.as_bytes()),
                    negotiated: false,
                })),
            })
            .unwrap();
        while let Some(msg) = pc.get_datachannel_handler().poll_read() {
            pc.route_read_out(msg);
        }
    }

    /// Route one media packet to the public media queue at `now`.
    fn deliver_media(pc: &mut RTCPeerConnection, now: Instant) {
        pc.route_read_out(TaggedRTCMessageInternal {
            now,
            transport: TransportContext::default(),
            message: RTCMessageInternal::Rtp(RTPMessage::TrackPacket(TrackPacket {
                track_id: Default::default(),
                packet: Packet::Rtp(::rtp::packet::Packet::default()),
            })),
        });
    }

    /// The remote close as the SCTP handler reports it: the datachannel handler removes the
    /// channel occupying `stream_id` and emits `OnClose(handle)` at most once.
    fn remote_close(pc: &mut RTCPeerConnection, stream_id: StreamId, now: Instant) {
        pc.get_datachannel_handler()
            .handle_event(TaggedRTCEventInternal {
                now,
                event: RTCEventInternal::SCTPStreamClosed(0, stream_id),
            })
            .unwrap();
    }

    fn is_close(event: &RTCPeerConnectionEvent, id: RTCDataChannelId) -> bool {
        matches!(
            event,
            RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(closed))
                if *closed == id
        )
    }

    fn is_any_close(event: &RTCPeerConnectionEvent) -> bool {
        matches!(
            event,
            RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(_))
        )
    }

    fn drain_events(pc: &mut RTCPeerConnection) -> Vec<RTCPeerConnectionEvent> {
        let mut events = Vec::new();
        while let Some(event) = pc.poll_event() {
            events.push(event);
        }
        events
    }

    fn text(msg: &TaggedRTCMessage) -> (RTCDataChannelId, String) {
        match &msg.message {
            RTCMessage::DataChannelMessage(id, message) => {
                (*id, String::from_utf8(message.data.to_vec()).unwrap())
            }
            other => panic!("expected a data-channel message, got {other:?}"),
        }
    }

    fn held_ids(pc: &RTCPeerConnection) -> Vec<RTCDataChannelId> {
        pc.pipeline_context
            .held_data_channel_closes
            .iter()
            .map(|(id, _)| *id)
            .collect()
    }

    fn pending(pc: &RTCPeerConnection, id: RTCDataChannelId) -> Option<usize> {
        pc.pipeline_context
            .pending_data_by_channel
            .get(&id)
            .copied()
    }

    #[test]
    fn single_channel_close_waits_for_the_accepted_payload() {
        let now = Instant::now();
        let mut pc = peer(now);
        let a = open_channel(&mut pc, 1);
        let baseline = pc.poll_timeout();

        // Final payload and the stream reset land in one intake.
        deliver(&mut pc, 1, now, "final");
        remote_close(&mut pc, 1, now);

        // Events first, as the driver polls.
        let events = drain_events(&mut pc);
        assert!(
            !events.iter().any(is_any_close),
            "close must not surface while the payload is unread: {events:?}"
        );
        assert_eq!(held_ids(&pc), vec![a]);
        assert_eq!(pending(&pc, a), Some(1));
        assert_eq!(
            pc.poll_timeout(),
            baseline,
            "no wake is due while the payload stays queued"
        );

        let payload = pc
            .poll_data_read()
            .expect("the accepted payload is readable");
        assert_eq!(text(&payload), (a, "final".to_owned()));
        assert!(pc.poll_data_read().is_none());
        assert!(held_ids(&pc).is_empty(), "the read moved the close on");
        assert_eq!(pending(&pc, a), None, "zero entries are removed");

        let due = pc.poll_timeout().expect("the released close is due");
        assert_eq!(
            due,
            baseline.map_or(now, |deadline| deadline.min(now)),
            "the wake is the last observed logical instant, folded into the handler minimum"
        );

        let events = drain_events(&mut pc);
        assert_eq!(events.len(), 1, "exactly the released close: {events:?}");
        assert!(is_close(&events[0], a));
        assert_eq!(pc.poll_timeout(), baseline, "no wake remains after release");
        assert!(
            drain_events(&mut pc).is_empty(),
            "the close is delivered once"
        );
    }

    /// The SCTP stream id is reused by a successor channel while the predecessor's close is
    /// still held. The successor gets a distinct public handle, its payload counts under
    /// that handle only, and the predecessor's close is released by the predecessor's read
    /// alone. The successor's own close then waits for the successor's payload.
    #[test]
    fn reused_wire_id_gets_a_distinct_handle_and_its_own_count() {
        let now = Instant::now();
        let mut pc = peer(now);
        let a = open_channel(&mut pc, 1);
        deliver(&mut pc, 1, now, "from-a");
        remote_close(&mut pc, 1, now);
        assert!(!drain_events(&mut pc).iter().any(is_any_close));
        assert_eq!(held_ids(&pc), vec![a]);

        // Stream id 1 is free again; the successor takes it with a new handle.
        let b = open_channel(&mut pc, 1);
        assert_ne!(a, b, "handles are never reused");
        deliver(&mut pc, 1, now, "from-b");
        assert_eq!(
            pending(&pc, a),
            Some(1),
            "the successor did not extend a's count"
        );
        assert_eq!(pending(&pc, b), Some(1));

        // Reading a's payload releases a's close even though b's payload is unread.
        assert_eq!(
            text(&pc.poll_data_read().unwrap()),
            (a, "from-a".to_owned())
        );
        assert_eq!(pending(&pc, a), None);
        assert_eq!(
            pending(&pc, b),
            Some(1),
            "a's read did not consume b's count"
        );
        let events = drain_events(&mut pc);
        assert_eq!(events.len(), 1, "{events:?}");
        assert!(is_close(&events[0], a));

        // b's close waits for b's payload.
        remote_close(&mut pc, 1, now);
        assert!(!drain_events(&mut pc).iter().any(is_any_close));
        assert_eq!(held_ids(&pc), vec![b]);
        assert_eq!(
            text(&pc.poll_data_read().unwrap()),
            (b, "from-b".to_owned())
        );
        let events = drain_events(&mut pc);
        assert_eq!(events.len(), 1, "{events:?}");
        assert!(is_close(&events[0], b));
        assert!(pc.pipeline_context.pending_data_by_channel.is_empty());
    }

    #[test]
    fn back_pressured_channel_does_not_block_a_sibling_close() {
        let now = Instant::now();
        let mut pc = peer(now);
        let a = open_channel(&mut pc, 1);
        let b = open_channel(&mut pc, 2);
        let baseline = pc.poll_timeout();

        deliver(&mut pc, 1, now, "held-back");
        remote_close(&mut pc, 1, now);
        remote_close(&mut pc, 2, now);

        let events = drain_events(&mut pc);
        assert_eq!(
            events.iter().filter(|e| is_any_close(e)).count(),
            1,
            "only the drained channel closes now: {events:?}"
        );
        assert!(events.iter().any(|e| is_close(e, b)));
        assert_eq!(held_ids(&pc), vec![a]);

        // The consumer stays behind on channel a: repeated polls add no timer.
        for _ in 0..5 {
            assert_eq!(pc.poll_timeout(), baseline);
            assert!(drain_events(&mut pc).is_empty());
        }

        assert_eq!(
            text(&pc.poll_data_read().unwrap()),
            (a, "held-back".to_owned())
        );
        let events = drain_events(&mut pc);
        assert_eq!(events.len(), 1);
        assert!(is_close(&events[0], a));
        assert!(held_ids(&pc).is_empty());
    }

    /// `poll_read` with media queued behind the data message: the data-before-media branch.
    #[test]
    fn public_poll_read_data_before_media_branch_releases_the_close() {
        let now = Instant::now();
        let mut pc = peer(now);
        let a = open_channel(&mut pc, 1);

        deliver(&mut pc, 1, now, "data");
        deliver_media(&mut pc, now + Duration::from_millis(1));
        remote_close(&mut pc, 1, now);

        assert!(!drain_events(&mut pc).iter().any(is_any_close));
        assert_eq!(held_ids(&pc), vec![a]);

        let first = pc.poll_read().unwrap();
        assert_eq!(text(&first), (a, "data".to_owned()));
        assert!(held_ids(&pc).is_empty());
        let second = pc.poll_read().unwrap();
        assert!(matches!(second.message, RTCMessage::RtpPacket(..)));
        assert!(pc.poll_read().is_none());

        let events = drain_events(&mut pc);
        assert_eq!(events.len(), 1);
        assert!(is_close(&events[0], a));
    }

    /// `poll_read` with media queued ahead of the data message, then none: the media-first
    /// branch followed by the data-only branch.
    #[test]
    fn public_poll_read_media_first_and_data_only_branches_release_the_close() {
        let now = Instant::now();
        let mut pc = peer(now);
        let a = open_channel(&mut pc, 1);

        deliver_media(&mut pc, now);
        deliver(&mut pc, 1, now + Duration::from_millis(1), "first");
        deliver(&mut pc, 1, now + Duration::from_millis(2), "second");
        remote_close(&mut pc, 1, now + Duration::from_millis(2));

        assert!(!drain_events(&mut pc).iter().any(is_any_close));

        let media = pc.poll_read().unwrap();
        assert!(matches!(media.message, RTCMessage::RtpPacket(..)));
        assert_eq!(held_ids(&pc), vec![a]);
        // Media is empty now: the data-only branch pops both messages.
        assert_eq!(text(&pc.poll_read().unwrap()), (a, "first".to_owned()));
        assert_eq!(
            held_ids(&pc),
            vec![a],
            "one of two messages read is not drained"
        );
        assert!(drain_events(&mut pc).is_empty());
        assert_eq!(text(&pc.poll_read().unwrap()), (a, "second".to_owned()));
        assert!(held_ids(&pc).is_empty());

        let events = drain_events(&mut pc);
        assert_eq!(events.len(), 1);
        assert!(is_close(&events[0], a));
    }

    /// The barrier adds no deadline while data stays undrained, and it never displaces an
    /// existing handler deadline: the DCEP handshake deadline is reported before, during,
    /// and after the held close.
    #[test]
    fn no_timer_spin_while_data_stays_undrained_and_handler_deadlines_survive() {
        let now = Instant::now();
        let handshake_deadline = now + Duration::from_secs(10);
        let mut pc = peer(now);
        let a = open_channel(&mut pc, 1);
        let _connecting = connecting_channel_with_deadline(&mut pc, 3, handshake_deadline);
        let baseline = pc.poll_timeout();
        let baseline_deadline = baseline.expect("the handshake deadline is a handler timer");
        assert!(baseline_deadline <= handshake_deadline);
        assert!(baseline_deadline > now, "no handler timer is already due");

        deliver(&mut pc, 1, now, "undrained");
        remote_close(&mut pc, 1, now);
        assert!(!drain_events(&mut pc).iter().any(is_any_close));

        for _ in 0..8 {
            assert_eq!(
                pc.poll_timeout(),
                baseline,
                "back-pressure must add no due deadline beyond the handler minimum"
            );
            assert!(drain_events(&mut pc).is_empty());
        }
        assert_eq!(held_ids(&pc), vec![a]);

        pc.poll_data_read().unwrap();
        assert_eq!(
            pc.poll_timeout(),
            Some(now),
            "the release wake is due once, at the observed logical instant"
        );
        let events = drain_events(&mut pc);
        assert_eq!(events.len(), 1);
        assert!(is_close(&events[0], a));
        assert_eq!(
            pc.poll_timeout(),
            baseline,
            "the handler deadline is unchanged after release"
        );
    }

    /// Two closes held; two reads with no event poll between them. Each read moves its own
    /// close into the event queue, so the closes surface in read order, one per poll, and
    /// the wake stays due while the second still waits.
    #[test]
    fn multiple_eligible_closes_release_in_read_order() {
        let now = Instant::now();
        let mut pc = peer(now);
        let a = open_channel(&mut pc, 1);
        let b = open_channel(&mut pc, 2);
        let c = open_channel(&mut pc, 3);

        // b's payload is queued ahead of a's, but a's close is held first: the public data
        // queue is FIFO, so the reads come out b then a, while the hold order is a then b.
        deliver(&mut pc, 2, now, "two");
        deliver(&mut pc, 1, now, "one");
        remote_close(&mut pc, 1, now);
        remote_close(&mut pc, 2, now);
        remote_close(&mut pc, 3, now);

        let events = drain_events(&mut pc);
        let closes: Vec<_> = events.iter().filter(|e| is_any_close(e)).collect();
        assert_eq!(closes.len(), 1, "{events:?}");
        assert!(is_close(closes[0], c));
        assert_eq!(held_ids(&pc), vec![a, b]);

        // The reads come out b then a: the closes follow the reads, not the hold order.
        assert_eq!(text(&pc.poll_data_read().unwrap()), (b, "two".to_owned()));
        assert_eq!(text(&pc.poll_data_read().unwrap()), (a, "one".to_owned()));
        assert!(held_ids(&pc).is_empty());
        assert_eq!(pc.pipeline_context.event_outs.len(), 2);

        let first = pc.poll_event().unwrap();
        assert!(is_close(&first, b));
        assert_eq!(
            pc.poll_timeout(),
            Some(now),
            "the wake must stay due while another released close waits"
        );
        let second = pc.poll_event().unwrap();
        assert!(is_close(&second, a));
        assert!(pc.poll_event().is_none());
        assert_ne!(
            pc.poll_timeout(),
            Some(now),
            "nothing is due once both are consumed"
        );
    }

    /// Duplicate handling inside the channel lifecycle: the datachannel handler removes the
    /// channel on the first `SCTPStreamClosed`, so a second one emits nothing. Below that,
    /// the barrier drops a second `OnClose` for a handle it already holds.
    #[test]
    fn duplicate_close_notifications_yield_one_close_after_the_read() {
        let now = Instant::now();
        let mut pc = peer(now);
        let a = open_channel(&mut pc, 1);

        deliver(&mut pc, 1, now, "once");
        remote_close(&mut pc, 1, now);
        remote_close(&mut pc, 1, now);
        assert!(!drain_events(&mut pc).iter().any(is_any_close));
        assert_eq!(held_ids(&pc), vec![a]);
        pc.poll_data_read().unwrap();
        let events = drain_events(&mut pc);
        assert_eq!(events.len(), 1, "{events:?}");
        assert!(is_close(&events[0], a));
        assert!(drain_events(&mut pc).is_empty());

        // Second line: an `OnClose` that reaches the public queue while one is already
        // held for the same handle.
        let b = open_channel(&mut pc, 1);
        deliver(&mut pc, 1, now, "again");
        remote_close(&mut pc, 1, now);
        assert!(!drain_events(&mut pc).iter().any(is_any_close));
        pc.pipeline_context
            .datachannel_handler_context
            .event_outs
            .push_back(TaggedRTCEventInternal {
                now,
                event: RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(b)),
                ),
            });
        assert!(!drain_events(&mut pc).iter().any(is_any_close));
        assert_eq!(held_ids(&pc), vec![b], "at most one held close per handle");
        pc.poll_data_read().unwrap();
        let events = drain_events(&mut pc);
        assert_eq!(events.len(), 1, "{events:?}");
        assert!(is_close(&events[0], b));
        assert!(drain_events(&mut pc).is_empty());
    }

    /// Explicit whole-connection teardown is a separate case from ordinary channel
    /// closure. `close()` keeps queued events and accepted data pollable, so it flushes the
    /// held close ahead of the `Closed` state event. A consumer that stops at `OnClose`
    /// then sees closure before the retained data. This is teardown behavior; it is not
    /// proof of graceful delivery, which the cases above establish.
    #[test]
    fn connection_teardown_flushes_the_held_close_and_keeps_data_readable() {
        let now = Instant::now();
        let mut pc = peer(now);
        let a = open_channel(&mut pc, 1);

        deliver(&mut pc, 1, now, "kept-a");
        deliver(&mut pc, 1, now, "kept-b");
        remote_close(&mut pc, 1, now);
        assert!(!drain_events(&mut pc).iter().any(is_any_close));
        assert_eq!(held_ids(&pc), vec![a]);

        pc.close().unwrap();
        assert!(
            held_ids(&pc).is_empty(),
            "no held state outlives the connection"
        );
        assert!(pc.pipeline_context.pending_data_by_channel.is_empty());
        assert_eq!(pc.peer_connection_state, RTCPeerConnectionState::Closed);

        let events = drain_events(&mut pc);
        let close_index = events.iter().position(|e| is_close(e, a));
        let closed_index = events.iter().position(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Closed
                )
            )
        });
        assert!(
            matches!((close_index, closed_index), (Some(c), Some(s)) if c < s),
            "the flushed close precedes the Closed state event: {events:?}"
        );

        // Retained data is still readable through both APIs after teardown.
        assert_eq!(text(&pc.poll_read().unwrap()), (a, "kept-a".to_owned()));
        assert_eq!(
            text(&pc.poll_data_read().unwrap()),
            (a, "kept-b".to_owned())
        );
        assert!(pc.poll_data_read().is_none());
        assert!(
            drain_events(&mut pc).is_empty(),
            "the close was delivered once"
        );

        // A close that reaches the public queue after teardown is never held again.
        let b = open_channel(&mut pc, 2);
        deliver(&mut pc, 2, now, "late");
        remote_close(&mut pc, 2, now);
        let events = drain_events(&mut pc);
        assert!(events.iter().any(|e| is_close(e, b)), "{events:?}");
        assert!(held_ids(&pc).is_empty());
    }
}

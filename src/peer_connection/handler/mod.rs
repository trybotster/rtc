pub(crate) mod datachannel;
pub(crate) mod demuxer;
pub(crate) mod dtls;
pub(crate) mod endpoint;
pub(crate) mod ice;
pub(crate) mod interceptor;
pub(crate) mod sctp;
pub(crate) mod srtp;

use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::event::RTCPeerConnectionEvent;
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
use std::collections::VecDeque;
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

    // Statistics accumulator
    pub(crate) stats: RTCStatsAccumulator,
}

impl RTCPeerConnection {
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
        self.pipeline_context.data_read_outs.pop_front()
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
                    RTCMessage::DataChannelMessage(..) => {
                        self.pipeline_context.data_read_outs.push_back(tagged)
                    }
                    _ => self.pipeline_context.media_read_outs.push_back(tagged),
                }
            }
        }

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        if let (Some(data), Some(media)) = (
            self.pipeline_context.data_read_outs.front(),
            self.pipeline_context.media_read_outs.front(),
        ) {
            if data.now <= media.now {
                self.pipeline_context.data_read_outs.pop_front()
            } else {
                self.pipeline_context.media_read_outs.pop_front()
            }
        } else if self.pipeline_context.data_read_outs.front().is_some() {
            self.pipeline_context.data_read_outs.pop_front()
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

            if let RTCEventInternal::RTCPeerConnectionEvent(evt) = evt_internal.event {
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
        let mut dc = RTCDataChannelInternal::new(
            1,
            DataChannelParameters {
                label: "enqueue-close-probe".to_owned(),
                protocol: String::new(),
                ordered: true,
                max_packet_life_time: None,
                max_retransmits: None,
                negotiated: Some(1),
            },
        );
        // This check establishes only the local queue path. It creates no peer.
        dc.dial(0).unwrap();
        pc.data_channels.insert(1, dc);
        while pc.get_datachannel_handler().poll_write().is_some() {}
        pc.data_channel(1)
            .unwrap()
            .send_text(now, "exit-probe")
            .unwrap();
        if advance_before_close {
            let queued = pc.get_endpoint_handler().poll_write().unwrap();
            pc.get_datachannel_handler().handle_write(queued).unwrap();
        }
        pc.data_channel(1).unwrap().close().unwrap();
        pc.data_channel(1).unwrap().close().unwrap();
        assert!(matches!(
            pc.data_channel(1).unwrap().send_text(now, "late"),
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
        let mut dc = RTCDataChannelInternal::new(
            1,
            DataChannelParameters {
                label: "close-before-open".to_owned(),
                protocol: String::new(),
                ordered: true,
                max_packet_life_time: None,
                max_retransmits: None,
                negotiated: None,
            },
        );
        dc.dial(0).unwrap();
        pc.data_channels.insert(1, dc);
        // Nothing is drained: the DCEP OPEN stays queued when the public close runs.
        pc.data_channel(1).unwrap().close().unwrap();
        pc.data_channel(1).unwrap().close().unwrap();
        assert!(matches!(
            pc.data_channel(1).unwrap().send_text(now, "late"),
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
            pc.data_channels.get(&1).unwrap().ready_state,
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

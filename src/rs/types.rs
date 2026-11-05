// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ffi::{QUIC_BUFFER, QUIC_CONNECTION_EVENT};
use std::ffi::c_void;

/// Listener event converted from ffi type.
#[derive(Debug)]
pub enum ListenerEvent<'a> {
    NewConnection {
        info: NewConnectionInfo<'a>,
        /// User app needs to take ownership of this new connection.
        /// User app needs to set configuration for this connection
        /// before returning from the callback.
        connection: crate::Connection,
    },
    StopComplete {
        app_close_in_progress: bool,
    },
}

#[derive(Debug)]
pub struct NewConnectionInfo<'a> {
    pub quic_version: u32,
    pub local_address: &'a crate::Addr,
    pub remote_address: &'a crate::Addr,
    pub crypto_buffer: &'a [u8],
    pub client_alpn_list: &'a [u8],
    pub server_name: &'a [u8],
    pub negotiated_alpn: &'a [u8],
}

impl<'a> From<&'a crate::ffi::QUIC_NEW_CONNECTION_INFO> for NewConnectionInfo<'a> {
    fn from(value: &crate::ffi::QUIC_NEW_CONNECTION_INFO) -> Self {
        Self {
            quic_version: value.QuicVersion,
            local_address: unsafe { (value.LocalAddress as *const crate::Addr).as_ref().unwrap() },
            remote_address: unsafe {
                (value.RemoteAddress as *const crate::Addr)
                    .as_ref()
                    .unwrap()
            },
            crypto_buffer: unsafe {
                slice_conv(value.CryptoBuffer, value.CryptoBufferLength as usize)
            },
            client_alpn_list: unsafe {
                slice_conv(value.ClientAlpnList, value.ClientAlpnListLength as usize)
            },
            server_name: unsafe {
                slice_conv(
                    value.ServerName as *const u8,
                    value.ServerNameLength as usize,
                )
            },
            negotiated_alpn: unsafe {
                slice_conv(value.NegotiatedAlpn, value.NegotiatedAlpnLength as usize)
            },
        }
    }
}

impl<'a> From<&'a crate::ffi::QUIC_LISTENER_EVENT> for ListenerEvent<'a> {
    fn from(value: &'a crate::ffi::QUIC_LISTENER_EVENT) -> Self {
        match value.Type {
            crate::ffi::QUIC_LISTENER_EVENT_TYPE_QUIC_LISTENER_EVENT_NEW_CONNECTION => {
                let ev = unsafe { &value.__bindgen_anon_1.NEW_CONNECTION };
                Self::NewConnection {
                    info: NewConnectionInfo::from(unsafe { ev.Info.as_ref().unwrap() }),
                    connection: unsafe { crate::Connection::from_raw(ev.Connection) },
                }
            }
            crate::ffi::QUIC_LISTENER_EVENT_TYPE_QUIC_LISTENER_EVENT_STOP_COMPLETE => {
                let ev = unsafe { &value.__bindgen_anon_1.STOP_COMPLETE };
                Self::StopComplete {
                    app_close_in_progress: ev.AppCloseInProgress() != 0,
                }
            }
            _ => panic!("unknown listener event {}", value.Type),
        }
    }
}

/// Connection callback events.
/// TODO: derive Debug once all enums are safe.
#[derive(Debug)]
pub enum ConnectionEvent<'a> {
    Connected {
        session_resumed: bool,
        negotiated_alpn: &'a [u8],
    },
    // The transport started the shutdown process.
    ShutdownInitiatedByTransport {
        status: crate::Status,
        error_code: crate::u62,
    },
    // The peer application started the shutdown process.
    ShutdownInitiatedByPeer {
        error_code: crate::u62,
    },
    // Ready for the handle to be closed.
    ShutdownComplete {
        handshake_completed: bool,
        peer_acknowledged_shutdown: bool,
        app_close_in_progress: bool,
    },
    LocalAddressChanged {
        address: &'a crate::Addr,
    },
    PeerAddressChanged {
        address: &'a crate::Addr,
    },
    /// Stream ownership and cleanup is on user app.
    /// App needs to set the stream callback handler before
    /// returning from connection callback.
    // TODO: may need to change StreamRef to Stream for better safety.
    PeerStreamStarted {
        stream: crate::StreamRef,
        flags: StreamOpenFlags,
    },
    StreamsAvailable {
        bidirectional_count: u16,
        unidirectional_count: u16,
    },
    PeerNeedsStreams {
        bidirectional: bool,
    },
    IdealProcessorChanged {
        ideal_processor: u16,
        partition_index: u16,
    },
    DatagramStateChanged {
        send_enabled: bool,
        max_send_length: u16,
    },
    DatagramReceived {
        buffer: &'a BufferRef,
        flags: ReceiveFlags,
    },
    DatagramSendStateChanged {
        client_context: *const c_void,
        state: DatagramSendState,
    },
    // Server-only; provides resumption data, if any.
    Resumed {
        resumption_state: &'a [u8],
    },
    // Client-only; provides ticket to persist, if any.
    ResumptionTicketReceived {
        resumption_ticket: &'a [u8],
    },
    // Only with QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED set
    PeerCertificateReceived {
        certificate: *mut crate::ffi::QUIC_CERTIFICATE,
        deferred_error_flags: u32,
        deferred_status: crate::Status,
        chain: *mut crate::ffi::QUIC_CERTIFICATE_CHAIN,
    },
    // TODO: preview features
    // ReliableResetNegotiated, // Only indicated if QUIC_SETTINGS.ReliableResetEnabled is TRUE.
    // OneWayDelayNegotiated,   // Only indicated if QUIC_SETTINGS.OneWayDelayEnabled is TRUE.
    // NetworkStatistics,       // Only indicated if QUIC_SETTINGS.EnableNetStatsEvent is TRUE.
    #[cfg(feature = "preview-api")]
    NotifyObservedAddress {
        local_address: &'a crate::Addr,
        observed_address: &'a crate::Addr,
    },
    #[cfg(feature = "preview-api")]
    NotifyRemoteAddressAdded {
        address: &'a crate::Addr,
        sequence_number: crate::u62,
    },
    #[cfg(feature = "preview-api")]
    PathValidated {
        local_address: &'a crate::Addr,
        remote_address: &'a crate::Addr,
    },
    #[cfg(feature = "preview-api")]
    NotifyRemoteAddressRemoved {
        sequence_number: crate::u62,
    },
    #[cfg(feature = "preview-api")]
    PathAdded {
        peer_address: &'a crate::Addr,
        local_address: &'a crate::Addr,
        path_id: u32,
    },
    #[cfg(feature = "preview-api")]
    PathRemoved {
        peer_address: &'a crate::Addr,
        local_address: &'a crate::Addr,
        path_id: u32,
    },
    #[cfg(feature = "preview-api")]
    PathStatusChanged {
        peer_address: &'a crate::Addr,
        local_address: &'a crate::Addr,
        path_id: u32,
        is_active: bool,
    },
    /// The host's set of local addresses changed.
    ///
    /// Only indicated when the connection is in
    /// [`LocalAddressChangeMode::Notify`](crate::LocalAddressChangeMode), the
    /// mode in which the library reports what changed and leaves the decision
    /// to the application.
    ///
    /// In `Auto` the connection acts for itself and never raises this event.
    /// What it raises instead depends on whether multipath is negotiated: a
    /// single-path connection migrates its active path and raises
    /// [`ConnectionEvent::LocalAddressChanged`], while a multipath connection
    /// opens and abandons paths and raises [`ConnectionEvent::PathAdded`] and
    /// [`ConnectionEvent::PathRemoved`]. An application that sets `Auto`
    /// without multipath and watches only the path events will see nothing
    /// when its address moves.
    ///
    /// Addresses in `added` and `removed` carry a zero port.
    ///
    /// # Lifetimes
    ///
    /// Every slice borrows memory that is only valid for the duration of the
    /// callback, and the two halves need different care:
    ///
    /// - `added` and `removed` hold the addresses inline, so copying the
    ///   [`crate::Addr`] values out is enough.
    /// - `lost_paths` does not. Each element holds two raw *pointers* into the
    ///   library's own stack frame, so copying the element copies only those
    ///   pointers and leaves them dangling the moment the callback returns.
    ///   Anything kept past the callback has to deep-copy both addresses. The
    ///   borrow checker cannot help here: the `'a` lifetime covers the slice,
    ///   not what its pointers refer to.
    #[cfg(feature = "preview-api")]
    LocalAddressesChanged {
        /// Addresses the host has that this connection is not already sending
        /// from -- what it could open a path on now.
        ///
        /// A view of the present rather than a delta: the library rebuilds it
        /// from the current snapshot on every indication instead of diffing
        /// against the last one. It is therefore complete as it stands, and
        /// accumulating it across indications is wrong -- the union would
        /// include addresses the host has since dropped.
        added: &'a [crate::Addr],
        /// Addresses the host no longer has, as of this change.
        ///
        /// A delta, and the one list that can be incomplete: it covers only
        /// the most recent change, so a burst that collapses into a single
        /// indication reports only its last step. Informational for that
        /// reason -- `lost_paths` is the list to act on.
        removed: &'a [crate::Addr],
        /// This connection's paths whose local address is gone. Always
        /// complete, unlike `removed`.
        ///
        /// Each element is already in the form `QUIC_PARAM_CONN_REMOVE_PATH`
        /// takes and can be passed straight back -- but only from inside the
        /// callback, for the lifetime reason above.
        lost_paths: &'a [crate::ffi::QUIC_PATH_PARAM],
    },
}

impl<'a> From<&'a QUIC_CONNECTION_EVENT> for ConnectionEvent<'a> {
    fn from(value: &QUIC_CONNECTION_EVENT) -> Self {
        match value.Type {
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_CONNECTED => {
                let ev = unsafe { value.__bindgen_anon_1.CONNECTED };
                let alpn = unsafe { slice_conv(ev.NegotiatedAlpn, ev.NegotiatedAlpnLength as usize) };
                Self::Connected { session_resumed: ev.SessionResumed != 0, negotiated_alpn: alpn }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT => {
              let ev = unsafe { value.__bindgen_anon_1.SHUTDOWN_INITIATED_BY_TRANSPORT };
              Self::ShutdownInitiatedByTransport { status: crate::Status(ev.Status), error_code: ev.ErrorCode }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER => {
              let ev = unsafe { value.__bindgen_anon_1.SHUTDOWN_INITIATED_BY_PEER };
              Self::ShutdownInitiatedByPeer { error_code: ev.ErrorCode }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE => {
              let ev = unsafe { value.__bindgen_anon_1.SHUTDOWN_COMPLETE };
               Self::ShutdownComplete { handshake_completed: ev.HandshakeCompleted() != 0,
                  peer_acknowledged_shutdown: ev.PeerAcknowledgedShutdown() != 0,
                  app_close_in_progress: ev.AppCloseInProgress() != 0 }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED => {
              let ev = unsafe { value.__bindgen_anon_1.LOCAL_ADDRESS_CHANGED };
              let addr = ev.Address as *const crate::Addr;
              Self::LocalAddressChanged { address: unsafe { addr.as_ref().unwrap() } }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED => {
              let ev = unsafe { value.__bindgen_anon_1.PEER_ADDRESS_CHANGED };
              let addr = ev.Address as *const crate::Addr;
              Self::PeerAddressChanged { address: unsafe { addr.as_ref().unwrap() } }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED => {
              let ev = unsafe { value.__bindgen_anon_1.PEER_STREAM_STARTED };
              Self::PeerStreamStarted { stream: unsafe { crate::StreamRef::from_raw(ev.Stream) }, flags: StreamOpenFlags::from_bits(ev.Flags).unwrap() }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE => {
              let ev = unsafe { value.__bindgen_anon_1.STREAMS_AVAILABLE };
              Self::StreamsAvailable { bidirectional_count: ev.BidirectionalCount, unidirectional_count: ev.UnidirectionalCount }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS => {
              let ev = unsafe { value.__bindgen_anon_1.PEER_NEEDS_STREAMS };
              Self::PeerNeedsStreams { bidirectional: ev.Bidirectional != 0 }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED => {
              let ev = unsafe { value.__bindgen_anon_1.IDEAL_PROCESSOR_CHANGED };
              Self::IdealProcessorChanged { ideal_processor: ev.IdealProcessor, partition_index: ev.PartitionIndex }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED => {
              let ev = unsafe { value.__bindgen_anon_1.DATAGRAM_STATE_CHANGED };
              Self::DatagramStateChanged { send_enabled: ev.SendEnabled != 0, max_send_length: ev.MaxSendLength }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED => {
              let ev = unsafe { value.__bindgen_anon_1.DATAGRAM_RECEIVED };
              Self::DatagramReceived { buffer: unsafe { BufferRef::from_ffi_ref(ev.Buffer.as_ref().unwrap()) }, flags: ReceiveFlags::from_bits(ev.Flags).unwrap() }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED => {
              let ev = unsafe { value.__bindgen_anon_1.DATAGRAM_SEND_STATE_CHANGED };
              Self::DatagramSendStateChanged { client_context: ev.ClientContext, state: DatagramSendState::from(ev.State) }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_RESUMED =>{
              let ev = unsafe { value.__bindgen_anon_1.RESUMED };
              Self::Resumed {
                resumption_state:  unsafe { slice_conv(ev.ResumptionState, ev.ResumptionStateLength as usize) }
              }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED =>{
              let ev = unsafe { value.__bindgen_anon_1.RESUMPTION_TICKET_RECEIVED };
              Self::ResumptionTicketReceived {
                resumption_ticket:  unsafe {slice_conv(ev.ResumptionTicket, ev.ResumptionTicketLength as usize) }
              }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED => {
              let ev = unsafe { value.__bindgen_anon_1.PEER_CERTIFICATE_RECEIVED };
              Self::PeerCertificateReceived {
                certificate: ev.Certificate,
                deferred_error_flags: ev.DeferredErrorFlags,
                deferred_status: crate::Status(ev.DeferredStatus),
                chain: ev.Chain
              }
            }
            #[cfg(feature = "preview-api")]
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_NOTIFY_OBSERVED_ADDRESS => {
              let ev = unsafe { value.__bindgen_anon_1.NOTIFY_OBSERVED_ADDRESS };
              let local_addr = ev.LocalAddress as *const crate::Addr;
              let observed_addr = ev.ObservedAddress as *const crate::Addr;
              Self::NotifyObservedAddress { local_address: unsafe { local_addr.as_ref().unwrap() }, observed_address: unsafe { observed_addr.as_ref().unwrap() } }
            }
            #[cfg(feature = "preview-api")]
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_ADDED => {
              let ev = unsafe { value.__bindgen_anon_1.NOTIFY_REMOTE_ADDRESS_ADDED };
              let addr = ev.Address as *const crate::Addr;
              Self::NotifyRemoteAddressAdded { address: unsafe { addr.as_ref().unwrap() }, sequence_number: ev.SequenceNumber }
            }
            #[cfg(feature = "preview-api")]
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_PATH_VALIDATED => {
              let ev = unsafe { value.__bindgen_anon_1.PATH_VALIDATED };
              let local_addr = ev.LocalAddress as *const crate::Addr;
              let remote_addr = ev.RemoteAddress as *const crate::Addr;
              Self::PathValidated { local_address: unsafe { local_addr.as_ref().unwrap() }, remote_address: unsafe { remote_addr.as_ref().unwrap() } }
            }
            #[cfg(feature = "preview-api")]
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_REMOVED => {
              let ev = unsafe { value.__bindgen_anon_1.NOTIFY_REMOTE_ADDRESS_REMOVED };
              Self::NotifyRemoteAddressRemoved { sequence_number: ev.SequenceNumber }
            }
            #[cfg(feature = "preview-api")]
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_PATH_ADDED => {
                let ev = unsafe { value.__bindgen_anon_1.PATH_ADDED };
                let peer_addr = ev.PeerAddress as *const crate::Addr;
                let local_addr = ev.LocalAddress as *const crate::Addr;
                Self::PathAdded { peer_address: unsafe { peer_addr.as_ref().unwrap() }, local_address: unsafe { local_addr.as_ref().unwrap() }, path_id: ev.PathId }
            }
            #[cfg(feature = "preview-api")]
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_PATH_REMOVED => {
                let ev = unsafe { value.__bindgen_anon_1.PATH_REMOVED };
                let peer_addr = ev.PeerAddress as *const crate::Addr;
                let local_addr = ev.LocalAddress as *const crate::Addr;
                Self::PathRemoved { peer_address: unsafe { peer_addr.as_ref().unwrap() }, local_address: unsafe { local_addr.as_ref().unwrap() }, path_id: ev.PathId }
            }
            #[cfg(feature = "preview-api")]
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_PATH_STATUS_CHANGED => {
                let ev = unsafe { value.__bindgen_anon_1.PATH_STATUS_CHANGED };
                let peer_addr = ev.PeerAddress as *const crate::Addr;
                let local_addr = ev.LocalAddress as *const crate::Addr;
                Self::PathStatusChanged { peer_address: unsafe { peer_addr.as_ref().unwrap() }, local_address: unsafe { local_addr.as_ref().unwrap() }, path_id: ev.PathId, is_active: ev.IsActive != 0 }
            }
            #[cfg(feature = "preview-api")]
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_LOCAL_ADDRESSES_CHANGED => {
                let ev = unsafe { value.__bindgen_anon_1.LOCAL_ADDRESSES_CHANGED };
                //
                // slice_conv rather than from_raw_parts: each count is
                // independently zero, and the library passes a null pointer
                // with a zero count rather than a dangling one.
                //
                Self::LocalAddressesChanged {
                    added: unsafe {
                        slice_conv(ev.Added as *const crate::Addr, ev.AddedCount as usize)
                    },
                    removed: unsafe {
                        slice_conv(ev.Removed as *const crate::Addr, ev.RemovedCount as usize)
                    },
                    lost_paths: unsafe { slice_conv(ev.LostPaths, ev.LostPathCount as usize) },
                }
            }
            _ => {
                todo!("unknown event. maybe preview feature.")
            }
        }
    }
}

/// Stream callback events
#[derive(Debug)]
pub enum StreamEvent<'a> {
    StartComplete {
        status: crate::Status,
        id: crate::u62,
        peer_accepted: bool,
    },
    Receive {
        absolute_offset: u64,
        total_buffer_length: &'a mut u64, // inout parameter
        buffers: &'a [BufferRef],
        flags: ReceiveFlags,
    },
    SendComplete {
        cancelled: bool,
        client_context: *const std::ffi::c_void,
    },
    PeerSendShutdown,
    PeerSendAborted {
        error_code: crate::u62,
    },
    PeerReceiveAborted {
        error_code: crate::u62,
    },
    SendShutdownComplete {
        graceful: bool,
    },
    ShutdownComplete {
        connection_shutdown: bool,
        app_close_in_progress: bool,
        connection_shutdown_by_app: bool,
        connection_closed_remotely: bool,
        connection_error_code: crate::u62,
        connection_close_status: crate::Status,
    },
    IdealSendBufferSize {
        byte_count: u64,
    },
    PeerAccepted,
    CancelOnLoss {
        error_code: &'a mut crate::u62, // out param
    },
}

impl<'b> From<&'b mut crate::ffi::QUIC_STREAM_EVENT> for StreamEvent<'b> {
    fn from(value: &'b mut crate::ffi::QUIC_STREAM_EVENT) -> Self {
        match value.Type {
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_START_COMPLETE => {
                let ev = unsafe { value.__bindgen_anon_1.START_COMPLETE };
                Self::StartComplete {
                    status: crate::Status(ev.Status),
                    id: ev.ID,
                    peer_accepted: ev.PeerAccepted() != 0,
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_RECEIVE => {
                let ev = unsafe { &mut value.__bindgen_anon_1.RECEIVE };
                Self::Receive {
                    absolute_offset: ev.AbsoluteOffset,
                    total_buffer_length: &mut ev.TotalBufferLength,
                    buffers: unsafe {
                        BufferRef::slice_from_ffi_ref(slice_conv(
                            ev.Buffers,
                            ev.BufferCount as usize,
                        ))
                    },
                    flags: ReceiveFlags::from_bits(ev.Flags).unwrap(),
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_SEND_COMPLETE => {
                let ev = unsafe { value.__bindgen_anon_1.SEND_COMPLETE };
                Self::SendComplete {
                    cancelled: ev.Canceled != 0,
                    client_context: ev.ClientContext,
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN => {
                Self::PeerSendShutdown
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_PEER_SEND_ABORTED => {
                let ev = unsafe { value.__bindgen_anon_1.PEER_SEND_ABORTED };
                Self::PeerSendAborted {
                    error_code: ev.ErrorCode,
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED => {
                let ev = unsafe { value.__bindgen_anon_1.PEER_RECEIVE_ABORTED };
                Self::PeerReceiveAborted {
                    error_code: ev.ErrorCode,
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE => {
                let ev = unsafe { value.__bindgen_anon_1.SEND_SHUTDOWN_COMPLETE };
                Self::SendShutdownComplete {
                    graceful: ev.Graceful != 0,
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE => {
                let ev = unsafe { value.__bindgen_anon_1.SHUTDOWN_COMPLETE };
                Self::ShutdownComplete {
                    connection_shutdown: ev.ConnectionShutdown != 0,
                    app_close_in_progress: ev.AppCloseInProgress() != 0,
                    connection_shutdown_by_app: ev.ConnectionShutdownByApp() != 0,
                    connection_closed_remotely: ev.ConnectionClosedRemotely() != 0,
                    connection_error_code: ev.ConnectionErrorCode,
                    connection_close_status: crate::Status(ev.ConnectionCloseStatus),
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE => {
                let ev = unsafe { value.__bindgen_anon_1.IDEAL_SEND_BUFFER_SIZE };
                Self::IdealSendBufferSize {
                    byte_count: ev.ByteCount,
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_PEER_ACCEPTED => {
                Self::PeerAccepted
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_CANCEL_ON_LOSS => {
                let ev = unsafe { &mut value.__bindgen_anon_1.CANCEL_ON_LOSS };
                Self::CancelOnLoss {
                    error_code: &mut ev.ErrorCode,
                }
            }
            _ => {
                panic!("unknown stream event: {}", value.Type)
            }
        }
    }
}

/// Buffer with same abi as ffi type.
/// # Safety
/// It has no ownership of the memory chunk,
/// and user needs to ensure that this ref has
/// the same lifetime as the original buffer
/// location.
#[repr(transparent)]
#[derive(Debug)]
pub struct BufferRef(pub QUIC_BUFFER);

impl BufferRef {
    /// Get the bytes of the buffer.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice_conv(self.0.Buffer, self.0.Length as usize) }
    }

    /// Cast from the ffi type.
    /// This achieves zero copy.
    pub fn from_ffi_ref(raw: &QUIC_BUFFER) -> &Self {
        unsafe { (raw as *const QUIC_BUFFER as *const Self).as_ref().unwrap() }
    }

    /// Cast from ffi slice type.
    /// This achieves zero copy.
    pub fn slice_from_ffi_ref(raw: &[QUIC_BUFFER]) -> &[Self] {
        unsafe {
            (raw as *const [QUIC_BUFFER] as *const [Self])
                .as_ref()
                .unwrap()
        }
    }
}

// Convert from various common buffer types
impl From<&str> for BufferRef {
    fn from(value: &str) -> Self {
        Self(QUIC_BUFFER {
            Length: value.len() as u32,
            Buffer: value.as_ptr() as *mut u8,
        })
    }
}

impl From<&[u8]> for BufferRef {
    fn from(value: &[u8]) -> Self {
        Self(QUIC_BUFFER {
            Length: value.len() as u32,
            Buffer: value.as_ptr() as *mut u8,
        })
    }
}

/// Convert array pointer to slice.
/// Allows empty buffer. slice::from_raw_parts does not allow empty buffer.
#[inline]
unsafe fn slice_conv<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

/// The different possible TLS providers used by MsQuic.
#[derive(Debug, PartialEq, Clone)]
pub enum TlsProvider {
    Schannel,
    Openssl,
}

impl From<TlsProvider> for crate::ffi::QUIC_TLS_PROVIDER {
    fn from(value: TlsProvider) -> Self {
        match value {
            TlsProvider::Schannel => crate::ffi::QUIC_TLS_PROVIDER_QUIC_TLS_PROVIDER_SCHANNEL,
            TlsProvider::Openssl => crate::ffi::QUIC_TLS_PROVIDER_QUIC_TLS_PROVIDER_OPENSSL,
        }
    }
}

impl From<crate::ffi::QUIC_TLS_PROVIDER> for TlsProvider {
    fn from(value: crate::ffi::QUIC_TLS_PROVIDER) -> Self {
        match value {
            crate::ffi::QUIC_TLS_PROVIDER_QUIC_TLS_PROVIDER_SCHANNEL => Self::Schannel,
            crate::ffi::QUIC_TLS_PROVIDER_QUIC_TLS_PROVIDER_OPENSSL => Self::Openssl,
            _ => panic!("unknown tls provider: {value}"),
        }
    }
}

bitflags::bitflags! {
    /// Controls connection shutdown behavior.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ConnectionShutdownFlags: crate::ffi::QUIC_CONNECTION_SHUTDOWN_FLAGS {
        const NONE = crate::ffi::QUIC_CONNECTION_SHUTDOWN_FLAGS_QUIC_CONNECTION_SHUTDOWN_FLAG_NONE;
        /// Don't send the close frame over the network.
        const SILENT = crate::ffi::QUIC_CONNECTION_SHUTDOWN_FLAGS_QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT;
    }
}

bitflags::bitflags! {
    /// Controls stream open behavior.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct StreamOpenFlags: crate::ffi::QUIC_STREAM_OPEN_FLAGS {
        const NONE = crate::ffi::QUIC_STREAM_OPEN_FLAGS_QUIC_STREAM_OPEN_FLAG_NONE;
        const UNIDIRECTIONAL = crate::ffi::QUIC_STREAM_OPEN_FLAGS_QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
        const ZERO_RTT = crate::ffi::QUIC_STREAM_OPEN_FLAGS_QUIC_STREAM_OPEN_FLAG_0_RTT;
        const DELAY_ID_FC_UPDATES = crate::ffi::QUIC_STREAM_OPEN_FLAGS_QUIC_STREAM_OPEN_FLAG_DELAY_ID_FC_UPDATES;
        #[cfg(feature = "preview-api")]
        const APP_OWNED_BUFFERS = crate::ffi::QUIC_STREAM_OPEN_FLAGS_QUIC_STREAM_OPEN_FLAG_APP_OWNED_BUFFERS;
    }
}

bitflags::bitflags! {
    /// Controls stream start behavior.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct StreamStartFlags: crate::ffi::QUIC_STREAM_START_FLAGS {
        const NONE                 = crate::ffi::QUIC_STREAM_START_FLAGS_QUIC_STREAM_START_FLAG_NONE;
        const IMMEDIATE            = crate::ffi::QUIC_STREAM_START_FLAGS_QUIC_STREAM_START_FLAG_IMMEDIATE;
        const FAIL_BLOCKED         = crate::ffi::QUIC_STREAM_START_FLAGS_QUIC_STREAM_START_FLAG_FAIL_BLOCKED;
        const SHUTDOWN_ON_FAIL     = crate::ffi::QUIC_STREAM_START_FLAGS_QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL;
        const INDICATE_PEER_ACCEPT = crate::ffi::QUIC_STREAM_START_FLAGS_QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT;
        const PRIORITY_WORK        = crate::ffi::QUIC_STREAM_START_FLAGS_QUIC_STREAM_START_FLAG_PRIORITY_WORK;
    }
}

bitflags::bitflags! {
    /// Controls stream shutdown behavior.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct StreamShutdownFlags: crate::ffi::QUIC_STREAM_SHUTDOWN_FLAGS {
        const NONE          = crate::ffi::QUIC_STREAM_SHUTDOWN_FLAGS_QUIC_STREAM_SHUTDOWN_FLAG_NONE;
        const GRACEFUL      = crate::ffi::QUIC_STREAM_SHUTDOWN_FLAGS_QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL;
        const ABORT_SEND    = crate::ffi::QUIC_STREAM_SHUTDOWN_FLAGS_QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND;
        const ABORT_RECEIVE = crate::ffi::QUIC_STREAM_SHUTDOWN_FLAGS_QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE;
        const ABORT         = crate::ffi::QUIC_STREAM_SHUTDOWN_FLAGS_QUIC_STREAM_SHUTDOWN_FLAG_ABORT;
        const IMMEDIATE     = crate::ffi::QUIC_STREAM_SHUTDOWN_FLAGS_QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE;
        const INLINE        = crate::ffi::QUIC_STREAM_SHUTDOWN_FLAGS_QUIC_STREAM_SHUTDOWN_FLAG_INLINE;
    }
}

bitflags::bitflags! {
    /// Controls stream and datagram send behavior.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SendFlags: crate::ffi::QUIC_SEND_FLAGS {
        const NONE                     = crate::ffi::QUIC_SEND_FLAGS_QUIC_SEND_FLAG_NONE;
        const ALLOW_0_RTT              = crate::ffi::QUIC_SEND_FLAGS_QUIC_SEND_FLAG_ALLOW_0_RTT;
        const START                    = crate::ffi::QUIC_SEND_FLAGS_QUIC_SEND_FLAG_START;
        const FIN                      = crate::ffi::QUIC_SEND_FLAGS_QUIC_SEND_FLAG_FIN;
        const DGRAM_PRIORITY           = crate::ffi::QUIC_SEND_FLAGS_QUIC_SEND_FLAG_DGRAM_PRIORITY;
        const DELAY_SEND               = crate::ffi::QUIC_SEND_FLAGS_QUIC_SEND_FLAG_DELAY_SEND;
        const CANCEL_ON_LOSS           = crate::ffi::QUIC_SEND_FLAGS_QUIC_SEND_FLAG_CANCEL_ON_LOSS;
        const PRIORITY_WORK            = crate::ffi::QUIC_SEND_FLAGS_QUIC_SEND_FLAG_PRIORITY_WORK;
        const CANCEL_ON_BLOCKED        = crate::ffi::QUIC_SEND_FLAGS_QUIC_SEND_FLAG_CANCEL_ON_BLOCKED;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ReceiveFlags: crate::ffi::QUIC_RECEIVE_FLAGS {
        const NONE      = crate::ffi::QUIC_RECEIVE_FLAGS_QUIC_RECEIVE_FLAG_NONE;
        const ZERO_RTT  = crate::ffi::QUIC_RECEIVE_FLAGS_QUIC_RECEIVE_FLAG_0_RTT;
        const FIN       = crate::ffi::QUIC_RECEIVE_FLAGS_QUIC_RECEIVE_FLAG_FIN;
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DatagramSendState {
    Unknown,              // Not yet sent
    Sent,                 // Sent and awaiting acknowledgment
    LostSuspect,          // Suspected as lost, but still tracked
    LostDiscarded,        // Lost and no longer being tracked
    Acknowledged,         // Acknowledged
    AcknowledgedSpurious, // Acknowledged after being suspected lost
    Canceled,             // Canceled before send
}

impl From<crate::ffi::QUIC_DATAGRAM_SEND_STATE> for DatagramSendState {
    fn from(value: crate::ffi::QUIC_DATAGRAM_SEND_STATE) -> Self {
        match value {
            crate::ffi::QUIC_DATAGRAM_SEND_STATE_QUIC_DATAGRAM_SEND_UNKNOWN => Self::Unknown,
            crate::ffi::QUIC_DATAGRAM_SEND_STATE_QUIC_DATAGRAM_SEND_SENT => Self::Sent,
            crate::ffi::QUIC_DATAGRAM_SEND_STATE_QUIC_DATAGRAM_SEND_LOST_SUSPECT => {
                Self::LostSuspect
            }
            crate::ffi::QUIC_DATAGRAM_SEND_STATE_QUIC_DATAGRAM_SEND_LOST_DISCARDED => {
                Self::LostDiscarded
            }
            crate::ffi::QUIC_DATAGRAM_SEND_STATE_QUIC_DATAGRAM_SEND_ACKNOWLEDGED => {
                Self::Acknowledged
            }
            crate::ffi::QUIC_DATAGRAM_SEND_STATE_QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS => {
                Self::AcknowledgedSpurious
            }
            crate::ffi::QUIC_DATAGRAM_SEND_STATE_QUIC_DATAGRAM_SEND_CANCELED => Self::Canceled,
            _ => panic!("Unknown state: {value:?}"),
        }
    }
}

#[cfg(all(test, feature = "preview-api"))]
mod local_addresses_changed_tests {
    use crate::{ffi, ConnectionEvent};

    //
    // The decode casts QUIC_ADDR arrays to crate::Addr arrays, so the stride
    // has to match the C union. sizeof(QUIC_ADDR) is 28 -- the size of
    // sockaddr_in6, its largest member -- and Addr is #[repr(C)] over the
    // same pair, so this pins the Rust half against an accidental change.
    //
    const _: () = assert!(std::mem::size_of::<crate::Addr>() == 28);

    //
    // Builds the event the library raises in NOTIFY mode and decodes it. The
    // arrays are owned by locals here, standing in for the library's stack --
    // which is exactly their lifetime in a real callback.
    //
    fn make_event(
        added: &[crate::Addr],
        removed: &[crate::Addr],
        lost: &[ffi::QUIC_PATH_PARAM],
    ) -> ffi::QUIC_CONNECTION_EVENT {
        let mut ev: ffi::QUIC_CONNECTION_EVENT = unsafe { std::mem::zeroed() };
        ev.Type = ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_LOCAL_ADDRESSES_CHANGED;
        ev.__bindgen_anon_1.LOCAL_ADDRESSES_CHANGED =
            ffi::QUIC_CONNECTION_EVENT__bindgen_ty_1__bindgen_ty_26 {
                AddedCount: added.len() as u32,
                Added: if added.is_empty() {
                    std::ptr::null()
                } else {
                    added.as_ptr() as *const ffi::QUIC_ADDR
                },
                RemovedCount: removed.len() as u32,
                Removed: if removed.is_empty() {
                    std::ptr::null()
                } else {
                    removed.as_ptr() as *const ffi::QUIC_ADDR
                },
                LostPathCount: lost.len() as u32,
                LostPaths: if lost.is_empty() {
                    std::ptr::null()
                } else {
                    lost.as_ptr()
                },
            };
        ev
    }

    fn v4(last_octet: u8) -> crate::Addr {
        //
        // Through the public From<SocketAddr>, so the test does not depend on
        // the shape of the union it is checking the decode against.
        //
        crate::Addr::from(std::net::SocketAddr::from((
            std::net::Ipv4Addr::new(127, 0, 0, last_octet),
            0,
        )))
    }

    #[test]
    fn decodes_added_removed_and_lost_paths() {
        let added = [v4(2), v4(3)];
        let removed = [v4(4)];
        let mut lost_local = v4(4);
        let mut lost_remote = v4(1);
        let lost = [ffi::QUIC_PATH_PARAM {
            LocalAddress: &mut lost_local as *mut crate::Addr as *mut ffi::QUIC_ADDR,
            RemoteAddress: &mut lost_remote as *mut crate::Addr as *mut ffi::QUIC_ADDR,
        }];

        let raw = make_event(&added, &removed, &lost);
        let decoded = ConnectionEvent::from(&raw);

        match decoded {
            ConnectionEvent::LocalAddressesChanged {
                added,
                removed,
                lost_paths,
            } => {
                assert_eq!(added.len(), 2);
                assert_eq!(removed.len(), 1);
                assert_eq!(lost_paths.len(), 1);
                //
                // Read back through the safe Addr view. Note what this does
                // and does not establish: make_event writes crate::Addr and
                // the decode reads crate::Addr, so the stride is
                // self-consistent whatever the C QUIC_ADDR happens to be.
                // ffi::QUIC_ADDR is an opaque c_void in the bindings, so
                // there is nothing to size-check it against either. The
                // assertion below pins the Rust side, which is the half that
                // could drift here; the C side is 28 bytes, matching
                // sockaddr_in6, and this is the first slice decode in the
                // file -- a stride divergence would silently misdecode
                // everything past index 0 rather than fail outright.
                //
                assert_eq!(added[0].as_socket().unwrap().ip().to_string(), "127.0.0.2");
                assert_eq!(added[1].as_socket().unwrap().ip().to_string(), "127.0.0.3");
                assert_eq!(
                    removed[0].as_socket().unwrap().ip().to_string(),
                    "127.0.0.4"
                );
                //
                // A lost path is handed back in the form REMOVE_PATH takes, so
                // its pointers have to be the ones the library put there.
                //
                assert_eq!(
                    lost_paths[0].LocalAddress,
                    &mut lost_local as *mut crate::Addr as *mut ffi::QUIC_ADDR
                );
                assert_eq!(
                    lost_paths[0].RemoteAddress,
                    &mut lost_remote as *mut crate::Addr as *mut ffi::QUIC_ADDR
                );
            }
            other => panic!("decoded to the wrong variant: {other:?}"),
        }
    }

    //
    // The case that would be undefined behaviour with a bare from_raw_parts:
    // the library passes a null pointer with a zero count, which it does
    // whenever a change has no additions, no removals, or no lost paths. A
    // route-only change has none of the three.
    //
    //
    // The precondition for ever receiving this event, reached through the
    // crate root -- which is the only path a downstream crate has. The mode
    // enum lives in a private module, so it was declared, settable in theory,
    // and unnameable in practice until it was re-exported: Settings took an
    // argument of a type no caller outside the crate could write down. Naming
    // it as crate::LocalAddressChangeMode here is what pins that.
    //
    #[test]
    fn notify_mode_is_settable_through_the_public_api() {
        //
        // Naming the type as crate::LocalAddressChangeMode is half the point:
        // that path is the only one a downstream crate has, and until the
        // re-export was added the enum lived in a private module, which left
        // Settings::set_LocalAddressChangeMode taking an argument no outside
        // caller could write down. If the re-export is dropped again this stops
        // compiling.
        //
        let _settings = crate::Settings::new()
            .set_LocalAddressChangeMode(crate::LocalAddressChangeMode::Notify);

        //
        // The other half: that Notify reaches the library as the mode the C
        // side tests for. QuicConnReconcileLocalAddresses raises this event
        // only on QUIC_LOCAL_ADDRESS_CHANGE_NOTIFY, so a mismapped
        // discriminant would mean the event never arrives at all.
        //
        assert_eq!(
            crate::ffi::QUIC_LOCAL_ADDRESS_CHANGE_MODE::from(crate::LocalAddressChangeMode::Notify),
            crate::ffi::QUIC_LOCAL_ADDRESS_CHANGE_MODE_QUIC_LOCAL_ADDRESS_CHANGE_NOTIFY
        );
    }

    #[test]
    fn decodes_all_empty() {
        let raw = make_event(&[], &[], &[]);
        let decoded = ConnectionEvent::from(&raw);

        match decoded {
            ConnectionEvent::LocalAddressesChanged {
                added,
                removed,
                lost_paths,
            } => {
                assert!(added.is_empty());
                assert!(removed.is_empty());
                assert!(lost_paths.is_empty());
            }
            other => panic!("decoded to the wrong variant: {other:?}"),
        }
    }
}

#[cfg(test)]
mod buff_tests {
    use crate::{ffi::QUIC_BUFFER, types::slice_conv, BufferRef};
    #[test]
    fn slice_conv_test() {
        {
            let ptr = std::ptr::null::<u8>();
            let len = 0;
            let buff = unsafe { slice_conv(ptr, len) };
            assert_eq!(buff.len(), 0)
        }
        {
            let original = b"hello";
            let buff = unsafe { slice_conv(original.as_ptr(), original.len()) };
            assert_eq!(buff, original.as_slice())
        }
    }

    #[test]
    fn buffer_ref_raw_test() {
        let first = Box::new(b"first");
        let second = b"second";
        let buffers = Box::new([
            QUIC_BUFFER {
                Buffer: first.as_ptr() as *mut u8,
                Length: first.len() as u32,
            },
            QUIC_BUFFER {
                Buffer: second.as_ptr() as *mut u8,
                Length: second.len() as u32,
            },
        ]);
        let buffer_refs = BufferRef::slice_from_ffi_ref(buffers.as_ref());
        let buffs = buffer_refs;
        // In callback events, buffers has memory from C,
        // and it has the right lifetime.
        // In this test, `buffers` variable emulates the memory from C.

        let first1 = &buffs[0];
        // If we drop buffers here on this line, compiler can catch the first1's lifetime is violated.
        // This shows that the BufferSlice wrapper captures the right lifetime of the buffers.
        // However there is no way to carry the lifetime of the var `first` into var `buffers` because the C style
        // api raw pointer boundary has been crossed.
        // TODO: msquic has feature to hold on to buffers even after callback have returned. This is
        // is not supported safely in rust. (event if we support this, buffs reference's lifetime is still only valid
        // at the end of the callback function. However, the lifetime of content of the buffer, i.e. &[u8], can be extended.)
        let second1 = &buffs[1];
        assert_eq!(first.as_slice(), first1.as_bytes());
        assert_eq!(second, second1.as_bytes());
    }

    /// This test shows how to construct simple
    /// buffers to call msquic.
    #[test]
    fn buffer_ref_conv_test() {
        let b1 = b"11";
        let b2 = b"22".to_vec();
        let b3 = "33";

        let buffer_refs = [
            BufferRef::from(b1.as_slice()),
            BufferRef::from(b2.as_slice()),
            BufferRef::from(b3),
        ];
        // One can call msquic api here using the slice.

        assert_eq!(buffer_refs[0].as_bytes(), b1);
        assert_eq!(buffer_refs[1].as_bytes(), b2);
        assert_eq!(buffer_refs[2].as_bytes(), b3.as_bytes());
    }

    #[test]
    fn buffer_ref_detach_test() {
        let data = b"data".to_vec().into_boxed_slice();
        let buff_refs = [BufferRef::from(data.as_ref())];

        // Detach the data as raw ptr.
        // raw ptr can be pass to msquic as client context.
        let raw = Box::into_raw(data);

        // MsQuic takes ownership of the buff and can inspect it.
        assert_eq!(buff_refs[0].as_bytes(), b"data");

        // Attach back the ownership
        // Usually used when msquic gives back the client context
        // in the callback event.
        let _ = unsafe { Box::from_raw(raw) };
    }

    #[test]
    fn multi_buffer_ref_detach_test() {
        let data = b"data".to_vec();
        let data2 = Box::new("data2");
        let buff_refs = [
            BufferRef::from(data.as_slice()),
            BufferRef::from(data2.as_bytes()),
        ];

        let ctx = Box::new((data, data2));

        // Detach the data as raw ptr.
        // raw ptr can be pass to msquic as client context.
        let raw = Box::into_raw(ctx);

        // MsQuic takes ownership of the buff and can inspect it.
        assert_eq!(buff_refs[0].as_bytes(), b"data");
        assert_eq!(buff_refs[1].as_bytes(), b"data2");

        // Attach back the ownership
        // Usually used when msquic gives back the client context
        // in the callback event.
        let _ = unsafe { Box::from_raw(raw) };
    }
}

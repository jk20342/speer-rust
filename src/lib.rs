//! Safe Rust bindings to **libspeer** (`speer.h` in the C workspace).
//!
//! # Layers
//!
//! - **This crate** ([`Host`], [`Peer`], [`Stream`]) keeps raw pointers alive with PhantomData borrow
//!   so handles cannot escape their logical owner.
//! - **[`sys`]** (`speer_sys`) re-exports `bindgen` types and `unsafe` FFI; use only when integrating
//!   with other C shim code.
//!
//! # Reading these docs
//!
//! Run `cargo doc -p speer --no-deps --open`. Public types expose concrete lifetimes (`'host`, `'peer`,
//! `'event`) so rust-analyzer surfaces the borrow graph the same way as normal Rust wrappers.
//!
//! # Example
//!
//! ```no_run
//! use speer::{Host, PRIVATE_KEY_SIZE};
//!
//! fn main() -> speer::Result<()> {
//!     let seed = [0u8; PRIVATE_KEY_SIZE];
//!     let mut host = Host::new(&seed, None)?;
//!     host.poll(100);
//!     Ok(())
//! }
//! ```

use std::ffi::{c_void, CStr, CString, NulError};
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::slice;

/// Raw FFI from [`speer_sys`] (generated `bindings.rs`).
///
/// Prefer the safe types in this crate (`Host`, [`Peer`], …). Reach for `sys` when you must call
/// C helpers not yet wrapped here.
pub mod sys {
    pub use speer_sys::*;
}

/// Matches [`crate::sys::SPEER_PUBLIC_KEY_SIZE`].
pub const PUBLIC_KEY_SIZE: usize = sys::SPEER_PUBLIC_KEY_SIZE as usize;
/// Matches [`crate::sys::SPEER_PRIVATE_KEY_SIZE`].
pub const PRIVATE_KEY_SIZE: usize = sys::SPEER_PRIVATE_KEY_SIZE as usize;
/// Connection id width used in QUIC-style addressing.
pub const CONNECTION_ID_SIZE: usize = sys::SPEER_CONNECTION_ID_SIZE as usize;
pub const MAX_PACKET_SIZE: usize = sys::SPEER_MAX_PACKET_SIZE as usize;
pub const MAX_STREAMS: usize = sys::SPEER_MAX_STREAMS as usize;
pub const MAX_PEERS: usize = sys::SPEER_MAX_PEERS as usize;

/// Serialized public identity as returned by [`Host::public_key`] / [`Peer::public_key`].
#[doc(alias = "IdentityPub")]
pub type PublicKey = [u8; PUBLIC_KEY_SIZE];
/// Secret seed/key material handed to [`Host::new`] (libspeer derives long-term keys internally).
#[doc(alias = "SeedKey")]
pub type PrivateKey = [u8; PRIVATE_KEY_SIZE];

/// [`core::result::Result`] specialization using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Rust projection of libspeer failures (`SPEER_ERROR_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(alias = "speer_result_t")]
pub enum Error {
    /// Wrapped `SPEER_ERROR_INVALID_PARAM`.
    InvalidParam,
    /// Wrapped `SPEER_ERROR_NO_MEMORY`.
    NoMemory,
    /// Wrapped `SPEER_ERROR_NETWORK`.
    Network,
    /// Wrapped `SPEER_ERROR_CRYPTO`.
    Crypto,
    /// Wrapped `SPEER_ERROR_HANDSHAKE`.
    Handshake,
    /// Wrapped `SPEER_ERROR_TIMEOUT`.
    Timeout,
    /// Wrapped `SPEER_ERROR_PEER_NOT_FOUND`.
    PeerNotFound,
    /// Wrapped `SPEER_ERROR_STREAM_CLOSED`.
    StreamClosed,
    /// Wrapped `SPEER_ERROR_BUFFER_TOO_SMALL`.
    BufferTooSmall,
    /// Returned when libspeer exposes a NULL where a handle was promised.
    Null,
    /// [`CString`] conversion helpers tripped [`NulError`].
    InteriorNul,
    /// Any numeric code not statically mapped yet.
    Unknown(i32),
}

impl Error {
    fn from_code(code: i32) -> Self {
        match code {
            x if x == sys::speer_result_t_SPEER_ERROR_INVALID_PARAM => Self::InvalidParam,
            x if x == sys::speer_result_t_SPEER_ERROR_NO_MEMORY => Self::NoMemory,
            x if x == sys::speer_result_t_SPEER_ERROR_NETWORK => Self::Network,
            x if x == sys::speer_result_t_SPEER_ERROR_CRYPTO => Self::Crypto,
            x if x == sys::speer_result_t_SPEER_ERROR_HANDSHAKE => Self::Handshake,
            x if x == sys::speer_result_t_SPEER_ERROR_TIMEOUT => Self::Timeout,
            x if x == sys::speer_result_t_SPEER_ERROR_PEER_NOT_FOUND => Self::PeerNotFound,
            x if x == sys::speer_result_t_SPEER_ERROR_STREAM_CLOSED => Self::StreamClosed,
            x if x == sys::speer_result_t_SPEER_ERROR_BUFFER_TOO_SMALL => Self::BufferTooSmall,
            other => Self::Unknown(other),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParam => f.write_str("invalid parameter"),
            Self::NoMemory => f.write_str("out of memory"),
            Self::Network => f.write_str("network error"),
            Self::Crypto => f.write_str("crypto error"),
            Self::Handshake => f.write_str("handshake error"),
            Self::Timeout => f.write_str("timeout"),
            Self::PeerNotFound => f.write_str("peer not found"),
            Self::StreamClosed => f.write_str("stream closed"),
            Self::BufferTooSmall => f.write_str("buffer too small"),
            Self::Null => f.write_str("speer returned a null pointer"),
            Self::InteriorNul => f.write_str("string contains an interior NUL byte"),
            Self::Unknown(code) => write!(f, "unknown speer error code {code}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<NulError> for Error {
    fn from(_: NulError) -> Self {
        Self::InteriorNul
    }
}

fn result_from_code(code: i32) -> Result<()> {
    if code >= 0 {
        Ok(())
    } else {
        Err(Error::from_code(code))
    }
}

/// Mirrors [`sys::speer_config_t`] with owned [`String`] knobs that survive FFI pinning.
///
/// CString copies are rebuilt internally when cloning into [`Host::new`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Listening UDP port (`0` lets the OS allocate).
    pub bind_port: u16,
    /// IPv4 dotted-quad literal or `"0.0.0.0"`.
    pub bind_address: Option<String>,
    pub stun_server: Option<String>,
    pub relay_server: Option<String>,
    pub max_peers: u32,
    pub max_streams: u32,
    pub handshake_timeout_ms: u32,
    pub keepalive_interval_ms: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_port: 0,
            bind_address: None,
            stun_server: None,
            relay_server: None,
            max_peers: MAX_PEERS as u32,
            max_streams: MAX_STREAMS as u32,
            handshake_timeout_ms: 10_000,
            keepalive_interval_ms: 5_000,
        }
    }
}

#[derive(Default)]
struct ConfigStrings {
    bind_address: Option<CString>,
    stun_server: Option<CString>,
    relay_server: Option<CString>,
}

impl ConfigStrings {
    fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            bind_address: optional_cstring(config.bind_address.as_deref())?,
            stun_server: optional_cstring(config.stun_server.as_deref())?,
            relay_server: optional_cstring(config.relay_server.as_deref())?,
        })
    }

    fn as_raw(&self, config: &Config) -> sys::speer_config_t {
        sys::speer_config_t {
            bind_port: config.bind_port,
            bind_address: optional_ptr(self.bind_address.as_ref()),
            stun_server: optional_ptr(self.stun_server.as_ref()),
            relay_server: optional_ptr(self.relay_server.as_ref()),
            max_peers: config.max_peers,
            max_streams: config.max_streams,
            handshake_timeout_ms: config.handshake_timeout_ms,
            keepalive_interval_ms: config.keepalive_interval_ms,
        }
    }
}

fn optional_cstring(value: Option<&str>) -> Result<Option<CString>> {
    value.map(CString::new).transpose().map_err(Into::into)
}

fn optional_ptr(value: Option<&CString>) -> *const std::ffi::c_char {
    value.map_or(std::ptr::null(), |s| s.as_ptr())
}

/// Owns [`sys::speer_host_t`]. Implements [`Drop`] (`speer_host_free`).
///
/// Typical loop: [`Host::set_callback`], then [`Host::poll`] until shutdown.
///
/// [`Peer`] values borrow this host implicitly via lifetimes (`'host`), and [`PeerRef`]/[`StreamRef`]
/// mirror callback borrows scoped to `'event`.
pub struct Host {
    raw: NonNull<sys::speer_host_t>,
    _config_strings: ConfigStrings,
    callback: Option<Box<CallbackState>>,
}

impl Host {
    /// Allocate a libspeer stack host from `seed_key` (see [`PRIVATE_KEY_SIZE`]).
    pub fn new(seed_key: &PrivateKey, config: Option<Config>) -> Result<Self> {
        let config_strings;
        let raw_config;
        let config_ptr = if let Some(config) = config.as_ref() {
            config_strings = ConfigStrings::new(config)?;
            raw_config = config_strings.as_raw(config);
            &raw_config as *const sys::speer_config_t
        } else {
            config_strings = ConfigStrings::default();
            std::ptr::null()
        };

        let raw = unsafe { sys::speer_host_new(seed_key.as_ptr(), config_ptr) };
        let raw = NonNull::new(raw).ok_or(Error::Null)?;

        Ok(Self {
            raw,
            _config_strings: config_strings,
            callback: None,
        })
    }

    /// Escape hatch for FFI interop (**`*mut sys::speer_host_t`**).
    pub fn as_raw(&self) -> *mut sys::speer_host_t {
        self.raw.as_ptr()
    }

    /// Thin wrapper around `speer_host_poll`.
    pub fn poll(&mut self, timeout_ms: i32) -> i32 {
        unsafe { sys::speer_host_poll(self.raw.as_ptr(), timeout_ms) }
    }

    /// Installs Rust closure trampoline; boxed until [`Host`] is dropped/cleared.
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: for<'event> FnMut(Event<'event>) + 'static,
    {
        self.callback = Some(Box::new(CallbackState {
            callback: Box::new(callback),
        }));

        let user_data = self
            .callback
            .as_mut()
            .map(|state| state.as_mut() as *mut CallbackState as *mut c_void)
            .unwrap_or(std::ptr::null_mut());

        unsafe {
            sys::speer_host_set_callback(self.raw.as_ptr(), Some(callback_trampoline), user_data);
        }
    }

    /// Removes dispatch + frees boxed callback state **before** `Drop`.
    pub fn clear_callback(&mut self) {
        unsafe {
            sys::speer_host_set_callback(self.raw.as_ptr(), None, std::ptr::null_mut());
        }
        self.callback = None;
    }

    /// Local static public key libspeer derives from [`Host::new`]'s [`PrivateKey`].
    pub fn public_key(&self) -> Option<PublicKey> {
        copy_key(unsafe { sys::speer_host_get_public_key(self.raw.as_ptr()) })
    }

    /// Bound UDP socket port after libspeer initializes transport.
    pub fn port(&self) -> u16 {
        unsafe { sys::speer_host_get_port(self.raw.as_ptr()) }
    }

    /// Blocking dial helper (`speer_connect`).
    pub fn connect(&self, public_key: &PublicKey, address: Option<&str>) -> Result<Peer<'_>> {
        let address = optional_cstring(address)?;
        let address_ptr = optional_ptr(address.as_ref());
        let raw =
            unsafe { sys::speer_connect(self.raw.as_ptr(), public_key.as_ptr(), address_ptr) };
        let raw = NonNull::new(raw).ok_or(Error::Null)?;
        Ok(Peer {
            raw,
            _host: PhantomData,
        })
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.clear_callback();
        unsafe {
            sys::speer_host_free(self.raw.as_ptr());
        }
    }
}

struct CallbackState {
    callback: Box<dyn for<'event> FnMut(Event<'event>)>,
}

extern "C" fn callback_trampoline(
    _host: *mut sys::speer_host_t,
    event: *const sys::speer_event_t,
    user_data: *mut c_void,
) {
    if event.is_null() || user_data.is_null() {
        return;
    }

    let state = unsafe { &mut *(user_data as *mut CallbackState) };
    let event = unsafe { Event::from_raw(&*event) };
    (state.callback)(event);
}

/// Rust-facing mapping of [`sys::speer_event_type_t`].
///
/// Inspect [`Event::event_type`] delivered to [`Host::set_callback`] closures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(alias = "speer_event_type_t")]
pub enum EventType {
    /// `SPEER_EVENT_NONE`.
    None,
    /// Remote peer completed cryptographic handshake (`SPEER_EVENT_PEER_CONNECTED`).
    PeerConnected,
    /// `SPEER_EVENT_PEER_DISCONNECTED`.
    PeerDisconnected,
    /// Yamux shim opened multiplex id (`SPEER_EVENT_STREAM_OPENED`).
    StreamOpened,
    /// Payload surfaced in [`Event::data`] (`SPEER_EVENT_STREAM_DATA`).
    StreamData,
    /// FIN/reset surfaced for stream (`SPEER_EVENT_STREAM_CLOSED`).
    StreamClosed,
    /// Generic error bucket (`SPEER_EVENT_ERROR`); probe [`Event::error_code`].
    Error,
    /// Unknown integer from future libspeer versions.
    Unknown(i64),
}

impl From<sys::speer_event_type_t> for EventType {
    fn from(value: sys::speer_event_type_t) -> Self {
        match value {
            x if x == sys::speer_event_type_t_SPEER_EVENT_NONE => Self::None,
            x if x == sys::speer_event_type_t_SPEER_EVENT_PEER_CONNECTED => Self::PeerConnected,
            x if x == sys::speer_event_type_t_SPEER_EVENT_PEER_DISCONNECTED => {
                Self::PeerDisconnected
            }
            x if x == sys::speer_event_type_t_SPEER_EVENT_STREAM_OPENED => Self::StreamOpened,
            x if x == sys::speer_event_type_t_SPEER_EVENT_STREAM_DATA => Self::StreamData,
            x if x == sys::speer_event_type_t_SPEER_EVENT_STREAM_CLOSED => Self::StreamClosed,
            x if x == sys::speer_event_type_t_SPEER_EVENT_ERROR => Self::Error,
            other => Self::Unknown(other.into()),
        }
    }
}

/// Explains why a peer disconnected (`speer_disconnect_reason_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(alias = "speer_disconnect_reason_t")]
pub enum DisconnectReason {
    /// `SPEER_DISCONNECT_NORMAL`.
    Normal,
    /// `SPEER_DISCONNECT_TIMEOUT`.
    Timeout,
    /// `SPEER_DISCONNECT_HANDSHAKE_FAILED`.
    HandshakeFailed,
    /// `SPEER_DISCONNECT_PROTOCOL_ERROR`.
    ProtocolError,
    /// `SPEER_DISCONNECT_APPLICATION`.
    Application,
    /// Unknown enumerator from forward-compatible builds.
    Unknown(i64),
}

impl From<sys::speer_disconnect_reason_t> for DisconnectReason {
    fn from(value: sys::speer_disconnect_reason_t) -> Self {
        match value {
            x if x == sys::speer_disconnect_reason_t_SPEER_DISCONNECT_NORMAL => Self::Normal,
            x if x == sys::speer_disconnect_reason_t_SPEER_DISCONNECT_TIMEOUT => Self::Timeout,
            x if x == sys::speer_disconnect_reason_t_SPEER_DISCONNECT_HANDSHAKE_FAILED => {
                Self::HandshakeFailed
            }
            x if x == sys::speer_disconnect_reason_t_SPEER_DISCONNECT_PROTOCOL_ERROR => {
                Self::ProtocolError
            }
            x if x == sys::speer_disconnect_reason_t_SPEER_DISCONNECT_APPLICATION => {
                Self::Application
            }
            other => Self::Unknown(other.into()),
        }
    }
}

/// Payload handed to [`Host::set_callback`]. Borrowed slices alias libspeer internals only for the
/// duration of your closure—copy bytes if needed beyond the dispatch call.
#[derive(Debug, Clone, Copy)]
pub struct Event<'event> {
    /// Mirrors [`sys::speer_event_t::type_`].
    pub event_type: EventType,
    /// Present for peer-bearing events (`PeerConnected`, `PeerDisconnected`, …).
    pub peer: Option<PeerRef<'event>>,
    pub stream: Option<StreamRef<'event>>,
    pub stream_id: u32,
    /// Readable range for [`EventType::StreamData`].
    pub data: &'event [u8],
    pub error_code: i32,
    pub disconnect_reason: DisconnectReason,
}

impl<'event> Event<'event> {
    unsafe fn from_raw(raw: &'event sys::speer_event_t) -> Self {
        let data = if raw.data.is_null() || raw.len == 0 {
            &[]
        } else {
            slice::from_raw_parts(raw.data, raw.len)
        };

        Self {
            event_type: EventType::from(raw.type_),
            peer: NonNull::new(raw.peer).map(PeerRef::new),
            stream: NonNull::new(raw.stream).map(StreamRef::new),
            stream_id: raw.stream_id,
            data,
            error_code: raw.error_code,
            disconnect_reason: DisconnectReason::from(raw.disconnect_reason),
        }
    }
}

/// Immutable peer handle surfaced inside callbacks (`'event` tied to trampolined FFI frame).
#[derive(Debug, Clone, Copy)]
pub struct PeerRef<'event> {
    raw: NonNull<sys::speer_peer_t>,
    _marker: PhantomData<&'event sys::speer_peer_t>,
}

impl<'event> PeerRef<'event> {
    fn new(raw: NonNull<sys::speer_peer_t>) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    /// Raw `speer_peer_t *`; only valid inside the callback frame `'event`.
    pub fn as_raw(self) -> *mut sys::speer_peer_t {
        self.raw.as_ptr()
    }

    /// Whether the libspeer backend still considers this peer connected.
    pub fn is_connected(self) -> bool {
        unsafe { sys::speer_peer_is_connected(self.raw.as_ptr()) }
    }

    /// Public key backing this peer, if the FFI layer exposes one.
    pub fn public_key(self) -> Option<PublicKey> {
        copy_key(unsafe { sys::speer_peer_get_public_key(self.raw.as_ptr()) })
    }
}

/// Remote peer acquired via [`Host::connect`]; must not outlive its [`Host`].
#[derive(Debug)]
pub struct Peer<'host> {
    raw: NonNull<sys::speer_peer_t>,
    _host: PhantomData<&'host Host>,
}

impl<'host> Peer<'host> {
    pub fn as_raw(&self) -> *mut sys::speer_peer_t {
        self.raw.as_ptr()
    }

    /// Closes this side of the peer; further stream operations fail.
    pub fn close(&mut self) {
        unsafe {
            sys::speer_peer_close(self.raw.as_ptr());
        }
    }

    /// Updates the dialing address hint (CString passed to FFI).
    pub fn set_address(&mut self, address: &str) -> Result<()> {
        let address = CString::new(address)?;
        result_from_code(unsafe {
            sys::speer_peer_set_address(self.raw.as_ptr(), address.as_ptr())
        })
    }

    pub fn is_connected(&self) -> bool {
        unsafe { sys::speer_peer_is_connected(self.raw.as_ptr()) }
    }

    /// Remote public key noise identity, when available from the backend.
    pub fn public_key(&self) -> Option<PublicKey> {
        copy_key(unsafe { sys::speer_peer_get_public_key(self.raw.as_ptr()) })
    }

    /// Opens a multiplexed logical stream (`stream_id` is application-defined).
    pub fn open_stream(&mut self, stream_id: u32) -> Result<Stream<'_, 'host>> {
        let raw = unsafe { sys::speer_stream_open(self.raw.as_ptr(), stream_id) };
        let raw = NonNull::new(raw).ok_or(Error::Null)?;
        Ok(Stream {
            raw,
            _peer: PhantomData,
        })
    }
}

/// Stream handle surfaced read-only inside [`Event`].
#[derive(Debug, Clone, Copy)]
pub struct StreamRef<'event> {
    raw: NonNull<sys::speer_stream_t>,
    _marker: PhantomData<&'event sys::speer_stream_t>,
}

impl<'event> StreamRef<'event> {
    fn new(raw: NonNull<sys::speer_stream_t>) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    pub fn as_raw(self) -> *mut sys::speer_stream_t {
        self.raw.as_ptr()
    }

    /// Logical stream identifier chosen when the stream was opened.
    pub fn id(self) -> u32 {
        unsafe { sys::speer_stream_get_id(self.raw.as_ptr()) }
    }

    pub fn is_open(self) -> bool {
        unsafe { sys::speer_stream_is_open(self.raw.as_ptr()) }
    }
}

/// Multiplexed stream tied to a [`Peer`] (closes on [`Drop`]).
#[derive(Debug)]
pub struct Stream<'peer, 'host> {
    raw: NonNull<sys::speer_stream_t>,
    _peer: PhantomData<&'peer mut Peer<'host>>,
}

impl<'peer, 'host> Stream<'peer, 'host> {
    pub fn as_raw(&self) -> *mut sys::speer_stream_t {
        self.raw.as_ptr()
    }

    pub fn id(&self) -> u32 {
        unsafe { sys::speer_stream_get_id(self.raw.as_ptr()) }
    }

    pub fn is_open(&self) -> bool {
        unsafe { sys::speer_stream_is_open(self.raw.as_ptr()) }
    }

    /// Writes plaintext into the multiplexed channel; maps negative FFI codes to [`Error`].
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        let written =
            unsafe { sys::speer_stream_write(self.raw.as_ptr(), data.as_ptr(), data.len()) };
        if written < 0 {
            Err(Error::from_code(written))
        } else {
            Ok(written as usize)
        }
    }

    /// Blocking-style read filling `buf` from the multiplexed channel.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read =
            unsafe { sys::speer_stream_read(self.raw.as_ptr(), buf.as_mut_ptr(), buf.len()) };
        if read < 0 {
            Err(Error::from_code(read))
        } else {
            Ok(read as usize)
        }
    }
}

impl Drop for Stream<'_, '_> {
    fn drop(&mut self) {
        unsafe {
            sys::speer_stream_close(self.raw.as_ptr());
        }
    }
}

/// Deterministic Curve25519 / Noise-friendly keypair helper (`speer_generate_keypair`).
pub fn generate_keypair(seed: &[u8; 32]) -> Result<(PublicKey, PrivateKey)> {
    let mut public_key = [0u8; PUBLIC_KEY_SIZE];
    let mut private_key = [0u8; PRIVATE_KEY_SIZE];
    result_from_code(unsafe {
        sys::speer_generate_keypair(
            public_key.as_mut_ptr(),
            private_key.as_mut_ptr(),
            seed.as_ptr(),
        )
    })?;
    Ok((public_key, private_key))
}

/// Fills `buf` using `speer_random_bytes`.
pub fn random_bytes(buf: &mut [u8]) {
    unsafe {
        sys::speer_random_bytes(buf.as_mut_ptr(), buf.len());
    }
}

/// Same as [`random_bytes`] but returns [`Error`] on RNG failure paths.
pub fn random_bytes_or_fail(buf: &mut [u8]) -> Result<()> {
    result_from_code(unsafe { sys::speer_random_bytes_or_fail(buf.as_mut_ptr(), buf.len()) })
}

/// Monotonic-ish millisecond stamp from libspeer utilities.
pub fn timestamp_ms() -> u64 {
    unsafe { sys::speer_timestamp_ms() }
}

fn copy_key(ptr: *const u8) -> Option<PublicKey> {
    if ptr.is_null() {
        None
    } else {
        let mut key = [0u8; PUBLIC_KEY_SIZE];
        unsafe {
            key.copy_from_slice(slice::from_raw_parts(ptr, PUBLIC_KEY_SIZE));
        }
        Some(key)
    }
}

/// Lowercase hex encoding of [`PUBLIC_KEY_SIZE`] bytes (no prefixes).
pub fn public_key_to_hex(public_key: &PublicKey) -> String {
    let mut out = String::with_capacity(PUBLIC_KEY_SIZE * 2);
    for byte in public_key {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Parses a nul-terminated public key blob (e.g. from config strings).
pub fn cstr_from_public_key_bytes(bytes: &[u8]) -> Option<&CStr> {
    CStr::from_bytes_until_nul(bytes).ok()
}

#[cfg(any(feature = "libp2p-identify", feature = "libp2p-kad"))]
pub mod libp2p {
    use super::{Error, Result};
    use std::ffi::CStr;

    #[cfg(feature = "libp2p-identify")]
    pub mod identify {
        use super::*;

        #[derive(Debug, Clone, Default)]
        pub struct IdentifyInfo {
            pub pubkey_proto: Vec<u8>,
            pub listen_addrs: Vec<Vec<u8>>,
            pub protocols: Vec<String>,
            pub agent_version: String,
            pub protocol_version: String,
            pub observed_addr: Option<Vec<u8>>,
        }

        impl IdentifyInfo {
            pub fn encode(&self) -> Result<Vec<u8>> {
                let raw = self.to_raw();
                let mut out = vec![0u8; 4096];
                let mut out_len = out.len();
                super::result_from_code(unsafe {
                    crate::sys::speer_libp2p_identify_encode(
                        &raw,
                        out.as_mut_ptr(),
                        out.len(),
                        &mut out_len,
                    )
                })?;
                out.truncate(out_len);
                Ok(out)
            }

            pub fn decode(bytes: &[u8]) -> Result<Self> {
                let mut raw =
                    unsafe { std::mem::zeroed::<crate::sys::speer_libp2p_identify_info_t>() };
                super::result_from_code(unsafe {
                    crate::sys::speer_libp2p_identify_decode(&mut raw, bytes.as_ptr(), bytes.len())
                })?;
                Ok(Self::from_raw(&raw))
            }

            fn to_raw(&self) -> crate::sys::speer_libp2p_identify_info_t {
                let mut raw =
                    unsafe { std::mem::zeroed::<crate::sys::speer_libp2p_identify_info_t>() };
                copy_slice(&self.pubkey_proto, &mut raw.pubkey_proto);
                raw.pubkey_proto_len = self.pubkey_proto.len().min(raw.pubkey_proto.len());
                raw.num_listen_addrs = self.listen_addrs.len().min(raw.listen_addrs.len());
                for (idx, addr) in self
                    .listen_addrs
                    .iter()
                    .take(raw.listen_addrs.len())
                    .enumerate()
                {
                    copy_slice(addr, &mut raw.listen_addrs[idx]);
                    raw.listen_addr_lens[idx] = addr.len().min(raw.listen_addrs[idx].len());
                }
                raw.num_protocols = self.protocols.len().min(raw.protocols.len());
                for (idx, protocol) in self.protocols.iter().take(raw.protocols.len()).enumerate() {
                    copy_str(protocol, &mut raw.protocols[idx]);
                }
                copy_str(&self.agent_version, &mut raw.agent_version);
                copy_str(&self.protocol_version, &mut raw.protocol_version);
                if let Some(observed) = &self.observed_addr {
                    copy_slice(observed, &mut raw.observed_addr);
                    raw.observed_addr_len = observed.len().min(raw.observed_addr.len());
                    raw.has_observed = 1;
                }
                raw
            }

            fn from_raw(raw: &crate::sys::speer_libp2p_identify_info_t) -> Self {
                let pubkey_proto =
                    raw.pubkey_proto[..raw.pubkey_proto_len.min(raw.pubkey_proto.len())].to_vec();
                let mut listen_addrs = Vec::new();
                for idx in 0..raw.num_listen_addrs.min(raw.listen_addrs.len()) {
                    listen_addrs.push(
                        raw.listen_addrs[idx]
                            [..raw.listen_addr_lens[idx].min(raw.listen_addrs[idx].len())]
                            .to_vec(),
                    );
                }
                let mut protocols = Vec::new();
                for idx in 0..raw.num_protocols.min(raw.protocols.len()) {
                    protocols.push(cstr_array_to_string(&raw.protocols[idx]));
                }
                let observed_addr = if raw.has_observed != 0 {
                    Some(
                        raw.observed_addr[..raw.observed_addr_len.min(raw.observed_addr.len())]
                            .to_vec(),
                    )
                } else {
                    None
                };
                Self {
                    pubkey_proto,
                    listen_addrs,
                    protocols,
                    agent_version: cstr_array_to_string(&raw.agent_version),
                    protocol_version: cstr_array_to_string(&raw.protocol_version),
                    observed_addr,
                }
            }
        }
    }

    #[cfg(feature = "libp2p-kad")]
    pub mod kad {
        use super::*;
        use std::ptr::NonNull;

        pub const PING: u8 = crate::sys::SPEER_LIBP2P_KAD_PING as u8;
        pub const FIND_NODE: u8 = crate::sys::SPEER_LIBP2P_KAD_FIND_NODE as u8;
        pub const GET_VALUE: u8 = crate::sys::SPEER_LIBP2P_KAD_GET_VALUE as u8;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct KadPeer {
            pub id: [u8; crate::sys::SPEER_LIBP2P_KAD_ID_BYTES as usize],
            pub address: String,
        }

        #[derive(Debug, Clone, Default)]
        pub struct KadMessage {
            pub msg_type: u8,
            pub key: Vec<u8>,
            pub value: Vec<u8>,
            pub closer_peers: Vec<KadPeer>,
        }

        impl KadMessage {
            pub fn encode(&self) -> Result<Vec<u8>> {
                let raw_peers = self.raw_peers();
                let raw = crate::sys::speer_libp2p_kad_msg_t {
                    type_: self.msg_type,
                    key: optional_ptr(self.key.as_slice()),
                    key_len: self.key.len(),
                    value: optional_ptr(self.value.as_slice()),
                    value_len: self.value.len(),
                    closer_peers: optional_ptr(raw_peers.as_slice()),
                    num_closer_peers: raw_peers.len(),
                };
                let mut out = vec![0u8; 4096];
                let mut out_len = out.len();
                super::result_from_code(unsafe {
                    crate::sys::speer_libp2p_kad_encode_message(
                        &raw,
                        out.as_mut_ptr(),
                        out.len(),
                        &mut out_len,
                    )
                })?;
                out.truncate(out_len);
                Ok(out)
            }

            pub fn decode(bytes: &[u8]) -> Result<Self> {
                let mut raw = unsafe { std::mem::zeroed::<crate::sys::speer_libp2p_kad_msg_t>() };
                let mut raw_peers =
                    vec![unsafe { std::mem::zeroed::<crate::sys::speer_libp2p_kad_peer_t>() }; 20];
                super::result_from_code(unsafe {
                    crate::sys::speer_libp2p_kad_decode_message(
                        bytes.as_ptr(),
                        bytes.len(),
                        &mut raw,
                        raw_peers.as_mut_ptr(),
                        raw_peers.len(),
                    )
                })?;
                let closer_peers = raw_peers
                    .iter()
                    .take(raw.num_closer_peers.min(raw_peers.len()))
                    .map(|peer| KadPeer {
                        id: peer.id,
                        address: cstr_array_to_string(&peer.address),
                    })
                    .collect();
                Ok(Self {
                    msg_type: raw.type_,
                    key: copy_optional(raw.key, raw.key_len),
                    value: copy_optional(raw.value, raw.value_len),
                    closer_peers,
                })
            }

            fn raw_peers(&self) -> Vec<crate::sys::speer_libp2p_kad_peer_t> {
                self.closer_peers
                    .iter()
                    .map(|peer| {
                        let mut raw =
                            unsafe { std::mem::zeroed::<crate::sys::speer_libp2p_kad_peer_t>() };
                        raw.id = peer.id;
                        copy_str(&peer.address, &mut raw.address);
                        raw
                    })
                    .collect()
            }
        }

        pub struct KadClient {
            session: NonNull<crate::sys::speer_libp2p_tcp_session_t>,
        }

        impl KadClient {
            /// # Safety
            ///
            /// `session` must be a valid live libp2p TCP session for the lifetime of the client.
            pub unsafe fn from_raw(
                session: *mut crate::sys::speer_libp2p_tcp_session_t,
            ) -> Result<Self> {
                Ok(Self {
                    session: NonNull::new(session).ok_or(Error::Null)?,
                })
            }

            pub fn roundtrip(&mut self, request: &[u8]) -> Result<Vec<u8>> {
                let mut out = vec![0u8; 4096];
                let mut out_len = out.len();
                super::result_from_code(unsafe {
                    crate::sys::speer_libp2p_kad_stream_roundtrip(
                        self.session.as_ptr(),
                        request.as_ptr(),
                        request.len(),
                        out.as_mut_ptr(),
                        &mut out_len,
                    )
                })?;
                out.truncate(out_len);
                Ok(out)
            }
        }

        fn optional_ptr<T>(slice: &[T]) -> *const T {
            if slice.is_empty() {
                std::ptr::null()
            } else {
                slice.as_ptr()
            }
        }

        fn copy_optional(ptr: *const u8, len: usize) -> Vec<u8> {
            if ptr.is_null() || len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
            }
        }
    }

    fn result_from_code(code: i32) -> Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(Error::Unknown(code))
        }
    }

    fn copy_slice(src: &[u8], dst: &mut [u8]) {
        let len = src.len().min(dst.len());
        dst[..len].copy_from_slice(&src[..len]);
    }

    fn copy_str(src: &str, dst: &mut [std::ffi::c_char]) {
        if dst.is_empty() {
            return;
        }
        let bytes = src.as_bytes();
        let len = bytes.len().min(dst.len().saturating_sub(1));
        for (idx, byte) in bytes.iter().take(len).enumerate() {
            dst[idx] = *byte as std::ffi::c_char;
        }
        dst[len] = 0;
    }

    fn cstr_array_to_string(buf: &[std::ffi::c_char]) -> String {
        unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .to_string()
    }

    #[cfg(all(test, feature = "libp2p-kad"))]
    mod tests {
        use super::identify::IdentifyInfo;
        use super::kad::{KadMessage, FIND_NODE};

        #[test]
        fn identify_roundtrips() {
            let info = IdentifyInfo {
                pubkey_proto: b"pubkey".to_vec(),
                protocols: vec!["/ipfs/kad/1.0.0".to_string()],
                agent_version: "speer/0.2".to_string(),
                protocol_version: "ipfs/0.1.0".to_string(),
                ..IdentifyInfo::default()
            };
            let encoded = info.encode().unwrap();
            let decoded = IdentifyInfo::decode(&encoded).unwrap();
            assert_eq!(decoded.pubkey_proto, b"pubkey");
            assert_eq!(decoded.protocols, vec!["/ipfs/kad/1.0.0"]);
        }

        #[test]
        fn kad_message_roundtrips() {
            let msg = KadMessage {
                msg_type: FIND_NODE,
                key: vec![7; 32],
                ..KadMessage::default()
            };
            let encoded = msg.encode().unwrap();
            let decoded = KadMessage::decode(&encoded).unwrap();
            assert_eq!(decoded.msg_type, FIND_NODE);
            assert_eq!(decoded.key, vec![7; 32]);
        }
    }
}

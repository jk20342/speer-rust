use std::ffi::{c_void, CStr, CString, NulError};
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::slice;

pub mod sys {
    pub use speer_sys::*;
}

pub const PUBLIC_KEY_SIZE: usize = sys::SPEER_PUBLIC_KEY_SIZE as usize;
pub const PRIVATE_KEY_SIZE: usize = sys::SPEER_PRIVATE_KEY_SIZE as usize;
pub const CONNECTION_ID_SIZE: usize = sys::SPEER_CONNECTION_ID_SIZE as usize;
pub const MAX_PACKET_SIZE: usize = sys::SPEER_MAX_PACKET_SIZE as usize;
pub const MAX_STREAMS: usize = sys::SPEER_MAX_STREAMS as usize;
pub const MAX_PEERS: usize = sys::SPEER_MAX_PEERS as usize;

pub type PublicKey = [u8; PUBLIC_KEY_SIZE];
pub type PrivateKey = [u8; PRIVATE_KEY_SIZE];

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidParam,
    NoMemory,
    Network,
    Crypto,
    Handshake,
    Timeout,
    PeerNotFound,
    StreamClosed,
    BufferTooSmall,
    Null,
    InteriorNul,
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

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_port: u16,
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

pub struct Host {
    raw: NonNull<sys::speer_host_t>,
    _config_strings: ConfigStrings,
    callback: Option<Box<CallbackState>>,
}

impl Host {
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

    pub fn as_raw(&self) -> *mut sys::speer_host_t {
        self.raw.as_ptr()
    }

    pub fn poll(&self, timeout_ms: i32) -> i32 {
        unsafe { sys::speer_host_poll(self.raw.as_ptr(), timeout_ms) }
    }

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

    pub fn clear_callback(&mut self) {
        unsafe {
            sys::speer_host_set_callback(self.raw.as_ptr(), None, std::ptr::null_mut());
        }
        self.callback = None;
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        copy_key(unsafe { sys::speer_host_get_public_key(self.raw.as_ptr()) })
    }

    pub fn port(&self) -> u16 {
        unsafe { sys::speer_host_get_port(self.raw.as_ptr()) }
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    None,
    PeerConnected,
    PeerDisconnected,
    StreamOpened,
    StreamData,
    StreamClosed,
    Error,
    Unknown(i32),
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
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    Normal,
    Timeout,
    HandshakeFailed,
    ProtocolError,
    Application,
    Unknown(i32),
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
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Event<'event> {
    pub event_type: EventType,
    pub peer: Option<PeerRef<'event>>,
    pub stream: Option<StreamRef<'event>>,
    pub stream_id: u32,
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

    pub fn as_raw(self) -> *mut sys::speer_peer_t {
        self.raw.as_ptr()
    }

    pub fn is_connected(self) -> bool {
        unsafe { sys::speer_peer_is_connected(self.raw.as_ptr()) }
    }

    pub fn public_key(self) -> Option<PublicKey> {
        copy_key(unsafe { sys::speer_peer_get_public_key(self.raw.as_ptr()) })
    }
}

#[derive(Debug)]
pub struct Peer<'host> {
    raw: NonNull<sys::speer_peer_t>,
    _host: PhantomData<&'host Host>,
}

impl<'host> Peer<'host> {
    pub fn as_raw(&self) -> *mut sys::speer_peer_t {
        self.raw.as_ptr()
    }

    pub fn close(&mut self) {
        unsafe {
            sys::speer_peer_close(self.raw.as_ptr());
        }
    }

    pub fn set_address(&mut self, address: &str) -> Result<()> {
        let address = CString::new(address)?;
        result_from_code(unsafe {
            sys::speer_peer_set_address(self.raw.as_ptr(), address.as_ptr())
        })
    }

    pub fn is_connected(&self) -> bool {
        unsafe { sys::speer_peer_is_connected(self.raw.as_ptr()) }
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        copy_key(unsafe { sys::speer_peer_get_public_key(self.raw.as_ptr()) })
    }

    pub fn open_stream(&mut self, stream_id: u32) -> Result<Stream<'_, 'host>> {
        let raw = unsafe { sys::speer_stream_open(self.raw.as_ptr(), stream_id) };
        let raw = NonNull::new(raw).ok_or(Error::Null)?;
        Ok(Stream {
            raw,
            _peer: PhantomData,
        })
    }
}

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

    pub fn id(self) -> u32 {
        unsafe { sys::speer_stream_get_id(self.raw.as_ptr()) }
    }

    pub fn is_open(self) -> bool {
        unsafe { sys::speer_stream_is_open(self.raw.as_ptr()) }
    }
}

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

    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        let written =
            unsafe { sys::speer_stream_write(self.raw.as_ptr(), data.as_ptr(), data.len()) };
        if written < 0 {
            Err(Error::from_code(written))
        } else {
            Ok(written as usize)
        }
    }

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

pub fn random_bytes(buf: &mut [u8]) {
    unsafe {
        sys::speer_random_bytes(buf.as_mut_ptr(), buf.len());
    }
}

pub fn random_bytes_or_fail(buf: &mut [u8]) -> Result<()> {
    result_from_code(unsafe { sys::speer_random_bytes_or_fail(buf.as_mut_ptr(), buf.len()) })
}

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

pub fn public_key_to_hex(public_key: &PublicKey) -> String {
    let mut out = String::with_capacity(PUBLIC_KEY_SIZE * 2);
    for byte in public_key {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn cstr_from_public_key_bytes(bytes: &[u8]) -> Option<&CStr> {
    CStr::from_bytes_until_nul(bytes).ok()
}

use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder::{ByteOrder, NetworkEndian};

use {TransmitSeq, StreamSeq};

pub trait Wire<'a> {
    fn decode(data: &'a [u8]) -> Self;
    fn encode(&self, dest: &mut [u8]);
    fn size() -> u16;         // TODO: associated const once size_of is const fn
}

macro_rules! sum {
    ($h:expr) => ($h);
    ($h:expr, $($t:expr),*) => ($h + sum!($($t),*));
}

macro_rules! wire_nonempty {
    {$name:ident, $($field:ident : $ty:ty),*} => {
        wire_nonempty!{$name, $($field : $ty,)*}
    };
    {$name:ident, $($field:ident : $ty:ty,)*} => {
        #[derive(Debug, Copy, Clone)]
        pub struct $name {
            $(pub $field: $ty),*
        }
        impl<'a> Wire<'a> for $name {
            fn size() -> u16 { sum!($(::std::mem::size_of::<$ty>()),*) as u16 }
            #[allow(unused_assignments)]
            fn decode(data: &'a [u8]) -> Self {
                let mut i = 0;
                Self {
                    $($field: { let x = <$ty as Field>::decode(&data[i..]); i += mem::size_of::<$ty>(); x }),*
                }
            }
            #[allow(unused_assignments)]
            fn encode(&self, dest: &mut [u8]) {
                let mut i = 0;
                $(
                    <$ty as Field>::encode(self.$field, &mut dest[i..]);
                    i += mem::size_of::<$ty>();
                )*
            }
        }
    };
}

macro_rules! wire {
    {$name:ident,} => {
        #[derive(Debug, Copy, Clone)]
        pub struct $name {}
        impl<'a> Wire<'a> for $name {
            fn size() -> u16 { 0 }
            fn decode(data: &[u8]) -> Self { $name {} }
            fn encode(&self, dest: &mut [u8]) {}
        }
    };
    {$name:ident, $field0:ident : $ty0:ty, $($field:ident : $ty:ty,)*} => {
        wire_nonempty!{$name, $field0 : $ty0, $($field : $ty,)*}
    };
}

wire!{
    CommonHeader,
    source_port: u16,
    destination_port: u16,
    verification_tag: u32,
    checksum: u32,
}

impl CommonHeader {
    pub fn write_checksum(dest: &mut [u8], checksum: u32) {
        NetworkEndian::write_u32(&mut dest[8..12], checksum);
    }
}

pub trait Type: for<'a> Wire<'a> {
    type Flags: From<u8> + Into<u8> + Copy;
    const TYPE: u8;
}

pub trait Param<'a>: Wire<'a> {
    const TYPE: u16;
    fn dynamic_size(&self) -> u16;
}

pub struct UnrecognizedParameter<'a> {
    pub ty: u16,
    pub value: &'a [u8],
}

impl<'a> Wire<'a> for UnrecognizedParameter<'a> {
    fn size() -> u16 { 4 }
    fn decode(data: &'a [u8]) -> Self {
        let header = ParamHeader::decode(&data[0..4]);
        UnrecognizedParameter {
            ty: header.ty,
            value: &data[4..header.length as usize],
        }
    }
    fn encode(&self, dest: &mut [u8]) {
        ParamHeader {
            ty: self.ty,
            length: self.value.len() as u16,
        }.encode(&mut dest[0..4]);
        dest[4..].copy_from_slice(self.value);
    }
}

impl<'a> Param<'a> for UnrecognizedParameter<'a> {
    const TYPE: u16 = 8;
    fn dynamic_size(&self) -> u16 { self.value.len() as u16 + 4 }
}

wire!{
    ParamHeader,
    ty: u16,
    length: u16,
}

impl ParamHeader {
    /// If set for an unrecognized parameter, do not process any further parameters
    pub fn stop(ty: u16) -> bool { ty & (1 << 15) != 0 }
    /// If set for an unrecognized parameter, report the error in an "Unrecognized Parameter" parameter to an
    /// appropriate chunk
    pub fn report(ty: u16) -> bool { ty & (1 << 14) != 0 }
}

macro_rules! param {
    {$name:ident = $param_ty:expr, $($field:ident : $ty:ty,)*} => {
        wire!{$name, $($field : $ty,)*}
        impl<'a> Param<'a> for $name {
            const TYPE: u16 = $param_ty;
            fn dynamic_size(&self) -> u16 { <Self as Wire>::size() }
        }
    }
}

// TODO: MAC
param!{
    Cookie = 7,
    inbound_streams: u16,
    outbound_streams: u16,
    peer_verification_tag: u32,
    local_verification_tag: u32,
    timestamp: u64,
    tsn: TransmitSeq,
    recv_tsn: TransmitSeq,
}

param!{
    StaleCookieError = 3,
    measure: u32,
}

param!{
    Ipv4Address = 5,
    address: Ipv4Addr,
}

param!{
    Ipv6Address = 6,
    address: Ipv6Addr,
}

trait Field: Copy {
    fn decode(data: &[u8]) -> Self;
    fn encode(self, dest: &mut [u8]);
}

impl Field for u8 {
    fn decode(data: &[u8]) -> u8 { data[0] }
    fn encode(self, dest: &mut [u8]) { dest[0] = self; }
}

impl Field for u16 {
    fn decode(data: &[u8]) -> u16 { NetworkEndian::read_u16(data) }
    fn encode(self, dest: &mut [u8]) { NetworkEndian::write_u16(dest, self) }
}

impl Field for u32 {
    fn decode(data: &[u8]) -> u32 { NetworkEndian::read_u32(data) }
    fn encode(self, dest: &mut [u8]) { NetworkEndian::write_u32(dest, self) }
}

impl Field for u64 {
    fn decode(data: &[u8]) -> u64 { NetworkEndian::read_u64(data) }
    fn encode(self, dest: &mut [u8]) { NetworkEndian::write_u64(dest, self) }
}

impl Field for TransmitSeq {
    fn decode(data: &[u8]) -> Self { TransmitSeq(NetworkEndian::read_u32(data)) }
    fn encode(self, dest: &mut [u8]) { NetworkEndian::write_u32(dest, self.0) }
}

impl Field for StreamSeq {
    fn decode(data: &[u8]) -> Self { StreamSeq(NetworkEndian::read_u16(data)) }
    fn encode(self, dest: &mut [u8]) { NetworkEndian::write_u16(dest, self.0) }
}

impl Field for Ipv4Addr {
    fn decode(data: &[u8]) -> Self { Ipv4Addr::new(data[0], data[1], data[2], data[3]) }
    fn encode(self, dest: &mut [u8]) { dest.copy_from_slice(&self.octets()) }
}

impl Field for Ipv6Addr {
    fn decode(data: &[u8]) -> Self {
        if data.len() != 16 { panic!("incorrect length for an ipv6 address"); }
        unsafe { Self::from(*(data.as_ptr() as *const [u8; 16])) }
    }
    fn encode(self, dest: &mut [u8]) { dest.copy_from_slice(&self.octets()) }
}

pub struct Chunk<T: Type> {
    pub flags: T::Flags,
    pub length: u16,
    pub value: T,
}

impl<T: Type> Chunk<T> {
    pub fn size() -> u16 { T::size() + 4 }

    pub fn encode(&self, dest: &mut [u8]) {
        debug_assert_eq!(dest.len(), Self::size() as usize);
        dest[0] = T::TYPE;
        dest[1] = self.flags.into();
        NetworkEndian::write_u16(&mut dest[2..4], self.length);
        self.value.encode(&mut dest[4..]);
    }

    pub fn decode(data: &[u8]) -> Option<(Self, ParamIter)> {
        if data.len() < (Self::size() as usize) { return None; }
        let length = NetworkEndian::read_u16(&data[2..4]);
        if data.len() < length as usize { return None; }
        let fixed_end = Self::size() as usize;
        Some((
            Self {
                length,
                flags: data[1].into(),
                value: T::decode(&data[4..fixed_end]),
            },
            ParamIter(&data[fixed_end..])
        ))
    }
}

macro_rules! chunk_inner {
    {$name:ident = $chunk_ty:expr, $flags:ident, $($field:ident : $ty:ty,)*} => {
        wire!{$name, $($field : $ty,)*}
        impl Type for $name {
            type Flags = $flags;
            const TYPE: u8 = $chunk_ty;
        }
    }
}

macro_rules! chunk {
    {$name:ident = $chunk_ty:expr, $flags:ident { $($flag:ident = $val:expr),* }, $($field:ident : $ty:ty),*} => {
        chunk_inner!{$name = $chunk_ty, $flags, $($field : $ty,)*}
        bitflags! {
            pub struct $flags: u8 {
                $(const $flag = $val;)*
            }
        }
        impl From<u8> for $flags { fn from(x: u8) -> $flags { $flags::from_bits_truncate(x) } }
        impl Into<u8> for $flags { fn into(self) -> u8 { self.bits() } }
    };

    {$name:ident = $chunk_ty:expr, $flags:ident, $($field:ident : $ty:ty),*} => {
        chunk_inner!{$name = $chunk_ty, $flags, $($field : $ty,)*}
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
        pub struct $flags {}
        impl From<u8> for $flags { fn from(x: u8) -> $flags { $flags {} } }
        impl Into<u8> for $flags { fn into(self) -> u8 { 0 } }
        impl $flags {
            pub fn empty() -> Self { $flags {} }
        }
    };
}

chunk!{
    Data = 0,
    DataFlags { END = 0b001, BEGIN = 0b010, UNORDERED = 0b100 },
    tsn: TransmitSeq,
    stream: u16, stream_seq: u16,
    protocol: u32
}

chunk!{
    Init = 1,
    InitFlags,
    tag: u32,
    a_rwnd: u32,
    outbound_streams: u16,
    max_inbound_streams: u16,
    tsn: TransmitSeq
}

chunk!{
    InitAck = 2,
    InitAckFlags,
    tag: u32,
    a_rwnd: u32,
    outbound_streams: u16,
    max_inbound_streams: u16,
    tsn: TransmitSeq
}

chunk!{
    Abort = 6,
    AbortFlags { T = 0b1 },
}

chunk!{
    Error = 9,
    ErrorFlags,
}

chunk!{
    CookieEcho = 10,
    CookieEchoFlags,
}

chunk!{
    CookieAck = 11,
    CookieAckFlags,
}

pub struct ParamIter<'a>(&'a [u8]);

impl<'a> Iterator for ParamIter<'a> {
    type Item = (u16, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.0.len() < ParamHeader::size() as usize { return None; }
        let header = ParamHeader::decode(self.0);
        if self.0.len() < header.length as usize { return None; }
        let body = &self.0[ParamHeader::size() as usize..header.length as usize];
        self.0 = &self.0[header.length as usize..];
        Some((header.ty, body))
    }
}

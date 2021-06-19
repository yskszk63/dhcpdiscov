use std::convert::{TryFrom, TryInto};
use std::ffi::CStr;
use std::fmt;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::time::Duration;
use std::env;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use pnet::datalink::{self, Channel, Config, NetworkInterface, interfaces};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket, ipv4_checksum};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

trait Put {
    fn put<BUF>(&mut self, buf: BUF) where BUF: Buf;
    fn put_u8(&mut self, b: u8);
    fn put_u16(&mut self, b: u16);
    fn put_u32(&mut self, b: u32);
    fn put_u128(&mut self, b: u128);
}

#[derive(Debug, Default)]
struct Count(usize);

impl Put for Count {
    fn put<BUF>(&mut self, buf: BUF) where BUF: Buf {
        self.0 += buf.remaining();
    }

    fn put_u8(&mut self, _: u8) {
        self.0 += 1;
    }

    fn put_u16(&mut self, _: u16) {
        self.0 += 2;
    }

    fn put_u32(&mut self, _: u32) {
        self.0 += 4;
    }

    fn put_u128(&mut self, _: u128) {
        self.0 += 16;
    }
}

impl<B> Put for B where B: BufMut {
    fn put<BUF>(&mut self, buf: BUF) where BUF: Buf {
        B::put(self, buf)
    }

    fn put_u8(&mut self, b: u8) {
        B::put_u8(self, b)
    }

    fn put_u16(&mut self, b: u16) {
        B::put_u16(self, b)
    }

    fn put_u32(&mut self, b: u32) {
        B::put_u32(self, b)
    }

    fn put_u128(&mut self, b: u128) {
        B::put_u128(self, b)
    }
}

#[derive(Clone)]
struct DhcpString<const N: usize> {
    inner: [u8; N],
}

impl<const N: usize> DhcpString<N> {
    fn new(inner: [u8; N]) -> anyhow::Result<Self> {
        if !inner.iter().any(|p| *p == 0) {
            anyhow::bail!("no null char.")
        }
        Ok(Self { inner })
    }

    fn write_to<B>(&self, buf: &mut B) where B: Put {
        buf.put(self.as_ref())
    }
}

impl<const N: usize> Default for DhcpString<N> {
    fn default() -> Self {
        Self { inner: [0; N] }
    }
}

impl<const N: usize> AsRef<[u8]> for DhcpString<N> {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl<const N: usize> fmt::Debug for DhcpString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tail = self.inner.iter().position(|p| *p == 0).unwrap();
        let cstr = CStr::from_bytes_with_nul(&self.inner[..=tail]).unwrap();
        write!(f, "{:?}", cstr)
    }
}

#[derive(Debug, Clone)]
enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nack,
    Release,
}

impl DhcpMessageType {
    fn write_to<B>(&self, buf: &mut B) where B: Put {
        buf.put_u8(self.clone().into())
    }
}

impl TryFrom<u8> for DhcpMessageType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nack,
            7 => Self::Release,
            _ => anyhow::bail!("fixme"), // TODO
        })
    }
}

impl From<DhcpMessageType> for u8 {
    fn from(v: DhcpMessageType) -> Self {
        match v {
            DhcpMessageType::Discover => 1,
            DhcpMessageType::Offer => 2,
            DhcpMessageType::Request => 3,
            DhcpMessageType::Decline => 4,
            DhcpMessageType::Ack => 5,
            DhcpMessageType::Nack => 6,
            DhcpMessageType::Release => 7,
        }
    }
}

#[derive(Debug, Clone)]
enum DhcpOption {
    Pad,
    End,
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    DomainNameServer(Vec<Ipv4Addr>),
    IpAddressLeaseTime(Duration),
    MessageType(DhcpMessageType),
    ServerIdentifier(Ipv4Addr),
    RenewalTimeValue(Duration),
    RebindingTimeValue(Duration),
    Unknown(u8, Bytes),
}

impl DhcpOption {
    fn parse<B>(mut buf: B) -> anyhow::Result<Self>
    where
        B: Buf,
    {
        let code = buf.get_u8();
        match code {
            0x00 => return Ok(Self::Pad),
            0xFF => return Ok(Self::End),
            _ => {}
        }
        let len = buf.get_u8() as usize;

        match code {
            1 => Ok(Self::SubnetMask(buf.get_u32().into())),
            3 => {
                let mut addrs = vec![];
                for _ in 0..len/4 {
                    addrs.push(buf.get_u32().into())
                }
                Ok(Self::Router(addrs))
            }
            6 => {
                let mut addrs = vec![];
                for _ in 0..len/4 {
                    addrs.push(buf.get_u32().into())
                }
                Ok(Self::DomainNameServer(addrs))
            }
            51 => Ok(Self::IpAddressLeaseTime(Duration::from_secs(buf.get_u32() as u64))),
            53 => Ok(Self::MessageType(buf.get_u8().try_into()?)),
            54 => Ok(Self::ServerIdentifier(buf.get_u32().into())),
            58 => Ok(Self::RenewalTimeValue(Duration::from_secs(buf.get_u32() as u64))),
            59 => Ok(Self::RebindingTimeValue(Duration::from_secs(buf.get_u32() as u64))),
            _ => Ok(Self::Unknown(code, buf.copy_to_bytes(len))),
        }
    }

    fn write_to<B>(&self, buf: &mut B) where B: Put {
        match self {
            Self::Pad => buf.put_u8(0x00),
            Self::End => buf.put_u8(0xFF),
            Self::SubnetMask(s) => {
                buf.put_u8(1);
                buf.put_u8(4);
                buf.put_u32(s.clone().into());
            }
            Self::Router(r) => {
                buf.put_u8(3);
                buf.put_u8((r.len() * 4) as u8);
                r.iter().for_each(|r| buf.put_u32(r.clone().into()))
            }
            Self::DomainNameServer(r) => {
                buf.put_u8(6);
                buf.put_u8((r.len() * 4) as u8);
                r.iter().for_each(|r| buf.put_u32(r.clone().into()))
            }
            Self::IpAddressLeaseTime(t) => {
                buf.put_u8(51);
                buf.put_u8(4);
                buf.put_u32(t.as_secs() as u32);
            }
            Self::MessageType(ty) => {
                buf.put_u8(53);
                buf.put_u8(1);
                ty.write_to(buf);
            }
            Self::ServerIdentifier(ty) => {
                buf.put_u8(54);
                buf.put_u8(4);
                buf.put_u32(ty.clone().into());
            }
            Self::RenewalTimeValue(t) => {
                buf.put_u8(58);
                buf.put_u8(4);
                buf.put_u32(t.as_secs() as u32);
            }
            Self::RebindingTimeValue(t) => {
                buf.put_u8(59);
                buf.put_u8(4);
                buf.put_u32(t.as_secs() as u32);
            }
            Self::Unknown(code, bytes) => {
                buf.put_u8(*code);
                buf.put_u8(bytes.len() as u8);
                buf.put(bytes.as_ref());
            }
        }
    }
}

#[derive(Debug, Clone)]
enum DhcpOp {
    BootRequest,
    BootReply,
}

impl TryFrom<u8> for DhcpOp {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::BootRequest,
            2 => Self::BootReply,
            _ => anyhow::bail!("fixme"), // TODO
        })
    }
}

impl From<DhcpOp> for u8 {
    fn from(this: DhcpOp) -> Self {
        match this {
            DhcpOp::BootRequest => 1,
            DhcpOp::BootReply => 2,
        }
    }
}

#[derive(Debug, Clone)]
enum HardwareType {
    Ethernet,
}

impl TryFrom<u8> for HardwareType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::Ethernet,
            _ => anyhow::bail!("fixme"), // TODO
        })
    }
}

impl From<HardwareType> for u8 {
    fn from(_: HardwareType) -> Self {
        1
    }
}

bitflags::bitflags! {
    struct DhcpFlags: u16 {
        const BROADCAST = 0b1000_0000_0000_0000;
    }
}

#[derive(Debug)]
struct DhcpPacketBuilder {
    inner: DhcpPacket,
}

#[allow(dead_code)]
impl DhcpPacketBuilder {
    fn new(op: DhcpOp, xid: u32) -> Self {
        Self {
            inner: DhcpPacket {
                op,
                htype: HardwareType::Ethernet,
                hlen: 6,
                hops: 0,
                xid,
                secs: 0,
                flags: DhcpFlags::empty(),
                ciaddr: 0.into(),
                yiaddr: 0.into(),
                siaddr: 0.into(),
                giaddr: 0.into(),
                chaddr: Default::default(),
                sname: Default::default(),
                file: Default::default(),
                cookie: 1669485411,
                options: vec![],
            },
        }
    }

    fn op(&mut self, val: DhcpOp) -> &mut Self {
        self.inner.op = val;
        self
    }
    fn htype(&mut self, val: HardwareType) -> &mut Self {
        self.inner.htype = val;
        self
    }
    fn hlen(&mut self, val: u8) -> &mut Self {
        self.inner.hlen = val;
        self
    }
    fn hops(&mut self, val: u8) -> &mut Self {
        self.inner.hops = val;
        self
    }
    fn xid(&mut self, val: u32) -> &mut Self {
        self.inner.xid = val;
        self
    }
    fn secs(&mut self, val: u16) -> &mut Self {
        self.inner.secs = val;
        self
    }
    fn flags(&mut self, val: DhcpFlags) -> &mut Self {
        self.inner.flags = val;
        self
    }
    fn ciaddr(&mut self, val: Ipv4Addr) -> &mut Self {
        self.inner.ciaddr = val;
        self
    }
    fn yiaddr(&mut self, val: Ipv4Addr) -> &mut Self {
        self.inner.yiaddr = val;
        self
    }
    fn siaddr(&mut self, val: Ipv4Addr) -> &mut Self {
        self.inner.siaddr = val;
        self
    }
    fn giaddr(&mut self, val: Ipv4Addr) -> &mut Self {
        self.inner.giaddr = val;
        self
    }
    fn chaddr(&mut self, val: u128) -> &mut Self {
        self.inner.chaddr = val;
        self
    }
    fn sname(&mut self, val: DhcpString<64>) -> &mut Self {
        self.inner.sname = val;
        self
    }
    fn file(&mut self, val: DhcpString<128>) -> &mut Self {
        self.inner.file = val;
        self
    }
    fn cookie(&mut self, val: u32) -> &mut Self {
        self.inner.cookie = val;
        self
    }
    fn add_message_type(&mut self, ty: DhcpMessageType) -> &mut Self {
        self.inner.options.push(DhcpOption::MessageType(ty));
        self
    }
    fn add_server_identifier(&mut self, ident: Ipv4Addr) -> &mut Self {
        self.inner.options.push(DhcpOption::ServerIdentifier(ident));
        self
    }
    fn build(&mut self) -> DhcpPacket {
        if !matches!(self.inner.options.last(), Some(DhcpOption::End)) {
            self.inner.options.push(DhcpOption::End)
        }
        self.inner.clone()
    }
}

#[derive(Debug, Clone)]
struct DhcpPacket {
    op: DhcpOp,
    htype: HardwareType,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: DhcpFlags,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    chaddr: u128,
    sname: DhcpString<64>,
    file: DhcpString<128>,
    cookie: u32,
    options: Vec<DhcpOption>,
}

impl DhcpPacket {
    fn parse<B>(mut buf: B) -> anyhow::Result<Self>
    where
        B: Buf,
    {
        let op = buf.get_u8().try_into()?;
        let htype = buf.get_u8().try_into()?;
        let hlen = buf.get_u8();
        let hops = buf.get_u8();
        let xid = buf.get_u32();
        let secs = buf.get_u16();
        let flags = DhcpFlags::from_bits_truncate(buf.get_u16());
        let ciaddr = buf.get_u32().into();
        let yiaddr = buf.get_u32().into();
        let siaddr = buf.get_u32().into();
        let giaddr = buf.get_u32().into();
        let chaddr = buf.get_u128();
        let mut sname = [0; 64];
        buf.copy_to_slice(&mut sname);
        let sname = DhcpString::new(sname)?;
        let mut file = [0; 128];
        buf.copy_to_slice(&mut file);
        let file = DhcpString::new(file)?;
        let cookie = buf.get_u32();

        let mut options = vec![];
        while buf.has_remaining() {
            let opt = DhcpOption::parse(&mut buf)?;
            if matches!(opt, DhcpOption::End) {
                options.push(opt);
                break;
            }
            options.push(opt);
        }
        Ok(Self {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            cookie,
            options,
        })
    }

    fn builder(op: DhcpOp, xid: u32) -> DhcpPacketBuilder {
        DhcpPacketBuilder::new(op, xid)
    }

    fn write_to<B>(&self, buf: &mut B) where B: Put {
        buf.put_u8(self.op.clone().into());
        buf.put_u8(self.htype.clone().into());
        buf.put_u8(self.hlen.into());
        buf.put_u8(self.hops.into());
        buf.put_u32(self.xid.into());
        buf.put_u16(self.secs.into());
        buf.put_u16(self.flags.bits());
        buf.put_u32(self.ciaddr.into());
        buf.put_u32(self.yiaddr.into());
        buf.put_u32(self.siaddr.into());
        buf.put_u32(self.giaddr.into());
        buf.put_u128(self.chaddr.into());
        self.sname.write_to(buf);
        self.file.write_to(buf);
        buf.put_u32(self.cookie.into());
        for opt in &self.options {
            opt.write_to(buf);
        }
    }

    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        self.write_to(&mut buf);
        buf.freeze()
    }

    fn size(&self) -> usize {
        let mut c = Count::default();
        self.write_to(&mut c);
        c.0
    }
}

fn packet(iface: &NetworkInterface, xid: u32) -> Vec<u8> {
    let dhcp_pkt = DhcpPacket::builder(DhcpOp::BootRequest, xid)
        .flags(DhcpFlags::BROADCAST)
        .add_message_type(DhcpMessageType::Discover)
        .build();

    let dhcp_pkt_len = dhcp_pkt.size();
    let mut packet = vec![0; dhcp_pkt_len + 14 + 20 + 8];
    let mut ether = MutableEthernetPacket::new(&mut packet).unwrap();
    ether.set_source(iface.mac.unwrap());
    ether.set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
    ether.set_ethertype(EtherTypes::Ipv4);
    let mut ipv4 = MutableIpv4Packet::new(ether.payload_mut()).unwrap();
    ipv4.set_version(4);
    ipv4.set_header_length(5);
    ipv4.set_dscp(46);
    ipv4.set_ecn(0);
    ipv4.set_identification(rand::random());
    ipv4.set_flags(2);
    ipv4.set_fragment_offset(0);
    ipv4.set_ttl(32);
    ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ipv4.set_source([0, 0, 0, 0].into());
    ipv4.set_destination([255, 255, 255, 255].into());
    ipv4.set_total_length((dhcp_pkt_len + 20 + 8) as u16);
    ipv4.set_checksum(checksum(&ipv4.to_immutable()));
    let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).unwrap();
    udp.set_source(68);
    udp.set_destination(67);
    udp.set_payload(&dhcp_pkt.to_bytes());
    udp.set_length((dhcp_pkt_len + 8) as u16);
    let checksum = ipv4_checksum(&udp.to_immutable(), &[0, 0, 0, 0].into(), &0xFFFFFFFF.into());
    udp.set_checksum(checksum);

    packet
}

fn main() -> anyhow::Result<()> {
    let ifname = env::args().nth(1);
    let ifname = if let Some(ifname) = ifname {
        ifname
    } else {
        for iface in interfaces() {
            println!("{}", iface.name);
        }
        return Ok(())
    };

    let iface = interfaces()
        .into_iter()
        .find(|iface| iface.name == ifname)
        .unwrap();

    let mut conf = Config::default();
    conf.read_timeout = Some(Duration::from_secs(3));
    let (mut tx, mut rx) = match datalink::channel(&iface, conf)? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => panic!(),
    };

    loop {
        let xid = rand::random();
        let packet = packet(&iface, xid);
        tx.send_to(&packet, None).unwrap()?;

        loop {
            let packet = match rx.next() {
                Ok(packet) => packet,
                Err(err) if err.kind() == ErrorKind::TimedOut => break,
                Err(err) => return Err(err.into()),
            };
            let ether = EthernetPacket::new(packet).unwrap();
            match ether.get_ethertype() {
                EtherTypes::Ipv4 => {
                    let ipv4 = Ipv4Packet::new(ether.payload()).unwrap();
                    match ipv4.get_next_level_protocol() {
                        IpNextHeaderProtocols::Udp => {
                            let udp = UdpPacket::new(ipv4.payload()).unwrap();
                            let sport = udp.get_source();
                            let dport = udp.get_destination();
                            if sport == 67 && dport == 68 {
                                let packet = DhcpPacket::parse(udp.payload())?;
                                if packet.xid == xid {
                                    for opt in packet.options {
                                        match opt {
                                            DhcpOption::Pad => {},
                                            DhcpOption::End => {},
                                            DhcpOption::MessageType(..) => {},
                                            DhcpOption::ServerIdentifier(ip) => println!("server: {}", ip),
                                            DhcpOption::IpAddressLeaseTime(d) => println!("leasetime: {}s", d.as_secs()),
                                            DhcpOption::SubnetMask(ip) => println!("subnet mask: {}", ip),
                                            DhcpOption::Router(ips) => {
                                                for ip in ips {
                                                    println!("router: {}", ip)
                                                }
                                            }
                                            DhcpOption::DomainNameServer(ips) => {
                                                for ip in ips {
                                                    println!("domain name server: {}", ip)
                                                }
                                            }
                                            DhcpOption::RenewalTimeValue(d) => println!("renewaltime: {}s", d.as_secs()),
                                            DhcpOption::RebindingTimeValue(d) => println!("rebindtime: {}s", d.as_secs()),
                                            DhcpOption::Unknown(code, buf) => println!("{} {:X}", code, buf),
                                        }
                                    }
                                    return Ok(())
                                }
                            }
                        }
                        _ => {} //ty => println!("unhandled type {:?}", ty),
                    }
                }
                _ => {} //ty => println!("unhandled type {:?}", ty),
            }
        }
        eprintln!("timed out. retry.")
    }
}

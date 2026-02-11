// Copyright (c) 2023, FoxIO, LLC.
// All rights reserved.
// Patent Pending
// JA4 is Open-Source, Licensed under BSD 3-Clause
// JA4+ (JA4S, JA4H, JA4L, JA4X, JA4SSH) are licenced under the FoxIO License 1.1.
// For full license text, see the repo root.

use indexmap::{map::Entry, IndexMap};
use serde::Serialize;
use std::{
    io::Write,
    time::{Duration, Instant},
};

use crate::{
    conf::Conf,
    http, ssh, tcp,
    time::{self, TcpTimestamps, Timestamps, UdpTimestamps},
    tls, FormatFlags, OutputFormat, Packet, Result, Sender,
};

#[derive(Serialize)]
pub(crate) struct CsvRec {
    stream: StreamId,
    transport: Transport,
    src_ip: String,
    src_port: u32,
    dst_ip: String,
    dst_port: u32,
    ja4t: Option<String>,
    ja4: Option<String>,
    ja4l: Option<String>,
}

impl From<OutRec> for CsvRec {
    fn from(rec: OutRec) -> Self {
        CsvRec {
            stream: rec.stream,
            transport: rec.transport,
            src_ip: rec.sockets.src.to_string(),
            src_port: rec.sockets.src_port,
            dst_ip: rec.sockets.dst.to_string(),
            dst_port: rec.sockets.dst_port,
            ja4t: rec.payload.tcp.map(|o| o.ja4t),
            ja4: rec
                .payload
                .tls
                .as_ref()
                .and_then(|tls| tls.client.as_ref())
                .map(|client| match &client.ja4 {
                    tls::Ja4Fingerprint::Sorted(s) | tls::Ja4Fingerprint::Unsorted(s) => s.clone(),
                }),
            ja4l: rec.payload.ja4l.map(|f| f.ja4l_c),
        }
    }
}

/// User-facing record containing data obtained from a TCP or UDP stream.
#[derive(Debug, Serialize)]
pub(crate) struct OutRec {
    stream: StreamId,
    transport: Transport,
    #[serde(flatten)]
    sockets: SocketPair,
    #[serde(flatten)]
    payload: OutStream,
}

#[derive(Debug, Serialize)]
struct OutStream {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    tcp: Option<tcp::OutStream>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    tls: Option<tls::OutStream>,
    /// Light distance (latency) fingerprints.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    ja4l: Option<time::Fingerprints>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    http: Option<http::OutStream>,
    /// SSH fingerprints.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ja4ssh: Vec<ssh::Fingerprint>,
    /// Additional information from SSH packets.
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_extras: Option<ssh::Extras>,
}

#[derive(Debug, Default)]
struct Stream<T> {
    tcp: Option<tcp::Stream>,
    tls: Option<tls::Stream>,
    timestamps: Option<T>,
    http: http::Stream,
    ssh: ssh::Stream,
}

impl<T: Timestamps> Stream<T> {
    fn into_out(self, flags: FormatFlags) -> Option<OutStream> {
        let Self {
            tcp,
            tls,
            timestamps,
            http,
            ssh,
        } = self;

        let tcp = tcp.and_then(|stats| stats.into_out(flags));
        let tls = tls.and_then(|stats| stats.into_out(flags));
        let ja4l = timestamps.and_then(|ts| ts.finish());
        let http = http.into_out(flags);
        let (ja4ssh, ssh_extras) = ssh.finish();

        if tcp.is_none() && tls.is_none() && ja4l.is_none() && http.is_none() && ja4ssh.is_empty() {
            return None;
        }

        Some(OutStream {
            tcp,
            tls,
            ja4l,
            http,
            ja4ssh,
            ssh_extras,
        })
    }
}

#[derive(Debug)]
struct AddressedStream<T> {
    sockets: SocketPair,
    stream: Stream<T>,
    last_seen: Instant,
}

impl<T: Timestamps> AddressedStream<T> {
    fn new(sockets: SocketPair) -> Self {
        Self {
            sockets,
            stream: Stream::default(),
            last_seen: Instant::now(),
        }
    }

    fn update(&mut self, pkt: &Packet, conf: &Conf, store_pkt_num: bool, guessed_sender: Sender) {
        self.last_seen = Instant::now();

        if conf.tcp.enabled {
            if let Err(error) = self
                .stream
                .tcp
                .get_or_insert_with(Default::default)
                .update(pkt, store_pkt_num)
            {
                tracing::debug!(%pkt.num, %error, "failed to fingerprint TCP");
            }
        }

        if conf.tls.enabled {
            if let Err(error) = self
                .stream
                .tls
                .get_or_insert_with(Default::default)
                .update(pkt, store_pkt_num)
            {
                tracing::debug!(%pkt.num, %error, "failed to fingerprint TLS");
            }
        }

        if conf.http.enabled {
            if let Err(error) = self.stream.http.update(pkt, store_pkt_num) {
                tracing::debug!(%pkt.num, %error, "failed to fingerprint HTTP");
            }
        }

        if conf.time.enabled {
            match self
                .stream
                .timestamps
                .take()
                .unwrap_or_default()
                .update(pkt)
            {
                Ok(ts) => self.stream.timestamps = Some(ts),
                Err(error) => tracing::debug!(%pkt.num, %error, "failed to store timestamp"),
            }
        }

        if conf.ssh.enabled && pkt.find_proto("tcp").is_some() {
            if let Err(error) = self
                .stream
                .ssh
                .update(pkt, guessed_sender, conf.ssh.sample_size)
            {
                tracing::debug!(%pkt.num, %error, "failed to handle SSH packet");
            }
        }
    }

    fn is_idle(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() >= timeout
    }
}

/// Information collected from the capture file.
#[derive(Debug)]
pub(crate) struct Streams<W: Write> {
    tcp: IndexMap<StreamId, AddressedStream<TcpTimestamps>>,
    udp: IndexMap<StreamId, AddressedStream<UdpTimestamps>>,
    writer: W,
    csv_header_written: bool,
    flags: FormatFlags,
    output_format: OutputFormat,
    udp_idle_timeout: Duration,
    tcp_idle_timeout: Duration,
}

impl<W: Write> Streams<W> {
    pub fn new(writer: W, flags: FormatFlags, output_format: OutputFormat) -> Self {
        Self {
            tcp: IndexMap::new(),
            udp: IndexMap::new(),
            writer,
            csv_header_written: false,
            flags,
            output_format,
            udp_idle_timeout: Duration::from_secs(300),
            tcp_idle_timeout: Duration::from_secs(1200),
        }
    }

    pub(crate) fn update(&mut self, pkt: &Packet, conf: &Conf, store_pkt_num: bool) -> Result<()> {
        tracing::debug!(%pkt.num, "processing packet");
        let Some(attrs) = StreamAttrs::new(pkt)? else {
            return Ok(());
        };
        tracing::debug!(?attrs);
        let StreamAttrs {
            transport,
            stream_id,
            sockets,
        } = attrs;

        let sender_ip = sockets.src.clone();

        // HACK: We assume that the earliest `SocketPair` is the client's.
        // This is not always true. For example, the first packet (SYN) of a TCP stream
        // may not be captured. In this case, the earliest packet will be the server's.
        fn guess_sender(sender_ip: &str, earliest: &SocketPair) -> Sender {
            if sender_ip == earliest.src {
                Sender::Client
            } else {
                Sender::Server
            }
        }

        match transport {
            Transport::Tcp => {
                let mut remove_after = false;

                let stream = match self.tcp.entry(stream_id) {
                    Entry::Vacant(x) => x.insert(AddressedStream::new(sockets)),
                    Entry::Occupied(x) => {
                        x.get().sockets.check(&sockets);
                        x.into_mut()
                    }
                };
                stream.update(
                    pkt,
                    conf,
                    store_pkt_num,
                    guess_sender(&sender_ip, &stream.sockets),
                );

                if is_tcp_closed(pkt) {
                    remove_after = true;
                }

                if remove_after || stream.is_idle(self.tcp_idle_timeout) {
                    if let Some(closed) = self.tcp.swap_remove(&stream_id) {
                        self.export_stream(stream_id, closed, Transport::Tcp)?;
                    }
                }
            }
            Transport::Udp => {
                let stream = match self.udp.entry(stream_id) {
                    Entry::Vacant(x) => x.insert(AddressedStream::new(sockets)),
                    Entry::Occupied(x) => {
                        x.get().sockets.check(&sockets);
                        x.into_mut()
                    }
                };
                stream.update(
                    pkt,
                    conf,
                    store_pkt_num,
                    guess_sender(&sender_ip, &stream.sockets),
                );

                if stream.is_idle(self.udp_idle_timeout) {
                    if let Some(closed) = self.udp.swap_remove(&stream_id) {
                        self.export_stream(stream_id, closed, Transport::Udp)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn into_out(self, flags: FormatFlags) -> impl Iterator<Item = OutRec> {
        let Self {
            tcp,
            udp,
            writer: _,
            csv_header_written: _, 
            flags: _,
            output_format: _,
            tcp_idle_timeout: _,
            udp_idle_timeout: _,
        } = self;

        let tcp = tcp.into_iter().filter_map(move |(sid, addressed)| {
            let AddressedStream {
                sockets,
                stream,
                last_seen: _,
            } = addressed;
            Some(OutRec {
                stream: sid,
                transport: Transport::Tcp,
                sockets,
                payload: stream.into_out(flags)?,
            })
        });
        let udp = udp.into_iter().filter_map(move |(sid, addressed)| {
            let AddressedStream {
                sockets,
                stream,
                last_seen: _,
            } = addressed;
            Some(OutRec {
                stream: sid,
                transport: Transport::Udp,
                sockets,
                payload: stream.into_out(flags)?,
            })
        });
        tcp.chain(udp)
    }

    fn export_stream(
        &mut self,
        sid: StreamId,
        addressed: AddressedStream<impl Timestamps>,
        transport: Transport,
    ) -> Result<()> {
        let AddressedStream {
            sockets,
            stream,
            last_seen: _,
        } = addressed;

        if let Some(payload) = stream.into_out(self.flags) {
            let out = OutRec {
                stream: sid,
                transport,
                sockets,
                payload,
            };

            match self.output_format {
                OutputFormat::Csv => {
                    let write_header = !self.csv_header_written;

                    let mut wtr = csv::WriterBuilder::new()
                        .has_headers(write_header)
                        .from_writer(&mut self.writer);

                    wtr.serialize(CsvRec::from(out))?;
                    wtr.flush()?;

                    if write_header {
                        self.csv_header_written = true;
                    }
                }
                OutputFormat::Json => {
                    serde_json::to_writer(&mut self.writer, &out)?;
                    writeln!(self.writer)?;
                }
                OutputFormat::Yaml => {
                    let s = serde_yaml::to_string(&out)?;
                    self.writer.write_all(s.as_bytes())?;
                }
            }
        }

        Ok(())
    }

    pub fn flush_all(&mut self) -> Result<()> {
        let tcp_streams: Vec<_> = self.tcp.drain(..).collect();
        for (sid, s) in tcp_streams {
            self.export_stream(sid, s, Transport::Tcp)?;
        }

        let udp_streams: Vec<_> = self.udp.drain(..).collect();
        for (sid, s) in udp_streams {
            self.export_stream(sid, s, Transport::Udp)?;
        }

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Auxiliary definitions

fn is_tcp_closed(pkt: &Packet) -> bool {
    if let Some(tcp) = pkt.find_proto("tcp") {
        if let Ok(flags) = tcp.first("tcp.flags") {
            let flags = u16::from_str_radix(flags.trim_start_matches("0x"), 16).unwrap_or(0);

            const FIN: u16 = 0x01;
            const RST: u16 = 0x04;

            return (flags & FIN != 0) || (flags & RST != 0);
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpVersion {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
struct StreamId(u32);

#[derive(Debug, Clone, PartialEq, Serialize)]
struct SocketPair {
    #[serde(skip)]
    ip_ver: IpVersion,
    src: String,
    dst: String,
    src_port: u32,
    dst_port: u32,
}

impl SocketPair {
    #[cfg(debug_assertions)]
    fn opposite(self) -> Self {
        Self {
            ip_ver: self.ip_ver,
            src: self.dst,
            dst: self.src,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }

    #[cfg(debug_assertions)]
    fn check(&self, other: &Self) {
        assert!(*self == *other || *self == other.clone().opposite());
    }

    #[cfg(not(debug_assertions))]
    fn check(&self, _other: &Self) {}
}

#[derive(Debug)]
struct StreamAttrs {
    transport: Transport,
    stream_id: StreamId,
    sockets: SocketPair,
}

impl StreamAttrs {
    fn new(pkt: &Packet) -> Result<Option<Self>> {
        // A packet may contain multiple TCP and/or UDP layers. For example, Generic Routing
        // Encapsulation (GRE) tunneling protocol allows the encapsulation of packets from
        // one network protocol within the packets of another protocol:
        //
        // ```
        // $ tshark -r pcap/gre-erspan-vxlan.pcap -Tpdml -n 'frame.number == 2' | grep -E '<proto |ip\.(src|dst)|(tcp|udp)\.(stream|(src|dst)port)'
        //   <proto name="geninfo" pos="0" showname="General information" size="154">
        //   <proto name="frame" showname="Frame 2: 154 bytes on wire (1232 bits), 154 bytes captured (1232 bits)" size="154" pos="0">
        //   <proto name="eth" showname="Ethernet II, Src: aa:aa:aa:aa:aa:a1, Dst: bb:bb:bb:bb:bb:b1" size="14" pos="0">
        //   <proto name="ip" showname="Internet Protocol Version 4, Src: 100.20.9.2, Dst: 100.20.9.1" size="20" pos="14">
        //     <field name="ip.src" showname="Source Address: 100.20.9.2" size="4" pos="26" show="100.20.9.2" value="64140902"/>
        //     <field name="ip.src_host" showname="Source Host: 100.20.9.2" hide="yes" size="4" pos="26" show="100.20.9.2" value="64140902"/>
        //     <field name="ip.dst" showname="Destination Address: 100.20.9.1" size="4" pos="30" show="100.20.9.1" value="64140901"/>
        //     <field name="ip.dst_host" showname="Destination Host: 100.20.9.1" hide="yes" size="4" pos="30" show="100.20.9.1" value="64140901"/>
        //   <proto name="gre" showname="Generic Routing Encapsulation (ERSPAN)" size="8" pos="34">
        //   <proto name="erspan" showname="Encapsulated Remote Switch Packet ANalysis Type II" size="112" pos="42">
        //   <proto name="eth" showname="Ethernet II, Src: ee:ee:ee:ee:ee:e1, Dst: ff:dd:ff:ff:ff:f1" size="14" pos="50">
        //   <proto name="ip" showname="Internet Protocol Version 4, Src: 172.16.27.131, Dst: 172.16.27.121" size="20" pos="64">
        //     <field name="ip.src" showname="Source Address: 172.16.27.131" size="4" pos="76" show="172.16.27.131" value="ac101b83"/>
        //     <field name="ip.src_host" showname="Source Host: 172.16.27.131" hide="yes" size="4" pos="76" show="172.16.27.131" value="ac101b83"/>
        //     <field name="ip.dst" showname="Destination Address: 172.16.27.121" size="4" pos="80" show="172.16.27.121" value="ac101b79"/>
        //     <field name="ip.dst_host" showname="Destination Host: 172.16.27.121" hide="yes" size="4" pos="80" show="172.16.27.121" value="ac101b79"/>
        //   <proto name="udp" showname="User Datagram Protocol, Src Port: 4789, Dst Port: 4790" size="8" pos="84">
        //     <field name="udp.srcport" showname="Source Port: 4789" size="2" pos="84" show="4789" value="12b5"/>
        //     <field name="udp.dstport" showname="Destination Port: 4790" size="2" pos="86" show="4790" value="12b6"/>
        //     <field name="udp.stream" showname="Stream index: 0" size="0" pos="92" show="0"/>
        //   <proto name="vxlan" showname="Virtual eXtensible Local Area Network" size="8" pos="92">
        //   <proto name="eth" showname="Ethernet II, Src: aa:bb:cc:dd:cc:c1, Dst: dd:dd:dd:dd:dd:d1" size="14" pos="100">
        //   <proto name="ip" showname="Internet Protocol Version 4, Src: 10.16.27.131, Dst: 10.16.27.12" size="20" pos="114">
        //     <field name="ip.src" showname="Source Address: 10.16.27.131" size="4" pos="126" show="10.16.27.131" value="0a101b83"/>
        //     <field name="ip.src_host" showname="Source Host: 10.16.27.131" hide="yes" size="4" pos="126" show="10.16.27.131" value="0a101b83"/>
        //     <field name="ip.dst" showname="Destination Address: 10.16.27.12" size="4" pos="130" show="10.16.27.12" value="0a101b0c"/>
        //     <field name="ip.dst_host" showname="Destination Host: 10.16.27.12" hide="yes" size="4" pos="130" show="10.16.27.12" value="0a101b0c"/>
        //   <proto name="tcp" showname="Transmission Control Protocol, Src Port: 80, Dst Port: 65174, Seq: 0, Ack: 1, Len: 0" size="20" pos="134">
        //     <field name="tcp.srcport" showname="Source Port: 80" size="2" pos="134" show="80" value="0050"/>
        //     <field name="tcp.dstport" showname="Destination Port: 65174" size="2" pos="136" show="65174" value="fe96"/>
        //     <field name="tcp.stream" showname="Stream index: 0" size="0" pos="134" show="0"/>
        // ```
        //
        // Therefore we cannot use `Packet::find_proto` here --- it would return the first
        // protocol with given name. We need *the last* protocol.

        #[cfg_attr(debug_assertions, derive(Debug))]
        struct IpAttrs {
            ip_ver: IpVersion,
            src: String,
            dst: String,
        }

        #[cfg_attr(debug_assertions, derive(Debug))]
        struct TransportAttrs {
            transport: Transport,
            stream_id: StreamId,
            src_port: u32,
            dst_port: u32,
        }

        let mut last_ip = None::<IpAttrs>;
        let mut last_transport = None::<TransportAttrs>;

        for proto in pkt.iter() {
            match proto.name() {
                "icmp" | "icmpv6" => return Ok(None), // ignore ICMP packets
                "ip" => {
                    last_ip = Some(IpAttrs {
                        ip_ver: IpVersion::Ipv4,
                        src: proto.first("ip.src")?.to_owned(),
                        dst: proto.first("ip.dst")?.to_owned(),
                    })
                }
                "ipv6" => {
                    last_ip = Some(IpAttrs {
                        ip_ver: IpVersion::Ipv6,
                        src: proto.first("ipv6.src")?.to_owned(),
                        dst: proto.first("ipv6.dst")?.to_owned(),
                    })
                }
                "tcp" => {
                    last_transport = Some(TransportAttrs {
                        transport: Transport::Tcp,
                        stream_id: StreamId(proto.first("tcp.stream")?.parse()?),
                        src_port: proto.first("tcp.srcport")?.parse()?,
                        dst_port: proto.first("tcp.dstport")?.parse()?,
                    })
                }
                "udp" => {
                    last_transport = Some(TransportAttrs {
                        transport: Transport::Udp,
                        stream_id: StreamId(proto.first("udp.stream")?.parse()?),
                        src_port: proto.first("udp.srcport")?.parse()?,
                        dst_port: proto.first("udp.dstport")?.parse()?,
                    })
                }
                _ => continue,
            }
        }

        let (Some(ip), Some(transport)) = (last_ip, last_transport) else {
            return Ok(None);
        };

        let IpAttrs { ip_ver, src, dst } = ip;
        let TransportAttrs {
            transport,
            stream_id,
            src_port,
            dst_port,
        } = transport;

        Ok(Some(Self {
            transport,
            stream_id,
            sockets: SocketPair {
                ip_ver,
                src,
                dst,
                src_port,
                dst_port,
            },
        }))
    }
}

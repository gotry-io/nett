//! The DNS responder (design/names-and-diagnostics.md section 2, mesh.md section 11): on UDP port 53
//! of this machine's mesh addresses it answers `A` and `AAAA` for `<node name>.nett.internal`, from the
//! names in the desired state and the addresses in the verified admission material. Every other name is
//! refused: it never forwards and never recurses.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The suffix of every name the responder answers.
pub const SUFFIX: &str = "nett.internal";
pub const PORT: u16 = 53;
/// Queries and replies are at most this long.
const MAX_MESSAGE: usize = 512;
/// Time to live of every answer, in seconds.
const TTL: u32 = 60;
/// Queries per second the responder answers in total; above that they are dropped.
const MAX_RATE: u32 = 1000;
/// How long a read waits before the thread checks whether it should stop.
const POLL: Duration = Duration::from_millis(500);
/// Stack of the responder thread: it parses one small message at a time.
const STACK: usize = 64 * 1024;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;

/// The names the responder answers: the lower-case node name and its mesh addresses.
pub type NameTable = HashMap<String, (Ipv4Addr, Ipv6Addr)>;

/// The reply to one query, or `None` when the query gets no reply at all.
pub fn answer(query: &[u8], names: &NameTable) -> Option<Vec<u8>> {
    if query.len() < 12 || query.len() > MAX_MESSAGE {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let count = |i: usize| u16::from_be_bytes([query[i], query[i + 1]]);
    let is_query = flags & 0x8000 == 0;
    let opcode = (flags >> 11) & 0xf;
    // One question, nothing else but an optional EDNS record
    if !is_query || opcode != 0 || count(4) != 1 || count(6) != 0 || count(8) != 0 || count(10) > 1
    {
        return None;
    }
    let (labels, end) = read_name(query, 12)?;
    let qtype = u16::from_be_bytes([*query.get(end)?, *query.get(end + 1)?]);
    let qclass = u16::from_be_bytes([*query.get(end + 2)?, *query.get(end + 3)?]);
    let question = &query[12..end + 4];
    let suffix: Vec<&str> = SUFFIX.split('.').collect();
    let (rcode, records) = if qclass != CLASS_IN
        || labels.len() < suffix.len()
        || labels[labels.len() - suffix.len()..] != suffix[..]
    {
        (RCODE_REFUSED, Vec::new())
    } else {
        let host = &labels[..labels.len() - suffix.len()];
        match host {
            [name] => match names.get(name.as_str()) {
                Some((v4, v6)) => (0, records_for(qtype, *v4, *v6)),
                None => (RCODE_NXDOMAIN, Vec::new()),
            },
            // The suffix itself exists; nothing deeper does
            [] => (0, Vec::new()),
            _ => (RCODE_NXDOMAIN, Vec::new()),
        }
    };
    let rd = flags & 0x0100;
    let mut out = Vec::with_capacity(MAX_MESSAGE);
    out.extend_from_slice(&query[..2]);
    // A response, authoritative, recursion desired copied, recursion not available
    out.extend_from_slice(&(0x8400 | rd | u16::from(rcode)).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&u16::try_from(records.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(question);
    for rdata in &records {
        // The name points back at the question
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&TTL.to_be_bytes());
        out.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(rdata);
    }
    (out.len() <= MAX_MESSAGE).then_some(out)
}

fn records_for(qtype: u16, v4: Ipv4Addr, v6: Ipv6Addr) -> Vec<Vec<u8>> {
    match qtype {
        TYPE_A => vec![v4.octets().to_vec()],
        TYPE_AAAA => vec![v6.octets().to_vec()],
        _ => Vec::new(),
    }
}

/// The labels of an uncompressed name starting at `at`, lower case, and the offset after it.
fn read_name(msg: &[u8], mut at: usize) -> Option<(Vec<String>, usize)> {
    let mut labels = Vec::new();
    let mut total = 0usize;
    loop {
        let len = usize::from(*msg.get(at)?);
        at += 1;
        if len == 0 {
            return Some((labels, at));
        }
        // A compression pointer or a reserved label type has no place in a question
        if len > 63 {
            return None;
        }
        total += len + 1;
        if total > 255 {
            return None;
        }
        let label = msg.get(at..at + len)?;
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        at += len;
    }
}

/// The responder thread. Dropping it stops the thread.
pub struct DnsServer {
    names: Arc<Mutex<Arc<NameTable>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl DnsServer {
    /// Binds UDP port `port` on each of `addrs` (this machine's mesh addresses) and starts answering.
    pub fn spawn(addrs: &[IpAddr], port: u16) -> std::io::Result<Self> {
        let sockets = addrs
            .iter()
            .map(|a| {
                let socket = UdpSocket::bind(SocketAddr::new(*a, port))?;
                socket.set_read_timeout(Some(POLL))?;
                Ok(socket)
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        let names: Arc<Mutex<Arc<NameTable>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        for socket in sockets {
            let (names, stop) = (Arc::clone(&names), Arc::clone(&stop));
            threads.push(
                std::thread::Builder::new()
                    .name("nett-dns".into())
                    .stack_size(STACK)
                    .spawn(move || serve(&socket, &names, &stop))?,
            );
        }
        // One handle owns all the threads: joined together on drop
        let thread = std::thread::Builder::new()
            .name("nett-dns-join".into())
            .stack_size(STACK)
            .spawn(move || {
                for t in threads {
                    let _ = t.join();
                }
            })?;
        Ok(Self {
            names,
            stop,
            thread: Some(thread),
        })
    }

    /// Replaces the names it answers.
    pub fn set_names(&self, table: NameTable) {
        if let Ok(mut names) = self.names.lock() {
            *names = Arc::new(table);
        }
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(socket: &UdpSocket, names: &Mutex<Arc<NameTable>>, stop: &AtomicBool) {
    let mut buf = [0u8; MAX_MESSAGE + 1];
    let (mut window, mut answered) = (Instant::now(), 0u32);
    while !stop.load(Ordering::Relaxed) {
        let Ok((len, from)) = socket.recv_from(&mut buf) else {
            continue;
        };
        if window.elapsed() >= Duration::from_secs(1) {
            (window, answered) = (Instant::now(), 0);
        }
        if answered >= MAX_RATE {
            continue;
        }
        let table = names.lock().map(|n| Arc::clone(&n)).unwrap_or_default();
        if let Some(reply) = answer(&buf[..len], &table) {
            answered += 1;
            let _ = socket.send_to(&reply, from);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(u8::try_from(label.len()).expect("short"));
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    fn table() -> NameTable {
        [(
            "nas".to_owned(),
            (
                "100.88.0.6".parse().expect("v4"),
                "fd00:88::6".parse().expect("v6"),
            ),
        )]
        .into()
    }

    fn rcode(reply: &[u8]) -> u8 {
        reply[3] & 0x0f
    }

    fn answers(reply: &[u8]) -> u16 {
        u16::from_be_bytes([reply[6], reply[7]])
    }

    #[test]
    fn members_resolve_under_the_suffix() {
        let reply = answer(&query("NAS.nett.internal", TYPE_A), &table()).expect("reply");
        assert_eq!(&reply[..2], &[0x12, 0x34], "the query's id");
        assert_eq!(reply[2] & 0x84, 0x84, "a response, authoritative");
        assert_eq!((rcode(&reply), answers(&reply)), (0, 1));
        assert_eq!(&reply[reply.len() - 4..], &[100, 88, 0, 6]);
        let v6 = answer(&query("nas.nett.internal", TYPE_AAAA), &table()).expect("reply");
        assert_eq!(answers(&v6), 1);
        assert_eq!(
            &v6[v6.len() - 16..],
            &"fd00:88::6".parse::<Ipv6Addr>().expect("v6").octets()
        );
        let other = answer(&query("nas.nett.internal", 16), &table()).expect("reply");
        assert_eq!((rcode(&other), answers(&other)), (0, 0), "TXT: no records");
    }

    #[test]
    fn only_the_suffix_is_answered() {
        let unknown = answer(&query("mac.nett.internal", TYPE_A), &table()).expect("reply");
        assert_eq!(rcode(&unknown), RCODE_NXDOMAIN);
        let deeper = answer(&query("a.nas.nett.internal", TYPE_A), &table()).expect("reply");
        assert_eq!(rcode(&deeper), RCODE_NXDOMAIN);
        let elsewhere = answer(&query("example.com", TYPE_A), &table()).expect("reply");
        assert_eq!((rcode(&elsewhere), answers(&elsewhere)), (RCODE_REFUSED, 0));
        let suffix = answer(&query("nett.internal", TYPE_A), &table()).expect("reply");
        assert_eq!((rcode(&suffix), answers(&suffix)), (0, 0));
    }

    #[test]
    fn malformed_queries_get_no_reply() {
        assert!(answer(&[0; 11], &table()).is_none(), "too short");
        assert!(answer(&[0; 600], &table()).is_none(), "too long");
        let mut response = query("nas.nett.internal", TYPE_A);
        response[2] |= 0x80;
        assert!(answer(&response, &table()).is_none(), "a response");
        let mut two = query("nas.nett.internal", TYPE_A);
        two[5] = 2;
        assert!(answer(&two, &table()).is_none(), "two questions");
        let mut pointer = query("nas.nett.internal", TYPE_A);
        pointer[12] = 0xc0;
        assert!(
            answer(&pointer, &table()).is_none(),
            "a compression pointer"
        );
        let truncated = &query("nas.nett.internal", TYPE_A)[..20];
        assert!(answer(truncated, &table()).is_none(), "cut short");
    }

    #[test]
    fn the_responder_answers_on_its_socket() {
        let probe = UdpSocket::bind("127.0.0.1:0").expect("free port");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        let server = DnsServer::spawn(&["127.0.0.1".parse().expect("ip")], port).expect("bound");
        server.set_names(table());
        let client = UdpSocket::bind("127.0.0.1:0").expect("client");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        client
            .send_to(&query("nas.nett.internal", TYPE_A), ("127.0.0.1", port))
            .expect("sent");
        let mut buf = [0u8; 512];
        let (len, _) = client.recv_from(&mut buf).expect("answered");
        assert_eq!(&buf[len - 4..len], &[100, 88, 0, 6]);
        drop(server);
    }
}

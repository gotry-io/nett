//! Server-sent events as the Hub sends them on the live view's stream (design/top.md section 6):
//! `event:` and `data:` lines, a blank line after each event, comment lines starting with `:`.

/// The longest event kept: a machine's status, the largest, is far smaller.
pub const MAX_EVENT: usize = 1 << 20;

#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    pub event: String,
    pub data: String,
}

#[derive(Default)]
pub struct Parser {
    buf: Vec<u8>,
}

impl Parser {
    /// Adds what arrived and returns the events it completes; fails when one grows past
    /// [`MAX_EVENT`] (hard rule 14).
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Message>, String> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(end) = self.buf.windows(2).position(|w| w == b"\n\n") {
            let block: Vec<u8> = self.buf.drain(..end + 2).collect();
            let text = String::from_utf8_lossy(&block[..end]);
            let mut event = "message".to_owned();
            let mut data = Vec::new();
            for line in text.split('\n') {
                if line.is_empty() || line.starts_with(':') {
                    continue;
                }
                let (field, value) = line.split_once(':').unwrap_or((line, ""));
                let value = value.strip_prefix(' ').unwrap_or(value);
                match field {
                    "event" => value.clone_into(&mut event),
                    "data" => data.push(value),
                    _ => {}
                }
            }
            if !data.is_empty() {
                out.push(Message {
                    event,
                    data: data.join("\n"),
                });
            }
        }
        if self.buf.len() > MAX_EVENT {
            return Err(format!(
                "the Hub sent an event longer than {MAX_EVENT} bytes"
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Events split anywhere across reads come out whole; comments and keep-alives are skipped;
    /// an event that grows past the limit fails.
    #[test]
    fn events_come_out_whole_across_reads() {
        let mut p = Parser::default();
        let stream = ":\n\nevent: sample\ndata: {\"a\":1}\n\nevent: resync\ndata: {}\n\n";
        let mut got = Vec::new();
        for chunk in stream.as_bytes().chunks(5) {
            got.extend(p.push(chunk).expect("parse"));
        }
        assert_eq!(
            got,
            [
                Message {
                    event: "sample".into(),
                    data: "{\"a\":1}".into()
                },
                Message {
                    event: "resync".into(),
                    data: "{}".into()
                },
            ]
        );
        assert!(p.push(&vec![b'x'; MAX_EVENT + 1]).is_err());
    }
}

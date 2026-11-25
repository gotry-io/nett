//! The live view's stream (design/top.md section 6): while a stream is open, every connected
//! machine is asked for samples (design/hub.md section 5), and its samples and status reports are
//! passed to the open streams. The Hub keeps none of them.

use std::sync::Arc;
use std::time::Duration;

use nett_core::id::NodeId;
use nett_proto::api::{LivePeer, LiveSample, LiveStatus};
use nett_proto::v1::{LinkSample, SampleRequest};
use tokio::sync::{broadcast, watch};

/// Streams open at a time (protocol.md section 11).
pub const MAX_STREAMS: usize = 4;
/// Messages queued for each stream; a stream that falls further behind loses the oldest and is
/// told to read the status again.
pub const STREAM_QUEUE: usize = 64;
/// What the Hub asks of each machine while a stream is open, and how often it asks again: a
/// machine samples until 10 seconds after the last request, so a view that ends stops them
/// within that.
pub const SAMPLE_EVERY: Duration = Duration::from_secs(2);
pub const SAMPLE_FOR: Duration = Duration::from_secs(10);
pub const RENEW_EVERY: Duration = Duration::from_secs(5);
/// A comment line on an idle stream, so that proxies and the view see it alive.
pub const KEEP_ALIVE: Duration = Duration::from_secs(15);

/// One message for the streams: the event's name and its JSON.
#[derive(Debug, PartialEq, Eq)]
pub struct Item {
    pub event: &'static str,
    pub data: String,
}

pub struct LiveViews {
    items: broadcast::Sender<Arc<Item>>,
    /// How many streams are open; every node session watches it.
    open: watch::Sender<usize>,
    /// Set when the Hub begins to stop: streams end then, as the HTTP server waits for them.
    ended: watch::Sender<bool>,
}

impl Default for LiveViews {
    fn default() -> Self {
        Self {
            items: broadcast::channel(STREAM_QUEUE).0,
            open: watch::channel(0).0,
            ended: watch::channel(false).0,
        }
    }
}

impl LiveViews {
    /// Opens a stream, or `None` when [`MAX_STREAMS`] are open already.
    pub fn open(&self) -> Option<View> {
        let mut opened = false;
        self.open.send_if_modified(|n| {
            opened = *n < MAX_STREAMS;
            if opened {
                *n += 1;
            }
            opened
        });
        opened.then(|| View {
            items: self.items.subscribe(),
            open: self.open.clone(),
            ended: self.ended.subscribe(),
        })
    }

    /// The number of open streams, for a node session to follow.
    pub fn watch(&self) -> watch::Receiver<usize> {
        self.open.subscribe()
    }

    /// Whether any stream is open: only then is anything passed on.
    pub fn watched(&self) -> bool {
        *self.open.borrow() > 0
    }

    /// Ends every stream: the Hub is stopping.
    pub fn end(&self) {
        self.ended.send_replace(true);
    }

    /// What a node session sends its machine while streams are open.
    pub fn request() -> SampleRequest {
        let ms = |d: Duration| u32::try_from(d.as_millis()).unwrap_or(u32::MAX);
        SampleRequest {
            every_ms: ms(SAMPLE_EVERY),
            for_ms: ms(SAMPLE_FOR),
        }
    }

    /// Passes a machine's status report to the open streams.
    pub fn status(&self, name: &str, node: &NodeId, status_at: i64, status: &serde_json::Value) {
        if !self.watched() {
            return;
        }
        let item = LiveStatus {
            name: name.to_owned(),
            node_id: node.to_string(),
            status_at,
            status: status.clone(),
        };
        self.publish("status", &item);
    }

    /// Passes a machine's sample to the open streams, checked as data from the node (hard rule
    /// 13): a peer whose ID does not parse is left out, and a measurement that cannot be one is
    /// shown as missing.
    pub fn sample(&self, name: &str, node: &NodeId, sample: LinkSample) {
        if !self.watched() {
            return;
        }
        let measured =
            |v: Option<f64>, max: f64| v.filter(|v| v.is_finite() && (0.0..=max).contains(v));
        let item = LiveSample {
            name: name.to_owned(),
            node_id: node.to_string(),
            at_ms: sample.at_ms,
            peers: sample
                .peers
                .into_iter()
                .take(nett_mesh::config::MAX_MEMBERS)
                .filter(|p| p.node_id.parse::<NodeId>().is_ok())
                .map(|p| LivePeer {
                    id: p.node_id,
                    rx_bytes: p.rx_bytes,
                    tx_bytes: p.tx_bytes,
                    rtt_ms: measured(p.rtt_ms, f64::MAX),
                    loss: measured(p.loss, 1.0),
                    jitter_ms: measured(p.jitter_ms, f64::MAX),
                })
                .collect(),
        };
        self.publish("sample", &item);
    }

    fn publish(&self, event: &'static str, item: &impl serde::Serialize) {
        if let Ok(data) = serde_json::to_string(item) {
            // No stream listening is not an error: the last one may have just closed
            let _ = self.items.send(Arc::new(Item { event, data }));
        }
    }
}

/// An open stream; dropping it, as when the view's connection closes, counts it closed.
pub struct View {
    items: broadcast::Receiver<Arc<Item>>,
    open: watch::Sender<usize>,
    ended: watch::Receiver<bool>,
}

/// What a stream sends next.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    Item(Arc<Item>),
    /// Messages were dropped: the view reads the status again.
    Resync,
}

impl View {
    /// The next message, or `None` once the Hub is stopping, whatever is still queued.
    pub async fn next(&mut self) -> Option<Next> {
        tokio::select! {
            biased;
            _ = self.ended.wait_for(|ended| *ended) => None,
            item = self.items.recv() => match item {
                Ok(item) => Some(Next::Item(item)),
                Err(broadcast::error::RecvError::Lagged(_)) => Some(Next::Resync),
                Err(broadcast::error::RecvError::Closed) => None,
            },
        }
    }
}

impl Drop for View {
    fn drop(&mut self) {
        self.open.send_modify(|n| *n = n.saturating_sub(1));
    }
}

#[cfg(test)]
mod tests {
    use nett_proto::v1::PeerSample;

    use super::*;

    fn node(c: char) -> NodeId {
        format!("node_01JD7M3XQ4W8N2K5R9T6V3B7C{c}")
            .parse()
            .expect("id")
    }

    /// Streams are counted while open and dropped ones stop counting; a fifth is refused
    /// (design/top.md section 6).
    #[test]
    fn streams_are_counted_and_capped() {
        let live = LiveViews::default();
        let watch = live.watch();
        let views: Vec<View> = (0..MAX_STREAMS)
            .map(|_| live.open().expect("open"))
            .collect();
        assert_eq!(*watch.borrow(), MAX_STREAMS);
        assert!(live.open().is_none());
        drop(views);
        assert_eq!(*watch.borrow(), 0);
        assert!(live.open().is_some());
    }

    /// Nothing is published while no stream is open; with one open, samples arrive with their
    /// measurements checked, and a stream that falls behind is told to read the status again.
    #[tokio::test]
    async fn samples_reach_open_streams_checked() {
        let live = LiveViews::default();
        live.sample("a", &node('1'), LinkSample::default());
        let mut view = live.open().expect("open");
        let peer = |id: &str, rtt: f64, loss: f64| PeerSample {
            node_id: id.to_owned(),
            rx_bytes: 10,
            tx_bytes: 20,
            rtt_ms: Some(rtt),
            loss: Some(loss),
            jitter_ms: None,
        };
        live.sample(
            "a",
            &node('1'),
            LinkSample {
                at_ms: 2000,
                peers: vec![
                    peer("node_01JD7M3XQ4W8N2K5R9T6V3B7C2", 9.4, 0.0),
                    peer("node_01JD7M3XQ4W8N2K5R9T6V3B7C3", f64::NAN, 2.0),
                    peer("not a node", 1.0, 0.0),
                ],
            },
        );
        let Some(Next::Item(item)) = view.next().await else {
            panic!("a sample")
        };
        assert_eq!(item.event, "sample");
        let sample: LiveSample = serde_json::from_str(&item.data).expect("json");
        assert_eq!(
            (sample.name.as_str(), sample.at_ms, sample.peers.len()),
            ("a", 2000, 2)
        );
        assert_eq!(sample.peers[0].rtt_ms, Some(9.4));
        assert_eq!((sample.peers[1].rtt_ms, sample.peers[1].loss), (None, None));

        for i in 0..=STREAM_QUEUE {
            live.status(
                "a",
                &node('1'),
                i64::try_from(i).expect("small"),
                &serde_json::json!({}),
            );
        }
        assert_eq!(view.next().await, Some(Next::Resync));
        live.end();
        assert!(
            view.next().await.is_none(),
            "messages still queued are not sent"
        );
    }
}

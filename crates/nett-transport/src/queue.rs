//! The send queue of each end of a TLS relay connection (design/mesh.md section 5.3): it keeps the
//! newest packets and drops the oldest when another arrives. A packet that waited behind a slow
//! connection is worth less to the WireGuard and TCP it carries than a fresh one, which they would
//! otherwise send again; Tailscale's DERP keeps 32 per client and drops the head the same way
//! (v1.104.7 `derp/derpserver/derpserver.go`).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;

/// Packets waiting to be sent on one end of a TLS relay connection.
pub const SEND_QUEUE: usize = 32;

struct Shared<T> {
    state: Mutex<State<T>>,
    ready: Notify,
}

struct State<T> {
    /// The message that opens the connection: sent before anything waiting, and never dropped.
    first: Option<T>,
    waiting: VecDeque<T>,
    closed: bool,
}

impl<T> Shared<T> {
    fn lock(&self) -> MutexGuard<'_, State<T>> {
        // The lock is held only to move an item in or out, which cannot leave the state half done
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The side that queues packets: it never waits.
pub struct Sender<T>(Arc<Shared<T>>);

/// The side the connection's task takes packets from, oldest first.
pub struct Receiver<T>(Arc<Shared<T>>);

pub fn queue<T>() -> (Sender<T>, Receiver<T>) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            first: None,
            waiting: VecDeque::with_capacity(SEND_QUEUE),
            closed: false,
        }),
        ready: Notify::new(),
    });
    (Sender(Arc::clone(&shared)), Receiver(shared))
}

impl<T> Sender<T> {
    /// Queues `item`; when [`SEND_QUEUE`] items already wait, the oldest is dropped, and this
    /// returns true.
    pub fn push(&self, item: T) -> bool {
        let mut state = self.0.lock();
        let dropped = state.waiting.len() >= SEND_QUEUE;
        if dropped {
            state.waiting.pop_front();
        }
        state.waiting.push_back(item);
        drop(state);
        self.0.ready.notify_one();
        dropped
    }

    /// Queues the message that must open the connection, such as the probe a relay authenticates
    /// it by: it goes out before everything waiting, and no later packet pushes it out.
    pub fn first(&self, item: T) {
        self.0.lock().first = Some(item);
        self.0.ready.notify_one();
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        self.0.lock().closed = true;
        self.0.ready.notify_one();
    }
}

impl<T> Receiver<T> {
    /// The oldest waiting item; `None` once the sender is gone and nothing waits. Dropping the
    /// future loses no item.
    pub async fn recv(&mut self) -> Option<T> {
        loop {
            {
                let mut state = self.0.lock();
                if let Some(item) = state.first.take().or_else(|| state.waiting.pop_front()) {
                    return Some(item);
                }
                if state.closed {
                    return None;
                }
            }
            // A push between the check above and this wait leaves a permit, so it is not missed
            self.0.ready.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connection that falls behind sends the newest packets: once the queue is full, each new
    /// packet pushes out the oldest.
    #[tokio::test]
    async fn a_full_send_queue_drops_its_oldest_packet() {
        let (tx, mut rx) = queue();
        let extra = 8;
        let dropped: Vec<bool> = (0..SEND_QUEUE + extra).map(|i| tx.push(i)).collect();
        assert!(dropped[..SEND_QUEUE].iter().all(|d| !d));
        assert!(dropped[SEND_QUEUE..].iter().all(|d| *d));
        drop(tx);
        let mut sent = Vec::new();
        while let Some(i) = rx.recv().await {
            sent.push(i);
        }
        assert_eq!(sent, (extra..SEND_QUEUE + extra).collect::<Vec<_>>());
    }

    /// The message that opens a connection goes out first and stays, however many packets follow it
    /// before the connection's task gets to it.
    #[tokio::test]
    async fn the_opening_message_goes_first_and_is_never_dropped() {
        let (tx, mut rx) = queue();
        tx.push(100);
        tx.first(0);
        for i in 1..=2 * SEND_QUEUE {
            tx.push(i);
        }
        drop(tx);
        assert_eq!(rx.recv().await, Some(0));
        let mut rest = Vec::new();
        while let Some(i) = rx.recv().await {
            rest.push(i);
        }
        assert_eq!(rest, (SEND_QUEUE + 1..=2 * SEND_QUEUE).collect::<Vec<_>>());
    }

    /// The task waiting for a packet wakes when one is queued, and ends once the sender is gone.
    #[tokio::test]
    async fn the_receiver_wakes_for_a_packet_and_ends_with_the_sender() {
        let (tx, mut rx) = queue();
        let waiting = tokio::spawn(async move {
            let first = rx.recv().await;
            let after = rx.recv().await;
            (first, after)
        });
        tokio::task::yield_now().await;
        tx.push(7);
        drop(tx);
        let (first, after) = tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
            .await
            .expect("woke in time")
            .expect("task");
        assert_eq!((first, after), (Some(7), None));
    }
}

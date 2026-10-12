//! Server-Sent Events broker — the live-data backbone of the dashboard.
//!
//! Topics are simple strings (`fleet` for the global stream, `job:<id>`
//! for per-job streams). Publishers are the control-plane implementation
//! (the CLI adapter, in-process); subscribers are HTTP connection threads
//! parked on their `mpsc::Receiver` and writing SSE frames as they arrive.
//! Backpressure is bounded: a slow dashboard consumer that lets more than
//! [`CHANNEL_BOUND`] frames queue gets its frames dropped (the connection
//! is closed by the server on send failure) rather than stalling the wipe
//! engine.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CHANNEL_BOUND: usize = 256;
/// Keepalive interval for SSE connections (comment frames keep proxies
/// from idling out the stream).
pub const KEEPALIVE: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct EventFrame {
    pub event: String,
    pub data: String,
}

impl EventFrame {
    pub fn new(event: &str, data: String) -> Self {
        EventFrame {
            event: event.to_string(),
            data,
        }
    }

    /// SSE wire format (multi-line data is allowed — each line gets its
    /// own `data:` prefix per the SSE spec).
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(self.data.len() + self.event.len() + 32);
        if !self.event.is_empty() {
            out.push_str(&format!("event: {}\n", self.event));
        }
        for line in self.data.split('\n') {
            out.push_str(&format!("data: {line}\n"));
        }
        out.push('\n');
        out
    }
}

type Subscribers = Vec<SyncSender<EventFrame>>;

pub struct Broker {
    topics: Arc<Mutex<HashMap<String, Subscribers>>>,
}

impl Default for Broker {
    fn default() -> Self {
        Self::new()
    }
}

impl Broker {
    pub fn new() -> Self {
        Broker {
            topics: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Subscribe to a topic; frames arrive on the returned receiver.
    pub fn subscribe(&self, topic: &str) -> Receiver<EventFrame> {
        let (tx, rx) = sync_channel(CHANNEL_BOUND);
        self.topics
            .lock()
            .expect("broker lock poisoned")
            .entry(topic.to_string())
            .or_default()
            .push(tx);
        rx
    }

    /// Publish a frame to every subscriber of a topic. Failing subscribers
    /// (full queue = stalled dashboard tab) are pruned.
    pub fn publish(&self, topic: &str, frame: EventFrame) {
        let mut topics = self.topics.lock().expect("broker lock poisoned");
        if let Some(subs) = topics.get_mut(topic) {
            subs.retain(|tx| match tx.try_send(frame.clone()) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => false, // stalled consumer: drop it
                Err(TrySendError::Disconnected(_)) => false,
            });
        }
    }

    /// Publish a JSON-valued event.
    pub fn publish_json(&self, topic: &str, event: &str, data: &serde_json::Value) {
        let rendered = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
        self.publish(topic, EventFrame::new(event, rendered));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn frame_rendering() {
        let f = EventFrame::new("job.progress", "{\"pct\":42}".to_string());
        assert_eq!(f.render(), "event: job.progress\ndata: {\"pct\":42}\n\n");
        let multiline = EventFrame::new("log", "line1\nline2".to_string());
        assert_eq!(
            multiline.render(),
            "event: log\ndata: line1\ndata: line2\n\n"
        );
    }

    #[test]
    fn subscribe_publish_roundtrip() {
        let broker = Broker::new();
        let rx = broker.subscribe("job:abc");
        let rx2 = broker.subscribe("job:abc");
        broker.publish_json("job:abc", "tick", &json!({"pct": 10}));
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).expect("rx1").event,
            "tick"
        );
        assert_eq!(
            rx2.recv_timeout(Duration::from_secs(1)).expect("rx2").event,
            "tick"
        );
        // An unrelated topic receives nothing.
        let rx_other = broker.subscribe("job:xyz");
        broker.publish_json("job:abc", "tick", &json!({"pct": 20}));
        assert!(rx_other.recv_timeout(Duration::from_millis(50)).is_err());
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .expect("rx again")
                .data,
            "{\"pct\":20}"
        );
    }
}

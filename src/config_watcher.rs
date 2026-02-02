//! Configuration file watcher for hot-reloading allowlist.

use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher, event::ModifyKind};
use tracing::{debug, error, info, warn};

/// Message sent when configuration file changes.
#[derive(Debug)]
pub enum ConfigEvent {
    /// Configuration file was modified.
    Modified,
    /// Watcher encountered an error.
    Error(String),
}

/// Watches a configuration file for changes.
pub struct ConfigWatcher {
    _watcher: RecommendedWatcher,
    receiver: Receiver<ConfigEvent>,
}

impl ConfigWatcher {
    /// Creates a new watcher for the given configuration file path.
    pub fn new(config_path: &Path) -> Result<Self, notify::Error> {
        let (tx, rx) = mpsc::channel();

        let event_tx = tx.clone();
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    // Filter for modification events only
                    if matches!(
                        event.kind,
                        notify::EventKind::Modify(ModifyKind::Data(_))
                            | notify::EventKind::Modify(ModifyKind::Any)
                    ) {
                        debug!("config file modified: {:?}", event.paths);
                        let _ = event_tx.send(ConfigEvent::Modified);
                    }
                }
                Err(e) => {
                    error!("file watcher error: {}", e);
                    let _ = event_tx.send(ConfigEvent::Error(e.to_string()));
                }
            }
        })?;

        // Watch the parent directory to handle editor save behaviors
        // (some editors delete and recreate files)
        let watch_path = config_path.parent().unwrap_or(Path::new("."));

        watcher.watch(watch_path, RecursiveMode::NonRecursive)?;
        info!("watching configuration directory: {}", watch_path.display());

        Ok(Self {
            _watcher: watcher,
            receiver: rx,
        })
    }

    /// Tries to receive a configuration event without blocking.
    /// Returns `None` if no event is available.
    pub fn try_recv(&self) -> Option<ConfigEvent> {
        self.receiver.try_recv().ok()
    }

    /// Receives a configuration event, blocking until one is available
    /// or the timeout expires.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<ConfigEvent> {
        self.receiver.recv_timeout(timeout).ok()
    }
}

/// Starts a background thread that watches for config changes and sends
/// reload notifications through a channel.
pub fn spawn_config_watcher(config_path: &Path) -> Result<Receiver<ConfigEvent>, notify::Error> {
    let (tx, rx) = mpsc::channel();
    let watcher = ConfigWatcher::new(config_path)?;

    thread::spawn(move || {
        // Debounce: wait a bit after receiving an event before forwarding
        // This handles editors that save files in multiple steps
        let debounce_duration = Duration::from_millis(500);
        let mut pending_reload = false;

        loop {
            match watcher.recv_timeout(Duration::from_millis(100)) {
                Some(ConfigEvent::Modified) => {
                    pending_reload = true;
                }
                Some(ConfigEvent::Error(e)) => {
                    warn!("config watcher error: {}", e);
                }
                None => {
                    if pending_reload {
                        // Wait for debounce period
                        thread::sleep(debounce_duration);

                        // Check if more events came in during debounce
                        while watcher.try_recv().is_some() {
                            // Drain any additional events
                        }

                        debug!("sending config reload notification");
                        if tx.send(ConfigEvent::Modified).is_err() {
                            // Receiver dropped, exit thread
                            break;
                        }
                        pending_reload = false;
                    }
                }
            }
        }
    });

    Ok(rx)
}

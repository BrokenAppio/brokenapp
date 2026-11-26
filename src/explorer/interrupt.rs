//! SIGINT/SIGTERM handling for long scans (opt-in, see
//! [`super::ScanRunOptions::handle_signals`]): the first signal stops the
//! crawl, which then checkpoints (in-flight views go back to the queue) and
//! writes its artifacts with status `interrupted`, so `brokenapp resume`
//! continues where it stopped. A second signal, or any signal once the crawl
//! is over and the scan is finalizing, exits at once.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use tokio::sync::watch;

/// Which signal interrupted the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptKind {
    /// SIGINT (Ctrl-C).
    Interrupt,
    /// SIGTERM.
    Terminate,
}

impl InterruptKind {
    /// Conventional exit code (128 + signal number).
    pub fn exit_code(self) -> i32 {
        match self {
            InterruptKind::Interrupt => 130,
            InterruptKind::Terminate => 143,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            InterruptKind::Interrupt => "SIGINT",
            InterruptKind::Terminate => "SIGTERM",
        }
    }
}

/// The first signal this process received (0 = none, 1 = SIGINT, 2 = SIGTERM).
static LAST_SIGNAL: AtomicU8 = AtomicU8::new(0);

/// The signal that interrupted a scan in this process, if any.
pub fn last_signal() -> Option<InterruptKind> {
    match LAST_SIGNAL.load(Ordering::SeqCst) {
        1 => Some(InterruptKind::Interrupt),
        2 => Some(InterruptKind::Terminate),
        _ => None,
    }
}

/// Listens for SIGINT/SIGTERM for the lifetime of the process.
pub struct InterruptWatch {
    rx: watch::Receiver<Option<InterruptKind>>,
    crawling: Arc<AtomicBool>,
}

impl InterruptWatch {
    /// Start listening. Must run inside a tokio runtime.
    pub fn install() -> std::io::Result<Self> {
        let (tx, rx) = watch::channel(None);
        let crawling = Arc::new(AtomicBool::new(true));
        #[cfg(unix)]
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let crawling_task = Arc::clone(&crawling);
        tokio::spawn(async move {
            let mut first = true;
            loop {
                #[cfg(unix)]
                let kind = tokio::select! {
                    r = tokio::signal::ctrl_c() => match r {
                        Ok(()) => InterruptKind::Interrupt,
                        Err(_) => return,
                    },
                    r = terminate.recv() => match r {
                        Some(()) => InterruptKind::Terminate,
                        None => return,
                    },
                };
                #[cfg(not(unix))]
                let kind = match tokio::signal::ctrl_c().await {
                    Ok(()) => InterruptKind::Interrupt,
                    Err(_) => return,
                };
                let code = match kind {
                    InterruptKind::Interrupt => 1,
                    InterruptKind::Terminate => 2,
                };
                let _ = LAST_SIGNAL.compare_exchange(0, code, Ordering::SeqCst, Ordering::SeqCst);
                if first && crawling_task.load(Ordering::SeqCst) {
                    first = false;
                    eprintln!(
                        "{}: stopping the crawl and saving a checkpoint (send it again to exit now)",
                        kind.name()
                    );
                    let _ = tx.send(Some(kind));
                } else {
                    eprintln!("{}: exiting", kind.name());
                    std::process::exit(kind.exit_code());
                }
            }
        });
        Ok(Self { rx, crawling })
    }

    /// Resolves with the first signal.
    pub async fn triggered(&mut self) -> InterruptKind {
        loop {
            if let Some(kind) = *self.rx.borrow_and_update() {
                return kind;
            }
            if self.rx.changed().await.is_err() {
                // The listener is gone: no signal will ever arrive.
                std::future::pending::<()>().await;
            }
        }
    }

    /// The signal that arrived, if any.
    pub fn received(&self) -> Option<InterruptKind> {
        *self.rx.borrow()
    }

    /// The crawl is over: any further signal exits immediately.
    pub fn finishing(&self) {
        self.crawling.store(false, Ordering::SeqCst);
    }
}

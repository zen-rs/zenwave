//! hyper's runtime traits over `async-io` and the backend's spawner.

use std::{fmt, future::Future, sync::Arc, thread};

use async_io::block_on;
use executor_core::{AnyExecutor, Executor as _};
use hyper::rt::Executor;

#[cfg(http3)]
use crate::transport::Spawn;
#[cfg(feature = "http2")]
use {
    hyper::rt::Sleep,
    std::{
        pin::Pin,
        task::{Context, Poll},
        time::{Duration, Instant},
    },
};

/// Runs connection futures on the backend's executor, or a dedicated thread
/// each when no executor was configured.
///
/// Also serves as `hyper::rt::Executor`: hyper hands it h2 connection futures
/// and upgraded stream tasks.
#[derive(Clone)]
pub struct Spawner {
    executor: Option<Arc<AnyExecutor>>,
}

impl Spawner {
    /// Spawns on `executor`, or on one thread per future when `None`.
    pub fn new(executor: Option<AnyExecutor>) -> Self {
        Self {
            executor: executor.map(Arc::new),
        }
    }

    /// The spawner as the shared [`Spawn`] the transport hands to the QUIC
    /// endpoint and DNS resolver so they run wherever this backend's
    /// connection drivers run.
    #[cfg(http3)]
    pub fn as_spawn(&self) -> Spawn {
        let this = self.clone();
        Arc::new(move |future| this.spawn(future))
    }

    /// Run `future` to completion in the background.
    pub fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        if let Some(executor) = &self.executor {
            executor.spawn(future).detach();
        } else {
            thread::spawn(move || {
                block_on(future);
            });
        }
    }
}

impl fmt::Debug for Spawner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Spawner")
            .field("executor", &self.executor.as_ref().map(|_| ".."))
            .finish()
    }
}

impl<Fut> Executor<Fut> for Spawner
where
    Fut: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, fut: Fut) {
        self.spawn(fut);
    }
}

/// `hyper::rt::Timer` over `async_io::Timer`, for h2 keepalive pings.
#[cfg(feature = "http2")]
#[derive(Clone, Copy, Debug)]
pub struct Timer;

#[cfg(feature = "http2")]
impl hyper::rt::Timer for Timer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        Box::pin(TimerSleep(async_io::Timer::after(duration)))
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(TimerSleep(async_io::Timer::at(deadline)))
    }

    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, deadline: Instant) {
        if let Some(sleep) = sleep.as_mut().downcast_mut_pin::<TimerSleep>() {
            sleep.get_mut().0.set_at(deadline);
        } else {
            *sleep = self.sleep_until(deadline);
        }
    }
}

/// A `Sleep` future driven by an `async_io::Timer`.
#[cfg(feature = "http2")]
#[derive(Debug)]
struct TimerSleep(async_io::Timer);

#[cfg(feature = "http2")]
impl Future for TimerSleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|_| ())
    }
}

#[cfg(feature = "http2")]
impl Sleep for TimerSleep {}

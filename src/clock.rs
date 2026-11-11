//! The clock a client's request-level timers run on.
//!
//! [`Timeout`](crate::Timeout) and [`Retry`](crate::retry::Retry) sleep while
//! a request is awaited, on whatever executor polls it, a work-stealing one
//! included, so their sleeps must be `Send` and cannot be the thread-bound
//! `http_kit_io::Timer` futures that serve connection deadlines. A [`Clock`]
//! names a `Send` sleep future; each backend supplies the one that works on
//! its own runtime through [`Clocked`].

use std::{future::Future, time::Duration};

use http_kit::endpoint::WithMiddleware;

use crate::Client;
#[cfg(native_backend)]
pub use crate::backend::native::{PoolClock, PoolSleep};
#[cfg(browser)]
use crate::single_threaded::SingleThreaded;

/// A source of sleeps for request-level timers: they run on whatever executor
/// polls the request, any thread included.
pub trait Clock: Clone + Send + Sync + 'static {
    /// The future [`sleep`](Self::sleep) returns; it completes once the
    /// duration has passed, and its output is ignored.
    type Sleep: Future + Send + 'static;

    /// A future that completes when `duration` has passed.
    fn sleep(&self, duration: Duration) -> Self::Sleep;
}

/// A client that supplies the [`Clock`] its request-level timers run on:
/// every backend, and every wrapper around a clocked client.
///
/// [`Client::timeout`] and [`Client::retry`] need it. A client whose clock is
/// not the backend's builds the middleware from its own clock instead, with
/// [`Timeout::new`](crate::Timeout::new) and
/// [`Retry::new`](crate::retry::Retry::new).
pub trait Clocked: Client {
    /// The clock.
    type Clock: Clock;

    /// The clock this client's timers run on.
    fn clock(&self) -> Self::Clock;
}

impl<E: Clocked, M> Clocked for WithMiddleware<E, M>
where
    Self: Client,
{
    type Clock = E::Clock;

    fn clock(&self) -> E::Clock {
        self.endpoint().clock()
    }
}

impl<C: Clocked> Clocked for &mut C {
    type Clock = C::Clock;

    fn clock(&self) -> C::Clock {
        (**self).clock()
    }
}

/// async-io's timers: every backend whose sockets are driven by async-io, and
/// the clock of a build with no other.
#[cfg(reactor)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AsyncIoClock;

#[cfg(reactor)]
impl Clock for AsyncIoClock {
    type Sleep = async_io::Timer;

    fn sleep(&self, duration: Duration) -> async_io::Timer {
        async_io::Timer::after(duration)
    }
}

/// The browser's (or a Worker's) `setTimeout`.
#[cfg(browser)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BrowserClock;

#[cfg(browser)]
impl Clock for BrowserClock {
    type Sleep = SingleThreaded<gloo_timers::future::TimeoutFuture>;

    fn sleep(&self, duration: Duration) -> Self::Sleep {
        // gloo takes milliseconds as a `u32`: a longer sleep saturates.
        let millis = duration.as_millis().try_into().unwrap_or(u32::MAX);
        SingleThreaded(gloo_timers::future::TimeoutFuture::new(millis))
    }
}

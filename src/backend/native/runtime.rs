//! The runtimes the native backend can drive a pool on by itself, for
//! callers on no runtime: one driver thread per runtime and transport.

use std::{future::Future, io, thread};

use super::{NativeIo, PoolHandle, pool};
use crate::Transport;

/// A runtime the native backend can start a driver thread on.
pub trait Driver: NativeIo + Default + Send + 'static {
    /// The pool this runtime drives for `transport`, started on first use.
    fn pool(transport: &Transport) -> &PoolHandle;

    /// Runs `future` to completion on the current thread, inside a new
    /// runtime.
    ///
    /// # Errors
    ///
    /// The runtime cannot be built.
    fn block_on(future: impl Future<Output = ()> + 'static) -> io::Result<()>;
}

/// The driver `NativeBackend::new` uses: compio when it is enabled.
#[cfg(feature = "native-compio")]
pub type DefaultDriver = Compio;
/// The driver `NativeBackend::new` uses: tokio, compio being off.
#[cfg(all(feature = "native-tokio", not(feature = "native-compio")))]
pub type DefaultDriver = Tokio;

/// Starts a pool for `transport` on a new thread running runtime `D`.
fn start<D: Driver>(transport: &Transport, name: &'static str) -> PoolHandle {
    let (handle, receiver) = PoolHandle::channel();
    let weak = transport.downgrade();
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            D::block_on(pool::run(D::default(), weak, receiver)).unwrap_or_else(|error| {
                panic!("zenwave: cannot start the {name} runtime: {error}")
            });
        })
        .unwrap_or_else(|error| panic!("zenwave: cannot spawn the native pool thread: {error}"));
    handle
}

/// compio: `io_uring` on Linux, IOCP on Windows, polling elsewhere.
#[cfg(feature = "native-compio")]
pub use http_kit_io::compio::Compio;

#[cfg(feature = "native-compio")]
impl Driver for Compio {
    fn pool(transport: &Transport) -> &PoolHandle {
        transport.native_compio(|| start::<Self>(transport, "zenwave-compio"))
    }

    fn block_on(future: impl Future<Output = ()> + 'static) -> io::Result<()> {
        compio::runtime::Runtime::new()?.block_on(future);
        Ok(())
    }
}

/// tokio's current-thread runtime, under a `LocalSet`.
#[cfg(feature = "native-tokio")]
pub use http_kit_io::tokio::Tokio;

#[cfg(feature = "native-tokio")]
impl Driver for Tokio {
    fn pool(transport: &Transport) -> &PoolHandle {
        transport.native_tokio(|| start::<Self>(transport, "zenwave-tokio"))
    }

    fn block_on(future: impl Future<Output = ()> + 'static) -> io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        tokio::task::LocalSet::new().block_on(&runtime, future);
        Ok(())
    }
}

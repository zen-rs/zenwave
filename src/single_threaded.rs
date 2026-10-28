//! `Send`/`Sync` wrapper for handles that are thread-bound only because the
//! wasm32 module is single-threaded.
//!
//! `http-kit` types its executor-facing bounds as `Send`, while every JS
//! handle (`JsValue`, `Closure`, `JsFuture`, ...) is `!Send`. `SingleThreaded`
//! states in the type that the contents stay on the only thread that can run:
//! a wasm32 module built without the `atomics` target feature has no shared
//! memory, so a second thread cannot exist. Under `+atomics` shared-memory
//! workers can run the same instance on real threads, where these impls would
//! be unsound — so they are compiled out there and the `Send` bounds they
//! satisfy fail to compile instead of silently lying.

use core::{
    future::Future,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
};

use http_kit::utils::Stream;

pub struct SingleThreaded<T>(pub T);

// SAFETY: without `atomics` there is no shared memory, hence no second
// thread the contents could be sent to.
#[cfg(not(target_feature = "atomics"))]
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl<T> Send for SingleThreaded<T> {}

// SAFETY: as above — a `&SingleThreaded<T>` cannot be shared with a thread
// that does not exist.
#[cfg(not(target_feature = "atomics"))]
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl<T> Sync for SingleThreaded<T> {}

impl<T: Future> Future for SingleThreaded<T> {
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: SingleThreaded<T> is a newtype wrapper, and we do not move T out.
        let this = unsafe { self.get_unchecked_mut() };
        unsafe { Pin::new_unchecked(&mut this.0).poll(cx) }
    }
}

impl<T: Stream> Stream for SingleThreaded<T> {
    type Item = T::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // SAFETY: SingleThreaded<T> is a newtype wrapper, and we do not move T out.
        let this = unsafe { self.get_unchecked_mut() };
        unsafe { Pin::new_unchecked(&mut this.0).poll_next(cx) }
    }
}

impl<T> Deref for SingleThreaded<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

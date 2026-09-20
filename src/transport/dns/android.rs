//! `android.net.DnsResolver.rawQuery` over JNI (API 29+).
//!
//! A Rust library ships no Java classes, so `DnsResolver.Callback` is
//! implemented through `java.lang.reflect.Proxy` with an `InvocationHandler`
//! backed by a Rust closure — jni-min-helper's [`DynamicProxy`], an embedded
//! dex loaded through `InMemoryDexClassLoader`. `rawQuery` is asynchronous on
//! the Java side: the callback delivers the raw DNS message on an executor
//! thread, and a `oneshot` hands it to the async caller without blocking.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_io::Timer;
use futures_channel::oneshot;
use futures_util::{
    FutureExt,
    future::{Either, select},
};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::Record,
};
use jni::{
    Env, JavaVM, jni_sig, jni_str,
    objects::{JByteArray, JObject, JString, JValue},
    refs::{Global, LoaderContext},
};
use jni_min_helper::{DynamicProxy, JMethod};

use crate::Error;

/// `android.net.DnsResolver.CLASS_IN`.
const CLASS_IN: i32 = 1;
/// The HTTPS RR type number (RFC 9460 §9); `DnsResolver` has no `TYPE_HTTPS`.
const TYPE_HTTPS: i32 = 65;
/// `DnsResolver` exists since API 29.
const DNS_RESOLVER_MIN_API: i32 = 29;
/// How long a `rawQuery` may take before the lookup fails — hickory's
/// `ResolverOpts::default().timeout`, so both paths bound a query alike.
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// What the callback delivers: the raw response message, or the
/// `DnsException`'s text from `onError`.
type RawAnswer = Result<Vec<u8>, String>;

/// Query `domain` for HTTPS records through `DnsResolver`; NODATA and
/// NXDOMAIN answers come back as an empty set.
pub(super) async fn query_https(domain: String) -> Result<Vec<Record>, Error> {
    // The application registers the JVM through ndk-context.
    let vm = unsafe { JavaVM::from_raw(ndk_context::android_context().vm().cast()) };
    let (sender, receiver) = oneshot::channel::<RawAnswer>();

    let pending = vm
        .attach_current_thread(|env| raw_query(env, &domain, sender))
        .map_err(|error| Error::Transport(Box::new(error)))?;
    // Below API 29 there is no HTTPS-record resolver: a definitive empty
    // answer, not a failure.
    let Some(pending) = pending else {
        return Ok(Vec::new());
    };

    // A timed-out lookup is an error, as on the hickory path.
    let answer = match select(receiver.fuse(), Timer::after(DNS_QUERY_TIMEOUT).fuse()).await {
        Either::Left((answer, _)) => {
            answer.unwrap_or_else(|_| Err("the DNS query never delivered an answer".to_owned()))
        }
        Either::Right(_) => Err("the DNS query timed out".to_owned()),
    };
    // The query is over either way; the executor thread and the proxy's
    // Rust handler are no longer needed.
    let released = vm.attach_current_thread(|env| pending.release(env));
    let bytes = match answer {
        Ok(bytes) => bytes,
        Err(message) => {
            let _ = released;
            return Err(Error::Transport(Box::new(std::io::Error::other(message))));
        }
    };
    released.map_err(|error| Error::Transport(Box::new(error)))?;

    let message = Message::from_vec(&bytes).map_err(|error| Error::Transport(Box::new(error)))?;
    match message.metadata.response_code {
        ResponseCode::NoError => Ok(message.answers),
        ResponseCode::NXDomain => Ok(Vec::new()),
        code => Err(Error::Transport(Box::new(std::io::Error::other(format!(
            "DNS response code {code:?}"
        ))))),
    }
}

/// The Java objects a `rawQuery` call must keep alive until the callback
/// has fired.
struct PendingQuery {
    /// Held only for its `Drop`: it unregisters the Rust handler.
    _proxy: DynamicProxy,
    executor: Global<JObject<'static>>,
}

impl PendingQuery {
    /// Shut the executor thread down. Dropping `self` right after unregisters
    /// the proxy's Rust handler and releases the Java proxy.
    fn release(self, env: &mut Env) -> Result<(), jni::errors::Error> {
        env.call_method(&self.executor, jni_str!("shutdown"), jni_sig!("()V"), &[])?;
        Ok(())
    }
}

/// Call `DnsResolver.getInstance().rawQuery(null, domain, CLASS_IN,
/// TYPE_HTTPS, 0, executor, null, callback)`. `None` when the platform predates
/// `DnsResolver`.
fn raw_query(
    env: &mut Env,
    domain: &str,
    sender: oneshot::Sender<RawAnswer>,
) -> Result<Option<PendingQuery>, jni::errors::Error> {
    let api_level = env
        .get_static_field(
            jni_str!("android/os/Build$VERSION"),
            jni_str!("SDK_INT"),
            jni_sig!("I"),
        )?
        .i()?;
    if api_level < DNS_RESOLVER_MIN_API {
        return Ok(None);
    }

    let sender = Arc::new(Mutex::new(Some(sender)));
    let proxy = DynamicProxy::build(
        env,
        &LoaderContext::None,
        &[jni_str!("android.net.DnsResolver$Callback")],
        move |env, method, args| {
            let answer = callback(env, method, args);
            if let Some(sender) = sender.lock().ok().and_then(|mut guard| guard.take()) {
                let _ = sender.send(answer);
            }
            Ok(JObject::null())
        },
    )?;

    let resolver = env
        .call_static_method(
            jni_str!("android/net/DnsResolver"),
            jni_str!("getInstance"),
            jni_sig!("()Landroid/net/DnsResolver;"),
            &[],
        )?
        .l()?;
    let executor = env
        .call_static_method(
            jni_str!("java/util/concurrent/Executors"),
            jni_str!("newSingleThreadExecutor"),
            jni_sig!("()Ljava/util/concurrent/ExecutorService;"),
            &[],
        )?
        .l()?;
    let executor = env.new_global_ref(&executor)?;
    let domain = env.new_string(domain)?;

    env.call_method(
        &resolver,
        jni_str!("rawQuery"),
        jni_sig!(
            "(Landroid/net/Network;Ljava/lang/String;IIILjava/util/concurrent/Executor;Landroid/os/CancellationSignal;Landroid/net/DnsResolver$Callback;)V"
        ),
        &[
            // The default network.
            JValue::Object(&JObject::null()),
            JValue::Object(domain.as_ref()),
            JValue::Int(CLASS_IN),
            JValue::Int(TYPE_HTTPS),
            // FLAG_EMPTY.
            JValue::Int(0),
            JValue::Object(executor.as_obj()),
            // No cancellation signal.
            JValue::Object(&JObject::null()),
            JValue::Object(proxy.as_ref()),
        ],
    )?;
    Ok(Some(PendingQuery {
        _proxy: proxy,
        executor,
    }))
}

/// What `DnsResolver.Callback` delivered. `equals`, `hashCode` and `toString`
/// are answered by the Java handler itself; only the two interface methods
/// reach the closure.
fn callback(
    env: &mut Env,
    method: JMethod,
    args: jni::objects::JObjectArray<JObject>,
) -> RawAnswer {
    match callback_inner(env, method, args) {
        Ok(answer) => answer,
        Err(error) => Err(error.to_string()),
    }
}

fn callback_inner(
    env: &mut Env,
    method: JMethod,
    args: jni::objects::JObjectArray<JObject>,
) -> Result<RawAnswer, jni::errors::Error> {
    match &*method.get_name(env)?.to_string() {
        "onAnswer" => {
            let answer = args.get_element(env, 0)?;
            let answer = JByteArray::cast_local(env, answer)?;
            Ok(Ok(env.convert_byte_array(answer)?))
        }
        "onError" => {
            let error = args.get_element(env, 0)?;
            let message = env
                .call_method(
                    &error,
                    jni_str!("toString"),
                    jni_sig!("()Ljava/lang/String;"),
                    &[],
                )?
                .l()
                .and_then(|object| JString::cast_local(env, object))?;
            Ok(Err(message.to_string()))
        }
        other => Ok(Err(format!(
            "unexpected DnsResolver.Callback method {other}"
        ))),
    }
}

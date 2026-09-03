//! Android glue for the platform certificate verifier.
//!
//! On Android the system trust store is only reachable through the Java
//! runtime, so `rustls-platform-verifier` needs a `JavaVM` and an
//! `android.content.Context` before the first TLS handshake. zenwave takes
//! both from the `ndk-context` crate, the ecosystem's shared handle to the
//! Android runtime: `android-activity` and `ndk-glue` populate it before
//! `main` runs, and a host that embeds Rust in an existing app calls
//! `ndk_context::initialize_android_context` itself, once, from `JNI_OnLoad`.
//!
//! The Kotlin half of `rustls-platform-verifier` must also be on the class
//! path; see that crate's README for the Gradle dependency and the ProGuard
//! keep rule.

use std::sync::{Arc, OnceLock};

use jni::{objects::JObject, vm::JavaVM};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use rustls_platform_verifier::Verifier;

use crate::Error;

/// Hand the JVM to `rustls-platform-verifier` once.
pub(crate) fn ensure_initialized() -> Result<(), Error> {
    // The JVM handle is process-wide by nature; this only remembers that it
    // has been handed over.
    static HANDED_OVER: OnceLock<()> = OnceLock::new();
    if HANDED_OVER.get().is_some() {
        return Ok(());
    }

    // ndk-context panics with "android context was not initialized" when no
    // host (android-activity, ndk-glue, or a `JNI_OnLoad` calling
    // `ndk_context::initialize_android_context`) has registered the JVM: that
    // is the fail-fast path for a process that opens TLS connections without
    // an Android context.
    let context = ndk_context::android_context();
    if context.vm().is_null() || context.context().is_null() {
        return Err(Error::tls(
            "ndk-context holds a null JVM or Android context pointer; the host must register \
             real ones before TLS connections are opened",
        ));
    }

    // SAFETY: ndk-context stores the pointer the host obtained from the JVM.
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) };
    let raw_context: jni::sys::jobject = context.context().cast();
    vm.attach_current_thread(|env| {
        // SAFETY: the raw pointer is a global reference that the host keeps
        // alive; `as_cast_raw` borrows it without taking ownership, and the
        // verifier stores its own global reference.
        let borrowed = unsafe { env.as_cast_raw::<JObject<'_>>(&raw_context)? };
        let local = env.new_local_ref(&*borrowed)?;
        rustls_platform_verifier::android::init_with_env(env, local)
    })
    .map_err(Error::tls)?;

    let _ = HANDED_OVER.set(());
    tracing::debug!("rustls-platform-verifier initialised through ndk-context");
    Ok(())
}

/// The platform verifier, with webpki over the extra roots as a second anchor set.
///
/// A chain is accepted when either accepts it; when both refuse, the platform's
/// error is reported because that is the trust store the user administers.
#[derive(Debug)]
pub(super) struct PlatformOrExtraRoots {
    pub(super) platform: Verifier,
    pub(super) extra: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for PlatformOrExtraRoots {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.platform.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(platform_error) => self
                .extra
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .map_err(|_| platform_error),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.platform.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.platform.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.platform.supported_verify_schemes()
    }
}

//! JNI entry points of the instrumented test app: `initialize` hands the JVM
//! and the application context to `ndk-context`, exactly as an app embedding
//! zenwave does from `JNI_OnLoad`; `runSuite` runs the TLS cases and returns
//! the failures, one per line, empty on success.

#[allow(dead_code)]
#[path = "../../../common/mod.rs"]
mod common;
mod suite;

use jni::{
    EnvUnowned,
    errors::{Error, ThrowRuntimeExAndDefault},
    objects::{JClass, JObject, JString},
};

#[unsafe(no_mangle)]
pub extern "system" fn Java_cool_lexo_zenwave_androidtest_ZenwaveNative_initialize<'frame>(
    mut env: EnvUnowned<'frame>,
    _class: JClass<'frame>,
    context: JObject<'frame>,
) {
    env.with_env(|env| -> Result<(), Error> {
        let vm = env.get_java_vm()?;
        let context = env.new_global_ref(&context)?;
        // SAFETY: both pointers come from the running JVM; the global
        // reference is handed over for the lifetime of the process, which is
        // what ndk-context expects.
        unsafe {
            ndk_context::initialize_android_context(vm.get_raw().cast(), context.into_raw().cast());
        }
        Ok(())
    })
    .resolve::<ThrowRuntimeExAndDefault>();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_cool_lexo_zenwave_androidtest_ZenwaveNative_runSuite<'frame>(
    mut env: EnvUnowned<'frame>,
    _class: JClass<'frame>,
) -> JString<'frame> {
    env.with_env(|env| -> Result<JString<'frame>, Error> {
        let report = smol::block_on(suite::run());
        env.new_string(report)
    })
    .resolve::<ThrowRuntimeExAndDefault>()
}

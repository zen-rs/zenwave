//! JNI entry point of the instrumented test app: `runSuite` runs the TLS
//! cases from a real application process — the one that reads the system
//! trust anchors under the app's own SELinux domain — and returns the
//! failures, one per line, empty on success.

#[allow(dead_code)]
#[path = "../../../common/mod.rs"]
mod common;
mod suite;

use jni::{
    EnvUnowned,
    errors::{Error, ThrowRuntimeExAndDefault},
    objects::{JClass, JString},
};

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

# rustls-platform-verifier is reached only through JNI, which shrinkers cannot see.
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }

# CMake toolchain for cross-compiling BoringSSL (`boring-sys` / `quiche`) to
# single-threaded WASI (`wasm32-wasip2` / `wasm32-wasip3`) with `wasi-sdk` 34+.
#
# Requires `WASI_SDK_PATH` in the environment. `CMAKE_SYSTEM_NAME` is `Generic`
# rather than `WASI` so BoringSSL's `CMakeLists.txt` skips
# `find_package(Threads REQUIRED)`. BoringSSL's `include/openssl/target.h`
# recognizes `__wasm32__` and draws entropy from `<unistd.h>`'s `getentropy`,
# while its socket, POSIX fd BIO, assembly and threading paths are disabled
# explicitly below.
#
# During top-level configure this toolchain merges the target's exceptionless
# `noeh/libc++.a` and `noeh/libc++abi.a` from the WASI sysroot into
# `${CMAKE_BINARY_DIR}/lib/libc++.a`, which `boring-sys` searches when
# `BORING_BSSL_RUST_CPPLIB=c++` is set.

if(NOT DEFINED ENV{WASI_SDK_PATH} OR "$ENV{WASI_SDK_PATH}" STREQUAL "")
  message(FATAL_ERROR "WASI_SDK_PATH must be set to a wasi-sdk-34+ directory")
endif()
set(WASI_SDK "$ENV{WASI_SDK_PATH}")

if(NOT DEFINED ENV{TARGET} OR NOT "$ENV{TARGET}" MATCHES "^wasm32-wasip[123]$")
  message(FATAL_ERROR "TARGET must be wasm32-wasip1, wasm32-wasip2 or wasm32-wasip3 (got '$ENV{TARGET}')")
endif()
set(_wasi_target "$ENV{TARGET}")

set(_wasi_sysroot "${WASI_SDK}/share/wasi-sysroot")
set(_wasi_libcxx "${_wasi_sysroot}/lib/${_wasi_target}/noeh/libc++.a")
set(_wasi_libcxxabi "${_wasi_sysroot}/lib/${_wasi_target}/noeh/libc++abi.a")

foreach(_required
  "${WASI_SDK}/bin/clang"
  "${WASI_SDK}/bin/clang++"
  "${WASI_SDK}/bin/llvm-ar"
  "${WASI_SDK}/bin/llvm-ranlib"
  "${_wasi_sysroot}/include/${_wasi_target}"
  "${_wasi_libcxx}"
  "${_wasi_libcxxabi}"
)
  if(NOT EXISTS "${_required}")
    message(FATAL_ERROR "wasi-sdk installation at '${WASI_SDK}' is missing '${_required}' (wasi-sdk-34+ required)")
  endif()
endforeach()

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR wasm32)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(OPENSSL_NO_ASM ON CACHE BOOL "" FORCE)

set(CMAKE_SYSROOT "${_wasi_sysroot}")
set(CMAKE_C_COMPILER "${WASI_SDK}/bin/clang")
set(CMAKE_C_COMPILER_ARG1 "--target=${_wasi_target}")
set(CMAKE_CXX_COMPILER "${WASI_SDK}/bin/clang++")
set(CMAKE_CXX_COMPILER_ARG1 "--target=${_wasi_target}")
set(CMAKE_AR "${WASI_SDK}/bin/llvm-ar" CACHE FILEPATH "" FORCE)
set(CMAKE_RANLIB "${WASI_SDK}/bin/llvm-ranlib" CACHE FILEPATH "" FORCE)

set(BSSL_WASI_FLAGS
  "-DOPENSSL_NO_ASM -DOPENSSL_NO_SOCK -DOPENSSL_NO_POSIX_IO -DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED"
)

if(NOT CMAKE_C_FLAGS MATCHES "OPENSSL_NO_SOCK")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${BSSL_WASI_FLAGS}" CACHE STRING "" FORCE)
endif()
if(NOT CMAKE_CXX_FLAGS MATCHES "OPENSSL_NO_SOCK")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${BSSL_WASI_FLAGS} -fno-exceptions -fno-rtti" CACHE STRING "" FORCE)
endif()

get_property(_in_try_compile GLOBAL PROPERTY IN_TRY_COMPILE)
if(NOT _in_try_compile AND NOT EXISTS "${CMAKE_BINARY_DIR}/lib/libc++.a")
  file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
  execute_process(
    COMMAND
      "${WASI_SDK}/bin/llvm-ar" qcL "${CMAKE_BINARY_DIR}/lib/libc++.a"
      "${_wasi_libcxx}" "${_wasi_libcxxabi}"
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND "${WASI_SDK}/bin/llvm-ranlib" "${CMAKE_BINARY_DIR}/lib/libc++.a"
    COMMAND_ERROR_IS_FATAL ANY
  )
endif()

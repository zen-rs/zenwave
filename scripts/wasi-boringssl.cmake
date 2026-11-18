# CMake toolchain for cross-compiling BoringSSL (`boring-sys` / `quiche`) to
# single-threaded WASI (`wasm32-wasip2` / `wasm32-wasip3`).
#
# `CMAKE_SYSTEM_NAME` is `Generic` rather than `WASI` so BoringSSL's
# `CMakeLists.txt` skips `find_package(Threads REQUIRED)`. BoringSSL's
# `include/openssl/target.h` already recognizes `__wasm32__` and falls back to
# `<unistd.h>`'s `getentropy`, while its socket, POSIX fd BIO, assembly and
# threading paths are disabled explicitly below.
#
# On `wasm32-wasip3`, Rust nightly's linker enables `--cooperative-threading`,
# which requires Clang >= 23 (`--target=wasm32-wasip3`) so object files use
# `__wasm_get_stack_pointer` / `__wasm_set_stack_pointer` instead of globals.
# When a `wasm32-wasip3`-capable Clang is present alongside Zig's WASI headers,
# it is selected automatically; otherwise `zig cc` / `zig c++` builds
# `wasm32-wasi` archives (sufficient for `wasm32-wasip2` linking and
# `wasm32-wasip3` `cargo clippy`).
#
# During top-level configure this toolchain also stages a static `libc++.a`
# (`libc++` + `libc++abi`) under `${CMAKE_BINARY_DIR}/lib`, which `boring-sys`
# searches when `BORING_BSSL_RUST_CPPLIB=c++` is set.

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR wasm32)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(OPENSSL_NO_ASM ON CACHE BOOL "" FORCE)

# `cmake-rs` seeds `CMAKE_<LANG>_FLAGS` from `cc-rs` with `--target=wasm32-wasip2`
# or `--target=wasm32-wasip3`, which `zig cc` rejects in favor of `-target wasm32-wasi`.
foreach(LANG C CXX ASM)
  if(DEFINED CMAKE_${LANG}_FLAGS)
    string(REGEX REPLACE "--target=[^ ]+" "" _stripped "${CMAKE_${LANG}_FLAGS}")
    set(CMAKE_${LANG}_FLAGS "${_stripped}" CACHE STRING "" FORCE)
  endif()
endforeach()

set(BSSL_WASI_FLAGS
  "-DOPENSSL_NO_ASM -DOPENSSL_NO_SOCK -DOPENSSL_NO_POSIX_IO -DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED -fno-sanitize=undefined"
)

get_property(_in_try_compile GLOBAL PROPERTY IN_TRY_COMPILE)

set(_use_wasip3_clang FALSE)
if("$ENV{TARGET}" STREQUAL "wasm32-wasip3" AND NOT DEFINED ENV{WASI_SDK_PATH})
  find_program(
    WASI_P3_CLANG
    NAMES clang
    HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
    NO_CMAKE_SYSTEM_PATH
  )
  if(NOT WASI_P3_CLANG)
    find_program(WASI_P3_CLANG NAMES clang)
  endif()
  find_program(
    WASI_P3_CLANGXX
    NAMES clang++
    HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
    NO_CMAKE_SYSTEM_PATH
  )
  if(NOT WASI_P3_CLANGXX)
    find_program(WASI_P3_CLANGXX NAMES clang++)
  endif()
  if(WASI_P3_CLANG AND WASI_P3_CLANGXX)
    execute_process(
      COMMAND "${WASI_P3_CLANG}" --target=wasm32-wasip3 -x c -E -
      INPUT_FILE /dev/null
      OUTPUT_QUIET
      ERROR_QUIET
      RESULT_VARIABLE _p3_check
    )
    if(_p3_check EQUAL 0)
      set(_use_wasip3_clang TRUE)
    endif()
  endif()
endif()

if(DEFINED ENV{WASI_SDK_PATH})
  set(WASI_SDK "$ENV{WASI_SDK_PATH}")
  set(CMAKE_SYSROOT "${WASI_SDK}/share/wasi-sysroot")
  set(CMAKE_C_COMPILER "${WASI_SDK}/bin/clang")
  set(CMAKE_C_COMPILER_ARG1 "--target=wasm32-wasip1")
  set(CMAKE_CXX_COMPILER "${WASI_SDK}/bin/clang++")
  set(CMAKE_CXX_COMPILER_ARG1 "--target=wasm32-wasip1")
  set(CMAKE_AR "${WASI_SDK}/bin/llvm-ar" CACHE FILEPATH "" FORCE)
  set(CMAKE_RANLIB "${WASI_SDK}/bin/llvm-ranlib" CACHE FILEPATH "" FORCE)
  if(NOT _in_try_compile AND NOT EXISTS "${CMAKE_BINARY_DIR}/lib/libc++.a")
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
    execute_process(
      COMMAND
        "${WASI_SDK}/bin/llvm-ar" qcL "${CMAKE_BINARY_DIR}/lib/libc++.a"
        "${WASI_SDK}/share/wasi-sysroot/lib/wasm32-wasip1/libc++.a"
        "${WASI_SDK}/share/wasi-sysroot/lib/wasm32-wasip1/libc++abi.a"
      COMMAND_ERROR_IS_FATAL ANY
    )
    execute_process(
      COMMAND "${WASI_SDK}/bin/llvm-ranlib" "${CMAKE_BINARY_DIR}/lib/libc++.a"
      COMMAND_ERROR_IS_FATAL ANY
    )
  endif()
elseif(_use_wasip3_clang)
  find_program(ZIG_EXECUTABLE zig REQUIRED)
  execute_process(
    COMMAND "${ZIG_EXECUTABLE}" env
    OUTPUT_VARIABLE _zig_env
    COMMAND_ERROR_IS_FATAL ANY
  )
  string(REGEX MATCH "lib_dir[\" ]*[:=][ \"]*([^\"]+)" _ "${_zig_env}")
  set(_zig_lib "${CMAKE_MATCH_1}")
  if(NOT _zig_lib)
    message(FATAL_ERROR "could not parse lib_dir from `zig env`")
  endif()

  find_program(
    WASI_LLVM_AR
    NAMES llvm-ar
    HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
    REQUIRED
  )
  find_program(
    WASI_LLVM_RANLIB
    NAMES llvm-ranlib
    HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
    REQUIRED
  )

  set(_libcpp_defs
    "-D_LIBCPP_ABI_VERSION=1 -D_LIBCPP_ABI_NAMESPACE=__1 -D_LIBCPP_HAS_THREADS=0 -D_LIBCPP_HAS_MONOTONIC_CLOCK -D_LIBCPP_HAS_TERMINAL -D_LIBCPP_HAS_MUSL_LIBC=1 -D_LIBCXXABI_DISABLE_VISIBILITY_ANNOTATIONS -D_LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS -D_LIBCPP_HAS_VENDOR_AVAILABILITY_ANNOTATIONS=0 -D_LIBCPP_HAS_FILESYSTEM=0 -D_LIBCPP_HAS_RANDOM_DEVICE -D_LIBCPP_HAS_LOCALIZATION -D_LIBCPP_HAS_UNICODE -D_LIBCPP_HAS_WIDE_CHARACTERS -D_LIBCPP_HAS_NO_STD_MODULES -D_LIBCPP_PSTL_BACKEND_SERIAL -D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE -D_LIBCPP_ASSERTION_SEMANTIC_DEFAULT=_LIBCPP_ASSERTION_SEMANTIC_IGNORE"
  )
  set(_sys_includes
    "-nostdlibinc -idirafter ${_zig_lib}/libc/include/wasm-wasi-musl -idirafter ${_zig_lib}/libc/include/generic-musl"
  )
  set(_cxx_includes
    "-nostdinc++ -isystem ${_zig_lib}/libcxx/include -isystem ${_zig_lib}/libcxxabi/include ${_sys_includes} ${_libcpp_defs}"
  )

  set(CMAKE_C_COMPILER "${WASI_P3_CLANG}")
  set(CMAKE_C_COMPILER_ARG1 "--target=wasm32-wasip3")
  set(CMAKE_CXX_COMPILER "${WASI_P3_CLANGXX}")
  set(CMAKE_CXX_COMPILER_ARG1 "--target=wasm32-wasip3")
  set(CMAKE_AR "${WASI_LLVM_AR}" CACHE FILEPATH "" FORCE)
  set(CMAKE_RANLIB "${WASI_LLVM_RANLIB}" CACHE FILEPATH "" FORCE)
  set(BSSL_WASI_C_EXTRA "${_sys_includes}")
  set(BSSL_WASI_CXX_EXTRA "${_cxx_includes}")

  if(NOT _in_try_compile AND NOT EXISTS "${CMAKE_BINARY_DIR}/lib/libc++.a")
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/lib/_cxx_objs")
    set(_cxx_rt_srcs
      "${_zig_lib}/libcxx/src/algorithm.cpp"
      "${_zig_lib}/libcxx/src/new.cpp"
      "${_zig_lib}/libcxx/src/new_helpers.cpp"
      "${_zig_lib}/libcxx/src/verbose_abort.cpp"
      "${_zig_lib}/libcxxabi/src/cxa_virtual.cpp"
      "${_zig_lib}/libcxxabi/src/abort_message.cpp"
    )
    set(_cxx_rt_objs)
    separate_arguments(_cxx_rt_flags UNIX_COMMAND "${_cxx_includes}")
    foreach(_src IN LISTS _cxx_rt_srcs)
      if(EXISTS "${_src}")
        get_filename_component(_stem "${_src}" NAME_WE)
        set(_obj "${CMAKE_BINARY_DIR}/lib/_cxx_objs/${_stem}.o")
        execute_process(
          COMMAND
            "${WASI_P3_CLANGXX}" --target=wasm32-wasip3 -std=c++23 -O2
            -fno-exceptions -fno-rtti ${_cxx_rt_flags}
            -I "${_zig_lib}/libcxx/src" -I "${_zig_lib}/libcxxabi/src"
            -D_LIBCPP_BUILDING_LIBRARY -DLIBCXX_BUILDING_LIBCXXABI
            -D_LIBCPP_HAS_NO_EXCEPTIONS -D_LIBCXXABI_HAS_NO_THREADS
            -c "${_src}" -o "${_obj}"
          COMMAND_ERROR_IS_FATAL ANY
        )
        list(APPEND _cxx_rt_objs "${_obj}")
      endif()
    endforeach()
    execute_process(
      COMMAND "${WASI_LLVM_AR}" qc "${CMAKE_BINARY_DIR}/lib/libc++.a" ${_cxx_rt_objs}
      COMMAND_ERROR_IS_FATAL ANY
    )
    execute_process(
      COMMAND "${WASI_LLVM_RANLIB}" "${CMAKE_BINARY_DIR}/lib/libc++.a"
      COMMAND_ERROR_IS_FATAL ANY
    )
    file(REMOVE_RECURSE "${CMAKE_BINARY_DIR}/lib/_cxx_objs")
  endif()
else()
  find_program(ZIG_EXECUTABLE zig REQUIRED)
  set(CMAKE_C_COMPILER "${ZIG_EXECUTABLE}")
  set(CMAKE_C_COMPILER_ARG1 "cc -target wasm32-wasi")
  set(CMAKE_CXX_COMPILER "${ZIG_EXECUTABLE}")
  set(CMAKE_CXX_COMPILER_ARG1 "c++ -target wasm32-wasi")
  find_program(
    WASI_LLVM_AR
    NAMES llvm-ar
    HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
  )
  find_program(
    WASI_LLVM_RANLIB
    NAMES llvm-ranlib
    HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
  )
  if(WASI_LLVM_AR AND WASI_LLVM_RANLIB)
    set(CMAKE_AR "${WASI_LLVM_AR}" CACHE FILEPATH "" FORCE)
    set(CMAKE_RANLIB "${WASI_LLVM_RANLIB}" CACHE FILEPATH "" FORCE)
  else()
    set(CMAKE_C_ARCHIVE_CREATE "${ZIG_EXECUTABLE} ar qc <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_CXX_ARCHIVE_CREATE "${ZIG_EXECUTABLE} ar qc <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_C_ARCHIVE_FINISH "${ZIG_EXECUTABLE} ranlib <TARGET>")
    set(CMAKE_CXX_ARCHIVE_FINISH "${ZIG_EXECUTABLE} ranlib <TARGET>")
  endif()
  if(NOT _in_try_compile AND NOT EXISTS "${CMAKE_BINARY_DIR}/lib/libc++.a")
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
    set(_probe_src "${CMAKE_BINARY_DIR}/lib/_cxx_probe.cc")
    set(_probe_wasm "${CMAKE_BINARY_DIR}/lib/_cxx_probe.wasm")
    file(WRITE "${_probe_src}" "extern \"C\" void _bssl_cxx_probe(void) {}\n")
    execute_process(
      COMMAND
        "${CMAKE_COMMAND}" -E env ZIG_VERBOSE_LINK=1
        "${ZIG_EXECUTABLE}" c++ -target wasm32-wasi -mexec-model=reactor
        -fno-exceptions -fno-rtti "${_probe_src}" -o "${_probe_wasm}" -v
      OUTPUT_VARIABLE _zig_out
      ERROR_VARIABLE _zig_err
      RESULT_VARIABLE _zig_res
    )
    file(REMOVE "${_probe_src}" "${_probe_wasm}")
    if(NOT _zig_res EQUAL 0)
      message(FATAL_ERROR "zig c++ WASI C++ runtime probe failed: ${_zig_err}")
    endif()
    string(REGEX MATCH "[^ \t\r\n\"]+/libc\\+\\+\\.a" _zig_libcxx "${_zig_out}\n${_zig_err}")
    string(REGEX MATCH "[^ \t\r\n\"]+/libc\\+\\+abi\\.a" _zig_libcxxabi "${_zig_out}\n${_zig_err}")
    if(NOT _zig_libcxx OR NOT _zig_libcxxabi)
      message(FATAL_ERROR "could not locate zig WASI libc++.a / libc++abi.a in: ${_zig_err}")
    endif()
    execute_process(
      COMMAND "${ZIG_EXECUTABLE}" ar qcL "${CMAKE_BINARY_DIR}/lib/libc++.a" "${_zig_libcxx}" "${_zig_libcxxabi}"
      COMMAND_ERROR_IS_FATAL ANY
    )
    execute_process(
      COMMAND "${ZIG_EXECUTABLE}" ranlib "${CMAKE_BINARY_DIR}/lib/libc++.a"
      COMMAND_ERROR_IS_FATAL ANY
    )
  endif()
endif()

if(NOT CMAKE_C_FLAGS MATCHES "OPENSSL_NO_SOCK")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${BSSL_WASI_C_EXTRA} ${BSSL_WASI_FLAGS}" CACHE STRING "" FORCE)
endif()
if(NOT CMAKE_CXX_FLAGS MATCHES "OPENSSL_NO_SOCK")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${BSSL_WASI_CXX_EXTRA} ${BSSL_WASI_FLAGS} -fno-exceptions -fno-rtti" CACHE STRING "" FORCE)
endif()

# Build for the CacheFragSanitizer runtime support library.

add_custom_target(cfsan)

set(CFSAN_CFLAGS ${SANITIZER_COMMON_CFLAGS})
append_rtti_flag(OFF CFSAN_CFLAGS)
set(CFSAN_RTL_CFLAGS ${CFSAN_CFLAGS})

include_directories(..)

set(CFSAN_SOURCES
  cfsan.cc
  cfsan_interface.cc
  cfsan_interceptors.cc)

foreach (arch ${CFSAN_SUPPORTED_ARCH})
  add_compiler_rt_runtime(clang_rt.cfsan
    STATIC
    ARCHS ${arch}
    SOURCES ${CFSAN_SOURCES}
            $<TARGET_OBJECTS:RTInterception.${arch}>
            $<TARGET_OBJECTS:RTSanitizerCommon.${arch}>
            $<TARGET_OBJECTS:RTSanitizerCommonLibc.${arch}>
    CFLAGS ${CFSAN_RTL_CFLAGS})
  add_sanitizer_rt_symbols(clang_rt.cfsan
    ARCHS ${arch}
    EXTRA cfsan.syms.extra)
  add_dependencies(cfsan
    clang_rt.cfsan-${arch}
    clang_rt.cfsan-${arch}-symbols)
endforeach()

add_dependencies(compiler-rt cfsan)

if (COMPILER_RT_INCLUDE_TESTS)
  # TODO(bruening): add tests via add_subdirectory(tests)
endif()

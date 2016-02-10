# Build for the DeadStoreTuner runtime support library.

add_custom_target(dstune)

set(DSTUNE_CFLAGS ${SANITIZER_COMMON_CFLAGS})
append_no_rtti_flag(DSTUNE_CFLAGS)
set(DSTUNE_RTL_CFLAGS ${DSTUNE_CFLAGS})

include_directories(..)

set(DSTUNE_SOURCES
  dstune.cc
  dstune_interface.cc)

foreach (arch ${TSAN_SUPPORTED_ARCH})
  add_compiler_rt_runtime(clang_rt.dstune
    STATIC
    ARCHS ${arch}
    SOURCES ${DSTUNE_SOURCES}
            $<TARGET_OBJECTS:RTInterception.${arch}>
            $<TARGET_OBJECTS:RTSanitizerCommon.${arch}>
            $<TARGET_OBJECTS:RTSanitizerCommonLibc.${arch}>
    CFLAGS ${DSTUNE_RTL_CFLAGS})
  add_sanitizer_rt_symbols(clang_rt.dstune
    ARCHS ${arch}
    EXTRA dstune.syms.extra)
  add_dependencies(dstune
    clang_rt.dstune-${arch}
    clang_rt.dstune-${arch}-symbols)
endforeach()

add_dependencies(compiler-rt dstune)

if (COMPILER_RT_INCLUDE_TESTS)
  # FIXME: add tests via add_subdirectory(tests)
endif()

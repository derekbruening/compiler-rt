//===-- dstune_interface.h ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DeadStoreTuner (dstune), a dead store detector.
//
// The functions declared in this header will be inserted by the instrumentation
// module.
// This header can be included by the instrumented program or by dstune tests.
//===----------------------------------------------------------------------===//
#ifndef DSTUNE_INTERFACE_H
#define DSTUNE_INTERFACE_H

#include <sanitizer_common/sanitizer_internal_defs.h>

// This header should NOT include any other headers.
// All functions in this header are extern "C" and start with __dstune_.

#ifdef __cplusplus
extern "C" {
#endif

// This function should be called at the very beginning of the process,
// before any instrumented code is executed and before any call to malloc.
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_init();

SANITIZER_INTERFACE_ATTRIBUTE void __dstune_read1(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_read2(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_read4(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_read8(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_read16(void *Addr);

SANITIZER_INTERFACE_ATTRIBUTE void __dstune_write1(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_write2(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_write4(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_write8(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_write16(void *Addr);

SANITIZER_INTERFACE_ATTRIBUTE void __dstune_unaligned_read2(const void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_unaligned_read4(const void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_unaligned_read8(const void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_unaligned_read16(const void *Addr);

SANITIZER_INTERFACE_ATTRIBUTE void __dstune_unaligned_write2(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_unaligned_write4(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_unaligned_write8(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __dstune_unaligned_write16(void *Addr);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // DSTUNE_INTERFACE_H

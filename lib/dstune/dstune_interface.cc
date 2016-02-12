//===-- dstune_interface.cc -------------------------------------------------===//
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
//===----------------------------------------------------------------------===//

#include "dstune_interface.h"
#include "dstune.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

using namespace __dstune;  // NOLINT

void __dstune_init() {
  initializeLibrary();
}

// FIXME: put all of these in a header to ensure inlining -- though
// it would be better to manually inline the instru once we finalize it.

void __dstune_read1(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog1, false);
}

void __dstune_read2(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog2, false);
}

void __dstune_read4(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog4, false);
}

void __dstune_read8(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog8, false);
}

void __dstune_write1(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog1, true);
}

void __dstune_write2(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog2, true);
}

void __dstune_write4(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog4, true);
}

void __dstune_write8(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog8, true);
}

void __dstune_read16(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog8, false);
  processMemAccess(CALLERPC, (uptr)Addr + 8, kSizeLog8, false);
}

void __dstune_write16(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog8, true);
  processMemAccess(CALLERPC, (uptr)Addr + 8, kSizeLog8, true);
}

void __dstune_unaligned_read2(const void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 2, false);
}

void __dstune_unaligned_read4(const void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 4, false);
}

void __dstune_unaligned_read8(const void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 8, false);
}

void __dstune_unaligned_read16(const void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 16, false);
}

void __dstune_unaligned_write2(void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 2, true);
}

void __dstune_unaligned_write4(void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 4, true);
}

void __dstune_unaligned_write8(void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 8, true);
}

void __dstune_unaligned_write16(void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 16, true);
}

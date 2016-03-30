//===-- cfsan_interface.cc -------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of CacheFragSanitizer (cfsan), a cache fragmentation
// analysis tool.
//
//===----------------------------------------------------------------------===//

#include "cfsan_interface.h"
#include "cfsan.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

using namespace __cfsan;  // NOLINT

void __cfsan_init() {
  initializeLibrary();
}

// TODO(bruening): put all of these in a header to ensure inlining -- though
// we expect calling these to be rare as our instrumentation-inlined fastpath
// should handle all of the common cases.

void __cfsan_read1(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog1, false);
}

void __cfsan_read2(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog2, false);
}

void __cfsan_read4(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog4, false);
}

void __cfsan_read8(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog8, false);
}

void __cfsan_write1(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog1, true);
}

void __cfsan_write2(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog2, true);
}

void __cfsan_write4(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog4, true);
}

void __cfsan_write8(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog8, true);
}

void __cfsan_read16(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog8, false);
  processMemAccess(CALLERPC, (uptr)Addr + 8, kSizeLog8, false);
}

void __cfsan_write16(void *Addr) {
  processMemAccess(CALLERPC, (uptr)Addr, kSizeLog8, true);
  processMemAccess(CALLERPC, (uptr)Addr + 8, kSizeLog8, true);
}

void __cfsan_unaligned_read2(const void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 2, false);
}

void __cfsan_unaligned_read4(const void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 4, false);
}

void __cfsan_unaligned_read8(const void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 8, false);
}

void __cfsan_unaligned_read16(const void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 16, false);
}

void __cfsan_unaligned_write2(void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 2, true);
}

void __cfsan_unaligned_write4(void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 4, true);
}

void __cfsan_unaligned_write8(void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 8, true);
}

void __cfsan_unaligned_write16(void *Addr) {
  processUnalignedAccess(CALLERPC, (uptr)Addr, 16, true);
}

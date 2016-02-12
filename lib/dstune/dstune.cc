//===-- dstune.cc ---------------------------------------------------------===//
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
// Main file (entry points) for the Dstune run-time.
//===----------------------------------------------------------------------===//

#include "dstune.h"
#include "dstune_interface.h"
#include "sanitizer_common/sanitizer_common.h"

namespace __dstune {

bool DstuneIsInitialized;

void initializeLibrary() {
  // We assume there is only one thread during init.
  if (DstuneIsInitialized)
    return;
  DstuneIsInitialized = true;
  Printf("in dstune::%s\n", __FUNCTION__);//NOCHECKIN
  initializeInterceptors();
}

int finalizeLibrary() {
  Printf("in dstune::%s\n", __FUNCTION__);//NOCHECKIN
  return 0;
}

ALWAYS_INLINE USED
void processMemAccess(uptr PC, uptr Addr, int SizeLog, bool IsWrite) {
  Printf("in dstune::%s %p: %c %p %d\n", __FUNCTION__, PC,
         IsWrite ? 'w' : 'r', Addr, 1 << SizeLog);
}

ALWAYS_INLINE USED
void processUnalignedAccess(uptr PC, uptr Addr, int Size, bool IsWrite) {
  Printf("in dstune::%s %p: %c %p %d\n", __FUNCTION__, PC,
         IsWrite ? 'w' : 'r', Addr, Size);
}

void processRangeAccess(uptr PC, uptr Addr, int Size, bool IsWrite) {
  Printf("in dstune::%s %p: %c %p %d\n", __FUNCTION__, PC,
         IsWrite ? 'w' : 'r', Addr, Size);
}

}  // namespace __dstune
